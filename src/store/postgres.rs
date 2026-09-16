//! The shared store: every replica's counts in one Postgres.
//!
//! Every comparison, and every window's start, uses the database's clock.
//! Pods disagree about the time by whatever their clocks drift; one clock
//! means one answer, and a lease's expiry means the same thing to the pod
//! that took it and the pod that sweeps it.
//!
//! `try_lease` and `count` read a client's state and then write it, and two
//! replicas doing that for the same client at once must not both see room.
//! Each takes a transaction-scoped advisory lock on the client's key first,
//! so the read-then-write of one client is serialised across every replica
//! while different clients never wait on each other.

use std::time::Duration;

use async_trait::async_trait;
use sqlx::{
    postgres::PgPoolOptions,
    Executor,
    PgPool,
    Postgres,
    Transaction,
};

use super::{
    distinct_windows,
    redact,
    Dimension,
    LeaseId,
    LimitStore,
    StoreError,
    WindowLimits,
};
use crate::client_ip::ClientKey;

/// How long startup waits for the database, connection and schema together.
/// A database that is down should fail the process, not hang it.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A limit store keeps a connection only for the length of one small
/// transaction, so a handful is enough; a request that cannot get one within
/// this is refused rather than queued behind a stalled database.
const MAX_CONNECTIONS: u32 = 5;
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(2);

/// The advisory lock the schema is created under. Replicas start together,
/// and two `CREATE TABLE IF NOT EXISTS` racing on one name fail on the
/// catalog's unique index instead of one of them winning.
const SCHEMA_LOCK: i64 = 0x6e6f_7461_7279_5f6c; // "notary_l"

/// Created at connect time, in this order, and never migrated: a column that
/// has to change gets a new table.
const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS notary_leases (
        lease_id uuid PRIMARY KEY,
        client_key text NOT NULL,
        expires_at timestamptz NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS notary_leases_client_key_expires_at
        ON notary_leases (client_key, expires_at)",
    "CREATE TABLE IF NOT EXISTS notary_windows (
        client_key text NOT NULL,
        dimension text NOT NULL,
        window_secs bigint NOT NULL,
        window_start timestamptz NOT NULL,
        units bigint NOT NULL DEFAULT 0,
        PRIMARY KEY (client_key, dimension, window_secs, window_start)
    )",
    "CREATE INDEX IF NOT EXISTS notary_windows_window_start
        ON notary_windows (window_start)",
];

// The start of the window `$3` seconds long that the database's `now()`
// falls in: fixed windows, so a count is one upsert on a key every replica
// computes the same way.
const READ_WINDOW: &str = "SELECT units FROM notary_windows
    WHERE client_key = $1 AND dimension = $2 AND window_secs = $3
      AND window_start = to_timestamp(floor(extract(epoch FROM now()) / $3) * $3)";

const UPSERT_WINDOW: &str = "INSERT INTO notary_windows
        (client_key, dimension, window_secs, window_start, units)
    VALUES ($1, $2, $3, to_timestamp(floor(extract(epoch FROM now()) / $3) * $3), $4)
    ON CONFLICT (client_key, dimension, window_secs, window_start)
    DO UPDATE SET units = notary_windows.units + EXCLUDED.units";

impl From<sqlx::Error> for StoreError {
    fn from(e: sqlx::Error) -> Self {
        Self(e.to_string())
    }
}

/// Per-client counts in Postgres, shared by every replica.
#[derive(Debug)]
pub struct PostgresStore {
    pool: PgPool,
    description: String,
}

impl PostgresStore {
    /// Connect to `url`, create the tables if they are missing, and fail
    /// within ten seconds if the database does not answer. The URL's
    /// password never appears in the error.
    pub async fn connect(url: &str) -> Result<Self, StoreError> {
        let description = format!("postgres ({})", redact(url));
        let connect = async {
            let pool = PgPoolOptions::new()
                .max_connections(MAX_CONNECTIONS)
                .acquire_timeout(ACQUIRE_TIMEOUT)
                .connect(url)
                .await?;
            create_schema(&pool).await?;
            Ok::<_, sqlx::Error>(pool)
        };
        let pool = tokio::time::timeout(CONNECT_TIMEOUT, connect)
            .await
            .map_err(|_| {
                StoreError(format!(
                    "{description}: no answer within {}s",
                    CONNECT_TIMEOUT.as_secs()
                ))
            })?
            .map_err(|e| StoreError(format!("{description}: {e}")))?;
        Ok(Self { pool, description })
    }
}

async fn create_schema(pool: &PgPool) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(SCHEMA_LOCK)
        .execute(&mut *tx)
        .await?;
    for statement in SCHEMA {
        sqlx::query(statement).execute(&mut *tx).await?;
    }
    tx.commit().await
}

/// Serialise every read-then-write for `client` across all replicas, for
/// the rest of this transaction.
async fn lock_client(
    tx: &mut Transaction<'_, Postgres>,
    client: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
        .bind(client)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// `units` as the column type; a count past `i64` is not a count anyone set.
fn as_db_units(units: u64) -> Result<i64, StoreError> {
    i64::try_from(units)
        .map_err(|_| StoreError(format!("{units} units do not fit a bigint")))
}

/// What `client` has used of `dimension` in the current window of length
/// `window`; nothing, if no row yet.
async fn used<'e, E>(
    exec: E,
    client: &str,
    dimension: Dimension,
    window: Duration,
) -> Result<u64, StoreError>
where
    E: Executor<'e, Database = Postgres>,
{
    let used: Option<i64> = sqlx::query_scalar(READ_WINDOW)
        .bind(client)
        .bind(dimension.as_str())
        .bind(as_db_units(window.as_secs())?)
        .fetch_optional(exec)
        .await?;
    Ok(used.map_or(0, |u| u64::try_from(u).unwrap_or(0)))
}

/// Add `units` to `client`'s current window of length `window`.
async fn add<'e, E>(
    exec: E,
    client: &str,
    dimension: Dimension,
    window: Duration,
    units: i64,
) -> Result<(), StoreError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query(UPSERT_WINDOW)
        .bind(client)
        .bind(dimension.as_str())
        .bind(as_db_units(window.as_secs())?)
        .bind(units)
        .execute(exec)
        .await?;
    Ok(())
}

#[async_trait]
impl LimitStore for PostgresStore {
    async fn try_lease(
        &self,
        client: &ClientKey,
        limit: usize,
        ttl: Duration,
    ) -> Result<Option<LeaseId>, StoreError> {
        let client = client.to_string();
        let mut tx = self.pool.begin().await?;
        lock_client(&mut tx, &client).await?;
        let live: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM notary_leases WHERE client_key = $1 AND expires_at > now()",
        )
        .bind(&client)
        .fetch_one(&mut *tx)
        .await?;
        if live >= i64::try_from(limit).unwrap_or(i64::MAX) {
            tx.commit().await?;
            return Ok(None);
        }
        let id = LeaseId::new();
        sqlx::query(
            "INSERT INTO notary_leases (lease_id, client_key, expires_at)
             VALUES ($1, $2, now() + make_interval(secs => $3))",
        )
        .bind(id.0)
        .bind(&client)
        .bind(ttl.as_secs_f64())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some(id))
    }

    async fn release(&self, lease: &LeaseId) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM notary_leases WHERE lease_id = $1")
            .bind(lease.0)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn count(
        &self,
        client: &ClientKey,
        dimension: Dimension,
        units: u64,
        limits: &WindowLimits,
    ) -> Result<bool, StoreError> {
        let windows = distinct_windows(limits);
        if windows.is_empty() {
            return Ok(true);
        }
        let client = client.to_string();
        let mut tx = self.pool.begin().await?;
        lock_client(&mut tx, &client).await?;
        for w in &windows {
            let used = used(&mut *tx, &client, dimension, w.window).await?;
            if used.saturating_add(units) > w.limit {
                tx.commit().await?;
                return Ok(false);
            }
        }
        let db_units = as_db_units(units)?;
        for w in &windows {
            add(&mut *tx, &client, dimension, w.window, db_units).await?;
        }
        tx.commit().await?;
        Ok(true)
    }

    async fn would_fit(
        &self,
        client: &ClientKey,
        dimension: Dimension,
        units: u64,
        limits: &WindowLimits,
    ) -> Result<bool, StoreError> {
        let client = client.to_string();
        for w in distinct_windows(limits) {
            let used = used(&self.pool, &client, dimension, w.window).await?;
            if used.saturating_add(units) > w.limit {
                return Ok(false);
            }
        }
        Ok(true)
    }

    async fn charge(
        &self,
        client: &ClientKey,
        dimension: Dimension,
        units: u64,
        limits: &WindowLimits,
    ) -> Result<(), StoreError> {
        let windows = distinct_windows(limits);
        if windows.is_empty() {
            return Ok(());
        }
        let db_units = as_db_units(units)?;
        let client = client.to_string();
        for w in windows {
            add(&self.pool, &client, dimension, w.window, db_units).await?;
        }
        Ok(())
    }

    async fn sweep(&self) -> Result<u64, StoreError> {
        let leases = sqlx::query("DELETE FROM notary_leases WHERE expires_at <= now()")
            .execute(&self.pool)
            .await?
            .rows_affected();
        let windows = sqlx::query(
            "DELETE FROM notary_windows
             WHERE window_start + make_interval(secs => window_secs) < now()",
        )
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(leases + windows)
    }

    fn describe(&self) -> String {
        self.description.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::store::tests::{
        conformance,
        fresh_client,
    };

    /// The store under `NOTARY_TEST_DATABASE_URL`, or `None` with a note:
    /// a checkout without a database still passes, and CI with one runs
    /// these with no extra flags.
    async fn store() -> Result<Option<PostgresStore>, StoreError> {
        match std::env::var("NOTARY_TEST_DATABASE_URL") {
            Ok(url) if !url.trim().is_empty() => {
                Ok(Some(PostgresStore::connect(&url).await?))
            }
            _ => {
                println!("skipped: NOTARY_TEST_DATABASE_URL not set");
                Ok(None)
            }
        }
    }

    #[tokio::test]
    async fn conforms() -> Result<(), StoreError> {
        let Some(store) = store().await? else {
            return Ok(());
        };
        assert!(store.describe().starts_with("postgres ("));
        conformance(&store).await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn twenty_racers_get_exactly_four_leases() -> Result<(), StoreError> {
        let Some(store) = store().await? else {
            return Ok(());
        };
        let store = Arc::new(store);
        let client = fresh_client();
        let racers: Vec<_> = (0..20)
            .map(|_| {
                let store = store.clone();
                tokio::spawn(async move {
                    store.try_lease(&client, 4, Duration::from_secs(60)).await
                })
            })
            .collect();
        let mut granted = 0;
        for racer in racers {
            if racer.await.expect("racer ran")?.is_some() {
                granted += 1;
            }
        }
        assert_eq!(granted, 4);
        Ok(())
    }

    #[tokio::test]
    async fn a_dead_database_is_an_error_with_the_password_redacted() {
        let err = PostgresStore::connect("postgres://notary:hunter2@127.0.0.1:1/limits")
            .await
            .expect_err("nothing listens on port 1");
        let msg = err.to_string();
        assert!(
            msg.contains("postgres (postgres://notary:***@127.0.0.1:1/limits)"),
            "{msg}"
        );
        assert!(!msg.contains("hunter2"), "{msg}");
    }
}
