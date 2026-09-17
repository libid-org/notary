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
//!
//! The lock only orders what is read after it: every transaction here is
//! begun `READ COMMITTED` explicitly, so the read sees what the previous
//! holder committed. Under a `REPEATABLE READ` default the snapshot would be
//! taken before the lock was granted, and two racers would both see room.
//!
//! Every connection carries a lock, statement and idle-in-transaction
//! timeout. Without them a lock held elsewhere, or a database that stops
//! answering, parks a call forever; five such calls pin the whole pool and
//! every other client is refused for as long as the stall lasts.

use std::{
    str::FromStr,
    time::Duration,
};

use async_trait::async_trait;
use sqlx::{
    postgres::{
        PgConnectOptions,
        PgPoolOptions,
    },
    Connection,
    Executor,
    PgConnection,
    PgPool,
    Postgres,
    Transaction,
};

use super::{
    Dimension,
    LeaseId,
    LimitStore,
    PostgresUrl,
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

/// Set on every connection, in milliseconds. A call that waits longer than
/// this for a client's lock, for a statement, or between statements of its
/// own transaction fails instead of keeping its pool slot: one request is
/// refused, and the other connections keep answering everyone else.
const SESSION_OPTIONS: [(&str, &str); 3] = [
    ("lock_timeout", "1000"),
    ("statement_timeout", "2000"),
    ("idle_in_transaction_session_timeout", "5000"),
];

/// How every transaction here begins. Pinned rather than inherited:
/// `default_transaction_isolation` is settable per role, per database and
/// per server, and under `REPEATABLE READ` the advisory lock no longer
/// orders the reads (see the module docs).
const BEGIN_READ_COMMITTED: &str = "BEGIN ISOLATION LEVEL READ COMMITTED";

/// The advisory lock the schema is created under. Replicas start together,
/// and two `CREATE TABLE IF NOT EXISTS` racing on one name fail on the
/// catalog's unique index instead of one of them winning.
const SCHEMA_LOCK: i64 = 0x6e6f_7461_7279_5f6c; // "notary_l"

/// When a window row ends, as the sweep's index and its predicate both
/// spell it. `timestamptz + interval` is only STABLE -- it reads the
/// session time zone -- so it cannot be indexed; the same sum on the
/// UTC-naive timestamp is IMMUTABLE, and for a whole number of seconds
/// means the same instant.
macro_rules! window_end {
    () => {
        "((window_start AT TIME ZONE 'UTC') + make_interval(secs => window_secs))"
    };
}

/// Created at connect time, in this order, and never migrated: a column that
/// has to change gets a new table. An index may go: nothing reads one.
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
    // Superseded: the sweep's predicate is on the window's end, which a
    // start-only index cannot serve, and nothing else queried it.
    "DROP INDEX IF EXISTS notary_windows_window_start",
    concat!(
        "CREATE INDEX IF NOT EXISTS notary_windows_ends_at ON notary_windows (",
        window_end!(),
        ")"
    ),
];

/// The sweep's half for windows: every row whose window has ended. The
/// predicate is the indexed expression verbatim, so the planner can use
/// `notary_windows_ends_at` rather than scan the table.
const SWEEP_WINDOWS: &str = concat!(
    "DELETE FROM notary_windows WHERE ",
    window_end!(),
    " < (now() AT TIME ZONE 'UTC')"
);

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
    ///
    /// The schema goes in over a connection of its own, opened under
    /// `CONNECT_TIMEOUT`: the pool bounds every acquire, the first
    /// included, by `ACQUIRE_TIMEOUT`, which is right for a request and
    /// short for a cold start. The pool itself connects on first use.
    pub async fn connect(url: &str) -> Result<Self, StoreError> {
        let description = format!("postgres ({})", PostgresUrl::new(url));
        let connect = async {
            let options = PgConnectOptions::from_str(url)?.options(SESSION_OPTIONS);
            let mut conn = PgConnection::connect_with(&options).await?;
            create_schema(&mut conn).await?;
            conn.close().await?;
            let pool = PgPoolOptions::new()
                .max_connections(MAX_CONNECTIONS)
                .acquire_timeout(ACQUIRE_TIMEOUT)
                .connect_lazy_with(options);
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

    /// A pooled transaction at the isolation this module is written for.
    async fn begin(&self) -> Result<Transaction<'static, Postgres>, sqlx::Error> {
        self.pool.begin_with(BEGIN_READ_COMMITTED).await
    }
}

async fn create_schema(conn: &mut PgConnection) -> Result<(), sqlx::Error> {
    let mut tx = conn.begin_with(BEGIN_READ_COMMITTED).await?;
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
        let mut tx = self.begin().await?;
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
        let windows = limits.distinct();
        if windows.is_empty() {
            return Ok(true);
        }
        let client = client.to_string();
        let mut tx = self.begin().await?;
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
        for w in limits.distinct() {
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
        let windows = limits.distinct();
        if windows.is_empty() {
            return Ok(());
        }
        let db_units = as_db_units(units)?;
        let client = client.to_string();
        // One transaction: a connection lost mid-way must not leave the
        // short windows charged and the long ones not.
        let mut tx = self.begin().await?;
        for w in windows {
            add(&mut *tx, &client, dimension, w.window, db_units).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn sweep(&self) -> Result<u64, StoreError> {
        let leases = sqlx::query("DELETE FROM notary_leases WHERE expires_at <= now()")
            .execute(&self.pool)
            .await?
            .rows_affected();
        let windows = sqlx::query(SWEEP_WINDOWS)
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

    /// `NOTARY_TEST_DATABASE_URL`, or `None` with a note: a checkout
    /// without a database still passes, and CI with one runs these with no
    /// extra flags. CI without one is a broken workflow, not a checkout
    /// without a database: it fails here rather than passing on skips.
    fn url() -> Option<String> {
        match std::env::var("NOTARY_TEST_DATABASE_URL") {
            Ok(url) if !url.trim().is_empty() => Some(url),
            _ if std::env::var_os("CI").is_some() => panic!(
                "NOTARY_TEST_DATABASE_URL is unset under CI: the Postgres store tests \
                 would skip silently. Restore the env line on the test step in \
                 .github/workflows/ci.yml"
            ),
            _ => {
                println!("skipped: NOTARY_TEST_DATABASE_URL not set");
                None
            }
        }
    }

    /// The store under [`url`], or `None` when there is none.
    async fn store() -> Result<Option<PostgresStore>, StoreError> {
        match url() {
            Some(url) => Ok(Some(PostgresStore::connect(&url).await?)),
            None => Ok(None),
        }
    }

    /// Twenty tasks ask for a lease at once, four allowed; how many got one.
    async fn leases_granted_to_twenty_racers(
        store: Arc<PostgresStore>,
    ) -> Result<usize, StoreError> {
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
        Ok(granted)
    }

    /// Twenty tasks count one upgrade at once, four allowed in the hour;
    /// how many were counted.
    async fn counts_granted_to_twenty_racers(
        store: Arc<PostgresStore>,
    ) -> Result<usize, StoreError> {
        let client = fresh_client();
        let limits = Arc::new("4/1h".parse::<WindowLimits>().unwrap());
        let racers: Vec<_> = (0..20)
            .map(|_| {
                let (store, limits) = (store.clone(), limits.clone());
                tokio::spawn(async move {
                    store.count(&client, Dimension::Upgrades, 1, &limits).await
                })
            })
            .collect();
        let mut counted = 0;
        for racer in racers {
            if racer.await.expect("racer ran")? {
                counted += 1;
            }
        }
        Ok(counted)
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
        assert_eq!(leases_granted_to_twenty_racers(Arc::new(store)).await?, 4);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn twenty_racers_count_exactly_four() -> Result<(), StoreError> {
        let Some(store) = store().await? else {
            return Ok(());
        };
        assert_eq!(counts_granted_to_twenty_racers(Arc::new(store)).await?, 4);
        Ok(())
    }

    /// `name` as an SQL identifier: `ALTER DATABASE` takes a name, not a
    /// parameter.
    fn quote_ident(name: &str) -> String {
        format!("\"{}\"", name.replace('"', "\"\""))
    }

    /// The isolation is pinned per transaction, not inherited: with the
    /// database defaulting to `REPEATABLE READ`, a store that merely
    /// `BEGIN`s takes its snapshot before the advisory lock and grants
    /// twice the cap. The default is set database-wide, which is where an
    /// operator would set it, and reset whether or not the racers pass. A
    /// test process killed in between leaves it set; `ALTER DATABASE ...
    /// RESET default_transaction_isolation` puts it back.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn twenty_racers_get_exactly_four_under_repeatable_read(
    ) -> Result<(), StoreError> {
        let Some(url) = url() else {
            return Ok(());
        };
        let mut admin = PgConnection::connect(&url).await?;
        let db: String = sqlx::query_scalar("SELECT current_database()")
            .fetch_one(&mut admin)
            .await?;
        let db = quote_ident(&db);
        sqlx::query(&format!(
            "ALTER DATABASE {db} SET default_transaction_isolation = 'repeatable read'"
        ))
        .execute(&mut admin)
        .await?;
        // A task of its own, so a panic inside is a `JoinError` here and the
        // reset below still runs.
        let outcome = tokio::spawn(async move {
            let store = Arc::new(PostgresStore::connect(&url).await?);
            let default: String =
                sqlx::query_scalar("SHOW default_transaction_isolation")
                    .fetch_one(&store.pool)
                    .await?;
            assert_eq!(default, "repeatable read", "the new default did not take");
            let leases = leases_granted_to_twenty_racers(store.clone()).await?;
            let counts = counts_granted_to_twenty_racers(store).await?;
            Ok::<_, StoreError>((leases, counts))
        })
        .await;
        sqlx::query(&format!(
            "ALTER DATABASE {db} RESET default_transaction_isolation"
        ))
        .execute(&mut admin)
        .await?;
        assert_eq!(outcome.expect("racers ran")?, (4, 4), "(leases, counts)");
        Ok(())
    }

    /// A client's lock held elsewhere (a replica mid-transaction, a stuck
    /// backend) fails that client's call within `lock_timeout` instead of
    /// parking it: the pool slot comes back, and other clients never notice.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_lock_held_elsewhere_fails_fast_for_that_client_only(
    ) -> Result<(), StoreError> {
        let Some(store) = store().await? else {
            return Ok(());
        };
        let url = url().expect("a store means a url");
        let (stuck, other) = (fresh_client(), fresh_client());
        let (locked_tx, locked_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let holder = tokio::spawn(async move {
            let mut conn = PgConnection::connect(&url).await?;
            // The same key `lock_client` takes, as a session lock.
            sqlx::query("SELECT pg_advisory_lock(hashtext($1)::bigint)")
                .bind(stuck.to_string())
                .execute(&mut conn)
                .await?;
            locked_tx.send(()).expect("test is waiting");
            // Released on request, or after long enough that a call with
            // no lock timeout comes back granted and fails the test rather
            // than hanging it.
            let _ = tokio::time::timeout(Duration::from_secs(8), release_rx).await;
            conn.close().await
        });
        locked_rx.await.expect("holder took the lock");

        let long = Duration::from_secs(60);
        let started = std::time::Instant::now();
        let err = store
            .try_lease(&stuck, 1, long)
            .await
            .expect_err("the lock is held");
        assert!(err.to_string().contains("lock timeout"), "{err}");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "took {:?}",
            started.elapsed()
        );
        assert!(
            store.try_lease(&other, 1, long).await?.is_some(),
            "another client, meanwhile"
        );

        release_tx.send(()).expect("holder is waiting");
        holder.await.expect("holder ran")?;
        assert!(
            store.try_lease(&stuck, 1, long).await?.is_some(),
            "once released"
        );
        Ok(())
    }

    /// The sweep's window predicate is served by `notary_windows_ends_at`:
    /// with sequential scans priced out, the planner reaches for it, which
    /// it can only do if the expression is indexable and matches the index
    /// verbatim. The old start-only index is gone.
    #[tokio::test]
    async fn the_sweep_predicate_is_indexed() -> Result<(), StoreError> {
        let Some(store) = store().await? else {
            return Ok(());
        };
        drop(store);
        let url = url().expect("a store means a url");
        let mut conn = PgConnection::connect(&url).await?;
        sqlx::query("SET enable_seqscan = off")
            .execute(&mut conn)
            .await?;
        let plan: Vec<String> = sqlx::query_scalar(&format!("EXPLAIN {SWEEP_WINDOWS}"))
            .fetch_all(&mut conn)
            .await?;
        let plan = plan.join("\n");
        assert!(
            plan.contains("Index Scan on notary_windows_ends_at")
                || plan.contains("Index Scan using notary_windows_ends_at"),
            "{plan}"
        );
        let old: Option<String> =
            sqlx::query_scalar("SELECT to_regclass('notary_windows_window_start')::text")
                .fetch_one(&mut conn)
                .await?;
        assert_eq!(old, None, "the start-only index was not dropped");
        Ok(())
    }

    #[tokio::test]
    async fn a_dead_database_is_an_error_with_the_password_redacted() {
        for (url, shown) in [
            (
                "postgres://notary:hunter2@127.0.0.1:1/limits",
                "postgres://notary:***@127.0.0.1:1/limits",
            ),
            (
                "postgres://notary@127.0.0.1:1/limits?password=hunter2",
                "postgres://notary:***@127.0.0.1:1/limits?password=***",
            ),
        ] {
            let err = PostgresStore::connect(url)
                .await
                .expect_err("nothing listens on port 1");
            let msg = err.to_string();
            assert!(msg.contains(&format!("postgres ({shown})")), "{msg}");
            assert!(!msg.contains("hunter2"), "{msg}");
        }
    }
}
