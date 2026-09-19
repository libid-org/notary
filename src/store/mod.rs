//! Where the public listener's per-client limits are counted.
//!
//! The counts have to be shared across every replica, because the load
//! balancer spreads one client's connections over all of them: counted per
//! pod, every limit is silently multiplied by the replica count. So the
//! public listener asks a [`LimitStore`] before it spends anything on a
//! client, and the store answers from state every replica can see.
//!
//! Two kinds of limit live here:
//!
//! - **Leases** bound how many sessions a client holds *now*. A lease is
//!   released when its session ends, and expires by itself after the
//!   session's deadline, so a replica that dies holding leases costs its
//!   clients at most one deadline of quota, once. Nothing about which pod
//!   held a lease is recorded: a pod's name changes on every restart, and
//!   the deadline already bounds the leak.
//! - **Windows** bound how much of something a client did over a period:
//!   upgrades started, bytes relayed. Fixed windows, keyed by the period
//!   they started in, so a count is one upsert.
//!
//! Every method is one atomic step. A store that cannot answer returns an
//! error, and the public listener treats that as "no": a limit that fails
//! open under a store outage is a limit that an attacker can switch off.

use std::{
    fmt,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use bytesize::ByteSize;
use url::Url;

use crate::client_ip::ClientKey;

mod memory;
mod postgres;

pub use memory::MemoryStore;
pub use postgres::PostgresStore;

/// At most `limit` units per `window`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowLimit {
    pub limit: u64,
    pub window: Duration,
}

/// A set of windows that must all have room, e.g. a minute, a half hour and
/// an hour. Empty means the dimension is unlimited.
///
/// Parsed from a comma-separated list of `<limit>/<window>`. A limit is a
/// count, or bytes with a `KB`/`MB`/`GB` suffix (powers of ten). A window is
/// `<n>s`, `<n>m` or `<n>h`.
///
/// ```text
/// 10/1m,60/30m,100/1h
/// 100MB/1m,600MB/30m,1GB/1h
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WindowLimits(pub Vec<WindowLimit>);

impl FromStr for WindowLimits {
    type Err = String;

    /// Parse a spec; the empty string is "unlimited".
    fn from_str(spec: &str) -> Result<Self, Self::Err> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Ok(Self::default());
        }
        let mut out = Vec::new();
        for entry in spec.split(',') {
            let entry = entry.trim();
            let (limit, window) = entry.split_once('/').ok_or_else(|| {
                format!("'{entry}': expected <limit>/<window>, e.g. 10/1m or 100MB/1h")
            })?;
            out.push(WindowLimit {
                limit: parse_units(limit.trim())?,
                window: parse_window(window.trim())?,
            });
        }
        out.sort_by_key(|w| w.window);
        Ok(Self(out))
    }
}

impl WindowLimits {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The longest window, which is how long any count has to be kept.
    pub fn longest(&self) -> Option<Duration> {
        self.0.iter().map(|w| w.window).max()
    }

    /// The windows a store keys on: one per length, the tightest limit
    /// winning. Two entries of the same length name the same row, and
    /// counting once per entry would charge every unit twice.
    pub fn distinct(&self) -> Vec<WindowLimit> {
        let mut out: Vec<WindowLimit> = Vec::with_capacity(self.0.len());
        for w in &self.0 {
            match out.iter_mut().find(|o| o.window == w.window) {
                Some(o) => o.limit = o.limit.min(w.limit),
                None => out.push(*w),
            }
        }
        out
    }
}

impl fmt::Display for WindowLimits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return write!(f, "unlimited");
        }
        for (i, w) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, ",")?;
            }
            write!(f, "{}/{}s", w.limit, w.window.as_secs())?;
        }
        Ok(())
    }
}

fn parse_units(s: &str) -> Result<u64, String> {
    let n = match s.parse::<u64>() {
        Ok(n) => n,
        Err(_) => s
            .parse::<ByteSize>()
            .map(|size| size.as_u64())
            .map_err(|_| format!("'{s}': not a count (10) or a size (100MB)"))?,
    };
    if n == 0 {
        return Err(format!(
            "'{s}': a limit of 0 admits nothing; omit the window instead"
        ));
    }
    Ok(n)
}

fn parse_window(s: &str) -> Result<Duration, String> {
    let window =
        humantime::parse_duration(s).map_err(|error| format!("'{s}': {error}"))?;
    if window.is_zero() {
        return Err(format!("'{s}': a window of zero length"));
    }
    if window.subsec_nanos() != 0 {
        return Err(format!("'{s}': a window is whole seconds"));
    }
    Ok(window)
}

/// What a window counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Dimension {
    /// Sessions started (WebSocket upgrades that reached a session).
    Upgrades,
    /// Bytes relayed, both directions, charged when a session ends.
    Bytes,
}

impl Dimension {
    /// The stable name a store keys on.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Upgrades => "upgrades",
            Self::Bytes => "bytes",
        }
    }
}

/// A held concurrency lease. Opaque; hand it back to [`LimitStore::release`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LeaseId(pub uuid::Uuid);

impl LeaseId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

impl Default for LeaseId {
    fn default() -> Self {
        Self::new()
    }
}

/// The store could not answer. The public listener refuses on this.
#[derive(Debug, thiserror::Error)]
#[error("limits store: {0}")]
pub struct StoreError(pub String);

/// Shared per-client limits. See the module docs for the two kinds.
pub(crate) trait LimitStore: Send + Sync + 'static {
    /// A lease for `client` if fewer than `limit` are live; `None` if not.
    /// The lease expires by itself after `ttl`.
    async fn try_lease(
        &self,
        client: &ClientKey,
        limit: usize,
        ttl: Duration,
    ) -> Result<Option<LeaseId>, StoreError>;

    /// Give a lease back. Releasing an expired or unknown lease is not an
    /// error.
    async fn release(&self, lease: &LeaseId) -> Result<(), StoreError>;

    /// Count `units` of `dimension` for `client` if every window in `limits`
    /// still has room for them; `Ok(false)` and nothing counted otherwise.
    /// Empty `limits` always fits.
    async fn count(
        &self,
        client: &ClientKey,
        dimension: Dimension,
        units: u64,
        limits: &WindowLimits,
    ) -> Result<bool, StoreError>;

    /// Whether `units` more of `dimension` would fit, counting nothing.
    async fn would_fit(
        &self,
        client: &ClientKey,
        dimension: Dimension,
        units: u64,
        limits: &WindowLimits,
    ) -> Result<bool, StoreError>;

    /// Record `units` of `dimension` whether or not they fit. For what has
    /// already happened -- bytes a finished session relayed.
    async fn charge(
        &self,
        client: &ClientKey,
        dimension: Dimension,
        units: u64,
        limits: &WindowLimits,
    ) -> Result<(), StoreError>;

    /// Drop expired leases and windows nothing will read again. Returns how
    /// many rows went. Safe to run from every replica at once.
    async fn sweep(&self) -> Result<u64, StoreError>;

    /// One line for the startup log.
    fn describe(&self) -> String;
}

/// The store `spec` names, ready to use. A Postgres store connects and
/// creates its tables here, so a database that cannot be reached is a
/// startup error rather than a limit that fails closed on every request.
/// Where the shared counts live: `memory`, or a Postgres URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LimitsStoreSpec {
    /// In this process only. Correct for one replica; a multiplier otherwise.
    Memory,
    /// A Postgres URL.
    Postgres(PostgresUrl),
}

impl FromStr for LimitsStoreSpec {
    type Err = String;

    fn from_str(spec: &str) -> Result<Self, Self::Err> {
        let spec = spec.trim();
        if spec == "memory" {
            return Ok(Self::Memory);
        }
        if spec.starts_with("postgres://") || spec.starts_with("postgresql://") {
            return Ok(Self::Postgres(PostgresUrl::new(spec)));
        }
        Err(format!(
            "expected \"memory\" or a postgres:// URL, got '{}'",
            PostgresUrl::new(spec)
        ))
    }
}

impl fmt::Display for LimitsStoreSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Memory => f.write_str("memory"),
            Self::Postgres(url) => write!(f, "postgres ({url})"),
        }
    }
}

/// Where the counts live, as `--limits-store` says: this process, or a
/// Postgres every replica shares. One handle, cloned into every session;
/// each call goes to the backend the variant names.
#[derive(Clone)]
pub enum Store {
    Memory(Arc<MemoryStore>),
    Postgres(Arc<PostgresStore>),
    /// A test double, chosen at run time, so it is boxed.
    #[cfg(test)]
    Fake(Arc<dyn FakeStore>),
}

impl Store {
    /// Connect as `spec` says. A store that cannot be reached is an error
    /// here, at startup, not a limit that refuses every client later.
    pub async fn connect(spec: &LimitsStoreSpec) -> Result<Self, StoreError> {
        Ok(match spec {
            LimitsStoreSpec::Memory => Self::memory(),
            LimitsStoreSpec::Postgres(url) => {
                Self::Postgres(Arc::new(PostgresStore::connect(url.as_str()).await?))
            }
        })
    }

    /// Counts kept in this process only.
    pub fn memory() -> Self {
        Self::Memory(Arc::new(MemoryStore::new()))
    }

    #[cfg(test)]
    pub(crate) fn fake(store: impl FakeStore) -> Self {
        Self::Fake(Arc::new(store))
    }
}

impl LimitStore for Store {
    async fn try_lease(
        &self,
        client: &ClientKey,
        limit: usize,
        ttl: Duration,
    ) -> Result<Option<LeaseId>, StoreError> {
        match self {
            Self::Memory(store) => store.try_lease(client, limit, ttl).await,
            Self::Postgres(store) => store.try_lease(client, limit, ttl).await,
            #[cfg(test)]
            Self::Fake(store) => store.try_lease(client, limit, ttl).await,
        }
    }
    async fn release(&self, lease: &LeaseId) -> Result<(), StoreError> {
        match self {
            Self::Memory(store) => store.release(lease).await,
            Self::Postgres(store) => store.release(lease).await,
            #[cfg(test)]
            Self::Fake(store) => store.release(lease).await,
        }
    }
    async fn count(
        &self,
        client: &ClientKey,
        dimension: Dimension,
        units: u64,
        limits: &WindowLimits,
    ) -> Result<bool, StoreError> {
        match self {
            Self::Memory(store) => store.count(client, dimension, units, limits).await,
            Self::Postgres(store) => store.count(client, dimension, units, limits).await,
            #[cfg(test)]
            Self::Fake(store) => store.count(client, dimension, units, limits).await,
        }
    }
    async fn would_fit(
        &self,
        client: &ClientKey,
        dimension: Dimension,
        units: u64,
        limits: &WindowLimits,
    ) -> Result<bool, StoreError> {
        match self {
            Self::Memory(store) => {
                store.would_fit(client, dimension, units, limits).await
            }
            Self::Postgres(store) => {
                store.would_fit(client, dimension, units, limits).await
            }
            #[cfg(test)]
            Self::Fake(store) => store.would_fit(client, dimension, units, limits).await,
        }
    }
    async fn charge(
        &self,
        client: &ClientKey,
        dimension: Dimension,
        units: u64,
        limits: &WindowLimits,
    ) -> Result<(), StoreError> {
        match self {
            Self::Memory(store) => store.charge(client, dimension, units, limits).await,
            Self::Postgres(store) => store.charge(client, dimension, units, limits).await,
            #[cfg(test)]
            Self::Fake(store) => store.charge(client, dimension, units, limits).await,
        }
    }
    async fn sweep(&self) -> Result<u64, StoreError> {
        match self {
            Self::Memory(store) => store.sweep().await,
            Self::Postgres(store) => store.sweep().await,
            #[cfg(test)]
            Self::Fake(store) => store.sweep().await,
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::Memory(store) => store.describe(),
            Self::Postgres(store) => store.describe(),
            #[cfg(test)]
            Self::Fake(store) => store.describe(),
        }
    }
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe())
    }
}

/// [`LimitStore`] for a test double: the same calls, boxed, because which
/// double a test wants is decided at run time.
#[cfg(test)]
#[async_trait::async_trait]
pub trait FakeStore: Send + Sync + 'static {
    /// A lease for `client` if fewer than `limit` are live; `None` if not.
    /// The lease expires by itself after `ttl`.
    async fn try_lease(
        &self,
        client: &ClientKey,
        limit: usize,
        ttl: Duration,
    ) -> Result<Option<LeaseId>, StoreError>;

    /// Give a lease back. Releasing an expired or unknown lease is not an
    /// error.
    async fn release(&self, lease: &LeaseId) -> Result<(), StoreError>;

    /// Count `units` of `dimension` for `client` if every window in `limits`
    /// still has room for them; `Ok(false)` and nothing counted otherwise.
    /// Empty `limits` always fits.
    async fn count(
        &self,
        client: &ClientKey,
        dimension: Dimension,
        units: u64,
        limits: &WindowLimits,
    ) -> Result<bool, StoreError>;

    /// Whether `units` more of `dimension` would fit, counting nothing.
    async fn would_fit(
        &self,
        client: &ClientKey,
        dimension: Dimension,
        units: u64,
        limits: &WindowLimits,
    ) -> Result<bool, StoreError>;

    /// Record `units` of `dimension` whether or not they fit. For what has
    /// already happened -- bytes a finished session relayed.
    async fn charge(
        &self,
        client: &ClientKey,
        dimension: Dimension,
        units: u64,
        limits: &WindowLimits,
    ) -> Result<(), StoreError>;

    /// Drop expired leases and windows nothing will read again. Returns how
    /// many rows went. Safe to run from every replica at once.
    async fn sweep(&self) -> Result<u64, StoreError>;

    /// One line for the startup log.
    fn describe(&self) -> String;
}

/// A Postgres URL that prints with its password masked: the one in the user
/// info, and a `password=` query parameter, which sqlx honours too.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostgresUrl(String);

impl PostgresUrl {
    pub fn new(url: impl Into<String>) -> Self {
        Self(url.into())
    }

    /// The URL as given, for connecting. Log `self`, never this.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PostgresUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Ok(mut parsed) = Url::parse(&self.0) else {
            return f.write_str(&self.0);
        };
        if !parsed.username().is_empty() {
            let _ = parsed.set_password(Some("***"));
        }
        if let Some(query) = parsed.query() {
            let masked = query
                .split('&')
                .map(|pair| match pair.split_once('=') {
                    Some(("password", _)) => "password=***",
                    _ => pair,
                })
                .collect::<Vec<_>>()
                .join("&");
            parsed.set_query(Some(&masked));
        }
        f.write_str(parsed.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_window_spec_parses_counts_and_sizes() {
        let w = "10/1m, 60/30m,100/1h".parse::<WindowLimits>().unwrap();
        assert_eq!(
            w.0,
            vec![
                WindowLimit {
                    limit: 10,
                    window: Duration::from_secs(60)
                },
                WindowLimit {
                    limit: 60,
                    window: Duration::from_secs(1800)
                },
                WindowLimit {
                    limit: 100,
                    window: Duration::from_secs(3600)
                },
            ]
        );
        let b = "100MB/1m,1GB/1h".parse::<WindowLimits>().unwrap();
        assert_eq!(b.0[0].limit, 100_000_000);
        assert_eq!(b.0[1].limit, 1_000_000_000);
        assert_eq!(b.longest(), Some(Duration::from_secs(3600)));
    }

    #[test]
    fn an_empty_spec_is_unlimited_and_a_bad_one_says_why() {
        assert!("".parse::<WindowLimits>().unwrap().is_empty());
        assert!("  ".parse::<WindowLimits>().unwrap().is_empty());
        assert!("10"
            .parse::<WindowLimits>()
            .unwrap_err()
            .contains("<limit>/<window>"));
        assert!("10/1".parse::<WindowLimits>().unwrap_err().contains("unit"));
        assert!("0/1m"
            .parse::<WindowLimits>()
            .unwrap_err()
            .contains("admits nothing"));
        assert!("10/0m"
            .parse::<WindowLimits>()
            .unwrap_err()
            .contains("zero"));
        assert!("ten/1m".parse::<WindowLimits>().is_err());
    }

    #[test]
    fn windows_sort_shortest_first() {
        let w = "100/1h,10/1m".parse::<WindowLimits>().unwrap();
        assert_eq!(w.0[0].window, Duration::from_secs(60));
    }

    #[test]
    fn two_limits_on_one_window_count_as_the_tighter_one() {
        let w = "10/1m,5/1m,100/1h".parse::<WindowLimits>().unwrap();
        let d = w.distinct();
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].limit, 5);
        assert_eq!(d[1].limit, 100);
    }

    #[test]
    fn a_password_is_redacted_and_the_rest_kept() {
        assert_eq!(
            PostgresUrl::new(
                "postgres://notary:hunter2@db.internal:5432/limits?sslmode=require"
            )
            .to_string(),
            "postgres://notary:***@db.internal:5432/limits?sslmode=require"
        );
        assert_eq!(
            PostgresUrl::new("postgres://db/limits").to_string(),
            "postgres://db/limits"
        );
        assert_eq!(PostgresUrl::new("memory").to_string(), "memory");
    }

    #[test]
    fn a_password_in_the_query_is_redacted_too() {
        assert_eq!(
            PostgresUrl::new(
                "postgres://notary@db/limits?password=hunter2&sslmode=require"
            )
            .to_string(),
            "postgres://notary:***@db/limits?password=***&sslmode=require"
        );
        assert_eq!(
            PostgresUrl::new(
                "postgres://db:5432/limits?sslmode=require&password=hunter2"
            )
            .to_string(),
            "postgres://db:5432/limits?sslmode=require&password=***"
        );
        assert_eq!(
            PostgresUrl::new("postgres://db?password=hunter2").to_string(),
            "postgres://db?password=***"
        );
        // Both at once, and a `@` in the query is not a user info marker.
        assert_eq!(
            PostgresUrl::new(
                "postgres://n:hunter2@db/l?password=hunter2&application_name=a@b"
            )
            .to_string(),
            "postgres://n:***@db/l?password=***&application_name=a@b"
        );
        assert_eq!(
            PostgresUrl::new("postgres://db/l?not_password=x&passwordx=y").to_string(),
            "postgres://db/l?not_password=x&passwordx=y"
        );
    }

    /// A client no other test run has seen. `ClientKey` is an address, so
    /// the randomness is a uuid's first 48 bits as an IPv6 /48 prefix, which
    /// is what the key keeps of a v6 address.
    pub(super) fn fresh_client() -> ClientKey {
        let bytes = uuid::Uuid::new_v4().into_bytes();
        ClientKey::from_ip(std::net::Ipv6Addr::from(bytes).into())
    }

    /// What every store must do. Written once; each implementation's tests
    /// run it against a store of their own. Clients are fresh per step so a
    /// shared database can run this from several checkouts at once.
    pub(super) async fn conformance<S: LimitStore>(store: &S) -> Result<(), StoreError> {
        let long = Duration::from_secs(60);
        let hour = "10/1h".parse::<WindowLimits>().unwrap();

        // Leases up to the limit, then refused; a release frees exactly one
        // slot: the other lease keeps its own.
        let c = fresh_client();
        let a = store.try_lease(&c, 2, long).await?.expect("first lease");
        store.try_lease(&c, 2, long).await?.expect("second lease");
        assert!(
            store.try_lease(&c, 2, long).await?.is_none(),
            "over the cap"
        );
        store.release(&a).await?;
        assert!(
            store.try_lease(&c, 2, long).await?.is_some(),
            "released slot"
        );
        assert!(
            store.try_lease(&c, 2, long).await?.is_none(),
            "the release freed one slot, not the client"
        );
        store.release(&a).await?; // twice is not an error
        store.release(&LeaseId::new()).await?; // nor is an unknown lease

        // An expired lease no longer counts.
        let c = fresh_client();
        let short = Duration::from_millis(50);
        assert!(store.try_lease(&c, 1, short).await?.is_some());
        assert!(store.try_lease(&c, 1, short).await?.is_none());
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(store.try_lease(&c, 1, short).await?.is_some(), "expired");

        // A count is refused when any window is full, and then counts in no
        // window: the 2h window still has room afterwards.
        let c = fresh_client();
        let both = "2/1h,3/2h".parse::<WindowLimits>().unwrap();
        let two_hours = "3/2h".parse::<WindowLimits>().unwrap();
        assert!(store.count(&c, Dimension::Upgrades, 1, &both).await?);
        assert!(store.count(&c, Dimension::Upgrades, 1, &both).await?);
        assert!(
            !store.count(&c, Dimension::Upgrades, 1, &both).await?,
            "1h full"
        );
        assert!(!store.would_fit(&c, Dimension::Upgrades, 1, &both).await?);
        assert!(
            store
                .would_fit(&c, Dimension::Upgrades, 1, &two_hours)
                .await?,
            "the refused count must not have charged the 2h window"
        );

        // The same the other way round: a count the LONGER window refuses
        // must not have charged the shorter one. Two used of five in the
        // hour; three more fit only if the refusal counted nothing there.
        let c = fresh_client();
        let both = "5/1h,2/2h".parse::<WindowLimits>().unwrap();
        let one_hour = "5/1h".parse::<WindowLimits>().unwrap();
        assert!(store.count(&c, Dimension::Upgrades, 1, &both).await?);
        assert!(store.count(&c, Dimension::Upgrades, 1, &both).await?);
        assert!(
            !store.count(&c, Dimension::Upgrades, 1, &both).await?,
            "2h full"
        );
        assert!(
            store
                .would_fit(&c, Dimension::Upgrades, 3, &one_hour)
                .await?,
            "the refused count must not have charged the 1h window"
        );

        // Units are counted, not calls, and would_fit counts nothing.
        let c = fresh_client();
        let bytes = "100/1h".parse::<WindowLimits>().unwrap();
        assert!(store.count(&c, Dimension::Bytes, 60, &bytes).await?);
        assert!(!store.count(&c, Dimension::Bytes, 50, &bytes).await?);
        assert!(store.would_fit(&c, Dimension::Bytes, 40, &bytes).await?);
        assert!(store.would_fit(&c, Dimension::Bytes, 40, &bytes).await?);
        assert!(store.count(&c, Dimension::Bytes, 40, &bytes).await?);
        assert!(!store.would_fit(&c, Dimension::Bytes, 1, &bytes).await?);

        // A charge records whether or not it fits.
        let c = fresh_client();
        store.charge(&c, Dimension::Bytes, 15, &hour).await?;
        assert!(!store.would_fit(&c, Dimension::Bytes, 1, &hour).await?);
        assert!(!store.count(&c, Dimension::Bytes, 1, &hour).await?);

        // No windows, no limit.
        let c = fresh_client();
        let none = WindowLimits::default();
        assert!(store.count(&c, Dimension::Bytes, u64::MAX, &none).await?);
        assert!(
            store
                .would_fit(&c, Dimension::Bytes, u64::MAX, &none)
                .await?
        );
        store.charge(&c, Dimension::Bytes, u64::MAX, &none).await?;

        // Dimensions are counted apart.
        let c = fresh_client();
        assert!(store.count(&c, Dimension::Upgrades, 10, &hour).await?);
        assert!(store.would_fit(&c, Dimension::Bytes, 10, &hour).await?);

        // Clients are counted apart.
        let (c, d) = (fresh_client(), fresh_client());
        assert!(store.try_lease(&c, 1, long).await?.is_some());
        assert!(store.try_lease(&c, 1, long).await?.is_none());
        assert!(store.try_lease(&d, 1, long).await?.is_some());
        assert!(store.count(&c, Dimension::Upgrades, 10, &hour).await?);
        assert!(!store.would_fit(&c, Dimension::Upgrades, 1, &hour).await?);
        assert!(store.would_fit(&d, Dimension::Upgrades, 10, &hour).await?);

        // A sweep drops expired leases and windows past their own length,
        // and says how many: three leases and one window here, plus whatever
        // else has expired in a shared database. What is still live stays:
        // a lease with time left, a window that is still open.
        let c = fresh_client();
        for _ in 0..3 {
            store.try_lease(&c, 3, short).await?.expect("lease");
        }
        let second = "10/1s".parse::<WindowLimits>().unwrap();
        store.charge(&c, Dimension::Bytes, 1, &second).await?;
        let live = fresh_client();
        store.try_lease(&live, 1, long).await?.expect("long lease");
        store.charge(&live, Dimension::Bytes, 10, &hour).await?;
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert!(store.sweep().await? >= 4);
        assert!(
            store.try_lease(&live, 1, long).await?.is_none(),
            "the sweep took a live lease"
        );
        assert!(
            !store.would_fit(&live, Dimension::Bytes, 1, &hour).await?,
            "the sweep took an open window"
        );
        Ok(())
    }
}
