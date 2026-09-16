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
    time::Duration,
};

use async_trait::async_trait;

use crate::client_ip::ClientKey;

mod memory;

pub use memory::MemoryStore;

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

impl WindowLimits {
    /// Parse a spec; the empty string is "unlimited".
    pub fn parse(spec: &str) -> Result<Self, String> {
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

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The longest window, which is how long any count has to be kept.
    pub fn longest(&self) -> Option<Duration> {
        self.0.iter().map(|w| w.window).max()
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
    let (digits, mult) = if let Some(n) = s.strip_suffix("GB") {
        (n, 1_000_000_000)
    } else if let Some(n) = s.strip_suffix("MB") {
        (n, 1_000_000)
    } else if let Some(n) = s.strip_suffix("KB") {
        (n, 1_000)
    } else {
        (s, 1)
    };
    let n: u64 = digits
        .trim()
        .parse()
        .map_err(|_| format!("'{s}': not a count (10) or a size (100MB)"))?;
    if n == 0 {
        return Err(format!(
            "'{s}': a limit of 0 admits nothing; omit the window instead"
        ));
    }
    Ok(n * mult)
}

fn parse_window(s: &str) -> Result<Duration, String> {
    let (digits, secs) = if let Some(n) = s.strip_suffix('h') {
        (n, 3600)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1)
    } else {
        return Err(format!("'{s}': a window needs a unit: 30s, 5m or 1h"));
    };
    let n: u64 = digits
        .trim()
        .parse()
        .map_err(|_| format!("'{s}': not a duration"))?;
    if n == 0 {
        return Err(format!("'{s}': a window of zero length"));
    }
    Ok(Duration::from_secs(n * secs))
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
#[async_trait]
pub trait LimitStore: Send + Sync + 'static {
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

/// A URL with any password replaced, for logs and errors.
pub fn redact(url: &str) -> String {
    match url.split_once("://").and_then(|(scheme, rest)| {
        let (creds, host) = rest.split_once('@')?;
        let user = creds.split_once(':').map_or(creds, |(u, _)| u);
        Some(format!("{scheme}://{user}:***@{host}"))
    }) {
        Some(redacted) => redacted,
        None => url.to_string(),
    }
}

/// The windows a store keys on: one per length, the tightest limit winning.
/// Two entries of the same length name the same row, and counting once per
/// entry would charge every unit twice.
fn distinct_windows(limits: &WindowLimits) -> Vec<WindowLimit> {
    let mut out: Vec<WindowLimit> = Vec::with_capacity(limits.0.len());
    for w in &limits.0 {
        match out.iter_mut().find(|o| o.window == w.window) {
            Some(o) => o.limit = o.limit.min(w.limit),
            None => out.push(*w),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_window_spec_parses_counts_and_sizes() {
        let w = WindowLimits::parse("10/1m, 60/30m,100/1h").unwrap();
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
        let b = WindowLimits::parse("100MB/1m,1GB/1h").unwrap();
        assert_eq!(b.0[0].limit, 100_000_000);
        assert_eq!(b.0[1].limit, 1_000_000_000);
        assert_eq!(b.longest(), Some(Duration::from_secs(3600)));
    }

    #[test]
    fn an_empty_spec_is_unlimited_and_a_bad_one_says_why() {
        assert!(WindowLimits::parse("").unwrap().is_empty());
        assert!(WindowLimits::parse("  ").unwrap().is_empty());
        assert!(WindowLimits::parse("10")
            .unwrap_err()
            .contains("<limit>/<window>"));
        assert!(WindowLimits::parse("10/1").unwrap_err().contains("unit"));
        assert!(WindowLimits::parse("0/1m")
            .unwrap_err()
            .contains("admits nothing"));
        assert!(WindowLimits::parse("10/0m").unwrap_err().contains("zero"));
        assert!(WindowLimits::parse("ten/1m").is_err());
    }

    #[test]
    fn windows_sort_shortest_first() {
        let w = WindowLimits::parse("100/1h,10/1m").unwrap();
        assert_eq!(w.0[0].window, Duration::from_secs(60));
    }

    #[test]
    fn two_limits_on_one_window_count_as_the_tighter_one() {
        let w = WindowLimits::parse("10/1m,5/1m,100/1h").unwrap();
        let d = distinct_windows(&w);
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].limit, 5);
        assert_eq!(d[1].limit, 100);
    }

    #[test]
    fn a_password_is_redacted_and_the_rest_kept() {
        assert_eq!(
            redact("postgres://notary:hunter2@db.internal:5432/limits?sslmode=require"),
            "postgres://notary:***@db.internal:5432/limits?sslmode=require"
        );
        assert_eq!(redact("postgres://db/limits"), "postgres://db/limits");
        assert_eq!(redact("memory"), "memory");
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
    pub(super) async fn conformance(store: &dyn LimitStore) -> Result<(), StoreError> {
        let long = Duration::from_secs(60);
        let hour = WindowLimits::parse("10/1h").unwrap();

        // Leases up to the limit, then refused; a release frees a slot.
        let c = fresh_client();
        let a = store.try_lease(&c, 2, long).await?.expect("first lease");
        let _b = store.try_lease(&c, 2, long).await?.expect("second lease");
        assert!(
            store.try_lease(&c, 2, long).await?.is_none(),
            "over the cap"
        );
        store.release(&a).await?;
        assert!(
            store.try_lease(&c, 2, long).await?.is_some(),
            "released slot"
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
        let both = WindowLimits::parse("2/1h,3/2h").unwrap();
        let two_hours = WindowLimits::parse("3/2h").unwrap();
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

        // Units are counted, not calls, and would_fit counts nothing.
        let c = fresh_client();
        let bytes = WindowLimits::parse("100/1h").unwrap();
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
        // else has expired in a shared database.
        let c = fresh_client();
        for _ in 0..3 {
            store.try_lease(&c, 3, short).await?.expect("lease");
        }
        let second = WindowLimits::parse("10/1s").unwrap();
        store.charge(&c, Dimension::Bytes, 1, &second).await?;
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert!(store.sweep().await? >= 4);
        Ok(())
    }
}
