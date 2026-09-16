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
}
