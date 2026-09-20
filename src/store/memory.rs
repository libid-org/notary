//! The in-process store: one replica's counts, behind a mutex.
//!
//! Correct for exactly one replica. Behind a load balancer every replica
//! keeps its own copy of every count, and a client gets the limit times the
//! replica count; `--limits-store memory` is the operator saying that is
//! understood.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{
        Duration,
        Instant,
        SystemTime,
        UNIX_EPOCH,
    },
};

use super::{
    Dimension,
    LeaseId,
    LimitStore,
    StoreError,
    WindowLimits,
};
use crate::client_ip::ClientKey;

/// Per-client counts kept in this process only.
#[derive(Debug, Default)]
pub struct MemoryStore {
    inner: Mutex<Inner>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A panic while holding the lock leaves plain maps behind, never a
        // half-applied count: nothing here can panic between a check and its
        // write.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[derive(Debug, Default)]
struct Inner {
    leases: HashMap<LeaseId, Lease>,
    windows: HashMap<WindowKey, u64>,
}

#[derive(Debug)]
struct Lease {
    client: ClientKey,
    expires_at: Instant,
}

/// One fixed window: the one `window_secs` long that started at
/// `window_start_secs`, for one client and dimension.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct WindowKey {
    client: ClientKey,
    dimension: Dimension,
    window_secs: u64,
    window_start_secs: u64,
}

impl WindowKey {
    /// The window of length `window` that `now` (since the epoch) falls in.
    fn at(
        client: ClientKey,
        dimension: Dimension,
        window: Duration,
        now: Duration,
    ) -> Self {
        let window_secs = window.as_secs().max(1);
        Self {
            client,
            dimension,
            window_secs,
            window_start_secs: now.as_secs() / window_secs * window_secs,
        }
    }

    /// Whether nothing will read this window again: its end is behind `now`.
    fn is_past(&self, now: Duration) -> bool {
        Duration::from_secs(self.window_start_secs.saturating_add(self.window_secs)) < now
    }
}

fn unix_now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
}

impl Inner {
    fn live_leases(&self, client: &ClientKey, now: Instant) -> usize {
        self.leases
            .values()
            .filter(|l| l.client == *client && l.expires_at > now)
            .count()
    }

    /// Whether `units` more fit in every window of `limits` at `now`.
    fn room(
        &self,
        client: &ClientKey,
        dimension: Dimension,
        units: u64,
        limits: &WindowLimits,
        now: Duration,
    ) -> bool {
        limits.distinct().iter().all(|w| {
            let key = WindowKey::at(*client, dimension, w.window, now);
            let used = self.windows.get(&key).copied().unwrap_or(0);
            used.saturating_add(units) <= w.limit
        })
    }

    /// Add `units` to every window of `limits` at `now`.
    fn add(
        &mut self,
        client: &ClientKey,
        dimension: Dimension,
        units: u64,
        limits: &WindowLimits,
        now: Duration,
    ) {
        for w in limits.distinct() {
            let key = WindowKey::at(*client, dimension, w.window, now);
            let used = self.windows.entry(key).or_insert(0);
            *used = used.saturating_add(units);
        }
    }

    /// A new lease for `client` at `now`, or `None` when `limit` are live.
    fn lease(
        &mut self,
        client: &ClientKey,
        limit: usize,
        ttl: Duration,
        now: Instant,
    ) -> Option<LeaseId> {
        if self.live_leases(client, now) >= limit {
            return None;
        }
        let id = LeaseId::new();
        self.leases.insert(
            id.clone(),
            Lease {
                client: *client,
                expires_at: now + ttl,
            },
        );
        Some(id)
    }

    fn sweep(&mut self, now: Instant, unix: Duration) -> u64 {
        let before = self.leases.len() + self.windows.len();
        self.leases.retain(|_, l| l.expires_at > now);
        self.windows.retain(|k, _| !k.is_past(unix));
        (before - self.leases.len() - self.windows.len()) as u64
    }
}

impl LimitStore for MemoryStore {
    async fn try_lease(
        &self,
        client: &ClientKey,
        limit: usize,
        ttl: Duration,
    ) -> Result<Option<LeaseId>, StoreError> {
        Ok(self.lock().lease(client, limit, ttl, Instant::now()))
    }

    async fn release(&self, lease: &LeaseId) -> Result<(), StoreError> {
        self.lock().leases.remove(lease);
        Ok(())
    }

    async fn count(
        &self,
        client: &ClientKey,
        dimension: Dimension,
        units: u64,
        limits: &WindowLimits,
    ) -> Result<bool, StoreError> {
        let now = unix_now();
        let mut inner = self.lock();
        if !inner.room(client, dimension, units, limits, now) {
            return Ok(false);
        }
        inner.add(client, dimension, units, limits, now);
        Ok(true)
    }

    async fn would_fit(
        &self,
        client: &ClientKey,
        dimension: Dimension,
        units: u64,
        limits: &WindowLimits,
    ) -> Result<bool, StoreError> {
        Ok(self
            .lock()
            .room(client, dimension, units, limits, unix_now()))
    }

    async fn charge(
        &self,
        client: &ClientKey,
        dimension: Dimension,
        units: u64,
        limits: &WindowLimits,
    ) -> Result<(), StoreError> {
        self.lock()
            .add(client, dimension, units, limits, unix_now());
        Ok(())
    }

    async fn sweep(&self) -> Result<u64, StoreError> {
        Ok(self.lock().sweep(Instant::now(), unix_now()))
    }

    fn describe(&self) -> String {
        "memory".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::tests::{
        conformance,
        fresh_client,
    };

    #[tokio::test]
    async fn conforms() -> Result<(), StoreError> {
        conformance(&MemoryStore::new()).await
    }

    #[test]
    fn a_window_is_keyed_by_the_period_it_started_in() {
        let (c, d) = (fresh_client(), Dimension::Bytes);
        let minute = Duration::from_secs(60);
        let at = |secs| WindowKey::at(c, d, minute, Duration::from_secs(secs));
        assert_eq!(at(120).window_start_secs, 120);
        assert_eq!(at(179).window_start_secs, 120);
        assert_eq!(at(180).window_start_secs, 180);
        assert!(!at(120).is_past(Duration::from_secs(180)));
        assert!(at(120).is_past(Duration::from_millis(180_001)));
    }

    #[test]
    fn a_full_window_rolls_over_and_is_then_swept() {
        let (c, d) = (fresh_client(), Dimension::Upgrades);
        let limits = "2/1m".parse::<WindowLimits>().unwrap();
        let mut inner = Inner::default();
        let t0 = Duration::from_secs(60 * 16_667); // a minute boundary
        inner.add(&c, d, 2, &limits, t0);
        assert!(!inner.room(&c, d, 1, &limits, t0 + Duration::from_secs(59)));
        assert!(inner.room(&c, d, 1, &limits, t0 + Duration::from_secs(60)));
        assert_eq!(inner.sweep(Instant::now(), t0 + Duration::from_secs(60)), 0);
        assert_eq!(
            inner.sweep(Instant::now(), t0 + Duration::from_millis(60_001)),
            1
        );
        assert!(inner.windows.is_empty());
    }

    #[test]
    fn a_sweep_takes_exactly_the_expired() {
        let c = fresh_client();
        let mut inner = Inner::default();
        let t0 = Instant::now();
        // Mid-hour, on a whole second: the 1s window ends inside the test,
        // the 1h window does not.
        let u0 = Duration::from_secs(3600 * 277 + 1800);
        let blink = Duration::from_millis(20);
        inner.lease(&c, 9, blink, t0).expect("lease");
        inner.lease(&c, 9, blink, t0).expect("lease");
        let kept = inner
            .lease(&c, 9, Duration::from_secs(60), t0)
            .expect("lease");
        let second = "1/1s".parse::<WindowLimits>().unwrap();
        let hour = "1/1h".parse::<WindowLimits>().unwrap();
        inner.add(&c, Dimension::Bytes, 1, &second, u0);
        inner.add(&c, Dimension::Bytes, 1, &hour, u0);
        // Nothing is due while the blink and the second still run.
        let early = Duration::from_millis(19);
        assert_eq!(inner.sweep(t0 + early, u0 + Duration::from_secs(1)), 0);
        let later = Duration::from_millis(1100);
        assert_eq!(inner.sweep(t0 + later, u0 + later), 3);
        assert_eq!(inner.sweep(t0 + later, u0 + later), 0);
        assert!(inner.leases.contains_key(&kept));
    }
}
