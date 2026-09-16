//! Operator-tunable resource limits: how a setting is parsed and how the
//! limit is enforced. The server decides *where* each limit applies and what a
//! client sees when it trips; that lives in `server`.

use std::{
    collections::HashMap,
    fmt,
    io,
    num::NonZeroUsize,
    pin::Pin,
    str::FromStr,
    sync::{
        atomic::{
            AtomicUsize,
            Ordering,
        },
        Arc,
        Mutex,
    },
    task::{
        Context,
        Poll,
    },
};

use tokio::io::{
    AsyncRead,
    AsyncWrite,
    ReadBuf,
};
use tracing::warn;

use crate::client_ip::ClientKey;

/// A concurrency limit: an absolute count (`16`) or a multiple of the cores
/// the process may use (`4x`). A multiplier is resolved once, at startup, so a
/// container that is later resized keeps the number it started with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Concurrency {
    /// Exactly this many.
    Raw(NonZeroUsize),
    /// This many per core, see [`Concurrency::resolve`].
    PerCore(NonZeroUsize),
}

impl Concurrency {
    /// The number of sessions this setting allows on a machine with `cores`
    /// cores. `None` means the count could not be determined: a multiplier
    /// then behaves as on a single core, which is the conservative reading.
    pub fn resolve(self, cores: Option<NonZeroUsize>) -> usize {
        match self {
            Self::Raw(n) => n.get(),
            Self::PerCore(per_core) => {
                let cores = cores.map_or(1, NonZeroUsize::get);
                per_core.get().saturating_mul(cores)
            }
        }
    }
}

impl Default for Concurrency {
    /// Four sessions per core: MPC-TLS is CPU-bound, so beyond a few sessions
    /// per core they only slow each other down.
    fn default() -> Self {
        Self::PerCore(NonZeroUsize::new(4).expect("4 is not zero"))
    }
}

impl fmt::Display for Concurrency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Raw(n) => write!(f, "{n}"),
            Self::PerCore(n) => write!(f, "{n}x"),
        }
    }
}

impl FromStr for Concurrency {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = || {
            format!(
                "expected a positive integer (\"16\") or a core multiplier (\"4x\"), \
                 got {s:?}"
            )
        };
        let s = s.trim();
        let (digits, per_core) = match s.strip_suffix(['x', 'X']) {
            Some(digits) => (digits, true),
            None => (s, false),
        };
        let n: NonZeroUsize = digits.parse().map_err(|_| invalid())?;
        Ok(if per_core {
            Self::PerCore(n)
        } else {
            Self::Raw(n)
        })
    }
}

/// The cores this process may run on, as the runtime sees them.
///
/// `available_parallelism` honours cgroup CPU quotas and affinity masks, so in
/// a container this is the container's share and not the host's core count.
/// `None` when the platform cannot say; the warning tells the operator to set
/// a raw value instead of a multiplier.
pub fn available_cores() -> Option<NonZeroUsize> {
    match std::thread::available_parallelism() {
        Ok(cores) => Some(cores),
        Err(error) => {
            warn!(
                %error,
                "cannot determine the available core count; a per-core limit \
                 resolves as for one core -- set a raw value to override"
            );
            None
        }
    }
}

/// Bytes one ProxyMode session has relayed so far, both directions combined,
/// against the cap it may not cross.
///
/// Shared between the two halves of the relayed stream, so the cap is on the
/// session and not on a direction. Once crossed it stays crossed: every later
/// read or write fails too, and [`DataCap::exceeded`] tells the session's
/// owner that the cap, and not the peer, ended the relay.
#[derive(Debug)]
pub struct DataCap {
    limit: usize,
    used: AtomicUsize,
}

impl DataCap {
    /// A fresh counter that allows `limit` bytes.
    pub fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            used: AtomicUsize::new(0),
        })
    }

    /// The cap in bytes.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Bytes counted so far, including the operation that crossed the cap.
    pub fn used(&self) -> usize {
        self.used.load(Ordering::Relaxed)
    }

    /// Whether some read or write has crossed the cap.
    pub fn exceeded(&self) -> bool {
        self.used() > self.limit
    }

    /// Count `n` more bytes; the error names the totals so it reads on its own.
    fn charge(&self, n: usize) -> io::Result<()> {
        let used = self.used.fetch_add(n, Ordering::Relaxed).saturating_add(n);
        if used > self.limit {
            return Err(io::Error::other(format!(
                "PROXY_DATA_CAP_EXCEEDED: relayed {used} bytes, cap {}",
                self.limit
            )));
        }
        Ok(())
    }
}

/// An I/O stream whose reads and writes count against a shared [`DataCap`].
///
/// The count is taken as the bytes flow: each `poll_read` and `poll_write`
/// charges what it moved and fails the moment the session's total crosses the
/// cap. The stream is never cut short, so no consumer can mistake the cap for
/// the peer ending the conversation -- the operation that crosses it errors,
/// and the session that owns the stream fails with it. At most one I/O buffer
/// is moved beyond the cap, so memory stays bounded by the cap plus that.
#[derive(Debug)]
pub struct CappedIo<T> {
    inner: T,
    cap: Arc<DataCap>,
}

impl<T> CappedIo<T> {
    /// Wrap `inner` so that its traffic counts against `cap`.
    pub fn new(inner: T, cap: Arc<DataCap>) -> Self {
        Self { inner, cap }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for CappedIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.cap.exceeded() {
            return Poll::Ready(this.cap.charge(0));
        }
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let read = buf.filled().len() - before;
                Poll::Ready(this.cap.charge(read))
            }
            other => other,
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for CappedIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.cap.exceeded() {
            return Poll::Ready(this.cap.charge(0).map(|()| 0));
        }
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => {
                Poll::Ready(this.cap.charge(written).map(|()| written))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// A stream whose first bytes have already been read, put back in front of it.
///
/// The notary reads a connection's first byte before it will spend a session
/// slot on it: a client that has sent nothing is not a prover, and must not be
/// able to reserve the expensive resource by connecting alone. That byte
/// belongs to the protocol, so it is replayed here and the session reads the
/// stream it would have read.
#[derive(Debug)]
pub struct PeekedIo<T> {
    prefix: Vec<u8>,
    taken: usize,
    inner: T,
}

impl<T> PeekedIo<T> {
    /// Wrap `inner` so that `prefix` is read from it first.
    pub fn new(prefix: Vec<u8>, inner: T) -> Self {
        Self {
            prefix,
            taken: 0,
            inner,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for PeekedIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let left = &this.prefix[this.taken..];
        if !left.is_empty() {
            let n = left.len().min(buf.remaining());
            buf.put_slice(&left[..n]);
            this.taken += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for PeekedIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// How many sessions each client has running, and the slot one of them holds.
///
/// A keyed concurrency limit, which the tower ecosystem has no equivalent of:
/// `ConcurrencyLimitLayer` bounds the whole service, and a rate limiter counts
/// arrivals rather than what they hold. Concurrency is what matters here,
/// because a session costs its relay task and its transcript for as long as it
/// lives, not for as long as it took to ask.
///
/// The table holds only clients with a live session, and every session is
/// already bounded by the global session limit, so it needs no separate cap or
/// eviction: the last slot to drop takes the entry with it.
#[derive(Debug, Default)]
pub struct ClientSessions {
    live: Mutex<HashMap<ClientKey, usize>>,
}

impl ClientSessions {
    /// An empty table.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// A slot for `client`, or `None` if it already holds `limit` of them.
    pub fn try_take(
        self: &Arc<Self>,
        client: ClientKey,
        limit: usize,
    ) -> Option<ClientSlot> {
        let mut live = self.lock();
        let held = live.get(&client).copied().unwrap_or(0);
        if held >= limit {
            // Insert nothing: a client at its limit must not leave an entry
            // behind, or refusals alone would grow the table.
            return None;
        }
        live.insert(client, held + 1);
        drop(live);
        Some(ClientSlot {
            table: Arc::clone(self),
            client,
        })
    }

    /// Sessions `client` is running right now.
    pub fn held_by(&self, client: ClientKey) -> usize {
        self.lock().get(&client).copied().unwrap_or(0)
    }

    /// Clients with at least one live session.
    pub fn tracked(&self) -> usize {
        self.lock().len()
    }

    /// A poisoned lock here means a panic while holding a `HashMap`, which
    /// leaves it structurally sound. Refusing every later session over it
    /// would turn one panic into an outage.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<ClientKey, usize>> {
        self.live
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// One client's claim on one session, released when dropped.
#[derive(Debug)]
pub struct ClientSlot {
    table: Arc<ClientSessions>,
    client: ClientKey,
}

impl Drop for ClientSlot {
    fn drop(&mut self) {
        let mut live = self.table.lock();
        if let Some(held) = live.get_mut(&self.client) {
            *held -= 1;
            if *held == 0 {
                live.remove(&self.client);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use tokio::io::{
        AsyncReadExt,
        AsyncWriteExt,
    };

    use super::{
        CappedIo,
        ClientSessions,
        Concurrency,
        DataCap,
        PeekedIo,
    };
    use crate::client_ip::ClientKey;

    fn nz(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).unwrap()
    }

    #[test]
    fn concurrency_parses_a_raw_count_and_a_multiplier() {
        assert_eq!("16".parse::<Concurrency>(), Ok(Concurrency::Raw(nz(16))));
        assert_eq!("4x".parse::<Concurrency>(), Ok(Concurrency::PerCore(nz(4))));
        assert_eq!(
            " 2X ".parse::<Concurrency>(),
            Ok(Concurrency::PerCore(nz(2)))
        );
        assert_eq!(Concurrency::default().to_string(), "4x");
        assert_eq!(Concurrency::Raw(nz(16)).to_string(), "16");
    }

    #[test]
    fn concurrency_rejects_zero_and_garbage_naming_the_accepted_forms() {
        for bad in ["", "0", "0x", "x", "abc", "4 x", "-1", "1.5x"] {
            let error = bad
                .parse::<Concurrency>()
                .expect_err(&format!("{bad:?} must not parse"));
            assert!(
                error.contains("\"16\"") && error.contains("\"4x\""),
                "{error}"
            );
            assert!(error.contains(&format!("{bad:?}")), "{error}");
        }
    }

    #[test]
    fn multiplier_resolves_against_the_core_count_and_falls_back_to_one() {
        assert_eq!(Concurrency::PerCore(nz(4)).resolve(Some(nz(10))), 40);
        assert_eq!(Concurrency::PerCore(nz(4)).resolve(None), 4);
        assert_eq!(Concurrency::Raw(nz(16)).resolve(Some(nz(10))), 16);
        assert_eq!(Concurrency::Raw(nz(16)).resolve(None), 16);
    }

    /// Reads and writes on one stream share the cap, and the operation that
    /// crosses it fails rather than delivering a shortened stream.
    #[tokio::test]
    async fn capped_io_counts_both_directions_and_fails_on_the_crossing_call() {
        let cap = DataCap::new(10);
        let (near, mut far) = tokio::io::duplex(64);
        let mut capped = CappedIo::new(near, cap.clone());

        capped.write_all(&[1; 6]).await.unwrap();
        far.write_all(&[2; 4]).await.unwrap();
        let mut buf = [0u8; 4];
        capped.read_exact(&mut buf).await.unwrap();
        assert_eq!(cap.used(), 10);
        assert!(!cap.exceeded(), "exactly the cap is allowed");

        far.write_all(&[3; 1]).await.unwrap();
        let error = capped.read(&mut buf).await.unwrap_err();
        assert!(cap.exceeded());
        assert!(
            error.to_string().contains("PROXY_DATA_CAP_EXCEEDED"),
            "{error}"
        );
        assert_eq!(cap.used(), 11, "the crossing byte is counted, not hidden");

        // Once crossed, every later operation fails too.
        assert!(capped.write_all(&[4; 1]).await.is_err());
        assert!(capped.read(&mut buf).await.is_err());
    }

    #[tokio::test]
    async fn peeked_io_replays_the_first_byte_then_reads_the_rest() {
        let (mut client, server) = tokio::io::duplex(64);
        client.write_all(b"ello").await.unwrap();

        let mut peeked = PeekedIo::new(b"h".to_vec(), server);
        let mut seen = [0u8; 5];
        peeked.read_exact(&mut seen).await.unwrap();

        assert_eq!(&seen, b"hello");
    }

    #[tokio::test]
    async fn peeked_io_replays_a_prefix_longer_than_one_read() {
        let (client, server) = tokio::io::duplex(64);
        drop(client);

        let mut peeked = PeekedIo::new(b"abcd".to_vec(), server);
        let mut one = [0u8; 1];
        for expected in b"abcd" {
            peeked.read_exact(&mut one).await.unwrap();
            assert_eq!(one[0], *expected);
        }
        assert_eq!(peeked.read(&mut one).await.unwrap(), 0);
    }

    fn key(addr: &str) -> ClientKey {
        ClientKey::from_ip(addr.parse().unwrap())
    }

    /// A client gets `limit` slots at once and no more, and each one comes
    /// back the moment its session ends.
    #[test]
    fn a_client_holds_at_most_its_limit_of_sessions() {
        let table = ClientSessions::new();
        let client = key("203.0.113.7");

        let first = table.try_take(client, 2).expect("first session");
        let second = table.try_take(client, 2).expect("second session");
        assert_eq!(table.held_by(client), 2);
        assert!(
            table.try_take(client, 2).is_none(),
            "a third session was allowed past the limit"
        );

        drop(second);
        assert_eq!(table.held_by(client), 1);
        let third = table.try_take(client, 2).expect("the slot came back");

        drop((first, third));
        assert_eq!(table.held_by(client), 0);
    }

    /// One client at its limit does not spend another client's slots.
    #[test]
    fn clients_do_not_share_a_budget() {
        let table = ClientSessions::new();
        let busy = key("203.0.113.7");
        let other = key("198.51.100.4");

        let _held = (
            table.try_take(busy, 1).expect("first client"),
            table.try_take(other, 1).expect("second client"),
        );
        assert!(table.try_take(busy, 1).is_none());
        assert!(table.try_take(other, 1).is_none());
        assert_eq!(table.tracked(), 2);
    }

    /// The table only ever holds clients with a live session: a refusal adds
    /// nothing, and the last slot to drop takes the entry with it. That is
    /// what keeps it from needing a cap of its own.
    #[test]
    fn the_table_holds_nothing_at_rest() {
        let table = ClientSessions::new();
        let client = key("203.0.113.7");

        let slot = table.try_take(client, 1).expect("first session");
        assert!(table.try_take(client, 1).is_none());
        assert_eq!(table.tracked(), 1, "a refusal left an entry behind");

        drop(slot);
        assert_eq!(
            table.tracked(),
            0,
            "a finished session left an entry behind"
        );
    }
}
