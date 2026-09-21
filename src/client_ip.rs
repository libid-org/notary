//! Which client a public request came from.
//!
//! A notary that clients reach directly keys on the socket peer
//! (`--client-ip-header peer`). A request there that carries a proxy's
//! header came through a proxy the configuration does not know about, so
//! the peer would be the proxy; it is refused.
//!
//! Behind a load balancer the picture is the reverse.
//!
//! A per-client limit is only as good as the identity it counts against, and
//! behind a load balancer the socket peer is the balancer: every browser in
//! the world shares it. The client is named in a header instead, and
//! `--client-ip-header` says which one:
//!
//! - `x-forwarded-for`: the client is the RIGHTMOST `X-Forwarded-For` entry.
//!   A balancer appends the address that connected to it, after whatever the
//!   caller already sent, so the last entry is the balancer's own word and
//!   everything left of it is the caller's -- which may be the client, or the
//!   client making things up. Only the last entry is read; the rest are not
//!   even parsed. For a notary directly behind the ALB (Cloudflare DNS-only,
//!   grey cloud).
//! - `cf-connecting-ip`: the client is the `CF-Connecting-IP` value, which
//!   Cloudflare sets to the address that connected to its edge. Only for a
//!   proxied record (orange cloud): with the record grey nothing sets the
//!   header, and every public request is refused with 400 -- loud, rather
//!   than wrong.
//!
//! The limitation: nothing here verifies who wrote the header. Anything that
//! can reach the public port directly can set it and choose its own key, so
//! the public port must be reachable only through the load balancer. That is
//! the deployment's job, not the notary's.
//!
//! A request without the header is refused, never keyed on the socket peer:
//! falling back to the peer would key every proxied request to the balancer,
//! and the per-client cap would quietly become a cap on the whole service --
//! which looks exactly like real load. The MPC-TLS port and the internal
//! route never call this: our own services are the protocol, not users of
//! it.

use std::net::IpAddr;

use axum::http::HeaderMap;
use forwarded_header_value::Identifier;
use ipnet::Ipv6Net;

use crate::config::ClientIpHeader;

/// The `X-Forwarded-For` field name, lowercased as `HeaderMap` stores it.
const FORWARDED_FOR: &str = "x-forwarded-for";

/// The `CF-Connecting-IP` field name, lowercased as `HeaderMap` stores it.
const CF_CONNECTING_IP: &str = "cf-connecting-ip";

/// The headers a proxy names the client in. One of them on a request means
/// the request came through a proxy.
pub const PROXIED_BY: [&str; 2] = [FORWARDED_FOR, CF_CONNECTING_IP];

/// An upper bound on the `X-Forwarded-For` chain. A header is not evidence
/// about a hundred hops; past this it is someone trying to make the split
/// expensive.
const MAX_HOPS: usize = 64;

/// The identity a per-client limit counts against.
///
/// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) is keyed as the IPv4
/// address it carries. Without that, every one of them shares the first six
/// octets, and the /48 rule below keys the whole IPv4 internet to `::`.
///
/// IPv6 is keyed by its /48 prefix. A residential allocation is a /56 and a
/// site's is a /48, so keying anything finer lets one subscriber mint a new
/// identity per /64 -- 256 of them from a /56 -- and hold that many times the
/// cap. Keying at /48 means neighbours under one provider block share a
/// budget; that is the price of the cap meaning anything at all.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ClientKey(IpAddr);

impl ClientKey {
    /// The key `ip` counts against.
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip.to_canonical() {
            IpAddr::V4(v4) => Self(IpAddr::V4(v4)),
            IpAddr::V6(v6) => Self(IpAddr::V6(
                Ipv6Net::new(v6, 48)
                    .expect("48 is a valid IPv6 prefix length")
                    .network(),
            )),
        }
    }
}

impl std::fmt::Display for ClientKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Why a request could not be attributed to a client.
///
/// Each is a refusal, never a fallback. Falling back to the socket peer here
/// would key every proxied request to the load balancer, and the per-client
/// cap would silently become a global one -- which looks exactly like real
/// load, and which the health check cannot see because it never upgrades.
#[derive(Debug, PartialEq, Eq)]
pub enum Unattributed {
    /// The configured header did not arrive. Either the request reached the
    /// public port without going through the balancer, or the header mode
    /// does not match the deployment: `cf-connecting-ip` with a grey
    /// Cloudflare record, say.
    Missing,
    /// The configured header arrived as more than one field line.
    ///
    /// RFC 9110 lets a recipient join repeated field lines with commas, and
    /// nginx does. That is safe only if the proxy appends to the end of the
    /// joined list; nothing in AWS's documentation or this deployment pins
    /// which field line an ALB appends to, and guessing wrong hands the key
    /// to whoever sent the first one. A browser sends neither header, so
    /// refusing costs nothing real.
    Repeated,
    /// The entry read was not an IP address, or the `X-Forwarded-For` chain
    /// was longer than `MAX_HOPS` (64).
    Malformed,
    /// A proxy's header on a port whose client is the socket peer. The
    /// request came through a proxy the configuration does not know about,
    /// and keying on the peer would count every client behind it as one.
    Proxied(&'static str),
}

impl std::fmt::Display for Unattributed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => f.write_str("no client address header"),
            Self::Repeated => f.write_str("more than one client address header"),
            Self::Malformed => f.write_str("malformed client address header"),
            Self::Proxied(header) => {
                write!(f, "{header} on a port whose client is the socket peer")
            }
        }
    }
}

/// A header a proxy names the client in: which header, and which entry of
/// it is the proxy's word.
pub trait ClientSource {
    /// The header that names the client.
    fn header(&self) -> &'static str;

    /// The entry of `line` the balancer wrote.
    fn entry<'a>(&self, line: &'a str) -> Result<&'a str, Unattributed>;

    /// The client behind `headers`. The header must be present exactly once,
    /// and only the entry named is parsed: what a caller wrote left of the
    /// balancer's entry is not read, so it is not validated either.
    fn resolve(&self, headers: &HeaderMap) -> Result<ClientKey, Unattributed> {
        let mut lines = headers.get_all(self.header()).iter();
        let line = lines.next().ok_or(Unattributed::Missing)?;
        if lines.next().is_some() {
            return Err(Unattributed::Repeated);
        }
        let line = line.to_str().map_err(|_| Unattributed::Malformed)?;
        let ip = self
            .entry(line)?
            .parse::<Identifier>()
            .ok()
            .and_then(|identifier| identifier.ip())
            .ok_or(Unattributed::Malformed)?;
        Ok(ClientKey::from_ip(ip))
    }
}

/// The rightmost `X-Forwarded-For` entry: the address that connected to the
/// load balancer, which the balancer appended last.
pub struct XForwardedFor;

impl ClientSource for XForwardedFor {
    fn header(&self) -> &'static str {
        FORWARDED_FOR
    }

    fn entry<'a>(&self, line: &'a str) -> Result<&'a str, Unattributed> {
        // The balancer appended last, so the last entry is its word and the
        // ones before it are the caller's: not read, only counted, so that a
        // chain past `MAX_HOPS` is refused.
        let mut entries = line.rsplit(',');
        let last = entries.next().unwrap_or("");
        if entries.count() >= MAX_HOPS {
            return Err(Unattributed::Malformed);
        }
        Ok(last)
    }
}

/// The `CF-Connecting-IP` value Cloudflare sets to the address that connected
/// to its edge.
pub struct CfConnectingIp;

impl ClientSource for CfConnectingIp {
    fn header(&self) -> &'static str {
        CF_CONNECTING_IP
    }

    fn entry<'a>(&self, line: &'a str) -> Result<&'a str, Unattributed> {
        Ok(line)
    }
}

impl ClientIpHeader {
    /// The client a public request from `peer` with `headers` counts against.
    ///
    /// `Peer` is the socket peer, provided no proxy's header is present: one
    /// means the request came through a proxy, and the peer is then the proxy.
    /// A header mode is its source's word, and never the peer.
    pub fn client(
        &self,
        peer: IpAddr,
        headers: &HeaderMap,
    ) -> Result<ClientKey, Unattributed> {
        match self {
            Self::Peer => match PROXIED_BY
                .into_iter()
                .find(|header| headers.contains_key(*header))
            {
                Some(header) => Err(Unattributed::Proxied(header)),
                None => Ok(ClientKey::from_ip(peer)),
            },
            Self::XForwardedFor => XForwardedFor.resolve(headers),
            Self::CfConnectingIp => CfConnectingIp.resolve(headers),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{
        IpAddr,
        Ipv4Addr,
    };

    use axum::http::{
        HeaderMap,
        HeaderValue,
    };

    use super::{
        CfConnectingIp,
        ClientIpHeader,
        ClientKey,
        ClientSource,
        Unattributed,
        XForwardedFor,
        CF_CONNECTING_IP,
        FORWARDED_FOR,
    };

    const PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

    fn xff(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_FOR, HeaderValue::from_str(value).unwrap());
        headers
    }

    fn cf(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CF_CONNECTING_IP, HeaderValue::from_str(value).unwrap());
        headers
    }

    fn key(addr: &str) -> ClientKey {
        ClientKey::from_ip(addr.parse().unwrap())
    }

    /// One hop: the balancer's entry is the client.
    #[test]
    fn a_single_entry_is_the_client() {
        assert_eq!(
            XForwardedFor.resolve(&xff("203.0.113.7")),
            Ok(key("203.0.113.7"))
        );
    }

    /// A caller that writes its own header prepends to the chain. The
    /// balancer's entry is still the rightmost, and it is the only one read.
    #[test]
    fn the_rightmost_entry_wins_over_a_forged_prefix() {
        assert_eq!(
            XForwardedFor.resolve(&xff("9.9.9.9, 10.60.5.90, 203.0.113.7")),
            Ok(key("203.0.113.7"))
        );
    }

    /// Only the last entry is read. An entry left of it that is not even an
    /// address changes nothing: it was written by the caller, and it is
    /// neither believed nor validated.
    #[test]
    fn a_malformed_entry_left_of_the_last_is_ignored() {
        assert_eq!(
            XForwardedFor.resolve(&xff("not-an-ip, 203.0.113.7")),
            Ok(key("203.0.113.7"))
        );
        assert_eq!(
            XForwardedFor.resolve(&xff(", 203.0.113.7")),
            Ok(key("203.0.113.7"))
        );
    }

    /// No header is a refusal, never a fallback.
    #[test]
    fn a_missing_header_is_refused() {
        assert_eq!(
            XForwardedFor.resolve(&HeaderMap::new()),
            Err(Unattributed::Missing)
        );
        assert_eq!(
            CfConnectingIp.resolve(&HeaderMap::new()),
            Err(Unattributed::Missing)
        );
    }

    /// A chain arriving in more than one field line is not joined and
    /// guessed at.
    #[test]
    fn a_repeated_header_is_refused() {
        let mut repeated = xff("203.0.113.7");
        repeated.append(FORWARDED_FOR, HeaderValue::from_static("9.9.9.9"));
        assert_eq!(
            XForwardedFor.resolve(&repeated),
            Err(Unattributed::Repeated)
        );

        let mut repeated = cf("203.0.113.7");
        repeated.append(CF_CONNECTING_IP, HeaderValue::from_static("9.9.9.9"));
        assert_eq!(
            CfConnectingIp.resolve(&repeated),
            Err(Unattributed::Repeated)
        );
    }

    /// A last entry that is not an address is refused, not skipped: skipping
    /// it would read the caller's entry instead. So is a chain past
    /// `MAX_HOPS`.
    #[test]
    fn a_malformed_last_entry_is_refused() {
        for bad in [
            "203.0.113.7, not-an-ip",
            "not-an-ip",
            "203.0.113.7,",
            "",
            "203.0.113.7, 999.1.1.1",
        ] {
            assert_eq!(
                XForwardedFor.resolve(&xff(bad)),
                Err(Unattributed::Malformed),
                "{bad:?}"
            );
        }

        let long = (0..70)
            .map(|i| format!("203.0.113.{}", i % 250))
            .collect::<Vec<_>>()
            .join(", ");
        assert_eq!(
            XForwardedFor.resolve(&xff(&long)),
            Err(Unattributed::Malformed)
        );

        for bad in ["not-an-ip", "", "9.9.9.9, 203.0.113.7"] {
            assert_eq!(
                CfConnectingIp.resolve(&cf(bad)),
                Err(Unattributed::Malformed),
                "{bad:?}"
            );
        }
    }

    /// Ports appear when `xff_client_port` is on. A bracketed IPv6 keeps its
    /// address; a bare IPv6 is never truncated at its last colon.
    #[test]
    fn ports_are_stripped_without_mangling_ipv6() {
        for (entry, expected) in [
            ("203.0.113.7:51234", "203.0.113.7"),
            ("[2001:db8::1]:51234", "2001:db8::"),
            ("[2001:db8::1]", "2001:db8::"),
            ("2001:db8::1", "2001:db8::"),
        ] {
            assert_eq!(
                XForwardedFor.resolve(&xff(entry)),
                Ok(key(expected)),
                "{entry:?}"
            );
            assert_eq!(
                CfConnectingIp.resolve(&cf(entry)),
                Ok(key(expected)),
                "{entry:?}"
            );
        }
    }

    /// In `cf-connecting-ip` mode the client is `CF-Connecting-IP`, whole,
    /// and `X-Forwarded-For` is not read at all -- not as a key, and not
    /// as a fallback when the Cloudflare header is absent.
    #[test]
    fn cf_mode_reads_cf_connecting_ip_and_ignores_x_forwarded_for() {
        let mut both = cf("203.0.113.7");
        both.insert(FORWARDED_FOR, HeaderValue::from_static("9.9.9.9"));
        assert_eq!(CfConnectingIp.resolve(&both), Ok(key("203.0.113.7")));
        assert_eq!(XForwardedFor.resolve(&both), Ok(key("9.9.9.9")));

        assert_eq!(
            CfConnectingIp.resolve(&xff("9.9.9.9")),
            Err(Unattributed::Missing)
        );
        assert_eq!(
            XForwardedFor.resolve(&cf("203.0.113.7")),
            Err(Unattributed::Missing)
        );
    }

    /// One IPv6 subscriber is one key, however many /64s they enumerate: a
    /// /56 collapses to its /48, and only a different /48 is a different key.
    #[test]
    fn ipv6_collapses_to_its_48_prefix() {
        assert_eq!(key("2001:db8:0:1::1"), key("2001:db8:0:ff:ffff::9"));
        assert_eq!(key("2001:db8:0:1::1"), key("2001:db8::1"));
        assert_ne!(key("2001:db8:0:1::1"), key("2001:db8:1::1"));
    }

    /// An IPv4-mapped IPv6 address is keyed as `a.b.c.d` -- the /48 rule
    /// would otherwise key all of IPv4 to `::` -- in either header.
    #[test]
    fn an_ipv4_mapped_entry_is_its_ipv4_address() {
        assert_eq!(key("::ffff:203.0.113.7"), key("203.0.113.7"));
        assert_ne!(key("::ffff:203.0.113.7"), key("::ffff:203.0.113.8"));
        assert_ne!(key("::ffff:203.0.113.7"), key("::"));

        assert_eq!(
            XForwardedFor.resolve(&xff("9.9.9.9, ::ffff:203.0.113.7")),
            Ok(key("203.0.113.7"))
        );
        assert_eq!(
            CfConnectingIp.resolve(&cf("::ffff:203.0.113.7")),
            Ok(key("203.0.113.7"))
        );
    }

    /// On a port reached directly, the peer is the client: keyed as any
    /// address is, with nothing in the headers read.
    #[test]
    fn the_peer_is_the_client_on_a_port_reached_directly() {
        assert_eq!(
            ClientIpHeader::Peer.client(PEER, &HeaderMap::new()),
            Ok(key("203.0.113.7"))
        );
        for (peer, expected) in [
            ("::ffff:203.0.113.7", "203.0.113.7"),
            ("2001:db8:abcd:1234::1", "2001:db8:abcd::"),
        ] {
            assert_eq!(
                ClientIpHeader::Peer.client(peer.parse().unwrap(), &HeaderMap::new()),
                Ok(key(expected)),
                "{peer:?}"
            );
        }
    }

    /// A proxy's header on that port means the request came through a proxy
    /// the configuration does not know about, so the peer would be the
    /// proxy: refused, whichever header, and never keyed on the peer.
    #[test]
    fn a_proxied_request_on_a_peer_keyed_port_is_refused() {
        assert_eq!(
            ClientIpHeader::Peer.client(PEER, &xff("9.9.9.9")),
            Err(Unattributed::Proxied(FORWARDED_FOR))
        );
        assert_eq!(
            ClientIpHeader::Peer.client(PEER, &cf("9.9.9.9")),
            Err(Unattributed::Proxied(CF_CONNECTING_IP))
        );
        let mut both = xff("9.9.9.9");
        both.insert(CF_CONNECTING_IP, HeaderValue::from_static("8.8.8.8"));
        assert!(matches!(
            ClientIpHeader::Peer.client(PEER, &both),
            Err(Unattributed::Proxied(_))
        ));
    }

    /// A header mode is its source's word: the peer is never read, and a
    /// request the source cannot attribute is refused, not keyed on the peer.
    #[test]
    fn a_header_mode_is_its_sources_word_and_never_the_peer() {
        assert_eq!(
            ClientIpHeader::XForwardedFor.client(PEER, &xff("9.9.9.9, 198.51.100.4")),
            Ok(key("198.51.100.4"))
        );
        assert_eq!(
            ClientIpHeader::CfConnectingIp.client(PEER, &cf("198.51.100.4")),
            Ok(key("198.51.100.4"))
        );
        for mode in [
            ClientIpHeader::XForwardedFor,
            ClientIpHeader::CfConnectingIp,
        ] {
            assert_eq!(
                mode.client(PEER, &HeaderMap::new()),
                Err(Unattributed::Missing),
                "{mode}"
            );
        }
    }
}
