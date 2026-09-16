//! Which client a request came from, when a load balancer sits in front.
//!
//! A per-client limit is only as good as the identity it counts against. The
//! pod's socket peer is the ALB, so every browser in the world shares it; the
//! `X-Forwarded-For` header names the client, but a client can write that
//! header too. The resolution is the one nginx (`set_real_ip_from` plus
//! `real_ip_recursive`), Apache (`mod_remoteip`) and Rails
//! (`ActionDispatch::RemoteIp`) all settled on: trust the header only from
//! addresses configured as proxies, and walk it from the right until an
//! address outside that set appears. Everything left of it was written by
//! someone the notary has no reason to believe.

use std::net::{
    IpAddr,
    Ipv4Addr,
    Ipv6Addr,
    SocketAddr,
};

use axum::http::HeaderMap;
use ipnet::IpNet;

/// The `X-Forwarded-For` field name, lowercased as `HeaderMap` stores it.
const FORWARDED_FOR: &str = "x-forwarded-for";

/// An upper bound on the chain this will walk. A header is not evidence about
/// a hundred hops; past this it is someone trying to make the walk expensive.
const MAX_HOPS: usize = 64;

/// The identity a per-client limit counts against.
///
/// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`, which is how every IPv4
/// peer arrives on a `::` bind) is keyed as the IPv4 address it carries.
/// Without that, every one of them shares the first six octets, and the
/// /48 rule below keys the whole IPv4 internet to `::`.
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
            IpAddr::V6(v6) => {
                let mut octets = v6.octets();
                octets[6..].fill(0);
                Self(IpAddr::V6(Ipv6Addr::from(octets)))
            }
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
/// load, and which the ALB health check cannot see because it probes `/`.
#[derive(Debug, PartialEq, Eq)]
pub enum Unattributed {
    /// The request came through a trusted proxy that forwarded no client.
    Missing,
    /// The request carries `X-Forwarded-For` but did not come from a trusted
    /// proxy. Either a client wrote the header itself, or a balancer this
    /// notary was not told about is forwarding to it. Both are refused: the
    /// first has no honest reading, and the second is a stale
    /// `--trusted-proxies` -- which this makes loud on the first request,
    /// instead of quietly keying every user behind the new hop to one
    /// address.
    Unexpected,
    /// More than one `X-Forwarded-For` field line arrived.
    ///
    /// RFC 9110 lets a recipient join repeated field lines with commas, and
    /// nginx does. That is safe only if the proxy appends to the end of the
    /// joined list; nothing in AWS's documentation or this deployment pins
    /// which field line an ALB appends to, and guessing wrong hands the key
    /// to whoever sent the first one. A browser sends no `X-Forwarded-For`,
    /// so refusing costs nothing real.
    Repeated,
    /// An entry was not an IP address, or the chain was longer than
    /// `MAX_HOPS` (64).
    Malformed,
}

impl std::fmt::Display for Unattributed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason = match self {
            Self::Missing => "no X-Forwarded-For from a trusted proxy",
            Self::Unexpected => "X-Forwarded-For from an untrusted peer",
            Self::Repeated => "more than one X-Forwarded-For header",
            Self::Malformed => "malformed X-Forwarded-For",
        };
        f.write_str(reason)
    }
}

/// Who `peer` is calling for, given what the proxies in front said.
///
/// `trusted` is the set of addresses whose `X-Forwarded-For` is believed. A
/// peer inside it is a proxy, and the client is found in the header. A peer
/// outside it is the client itself, and must not be carrying the header at
/// all: with a balancer in front, a direct connection with `X-Forwarded-For`
/// is either forged or from a hop this notary was not configured to trust,
/// and both are refused rather than guessed at.
///
/// An empty `trusted` means nothing proxies this notary: every peer is the
/// client, and any `X-Forwarded-For` it sends is ignored, because there is
/// no proxy for it to have come from.
pub fn resolve(
    peer: SocketAddr,
    headers: &HeaderMap,
    trusted: &[IpNet],
) -> Result<ClientKey, Unattributed> {
    let mut lines = headers.get_all(FORWARDED_FOR).iter();
    let line = lines.next();
    let repeated = lines.next().is_some();

    // On a `::` bind an IPv4 peer is `::ffff:a.b.c.d`; `contains` and
    // `ClientKey::from_ip` both read it as `a.b.c.d`.
    if !contains(trusted, peer.ip()) {
        if line.is_some() && !trusted.is_empty() {
            return Err(Unattributed::Unexpected);
        }
        return Ok(ClientKey::from_ip(peer.ip()));
    }

    let line = line.ok_or(Unattributed::Missing)?;
    if repeated {
        return Err(Unattributed::Repeated);
    }
    let line = line.to_str().map_err(|_| Unattributed::Malformed)?;

    let mut chain = Vec::new();
    for entry in line.split(',') {
        if chain.len() == MAX_HOPS {
            return Err(Unattributed::Malformed);
        }
        chain.push(parse_entry(entry).ok_or(Unattributed::Malformed)?);
    }
    if chain.is_empty() {
        return Err(Unattributed::Missing);
    }

    // Right to left: the rightmost entry was written by the proxy nearest this
    // process, the leftmost by whoever spoke first -- which may be the client,
    // or may be the client making things up.
    let client = chain
        .iter()
        .rev()
        .find(|ip| !contains(trusted, **ip))
        // Every hop is a proxy of ours. The leftmost is then the closest this
        // can get to the client, and it is as trustworthy as the chain.
        .unwrap_or(&chain[0]);
    Ok(ClientKey::from_ip(*client))
}

/// Whether `ip` is in any of `nets`. An IPv4-mapped IPv6 address is matched
/// as its IPv4 address: `IpNet::contains` never matches a v4 network
/// against a v6 address, mapped or not.
fn contains(nets: &[IpNet], ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    nets.iter().any(|net| net.contains(&ip))
}

/// One `X-Forwarded-For` entry as an address.
///
/// Accepts what proxies actually write: a bare address, a bracketed IPv6 with
/// or without a port, and IPv4 with a port. A bare IPv6 is parsed before any
/// port is considered, so `2001:db8::1` is never mistaken for a host and port
/// and truncated at its last colon.
fn parse_entry(entry: &str) -> Option<IpAddr> {
    let entry = entry.trim();
    if entry.is_empty() {
        return None;
    }
    if let Some(rest) = entry.strip_prefix('[') {
        let (addr, _port) = rest.split_once(']')?;
        return addr.parse().ok();
    }
    if let Ok(ip) = entry.parse::<IpAddr>() {
        return Some(ip);
    }
    // Only an IPv4 address can carry a bare `:port`; one colon, and what is
    // left of it must parse as IPv4.
    let (addr, _port) = entry.split_once(':')?;
    if addr.contains(':') {
        return None;
    }
    addr.parse::<Ipv4Addr>().ok().map(IpAddr::V4)
}

/// A comma-separated CIDR list, or `direct` for the empty list.
///
/// `direct` is how `--trusted-proxies` states that nothing proxies this
/// notary, so the socket peer is the client. It is spelled out rather than
/// inferred from an empty setting, because an empty setting is also what a
/// missing environment variable looks like.
pub fn parse_networks(setting: &str) -> Result<Vec<IpNet>, String> {
    let setting = setting.trim();
    if setting.is_empty() || setting == "direct" {
        return Ok(Vec::new());
    }
    setting
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            entry
                .parse::<IpNet>()
                .or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
                .map_err(|_| {
                    format!(
                        "expected a CIDR (\"10.60.200.0/24\"), an address, or \
                         \"direct\", got {entry:?}"
                    )
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use axum::http::{
        HeaderMap,
        HeaderValue,
    };

    use super::{
        parse_networks,
        resolve,
        ClientKey,
        Unattributed,
        FORWARDED_FOR,
    };

    /// The testnet ALB's subnets: `cidrsubnet(vpc_cidr, 8, i + 200)`.
    fn alb() -> Vec<ipnet::IpNet> {
        parse_networks("10.60.200.0/24,10.60.201.0/24").unwrap()
    }

    fn none() -> Vec<ipnet::IpNet> {
        Vec::new()
    }

    fn peer(addr: &str) -> std::net::SocketAddr {
        let host = if addr.contains(':') {
            format!("[{addr}]")
        } else {
            addr.to_string()
        };
        format!("{host}:44321").parse().unwrap()
    }

    fn xff(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_FOR, HeaderValue::from_str(value).unwrap());
        headers
    }

    fn key(addr: &str) -> ClientKey {
        ClientKey::from_ip(addr.parse().unwrap())
    }

    /// The ordinary case: one hop, and the ALB's entry is the client.
    #[test]
    fn the_alb_names_the_client() {
        assert_eq!(
            resolve(peer("10.60.200.31"), &xff("203.0.113.7"), &alb()),
            Ok(key("203.0.113.7"))
        );
    }

    /// A client that writes its own header prepends to the chain. The ALB's
    /// entry is still the rightmost, and it is the only one believed.
    #[test]
    fn a_forged_prefix_is_ignored() {
        assert_eq!(
            resolve(peer("10.60.200.31"), &xff("9.9.9.9, 203.0.113.7"), &alb()),
            Ok(key("203.0.113.7"))
        );
    }

    /// A private address in the header buys nothing: the entry the walk lands
    /// on is the one the balancer wrote.
    #[test]
    fn a_proxied_request_is_keyed_on_what_the_balancer_wrote() {
        assert_eq!(
            resolve(
                peer("10.60.200.31"),
                &xff("10.60.5.90, 203.0.113.7"),
                &alb()
            ),
            Ok(key("203.0.113.7"))
        );
    }

    /// With no balancer configured, every peer is the client and any header
    /// it sends is ignored -- there is no proxy for it to have come from.
    #[test]
    fn with_no_proxies_the_peer_is_the_client() {
        assert_eq!(
            resolve(peer("203.0.113.7"), &xff("9.9.9.9"), &none()),
            Ok(key("203.0.113.7"))
        );
        assert_eq!(
            resolve(peer("203.0.113.7"), &HeaderMap::new(), &none()),
            Ok(key("203.0.113.7"))
        );
    }

    /// With a balancer configured, a direct connection carrying
    /// `X-Forwarded-For` is refused: it is either a forgery or a hop the
    /// notary was not told about, and refusing makes a stale trusted list
    /// loud on the first request rather than a silent collapse onto one key.
    #[test]
    fn a_forwarded_request_from_an_untrusted_peer_is_refused() {
        assert_eq!(
            resolve(peer("10.60.202.14"), &xff("203.0.113.7"), &alb()),
            Err(Unattributed::Unexpected)
        );
        // Without the header it is simply a direct client.
        assert_eq!(
            resolve(peer("10.60.202.14"), &HeaderMap::new(), &alb()),
            Ok(key("10.60.202.14"))
        );
    }

    /// Two hops of our own -- an ALB behind another proxy in the trusted set.
    /// The walk skips both.
    #[test]
    fn the_walk_skips_every_trusted_hop() {
        assert_eq!(
            resolve(
                peer("10.60.200.31"),
                &xff("203.0.113.7, 10.60.201.4"),
                &alb(),
            ),
            Ok(key("203.0.113.7"))
        );
    }

    /// A chain of nothing but proxies says nothing about a client. The
    /// leftmost is as close as this gets; it is not a fallback to the peer.
    #[test]
    fn an_all_trusted_chain_takes_the_leftmost() {
        assert_eq!(
            resolve(
                peer("10.60.200.31"),
                &xff("10.60.200.9, 10.60.201.4"),
                &alb(),
            ),
            Ok(key("10.60.200.9"))
        );
    }

    /// The two refusals that keep a mis-keyed notary from looking healthy: a
    /// trusted proxy that forwarded no client, and a chain arriving in more
    /// than one field line.
    #[test]
    fn a_trusted_peer_without_a_usable_header_is_refused() {
        assert_eq!(
            resolve(peer("10.60.200.31"), &HeaderMap::new(), &alb()),
            Err(Unattributed::Missing)
        );

        let mut repeated = xff("203.0.113.7");
        repeated.append(FORWARDED_FOR, HeaderValue::from_static("9.9.9.9"));
        assert_eq!(
            resolve(peer("10.60.200.31"), &repeated, &alb()),
            Err(Unattributed::Repeated)
        );
    }

    /// An entry that is not an address stops the walk. Accepting the text
    /// would let a client invent keys; skipping it would let a client hide a
    /// hop.
    #[test]
    fn a_malformed_entry_is_refused_not_skipped() {
        for bad in [
            "203.0.113.7, not-an-ip",
            "not-an-ip",
            "203.0.113.7,",
            "",
            "203.0.113.7, 999.1.1.1",
        ] {
            assert_eq!(
                resolve(peer("10.60.200.31"), &xff(bad), &alb()),
                Err(Unattributed::Malformed),
                "{bad:?}"
            );
        }

        let long = (0..70)
            .map(|i| format!("203.0.113.{}", i % 250))
            .collect::<Vec<_>>()
            .join(", ");
        assert_eq!(
            resolve(peer("10.60.200.31"), &xff(&long), &alb()),
            Err(Unattributed::Malformed)
        );
    }

    /// Ports appear when `xff_client_port` is on. A bracketed IPv6 keeps its
    /// address; a bare IPv6 is never truncated at its last colon.
    #[test]
    fn ports_are_stripped_without_mangling_ipv6() {
        for (entry, expected) in [
            ("203.0.113.7:51234", "203.0.113.7"),
            ("[2001:db8::1]:51234", "2001:db8::"),
            ("2001:db8::1", "2001:db8::"),
        ] {
            assert_eq!(
                resolve(peer("10.60.200.31"), &xff(entry), &alb()),
                Ok(key(expected)),
                "{entry:?}"
            );
        }
    }

    /// One IPv6 subscriber is one key, however many /64s they enumerate: a
    /// /56 collapses to its /48, and only a different /48 is a different key.
    #[test]
    fn ipv6_collapses_to_its_48_prefix() {
        assert_eq!(key("2001:db8:0:1::1"), key("2001:db8:0:ff:ffff::9"));
        assert_eq!(key("2001:db8:0:1::1"), key("2001:db8::1"));
        assert_ne!(key("2001:db8:0:1::1"), key("2001:db8:1::1"));
    }

    /// On a `::` bind every IPv4 peer is `::ffff:a.b.c.d`. It is keyed as
    /// `a.b.c.d` -- the /48 rule would otherwise key all of IPv4 to `::` --
    /// and it matches the IPv4 networks in the trusted list, so the ALB is
    /// still a proxy and the client it forwards is still the client.
    #[test]
    fn an_ipv4_mapped_peer_is_its_ipv4_address() {
        assert_eq!(key("::ffff:203.0.113.7"), key("203.0.113.7"));
        assert_ne!(key("::ffff:203.0.113.7"), key("::ffff:203.0.113.8"));
        assert_ne!(key("::ffff:203.0.113.7"), key("::"));

        // A direct client, and a trusted proxy, both v4-mapped.
        assert_eq!(
            resolve(peer("::ffff:203.0.113.7"), &HeaderMap::new(), &alb()),
            Ok(key("203.0.113.7"))
        );
        assert_eq!(
            resolve(peer("::ffff:10.60.200.31"), &xff("203.0.113.7"), &alb()),
            Ok(key("203.0.113.7"))
        );
        assert_eq!(
            resolve(peer("::ffff:10.60.200.31"), &HeaderMap::new(), &alb()),
            Err(Unattributed::Missing)
        );
        // A mapped entry in the header, and a mapped proxy hop in it.
        assert_eq!(
            resolve(
                peer("10.60.200.31"),
                &xff("::ffff:203.0.113.7, ::ffff:10.60.201.4"),
                &alb()
            ),
            Ok(key("203.0.113.7"))
        );
    }

    #[test]
    fn a_network_list_takes_cidrs_addresses_or_direct() {
        assert!(parse_networks("").unwrap().is_empty());
        assert!(parse_networks(" direct ").unwrap().is_empty());
        assert_eq!(parse_networks("10.0.0.0/8").unwrap().len(), 1);
        assert_eq!(
            parse_networks("10.60.200.0/24, 10.60.201.7").unwrap().len(),
            2
        );

        let error = parse_networks("10.60.200.0/24, nonsense")
            .expect_err("a bad entry must not be skipped");
        assert!(error.contains("nonsense"), "{error}");
        assert!(error.contains("direct"), "{error}");
    }
}
