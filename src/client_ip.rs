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
/// IPv6 is keyed by its /64 prefix. A single residential allocation is a /64
/// at best and often a /56, so keying the full address would let one
/// subscriber hold as many slots as they cared to enumerate.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ClientKey(IpAddr);

impl ClientKey {
    /// The key `ip` counts against.
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self(IpAddr::V4(v4)),
            IpAddr::V6(v6) => {
                let mut octets = v6.octets();
                octets[8..].fill(0);
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

/// Who is calling, and whether the per-client limits apply to them.
///
/// The distinction is the path, not the address. Anything that arrived through
/// the load balancer is public traffic, whatever address it claims; anything
/// that dialled the Service directly from a network configured as ours is one
/// of our own workloads, and capping those would be capping the protocol
/// against itself.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Client {
    /// Reached this notary directly from an exempt network. Not capped.
    Internal(ClientKey),
    /// Came through a trusted proxy, or directly from anywhere else. Capped.
    Public(ClientKey),
}

impl Client {
    /// The identity to count and to log, capped or not.
    pub fn key(self) -> ClientKey {
        match self {
            Self::Internal(key) | Self::Public(key) => key,
        }
    }

    /// Whether the per-client session cap applies.
    pub fn is_capped(self) -> bool {
        matches!(self, Self::Public(_))
    }
}

impl std::fmt::Display for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Internal(key) => write!(f, "{key} (internal)"),
            Self::Public(key) => write!(f, "{key}"),
        }
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
    /// [`MAX_HOPS`].
    Malformed,
}

impl std::fmt::Display for Unattributed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason = match self {
            Self::Missing => "no X-Forwarded-For from a trusted proxy",
            Self::Repeated => "more than one X-Forwarded-For header",
            Self::Malformed => "malformed X-Forwarded-For",
        };
        f.write_str(reason)
    }
}

/// Who `peer` is calling for, given what the proxies in front said.
///
/// `trusted` is the set of addresses whose `X-Forwarded-For` is believed;
/// `exempt` is the set whose direct connections are our own workloads. An
/// empty `trusted` means there is no proxy: the peer is the client.
///
/// `exempt` is checked first and only against the peer, so a request that came
/// through a load balancer can never claim exemption -- the header it carries
/// is written by whoever is calling, and a private address in it means
/// nothing.
pub fn resolve(
    peer: SocketAddr,
    headers: &HeaderMap,
    trusted: &[IpNet],
    exempt: &[IpNet],
) -> Result<Client, Unattributed> {
    if contains(exempt, peer.ip()) {
        return Ok(Client::Internal(ClientKey::from_ip(peer.ip())));
    }
    if !contains(trusted, peer.ip()) {
        // Reached directly from somewhere that is neither a proxy nor ours --
        // a public client on a notary with no balancer, or development.
        // Whatever the request claims about forwarding, this is the client.
        return Ok(Client::Public(ClientKey::from_ip(peer.ip())));
    }

    let mut lines = headers.get_all(FORWARDED_FOR).iter();
    let line = lines.next().ok_or(Unattributed::Missing)?;
    if lines.next().is_some() {
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
    Ok(Client::Public(ClientKey::from_ip(*client)))
}

fn contains(nets: &[IpNet], ip: IpAddr) -> bool {
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
        Client,
        ClientKey,
        Unattributed,
        FORWARDED_FOR,
    };

    /// The testnet ALB's subnets: `cidrsubnet(vpc_cidr, 8, i + 200)`.
    fn alb() -> Vec<ipnet::IpNet> {
        parse_networks("10.60.200.0/24,10.60.201.0/24").unwrap()
    }

    /// The testnet pod subnets: `cidrsubnet(vpc_cidr, 4, i)`.
    fn pods() -> Vec<ipnet::IpNet> {
        parse_networks("10.60.0.0/20,10.60.16.0/20").unwrap()
    }

    fn none() -> Vec<ipnet::IpNet> {
        Vec::new()
    }

    fn peer(addr: &str) -> std::net::SocketAddr {
        format!("{addr}:44321").parse().unwrap()
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
            resolve(peer("10.60.200.31"), &xff("203.0.113.7"), &alb(), &pods()),
            Ok(Client::Public(key("203.0.113.7")))
        );
    }

    /// A client that writes its own header prepends to the chain. The ALB's
    /// entry is still the rightmost, and it is the only one believed.
    #[test]
    fn a_forged_prefix_is_ignored() {
        assert_eq!(
            resolve(
                peer("10.60.200.31"),
                &xff("9.9.9.9, 203.0.113.7"),
                &alb(),
                &pods()
            ),
            Ok(Client::Public(key("203.0.113.7")))
        );
    }

    /// Our own pods dial the Service directly. They are not capped, and the
    /// header they send -- if any -- is not read.
    #[test]
    fn an_exempt_network_is_internal_and_uncapped() {
        let client =
            resolve(peer("10.60.5.90"), &xff("203.0.113.7"), &alb(), &pods()).unwrap();
        assert_eq!(client, Client::Internal(key("10.60.5.90")));
        assert!(!client.is_capped());
    }

    /// Exemption is about the path. A public client cannot claim it by putting
    /// a private address in the header, because the entry the walk lands on is
    /// the one the balancer wrote.
    #[test]
    fn a_proxied_request_can_never_claim_exemption() {
        let client = resolve(
            peer("10.60.200.31"),
            &xff("10.60.5.90, 203.0.113.7"),
            &alb(),
            &pods(),
        )
        .unwrap();
        assert_eq!(client, Client::Public(key("203.0.113.7")));
        assert!(client.is_capped());
    }

    /// Reached directly from somewhere that is neither a proxy nor ours: a
    /// public client on a notary with no balancer. Capped on its own address,
    /// and its header is still not read.
    #[test]
    fn a_direct_public_client_is_capped_on_its_peer() {
        let client =
            resolve(peer("203.0.113.7"), &xff("9.9.9.9"), &none(), &pods()).unwrap();
        assert_eq!(client, Client::Public(key("203.0.113.7")));
        assert!(client.is_capped());
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
                &none()
            ),
            Ok(Client::Public(key("203.0.113.7")))
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
                &none()
            ),
            Ok(Client::Public(key("10.60.200.9")))
        );
    }

    /// The two refusals that keep a mis-keyed notary from looking healthy: a
    /// trusted proxy that forwarded no client, and a chain arriving in more
    /// than one field line.
    #[test]
    fn a_trusted_peer_without_a_usable_header_is_refused() {
        assert_eq!(
            resolve(peer("10.60.200.31"), &HeaderMap::new(), &alb(), &pods()),
            Err(Unattributed::Missing)
        );

        let mut repeated = xff("203.0.113.7");
        repeated.append(FORWARDED_FOR, HeaderValue::from_static("9.9.9.9"));
        assert_eq!(
            resolve(peer("10.60.200.31"), &repeated, &alb(), &pods()),
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
                resolve(peer("10.60.200.31"), &xff(bad), &alb(), &none()),
                Err(Unattributed::Malformed),
                "{bad:?}"
            );
        }

        let long = (0..70)
            .map(|i| format!("203.0.113.{}", i % 250))
            .collect::<Vec<_>>()
            .join(", ");
        assert_eq!(
            resolve(peer("10.60.200.31"), &xff(&long), &alb(), &none()),
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
                resolve(peer("10.60.200.31"), &xff(entry), &alb(), &none()),
                Ok(Client::Public(key(expected))),
                "{entry:?}"
            );
        }
    }

    /// One IPv6 subscriber is one key, however many addresses they enumerate.
    #[test]
    fn ipv6_collapses_to_its_64_prefix() {
        assert_eq!(key("2001:db8:0:1::1"), key("2001:db8:0:1:ffff::9"));
        assert_ne!(key("2001:db8:0:1::1"), key("2001:db8:0:2::1"));
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
