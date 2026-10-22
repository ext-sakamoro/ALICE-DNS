//! The IPv4 address answered for spoofed (and, in neutralize mode, blocked) domains.
//!
//! Given with `--spoof-ip`, or else this host's own IPv4 address on the interface that routes to the upstream
//! resolver: a UDP socket is connected to the resolver (which sends no packet) and its local address is read. There is
//! no fixed default: a fixed address is right on one network only, and on any other it points clients at a host that
//! is not the null server.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs, UdpSocket};

/// Why no spoof address could be settled on
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpoofIpError {
    /// `--spoof-ip` was not a dotted-quad IPv4 address
    Invalid(String),
    /// no upstream resolver to detect the address toward
    NoUpstream,
    /// the upstream resolver has no IPv4 route from this host (or is not an address)
    Unroutable(String),
    /// the address the route uses cannot be answered to clients (loopback, unspecified, broadcast, multicast)
    NotUsable(IpAddr),
}

impl fmt::Display for SpoofIpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(s) => write!(f, "--spoof-ip {s:?} is not an IPv4 address (a.b.c.d)"),
            Self::NoUpstream => write!(
                f,
                "no upstream resolver to detect this host's address toward; give --spoof-ip"
            ),
            Self::Unroutable(why) => write!(
                f,
                "cannot find this host's IPv4 address ({why}); give --spoof-ip"
            ),
            Self::NotUsable(ip) => {
                write!(f, "this host's address toward the upstream is {ip}, which clients cannot reach; give --spoof-ip")
            }
        }
    }
}

impl std::error::Error for SpoofIpError {}

/// `--spoof-ip`: exactly four decimal octets
pub fn parse(s: &str) -> Result<Ipv4Addr, SpoofIpError> {
    s.parse::<Ipv4Addr>()
        .map_err(|_| SpoofIpError::Invalid(s.to_string()))
}

/// whether clients can be answered with this address
#[must_use]
pub fn usable(ip: Ipv4Addr) -> bool {
    !(ip.is_loopback() || ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast())
}

/// This host's IPv4 address on the interface that routes to `upstream` (`host:port`); sends no packet
pub fn local_ipv4_toward(upstream: &str) -> Result<Ipv4Addr, SpoofIpError> {
    let target = upstream
        .to_socket_addrs()
        .map_err(|e| SpoofIpError::Unroutable(format!("{upstream}: {e}")))?
        .find(std::net::SocketAddr::is_ipv4)
        .ok_or_else(|| SpoofIpError::Unroutable(format!("{upstream}: no IPv4 address")))?;
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .map_err(|e| SpoofIpError::Unroutable(format!("bind: {e}")))?;
    sock.connect(target)
        .map_err(|e| SpoofIpError::Unroutable(format!("{upstream}: {e}")))?;
    let local = sock
        .local_addr()
        .map_err(|e| SpoofIpError::Unroutable(format!("local address: {e}")))?;
    match local.ip() {
        IpAddr::V4(v4) if usable(v4) => Ok(v4),
        ip => Err(SpoofIpError::NotUsable(ip)),
    }
}

/// The spoof address: `--spoof-ip` when given, else detected toward the upstream resolvers in order (the first that
/// yields a usable address); the error of the last resolver tried when none does
pub fn resolve(given: Option<&str>, upstreams: &[&str]) -> Result<Ipv4Addr, SpoofIpError> {
    if let Some(s) = given {
        return parse(s);
    }
    let mut last = SpoofIpError::NoUpstream;
    for u in upstreams {
        match local_ipv4_toward(u) {
            Ok(ip) => return Ok(ip),
            Err(e) => last = e,
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    // oracle: RFC 791 dotted-quad, four octets 0..=255; anything else is refused (never silently ignored)
    #[test]
    fn parse_accepts_exactly_a_dotted_quad() {
        assert_eq!(parse("192.0.2.7"), Ok(Ipv4Addr::new(192, 0, 2, 7)));
        assert_eq!(parse("0.0.0.0"), Ok(Ipv4Addr::UNSPECIFIED));
        for bad in [
            "",
            "192.0.2",
            "192.0.2.7.1",
            "192.0.2.256",
            "a.b.c.d",
            " 192.0.2.7",
            "192.0.2.7 ",
            "-1.0.0.0",
        ] {
            assert_eq!(
                parse(bad),
                Err(SpoofIpError::Invalid(bad.to_string())),
                "{bad:?}"
            );
        }
    }

    // oracle: RFC 1122 / 5735: loopback, unspecified, limited broadcast and multicast are not host addresses
    #[test]
    fn usable_refuses_non_host_addresses() {
        assert!(usable(Ipv4Addr::new(192, 0, 2, 7)));
        assert!(usable(Ipv4Addr::new(10, 1, 2, 3)));
        for bad in [
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(127, 9, 9, 9),
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(224, 0, 0, 1),
        ] {
            assert!(!usable(bad), "{bad}");
        }
    }

    // a resolver on this host is reached over loopback: the source address is loopback, which clients cannot reach
    #[test]
    fn detect_toward_a_loopback_resolver_is_not_usable() {
        assert_eq!(
            local_ipv4_toward("127.0.0.1:53"),
            Err(SpoofIpError::NotUsable(IpAddr::V4(Ipv4Addr::LOCALHOST)))
        );
    }

    #[test]
    fn detect_toward_a_non_address_is_unroutable() {
        for bad in ["", "1.1.1.1", "not an address:53", "[::1]:53"] {
            assert!(
                matches!(local_ipv4_toward(bad), Err(SpoofIpError::Unroutable(_))),
                "{bad:?}"
            );
        }
    }

    // the routed case depends on the machine's network: with a route the answer is a usable host address, without
    // one it is Unroutable; both are checked, neither is a pass by default
    #[test]
    fn detect_toward_a_routed_resolver_is_a_host_address_or_unroutable() {
        match local_ipv4_toward("192.0.2.1:53") {
            Ok(ip) => assert!(usable(ip), "{ip}"),
            Err(e) => assert!(matches!(e, SpoofIpError::Unroutable(_)), "{e:?}"),
        }
    }

    #[test]
    fn given_address_wins_and_is_validated() {
        assert_eq!(
            resolve(Some("198.51.100.4"), &["127.0.0.1:53"]),
            Ok(Ipv4Addr::new(198, 51, 100, 4))
        );
        assert_eq!(
            resolve(Some("198.51.100.400"), &[]),
            Err(SpoofIpError::Invalid("198.51.100.400".into()))
        );
    }

    #[test]
    fn no_given_address_and_no_upstream_is_an_error() {
        assert_eq!(resolve(None, &[]), Err(SpoofIpError::NoUpstream));
    }

    // every upstream is tried in order; the last error is the one reported
    #[test]
    fn detection_reports_the_last_failure() {
        assert_eq!(
            resolve(None, &["not an address:53", "127.0.0.1:53"]),
            Err(SpoofIpError::NotUsable(IpAddr::V4(Ipv4Addr::LOCALHOST)))
        );
        assert!(matches!(
            resolve(None, &["127.0.0.1:53", "not an address:53"]),
            Err(SpoofIpError::Unroutable(_))
        ));
    }

    #[test]
    fn errors_name_the_way_out() {
        for e in [
            SpoofIpError::NoUpstream,
            SpoofIpError::Unroutable("x".into()),
            SpoofIpError::NotUsable(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ] {
            assert!(e.to_string().contains("--spoof-ip"), "{e}");
        }
    }
}
