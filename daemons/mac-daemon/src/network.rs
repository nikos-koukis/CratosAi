//! Tailscale: where to listen, and who may connect.
//!
//! In `tailscale` mode the daemon binds only to this Mac's Tailscale address
//! (a `utun` interface in 100.64.0.0/10 or fd7a:115c:a1e0::/48) and accepts
//! connections only from tailnet addresses. Tailscale ACLs decide which
//! tailnet nodes can reach it; mTLS decides which service identities may call.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use crate::config::NetworkMode;

const TAILSCALE_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// True for addresses Tailscale assigns to tailnet nodes.
pub fn is_tailnet(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            a == 100 && (b & 0xc0) == 64
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_tailnet(IpAddr::V4(v4));
            }
            let segments = v6.segments();
            segments[0] == 0xfd7a && segments[1] == 0x115c && segments[2] == 0xa1e0
        }
    }
}

/// This Mac's Tailscale address, preferring IPv4.
pub fn tailscale_address() -> Option<IpAddr> {
    if_addrs::get_if_addrs()
        .ok()?
        .into_iter()
        .filter(|interface| interface.name.starts_with("utun") && is_tailnet(interface.ip()))
        .map(|interface| interface.ip())
        .min_by_key(|ip| !ip.is_ipv4())
}

/// Resolves the listen address, waiting for Tailscale to come up if needed.
pub async fn listen_address(mode: NetworkMode, port: u16) -> SocketAddr {
    match mode {
        NetworkMode::Loopback => SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        NetworkMode::Tailscale => {
            let mut logged = false;
            loop {
                if let Some(ip) = tailscale_address() {
                    return SocketAddr::new(ip, port);
                }
                if !logged {
                    tracing::warn!("no Tailscale address yet; waiting for Tailscale to connect");
                    logged = true;
                }
                tokio::time::sleep(TAILSCALE_POLL_INTERVAL).await;
            }
        }
    }
}

/// Whether a connection from `peer` may be served in `mode`.
pub fn peer_allowed(mode: NetworkMode, peer: Option<SocketAddr>) -> bool {
    peer.is_some_and(|peer| match mode {
        NetworkMode::Tailscale => is_tailnet(peer.ip()),
        NetworkMode::Loopback => peer.ip().is_loopback(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn tailnet_ranges_are_recognised() {
        for inside in [
            "100.64.0.1",
            "100.101.102.103",
            "100.127.255.254",
            "fd7a:115c:a1e0::1",
            "::ffff:100.100.1.1",
        ] {
            assert!(is_tailnet(ip(inside)), "{inside}");
        }
        for outside in [
            "100.63.255.255",
            "100.128.0.1",
            "10.0.0.1",
            "192.168.1.10",
            "127.0.0.1",
            "fd7a:115c:a1e1::1",
            "::1",
        ] {
            assert!(!is_tailnet(ip(outside)), "{outside}");
        }
    }

    #[test]
    fn peers_are_checked_per_mode() {
        let tailnet: SocketAddr = "100.100.1.1:5000".parse().unwrap();
        let lan: SocketAddr = "192.168.1.20:5000".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:5000".parse().unwrap();

        assert!(peer_allowed(NetworkMode::Tailscale, Some(tailnet)));
        assert!(!peer_allowed(NetworkMode::Tailscale, Some(lan)));
        assert!(!peer_allowed(NetworkMode::Tailscale, Some(local)));
        assert!(peer_allowed(NetworkMode::Loopback, Some(local)));
        assert!(!peer_allowed(NetworkMode::Loopback, Some(tailnet)));
        assert!(!peer_allowed(NetworkMode::Loopback, None));
    }
}
