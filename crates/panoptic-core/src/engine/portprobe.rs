//! Kernel-truth port probing.
//!
//! A rootkit can filter the socket table (`/proc/net/tcp`, `GetExtendedTcpTable`)
//! but cannot stop the kernel from refusing to bind a port that is already in
//! use. Every port that fails with `EADDRINUSE` must therefore appear in the
//! socket table; any that do not are hidden listeners.

use super::traits::{CancelToken, EngineResult};
use crate::model::Protocol;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindOutcome {
    Free,
    InUse,
    /// Privileged / excluded port; tells us nothing.
    Unknown,
}

pub fn probe_one(proto: Protocol, port: u16) -> BindOutcome {
    let res = match proto {
        Protocol::Tcp => TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port))).map(drop),
        Protocol::Tcp6 => TcpListener::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, port))).map(drop),
        Protocol::Udp => UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port))).map(drop),
        Protocol::Udp6 => UdpSocket::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, port))).map(drop),
        Protocol::Raw | Protocol::Packet => return BindOutcome::Unknown,
    };
    match res {
        Ok(()) => BindOutcome::Free,
        Err(e) if e.kind() == ErrorKind::AddrInUse => BindOutcome::InUse,
        Err(_) => BindOutcome::Unknown,
    }
}

/// Lowest port worth probing: unprivileged users get `EACCES` below 1024 on Unix.
pub fn first_probe_port(elevated: bool) -> u16 {
    if cfg!(unix) && !elevated {
        1024
    } else {
        1
    }
}

/// Probe `ports` for `proto` across `threads` worker threads, returning every
/// port the kernel reports as in use.
pub fn bound_ports(proto: Protocol, first: u16, last: u16, threads: usize, cancel: &CancelToken) -> EngineResult<Vec<u16>> {
    let threads = threads.max(1);
    let total = u32::from(last).saturating_sub(u32::from(first)) + 1;
    let chunk = total.div_ceil(threads as u32);
    let mut found: Vec<u16> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..threads as u32)
            .map(|i| {
                let start = u32::from(first) + i * chunk;
                let end = (start + chunk).min(u32::from(last) + 1);
                s.spawn(move || {
                    let mut local = Vec::new();
                    for port in start..end {
                        if port % 1024 == 0 && cancel.is_cancelled() {
                            break;
                        }
                        if probe_one(proto, port as u16) == BindOutcome::InUse {
                            local.push(port as u16);
                        }
                    }
                    local
                })
            })
            .collect();
        handles.into_iter().flat_map(|h| h.join().unwrap_or_default()).collect()
    });
    cancel.check()?;
    found.sort_unstable();
    Ok(found)
}

/// Distinct local addresses seen in the socket table (interface IPs), plus loopback.
pub fn local_addresses(table: &[crate::model::SocketInfo]) -> Vec<std::net::IpAddr> {
    let mut out: Vec<std::net::IpAddr> = vec![Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()];
    for s in table {
        if let Ok(ip) = s.local_address.parse::<std::net::IpAddr>() {
            if !ip.is_unspecified() && !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    out
}

/// Does anything accept a TCP connection on `port` at any of `addrs`?
pub fn accepts_connection(port: u16, addrs: &[std::net::IpAddr]) -> bool {
    // All addresses in parallel so unroutable adapters cost one timeout, not N.
    std::thread::scope(|s| {
        let hs: Vec<_> = addrs
            .iter()
            .map(|ip| s.spawn(move || std::net::TcpStream::connect_timeout(&SocketAddr::new(*ip, port), std::time::Duration::from_millis(300)).is_ok()))
            .collect();
        hs.into_iter().any(|h| h.join().unwrap_or(false))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_accepts_but_bound_socket_does_not() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        assert!(accepts_connection(port, &[Ipv4Addr::LOCALHOST.into()]));
        drop(l);
        assert!(!accepts_connection(port, &[Ipv4Addr::LOCALHOST.into()]));
    }

    #[test]
    fn detects_a_port_we_hold() {
        let l = TcpListener::bind("0.0.0.0:0").unwrap();
        let port = l.local_addr().unwrap().port();
        assert_eq!(probe_one(Protocol::Tcp, port), BindOutcome::InUse);
        let found = bound_ports(Protocol::Tcp, port.saturating_sub(5).max(1024), port.saturating_add(5), 3, &CancelToken::new()).unwrap();
        assert!(found.contains(&port));
        drop(l);
    }

    #[test]
    fn udp_probe() {
        let u = UdpSocket::bind("0.0.0.0:0").unwrap();
        let port = u.local_addr().unwrap().port();
        assert_eq!(probe_one(Protocol::Udp, port), BindOutcome::InUse);
    }

    #[test]
    fn cancellation() {
        let c = CancelToken::new();
        c.cancel();
        assert!(bound_ports(Protocol::Tcp, 1024, 65535, 4, &c).is_err());
    }
}
