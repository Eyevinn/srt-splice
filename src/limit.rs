//! Rate limiting for handshakes.
//!
//! Only handshakes are limited; established sessions are never touched.
//! Handshakes come in two kinds, with separate budgets, so that one can
//! never starve the other:
//!
//! - **Unverified:** inductions, and conclusions without a valid cookie.
//!   Their source address may be spoofed. Limited per source network (an
//!   IPv4 address, or an IPv6 /56, the usual allocation for one customer
//!   site), so that one host cannot use up everyone's budget, and in
//!   total, so that a flood cannot take the forwarding thread. A spoofed
//!   flood can use up a network's budget while it lasts: that network then
//!   cannot start new connections, but its waiting callers and sessions are
//!   not affected.
//! - **Verified:** conclusions with a valid cookie. Their source is real
//!   (the cookie only went to that address), so they are limited per
//!   socket (IP and port), at several times what a waiting caller sends,
//!   and in total. A spoofed flood cannot touch this budget.
//!
//! The limits are far above what callers send, because many legitimate
//! callers can share one address: a cloud NAT gateway, a production cluster
//! with dozens of outputs, a venue, a carrier-grade NAT. A waiting caller
//! sends one induction per connection attempt (about every 3 s) and a
//! conclusion every 250 ms. Over the limit, handshakes are dropped, never
//! refused: a caller loses a few and keeps trying, as on a lossy path.
//!
//! There are no bans. A host that keeps getting refused is most likely a
//! caller retrying (a second receiver on a 1:1 stream, a reconnect loop),
//! and a ban would also lock out every legitimate caller behind the same
//! address.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// Unverified handshakes per second from one network, and the burst: room
/// for the inductions of some 3000 callers behind one address.
const NET_RATE: f64 = 1000.0;
const NET_BURST: f64 = 2000.0;
/// Unverified handshakes per second in total, and the burst.
const UNVERIFIED_RATE: f64 = 20_000.0;
const UNVERIFIED_BURST: f64 = 40_000.0;
/// Verified conclusions per second from one socket, and the burst. A
/// waiting caller sends 4 a second.
const SOCKET_RATE: f64 = 20.0;
const SOCKET_BURST: f64 = 40.0;
/// Verified conclusions per second in total, and the burst: 4 a second for
/// each of 20,000 waiting callers, with room to spare.
const VERIFIED_RATE: f64 = 100_000.0;
const VERIFIED_BURST: f64 = 200_000.0;
/// Networks and sockets tracked at once. Beyond that, new networks share
/// one bucket with the per-network limit; new sockets have only the total.
const MAX_NETS: usize = 65536;
const MAX_SOCKETS: usize = 262_144;
/// A network or socket not heard from for this long is forgotten. Callers
/// that wait are heard from every 250 ms, so they are never forgotten.
const FORGET_AFTER: Duration = Duration::from_secs(10);

/// The network an address counts against: IPv4 as is, IPv6 by its /56.
/// IPv4-mapped IPv6 addresses count as IPv4.
pub fn net(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(std::net::Ipv6Addr::new(
                    s[0],
                    s[1],
                    s[2],
                    s[3] & 0xFF00,
                    0,
                    0,
                    0,
                    0,
                ))
            }
        },
    }
}

#[derive(Clone, Copy, Debug)]
struct Bucket {
    tokens: f64,
    /// When it was last used.
    at: Instant,
}

impl Bucket {
    fn full(burst: f64, now: Instant) -> Bucket {
        Bucket {
            tokens: burst,
            at: now,
        }
    }

    /// Takes one token if there is one.
    fn take(&mut self, rate: f64, burst: f64, now: Instant) -> bool {
        let dt = now.saturating_duration_since(self.at).as_secs_f64();
        self.tokens = (self.tokens + dt * rate).min(burst);
        self.at = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn idle(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.at) >= FORGET_AFTER
    }
}

pub struct Limiter {
    enabled: bool,
    unverified: Bucket,
    verified: Bucket,
    nets: HashMap<IpAddr, Bucket>,
    /// Shared by networks that found `nets` full.
    overflow: Bucket,
    sockets: HashMap<SocketAddr, Bucket>,
    /// Handshakes dropped since the last `take_dropped`.
    dropped: u64,
}

impl Limiter {
    pub fn new(enabled: bool, now: Instant) -> Limiter {
        Limiter {
            enabled,
            unverified: Bucket::full(UNVERIFIED_BURST, now),
            verified: Bucket::full(VERIFIED_BURST, now),
            nets: HashMap::new(),
            overflow: Bucket::full(NET_BURST, now),
            sockets: HashMap::new(),
            dropped: 0,
        }
    }

    /// Whether to handle a handshake whose source is not proven (an
    /// induction, or a conclusion without a valid cookie) from `ip`.
    pub fn allow_unverified(&mut self, ip: IpAddr, now: Instant) -> bool {
        if !self.enabled {
            return true;
        }
        let key = net(ip);
        let bucket = if self.nets.contains_key(&key) || self.nets.len() < MAX_NETS {
            self.nets
                .entry(key)
                .or_insert_with(|| Bucket::full(NET_BURST, now))
        } else {
            &mut self.overflow
        };
        let ok = bucket.take(NET_RATE, NET_BURST, now)
            && self.unverified.take(UNVERIFIED_RATE, UNVERIFIED_BURST, now);
        self.dropped += u64::from(!ok);
        ok
    }

    /// Whether to handle a conclusion with a valid cookie from `addr`.
    pub fn allow_verified(&mut self, addr: SocketAddr, now: Instant) -> bool {
        if !self.enabled {
            return true;
        }
        // Without room for its socket, only the total applies.
        let socket_ok = if self.sockets.contains_key(&addr) || self.sockets.len() < MAX_SOCKETS {
            self.sockets
                .entry(addr)
                .or_insert_with(|| Bucket::full(SOCKET_BURST, now))
                .take(SOCKET_RATE, SOCKET_BURST, now)
        } else {
            true
        };
        let ok = socket_ok && self.verified.take(VERIFIED_RATE, VERIFIED_BURST, now);
        self.dropped += u64::from(!ok);
        ok
    }

    /// Forgets networks and sockets not heard from for `FORGET_AFTER`.
    pub fn prune(&mut self, now: Instant) {
        self.nets.retain(|_, b| !b.idle(now));
        self.sockets.retain(|_, b| !b.idle(now));
    }

    pub fn take_dropped(&mut self) -> u64 {
        std::mem::take(&mut self.dropped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn v4(i: u32) -> IpAddr {
        IpAddr::V4((0x0A00_0000 + i).into())
    }

    fn sock(ip: IpAddr, port: u16) -> SocketAddr {
        SocketAddr::new(ip, port)
    }

    #[test]
    fn ipv6_counts_by_56_and_mapped_ipv4_as_ipv4() {
        assert_eq!(net(ip("2001:db8:1:2:3:4:5:6")), ip("2001:db8:1::"));
        assert_eq!(net(ip("2001:db8:1:ff:ffff::1")), ip("2001:db8:1::"));
        assert_ne!(net(ip("2001:db8:1:100::1")), ip("2001:db8:1::"));
        assert_eq!(net(ip("::ffff:192.0.2.1")), ip("192.0.2.1"));
        assert_eq!(net(ip("192.0.2.1")), ip("192.0.2.1"));
    }

    #[test]
    fn unverified_rate_per_network_refills() {
        let t = Instant::now();
        let mut l = Limiter::new(true, t);
        let a = ip("192.0.2.1");
        let n = (0..5000).filter(|_| l.allow_unverified(a, t)).count();
        assert_eq!(n, NET_BURST as usize);
        // Another network is not affected.
        assert!(l.allow_unverified(ip("192.0.2.2"), t));
        // A second later, NET_RATE more.
        let t1 = t + Duration::from_secs(1);
        let n = (0..5000).filter(|_| l.allow_unverified(a, t1)).count();
        assert_eq!(n, NET_RATE as usize);
        assert_eq!(l.take_dropped(), 10_000 - 3000);
    }

    #[test]
    fn ipv6_networks_in_one_56_share_a_budget() {
        let t = Instant::now();
        let mut l = Limiter::new(true, t);
        let n = (0..5000u16)
            .filter(|i| l.allow_unverified(ip(&format!("2001:db8:0:{:x}:{i:x}::1", i % 256)), t))
            .count();
        assert_eq!(n, NET_BURST as usize);
    }

    #[test]
    fn a_thousand_callers_behind_one_address_are_never_limited() {
        // The per-network waiting cap, all behind one NAT, for a minute:
        // each sends a conclusion every 250 ms and reconnects (a new
        // induction from a new port) every 3 s.
        let t = Instant::now();
        let mut l = Limiter::new(true, t);
        let a = ip("192.0.2.1");
        for tick in 0..240u64 {
            let now = t + Duration::from_millis(250 * tick);
            let attempt = (tick / 12) as u16;
            for c in 0..1000u16 {
                let port = 1000 + c + 1000 * (attempt % 50);
                if tick % 12 == 0 {
                    assert!(l.allow_unverified(a, now), "induction {tick}/{c}");
                }
                assert!(
                    l.allow_verified(sock(a, port), now),
                    "conclusion {tick}/{c}"
                );
            }
            if tick % 4 == 0 {
                l.prune(now);
            }
        }
        assert_eq!(l.take_dropped(), 0);
    }

    #[test]
    fn a_spoofed_flood_does_not_starve_verified_conclusions() {
        let t = Instant::now();
        let mut l = Limiter::new(true, t);
        let victim = ip("192.0.2.1");
        // Spoofed from everywhere, and from the victim's own address.
        for i in 0..100_000u32 {
            l.allow_unverified(v4(i), t);
            l.allow_unverified(victim, t);
        }
        assert!(!l.allow_unverified(victim, t));
        assert!(!l.allow_unverified(ip("198.51.100.1"), t));
        // Callers that proved their address keep going.
        assert!(l.allow_verified(sock(victim, 1000), t));
        assert!(l.allow_verified(sock(victim, 1001), t));
        assert!(l.allow_verified(sock(ip("198.51.100.1"), 1000), t));
    }

    #[test]
    fn a_full_table_does_not_lift_the_per_network_limit() {
        let t = Instant::now();
        let mut l = Limiter::new(true, t);
        for i in 0..MAX_NETS as u32 {
            l.allow_unverified(v4(i), t);
        }
        // Not in the table: shares the overflow bucket, still limited.
        // (Two seconds later, so that the total has refilled.)
        let t2 = t + Duration::from_secs(2);
        let a = ip("192.0.2.1");
        let n = (0..5000).filter(|_| l.allow_unverified(a, t2)).count();
        assert_eq!(n, NET_BURST as usize);
    }

    #[test]
    fn verified_conclusions_are_limited_per_socket() {
        let t = Instant::now();
        let mut l = Limiter::new(true, t);
        let a = sock(ip("192.0.2.1"), 1000);
        let n = (0..1000).filter(|_| l.allow_verified(a, t)).count();
        assert_eq!(n, SOCKET_BURST as usize);
        // Another socket on the same address is not affected.
        assert!(l.allow_verified(sock(ip("192.0.2.1"), 1001), t));
    }

    #[test]
    fn disabled_allows_everything() {
        let t = Instant::now();
        let mut l = Limiter::new(false, t);
        let a = ip("192.0.2.1");
        assert!((0..100_000).all(|_| l.allow_unverified(a, t)));
        assert!((0..100_000).all(|_| l.allow_verified(sock(a, 1), t)));
    }

    #[test]
    fn prune_forgets_only_what_has_been_quiet() {
        let t = Instant::now();
        let mut l = Limiter::new(true, t);
        let (a, b) = (ip("192.0.2.1"), ip("192.0.2.2"));
        l.allow_unverified(a, t);
        l.allow_verified(sock(a, 1), t);
        l.allow_unverified(b, t + Duration::from_secs(9));
        l.prune(t + FORGET_AFTER);
        assert!(!l.nets.contains_key(&a) && l.nets.contains_key(&b));
        assert!(l.sockets.is_empty());
    }
}
