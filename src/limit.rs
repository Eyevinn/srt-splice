//! Rate limiting for handshakes.
//!
//! Only handshakes are limited; established sessions are never touched.
//! There is a token bucket per source network (an IPv4 address, or an IPv6
//! /64, since one host may hold a whole /64), so that one host cannot use up
//! the budget of everyone else, and one for all handshakes together, so that
//! a flood cannot take the forwarding thread.
//!
//! The limits are far above what callers send, because many legitimate
//! callers can share one address: everything behind a cloud NAT gateway, a
//! production cluster with dozens of outputs, a venue, a carrier-grade NAT.
//! A waiting caller sends about 4 handshakes a second (a conclusion every
//! 250 ms) and reconnects about every 3 s, so `NET_RATE` leaves room for
//! some 200 callers waiting at once behind one address. Over the limit, handshakes are dropped, never
//! refused: a caller loses a few repeats and keeps trying, as on a lossy
//! path.
//!
//! There are no bans. A host that keeps getting refused is most likely a
//! caller retrying (a second receiver on a 1:1 stream, a reconnect loop),
//! and a ban would also lock out every legitimate caller behind the same
//! address. The rate limit already bounds what any host can cost.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

/// Handshake packets per second from one network, and the burst.
const NET_RATE: f64 = 1000.0;
const NET_BURST: f64 = 2000.0;
/// Handshake packets per second in total, and the burst: some 5000 callers
/// waiting at once, at a few microseconds each.
const GLOBAL_RATE: f64 = 20_000.0;
const GLOBAL_BURST: f64 = 40_000.0;
/// Networks tracked at once. Beyond that, new ones share the global limit.
const MAX_NETS: usize = 65536;

/// The network an address counts against: IPv4 as is, IPv6 by its /64.
/// IPv4-mapped IPv6 addresses count as IPv4.
pub fn net(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
    }
}

#[derive(Clone, Copy, Debug)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn full(burst: f64, now: Instant) -> Bucket {
        Bucket {
            tokens: burst,
            at: now,
        }
    }

    fn refill(&mut self, rate: f64, burst: f64, now: Instant) {
        let dt = now.saturating_duration_since(self.at).as_secs_f64();
        self.tokens = (self.tokens + dt * rate).min(burst);
        self.at = now;
    }

    /// Takes one token if there is one.
    fn take(&mut self, rate: f64, burst: f64, now: Instant) -> bool {
        self.refill(rate, burst, now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn is_full(&self, rate: f64, burst: f64, now: Instant) -> bool {
        let mut b = *self;
        b.refill(rate, burst, now);
        b.tokens >= burst
    }
}

pub struct Limiter {
    enabled: bool,
    global: Bucket,
    nets: HashMap<IpAddr, Bucket>,
    /// Handshakes dropped since the last `take_dropped`.
    dropped: u64,
}

impl Limiter {
    pub fn new(enabled: bool, now: Instant) -> Limiter {
        Limiter {
            enabled,
            global: Bucket::full(GLOBAL_BURST, now),
            nets: HashMap::new(),
            dropped: 0,
        }
    }

    /// Whether to handle a handshake packet from `ip`.
    pub fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        if !self.enabled {
            return true;
        }
        let key = net(ip);
        // Without room for its network, only the global limit applies.
        let net_ok = if self.nets.contains_key(&key) || self.nets.len() < MAX_NETS {
            self.nets
                .entry(key)
                .or_insert_with(|| Bucket::full(NET_BURST, now))
                .take(NET_RATE, NET_BURST, now)
        } else {
            true
        };
        if !(net_ok && self.global.take(GLOBAL_RATE, GLOBAL_BURST, now)) {
            self.dropped += 1;
            return false;
        }
        true
    }

    /// Forgets networks whose bucket is full again.
    pub fn prune(&mut self, now: Instant) {
        self.nets
            .retain(|_, b| !b.is_full(NET_RATE, NET_BURST, now));
    }

    pub fn take_dropped(&mut self) -> u64 {
        std::mem::take(&mut self.dropped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn ipv6_counts_by_64_and_mapped_ipv4_as_ipv4() {
        assert_eq!(net(ip("2001:db8:1:2:3:4:5:6")), ip("2001:db8:1:2::"));
        assert_eq!(net(ip("2001:db8:1:2:ffff::1")), ip("2001:db8:1:2::"));
        assert_eq!(net(ip("::ffff:192.0.2.1")), ip("192.0.2.1"));
        assert_eq!(net(ip("192.0.2.1")), ip("192.0.2.1"));
    }

    #[test]
    fn rate_per_network_refills() {
        let t = Instant::now();
        let mut l = Limiter::new(true, t);
        let a = ip("192.0.2.1");
        let n = (0..5000).filter(|_| l.allow(a, t)).count();
        assert_eq!(n, NET_BURST as usize);
        // Another network is not affected.
        assert!(l.allow(ip("192.0.2.2"), t));
        // A second later, NET_RATE more.
        let t1 = t + Duration::from_secs(1);
        let n = (0..5000).filter(|_| l.allow(a, t1)).count();
        assert_eq!(n, NET_RATE as usize);
        assert_eq!(l.take_dropped(), 10_000 - 3000);
    }

    #[test]
    fn many_waiting_callers_behind_one_address_are_never_limited() {
        // 200 callers behind one NAT, each sending a conclusion every 250
        // ms, plus one induction each every 3 s (reconnects), for a minute.
        let t = Instant::now();
        let mut l = Limiter::new(true, t);
        let a = ip("192.0.2.1");
        for tick in 0..240u64 {
            let now = t + Duration::from_millis(250 * tick);
            let inductions = if tick % 12 == 0 { 200 } else { 0 };
            assert!(
                (0..200 + inductions).all(|_| l.allow(a, now)),
                "tick {tick}"
            );
        }
        assert_eq!(l.take_dropped(), 0);
    }

    #[test]
    fn ipv6_hosts_in_one_64_share_a_budget() {
        let t = Instant::now();
        let mut l = Limiter::new(true, t);
        let n = (0..5000u16)
            .filter(|i| l.allow(ip(&format!("2001:db8::{i:x}")), t))
            .count();
        assert_eq!(n, NET_BURST as usize);
    }

    #[test]
    fn global_limit_holds_across_networks() {
        let t = Instant::now();
        let mut l = Limiter::new(true, t);
        let n = (0..60_000u32)
            .filter(|i| l.allow(IpAddr::V4((0x0A00_0000 + i).into()), t))
            .count();
        assert_eq!(n, GLOBAL_BURST as usize);
    }

    #[test]
    fn disabled_allows_everything() {
        let t = Instant::now();
        let mut l = Limiter::new(false, t);
        let a = ip("192.0.2.1");
        assert!((0..100_000).all(|_| l.allow(a, t)));
    }

    #[test]
    fn prune_forgets_networks_that_are_quiet_again() {
        let t = Instant::now();
        let mut l = Limiter::new(true, t);
        l.allow(ip("192.0.2.1"), t);
        l.prune(t);
        assert_eq!(l.nets.len(), 1);
        l.prune(t + Duration::from_secs(1));
        assert!(l.nets.is_empty());
    }
}
