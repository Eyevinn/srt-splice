//! srt-splice: one UDP port, SRT callers pair up by streamid.
//!
//! The relay answers the induction itself and holds each caller's
//! conclusion until a second caller with the same streamid arrives. Then it
//! answers both conclusions with the *other* party's parameters (socket id,
//! ISN, flow window, SRT version and flags, a common latency, a handshake
//! timestamp on the other party's clock), so each caller believes it is
//! connected straight to the other. After that every packet is forwarded
//! untouched: only the UDP address changes. ARQ, TSBPD, key refresh and
//! shutdown run end to end; the relay never terminates SRT.
//!
//! Encryption: each caller generated its own key and expects its own KM
//! echoed in the KMRSP, so the relay echoes it, and right after the
//! handshake sends each side the other side's KM as an in-band KMREQ (a key
//! update). The KM is wrapped with the passphrase, so the relay neither
//! needs nor learns it.

mod api;
mod wire;

use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::hash::BuildHasher;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use wire::*;

/// Callers repeat their conclusion every 250 ms (libsrt, srt-protocol)
/// until answered or timed out. A waiting caller not heard from for this
/// long has given up (one lost repeat is tolerated).
const DEAD_AFTER: Duration = Duration::from_millis(400);
const IDLE_TTL: Duration = Duration::from_secs(5);
const TICK: Duration = Duration::from_millis(20);
const KM_RETRY: Duration = Duration::from_millis(100);
const KM_TRIES: u32 = 30;
const STATS_EVERY: Duration = Duration::from_secs(5);

/// The `m` key of an access-control streamid: this caller's own role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// `m=publish`: this caller sends.
    Publish,
    /// `m=request`: this caller receives.
    Request,
    /// `m=bidirectional` or no `m` at all: no hint.
    Unknown,
}

/// The pairing key and mode of a streamid. Plain streamids pair on the
/// whole string. Access-control ones (`#!::r=cam1,m=publish,...`) pair on
/// `r` (or the whole string without `r`) and give the mode, so
/// `#!::r=cam1,m=request` pairs with a plain `cam1`.
fn parse_streamid(sid: &str) -> (String, Mode) {
    let Some(kv) = sid.strip_prefix("#!::") else {
        return (sid.to_string(), Mode::Unknown);
    };
    let (mut key, mut mode) = (None, Mode::Unknown);
    for item in kv.split(',') {
        match item.split_once('=') {
            Some(("r", v)) => key = Some(v.to_string()),
            Some(("m", "publish")) => mode = Mode::Publish,
            Some(("m", "request")) => mode = Mode::Request,
            _ => {}
        }
    }
    (key.unwrap_or_else(|| sid.to_string()), mode)
}

/// A caller as seen in its (latest) conclusion.
struct Party {
    addr: SocketAddr,
    hs: Handshake,
    /// Pairing key (see `parse_streamid`).
    sid: String,
    mode: Mode,
    /// The caller's time zero on our clock (its packet timestamps are µs since).
    start: Instant,
    /// When this caller's first conclusion arrived.
    arrived: Instant,
    last_seen: Instant,
}

impl Party {
    fn ts_now(&self) -> u32 {
        self.start.elapsed().as_micros() as u32
    }

    fn alive(&self, now: Instant) -> bool {
        now - self.last_seen < DEAD_AFTER
    }

    /// Whether this caller sends from the ISN in the conclusion response
    /// (srt-protocol: one ISN for both directions, taken from the response)
    /// rather than from its own (libsrt: sends from its own ISN, expects the
    /// peer from the response's). Against a real listener the two never
    /// differ, since the listener echoes the caller's ISN; here they do.
    /// Fingerprint: srt-protocol 0.4 announces SRT 1.3.1 with exactly
    /// TSBPDSND|TSBPDRCV|CRYPT|REXMITFLG; libsrt always adds TLPKTDROP and
    /// NAKREPORT unless turned off.
    fn adopts_response_isn(&self) -> bool {
        matches!(self.hs.hsreq(), Some((0x0001_0301, 0x27, _)))
    }
}

/// Which side sends media, from the `m` keys: Some(true) = a, Some(false)
/// = b, None = no hint, Err = both claim the same role.
fn sender(a: Mode, b: Mode) -> Result<Option<bool>, ()> {
    use Mode::*;
    match (a, b) {
        (Publish, Publish) | (Request, Request) => Err(()),
        (Publish, _) | (_, Request) => Ok(Some(true)),
        (_, Publish) | (Request, _) => Ok(Some(false)),
        (Unknown, Unknown) => Ok(None),
    }
}

/// The ISNs to put in the responses to (a, b), so that the data sender
/// sends from what the receiver expects. Err if the modes conflict.
///
/// With a known direction, both responses carry the sender's own ISN: the
/// sender gets its ISN echoed, as from any listener, so it sends from it
/// whether it is libsrt (own ISN) or srt-protocol (response ISN); every
/// receiver expects the peer's data from the response ISN. No fingerprint.
///
/// Without one, fall back to recognising srt-protocol (`fingerprint`), or
/// assume libsrt on both sides.
fn response_isns(a: &Party, b: &Party, fingerprint: bool) -> Result<(u32, u32, String), ()> {
    if let Some(a_sends) = sender(a.mode, b.mode)? {
        let s = if a_sends { a } else { b };
        let who = if a_sends { "a" } else { "b" };
        return Ok((
            s.hs.isn,
            s.hs.isn,
            format!("direction: {who} sends, both get its ISN"),
        ));
    }
    let (fa, fb) = if fingerprint {
        (a.adopts_response_isn(), b.adopts_response_isn())
    } else {
        (false, false)
    };
    let (ia, ib) = match (fa, fb) {
        // libsrt both: each expects the other's own ISN.
        (false, false) => (b.hs.isn, a.hs.isn),
        // One adopts: both use the other's own ISN.
        (true, false) => (b.hs.isn, b.hs.isn),
        (false, true) => (a.hs.isn, a.hs.isn),
        // Both adopt: any common value.
        (true, true) => (a.hs.isn, a.hs.isn),
    };
    let how = if fingerprint {
        format!("no direction, fingerprint: srt-protocol a={fa} b={fb}")
    } else {
        "no direction, fingerprint off: assuming libsrt both".into()
    };
    Ok((ia, ib, how))
}

/// At most this many callers wait on one streamid at a time.
const MAX_WAITING: usize = 4;

/// How long a replaced attempt is ignored, so it cannot take the place back.
const REPLACED_TTL: Duration = Duration::from_secs(5);

/// Why two callers' encryption settings cannot work end to end, as the
/// rejection reason libsrt itself would give. `None` = they match: a KM on
/// both sides with the same cipher and key length, or on neither.
fn crypto_mismatch(a: &Party, b: &Party) -> Option<(u32, &'static str)> {
    match (a.hs.km(), b.hs.km()) {
        (None, None) => None,
        (Some(_), None) | (None, Some(_)) => Some((REJ_UNSECURE, "encrypted on one side only")),
        (Some(ka), Some(kb)) => {
            let (pa, pb) = (km_params(ka), km_params(kb));
            if pa == pb {
                None
            } else if pa.map(|k| k.0) != pb.map(|k| k.0) {
                Some((REJ_CRYPTO, "different cipher"))
            } else {
                Some((REJ_BADSECRET, "different key length"))
            }
        }
    }
}

/// Whether two waiting callers may be paired: never two that state the
/// same role (two `m=request` are one receiver reconnecting, or a mistake),
/// and never two whose encryption settings do not match.
fn compatible(a: &Party, b: &Party) -> bool {
    sender(a.mode, b.mode).is_ok() && crypto_mismatch(a, b).is_none()
}

/// `(a, b)` ordered by arrival: the caller that arrived first comes first.
fn oldest_first<P: std::borrow::Borrow<Party>>(a: P, b: P) -> (P, P) {
    if a.borrow().arrived <= b.borrow().arrived {
        (a, b)
    } else {
        (b, a)
    }
}

/// Whether `a` and `b` are both known to be there: the older of the two
/// has repeated its conclusion since the newer one arrived. A caller that
/// gave up, or a caller's own earlier attempt before it reconnected from a
/// new port, never repeats, so it is never paired.
fn both_alive(a: &Party, b: &Party, now: Instant) -> bool {
    let (old, new) = oldest_first(a, b);
    old.last_seen > new.arrived && new.alive(now) && old.alive(now)
}

/// The best peer for `waiting[i]`, which has just repeated its conclusion:
/// the compatible one, known to be alive, heard from most recently.
fn best_peer(waiting: &[Party], i: usize, now: Instant) -> Option<usize> {
    let x = &waiting[i];
    waiting
        .iter()
        .enumerate()
        .filter(|(j, y)| *j != i && compatible(x, y) && both_alive(x, y, now))
        .max_by_key(|(_, y)| y.last_seen)
        .map(|(j, _)| j)
}

/// What to do with a new caller (not a repeat) on a streamid where
/// `waiting` callers already wait.
#[derive(Debug, PartialEq, Eq)]
enum Admit {
    /// Add it to the waiting callers.
    Wait,
    /// It is the caller of `waiting[i]` reconnecting: it takes that place.
    Replace(usize),
    /// Refuse it with this reason.
    Reject(u32, String),
}

/// Admission of a new caller. Only waiting callers it could actually pair
/// with count against it, so a stray with the wrong encryption settings
/// can neither take a place nor block a correctly configured caller.
///
/// - Same role as a waiting caller with matching encryption: from the same
///   host it is that caller reconnecting (a new port after its connect
///   timeout) and replaces it; from another host while the first is alive,
///   it is a second sender or receiver and is rejected (1409).
/// - A clear caller where every waiting caller of a compatible role is
///   encrypted is refused with `SRT_REJ_UNSECURE`, as a listener with a
///   passphrase would. Encrypted callers are never refused for a mismatch:
///   the relay cannot tell which side is the stray, and refusing them would
///   let whoever came first block the session. Without a passphrase the
///   streamid is the only protection anyway.
fn admit(waiting: &[Party], new: &Party, now: Instant) -> Admit {
    if new.mode != Mode::Unknown {
        let same_role = waiting
            .iter()
            .position(|c| c.mode == new.mode && crypto_mismatch(c, new).is_none());
        if let Some(i) = same_role {
            let c = &waiting[i];
            if c.addr.ip() != new.addr.ip() && c.alive(now) {
                return Admit::Reject(
                    REJX_CONFLICT,
                    format!("another m={:?} is waiting", new.mode),
                );
            }
            return Admit::Replace(i);
        }
    }
    if new.hs.km().is_none() {
        let mut peers = waiting
            .iter()
            .filter(|c| c.alive(now) && sender(c.mode, new.mode).is_ok())
            .peekable();
        if peers.peek().is_some() && peers.all(|c| c.hs.km().is_some()) {
            return Admit::Reject(REJ_UNSECURE, "the waiting peer is encrypted".into());
        }
    }
    if waiting.len() >= MAX_WAITING {
        return Admit::Reject(REJX_CONFLICT, "too many callers waiting".into());
    }
    Admit::Wait
}

struct Inject {
    pkt: Vec<u8>,
    next: Instant,
    left: u32,
}

#[derive(Default)]
struct Stats {
    pkts: u64,
    bytes: u64,
    data: u64,
    rexmit: u64,
    clear_data: u64,
    ctrl: u64,
    first_seq: Option<u32>,
    last_seq: u32,
}

struct Leg {
    sid: String,
    peer: SocketAddr,
    socket_id: u32,
    encrypted: bool,
    /// Our conclusion response, resent if the caller repeats its conclusion.
    response: Vec<u8>,
    /// The peer's KM we sent this side as an in-band KMREQ; its KMRSPs
    /// (which echo it) are ours to consume, not the peer's.
    injected_km: Option<Vec<u8>>,
    /// Retries of that KMREQ until the first matching KMRSP.
    inject: Option<Inject>,
    last_rx: Instant,
    stats: Stats,
}

struct Relay {
    sock: UdpSocket,
    verbose: bool,
    /// Recognise srt-protocol when no direction is given.
    fingerprint: bool,
    t0: Instant,
    /// Per-process random key for handshake cookies.
    secret: RandomState,
    /// Callers waiting for a peer, per pairing key.
    pending: HashMap<String, Vec<Party>>,
    /// Attempts replaced by a reconnect of the same caller; ignored a while.
    replaced: HashMap<SocketAddr, Instant>,
    legs: HashMap<SocketAddr, Leg>,
}

macro_rules! log {
    ($r:expr, $($a:tt)*) => {
        eprintln!("[{:8.3}] {}", $r.t0.elapsed().as_secs_f64(), format!($($a)*))
    };
}

impl Relay {
    fn send(&self, to: SocketAddr, p: &[u8]) {
        if let Err(e) = self.sock.send_to(p, to) {
            log!(self, "send to {to}: {e}");
        }
    }

    fn on_packet(&mut self, from: SocketAddr, p: &[u8]) {
        if p.len() < HDR {
            return;
        }
        if is_control(p) && ctrl_type(p) == CTRL_HANDSHAKE {
            return self.on_handshake(from, p);
        }
        let Some(leg) = self.legs.get_mut(&from) else {
            if self.verbose {
                log!(self, "{from}: stray packet ({} bytes), no session", p.len());
            }
            return;
        };
        leg.last_rx = Instant::now();
        leg.stats.pkts += 1;
        leg.stats.bytes += p.len() as u64;
        let peer = leg.peer;
        if is_control(p) {
            leg.stats.ctrl += 1;
            let (ty, sub) = (ctrl_type(p), ctrl_subtype(p));
            if ty == CTRL_EXT && sub == CMD_KMRSP {
                let body = &p[HDR..];
                if leg.injected_km.as_deref() == Some(body) {
                    // An answer (maybe a duplicate) to our injected key.
                    if leg.inject.take().is_some() {
                        log!(self, "[{}] {from}: peer key accepted (KMRSP)", leg.sid);
                    }
                    return;
                }
                if body.len() == 4 && leg.inject.is_some() {
                    // An error state while our key is outstanding.
                    let state = u32::from_be_bytes(body.try_into().unwrap());
                    let sid = leg.sid.clone();
                    log!(self, "[{sid}] {from}: peer key REJECTED (KM state {state}): passphrase mismatch?");
                    self.teardown(from, "bad key");
                    return;
                }
            }
            if ty == CTRL_EXT && (sub == CMD_KMREQ || sub == CMD_KMRSP) {
                log!(
                    self,
                    "[{}] {from}: in-band {} forwarded (key refresh)",
                    leg.sid,
                    if sub == CMD_KMREQ { "KMREQ" } else { "KMRSP" }
                );
            }
            self.send(peer, p);
            if ty == CTRL_SHUTDOWN {
                self.teardown(from, "shutdown");
            }
        } else {
            let s = &mut leg.stats;
            s.data += 1;
            if data_rexmit(p) {
                s.rexmit += 1;
            }
            if leg.encrypted && data_kk(p) == 0 {
                s.clear_data += 1;
            }
            let seq = data_seq(p);
            s.first_seq.get_or_insert(seq);
            s.last_seq = seq;
            self.send(peer, p);
        }
    }

    fn on_handshake(&mut self, from: SocketAddr, p: &[u8]) {
        let Some(hs) = Handshake::parse(p) else {
            log!(self, "{from}: malformed handshake");
            return;
        };
        match hs.hs_type {
            HS_INDUCTION => {
                if self.legs.contains_key(&from) {
                    self.teardown(from, "caller restarted on the same address");
                }
                // Version 5, the SRT magic, no key length preference.
                let rsp = Handshake {
                    version: 5,
                    enc_field: 0,
                    ext_field: SRT_MAGIC,
                    // Not used after the induction; anything unpredictable.
                    socket_id: (self.cookie(from) & 0x3FFF_FFFF) | 1,
                    cookie: self.cookie(from),
                    exts: vec![],
                    ..hs.clone()
                };
                if self.verbose {
                    log!(
                        self,
                        "{from}: induction (socket {:#x}, peer ip field {:02x?})",
                        hs.socket_id,
                        &hs.peer_ip[..8]
                    );
                }
                self.send(from, &handshake_packet(&rsp, 0, hs.socket_id));
            }
            HS_CONCLUSION => self.on_conclusion(from, p, hs),
            other => {
                if self.verbose {
                    log!(self, "{from}: ignoring handshake type {other:#x}");
                }
            }
        }
    }

    fn on_conclusion(&mut self, from: SocketAddr, p: &[u8], hs: Handshake) {
        let now = Instant::now();
        if let Some(leg) = self.legs.get(&from) {
            // Our response got lost: repeat it.
            if self.verbose {
                log!(
                    self,
                    "[{}] {from}: repeated conclusion, resending response",
                    leg.sid
                );
            }
            let r = leg.response.clone();
            return self.send(from, &r);
        }
        if hs.cookie != self.cookie(from) {
            // No induction from this address: spoofed or stale. Drop
            // silently, so the relay cannot be made to send to it.
            if self.verbose {
                log!(self, "{from}: conclusion with a wrong cookie, dropped");
            }
            return;
        }
        if hs.version != 5 {
            return self.reject(from, &hs, REJ_PEER, "not HSv5");
        }
        let Some(raw_sid) = hs.streamid() else {
            return self.reject(from, &hs, REJX_BAD_REQUEST, "no streamid");
        };
        let (sid, mode) = parse_streamid(&raw_sid);
        if hs.hsreq().is_none() {
            return self.reject(from, &hs, REJ_ROGUE, "no HSREQ");
        }
        if hs.ext(CMD_FILTER).is_some() {
            return self.reject(from, &hs, REJ_FILTER, "packet filter not supported");
        }
        if hs.ext(CMD_GROUP).is_some() {
            return self.reject(from, &hs, REJ_GROUP, "groups not supported");
        }
        if self.legs.values().any(|l| l.sid == sid) {
            return self.reject(from, &hs, REJX_CONFLICT, &format!("streamid {sid:?} busy"));
        }
        // The caller's clock: its timestamp is µs since its start. Remote
        // input, so never let it underflow our clock.
        let ts = Duration::from_micros(timestamp(p) as u64);
        let mut party = Party {
            addr: from,
            sid: sid.clone(),
            mode,
            start: now.checked_sub(ts).unwrap_or(now),
            arrived: now,
            last_seen: now,
            hs,
        };
        if let Some(t) = self.replaced.get_mut(&from) {
            // Stays ignored for as long as it keeps repeating.
            *t = now;
            if self.verbose {
                log!(self, "[{sid}] {from}: replaced attempt, ignored");
            }
            return;
        }
        // No answer to a waiting caller: it keeps repeating its conclusion.
        let waiting = self.pending.entry(sid.clone()).or_default();
        if let Some(i) = waiting.iter().position(|c| c.addr == from) {
            // A repeat: refresh it, then pair with the best live peer.
            party.arrived = waiting[i].arrived;
            waiting[i] = party;
            if let Some(j) = best_peer(waiting, i, now) {
                let (hi, lo) = (i.max(j), i.min(j));
                let a = waiting.remove(hi);
                let b = waiting.remove(lo);
                if waiting.is_empty() {
                    self.pending.remove(&sid);
                }
                self.pair(a, b);
            }
            return;
        }
        match admit(waiting, &party, now) {
            Admit::Reject(code, why) => {
                if waiting.is_empty() {
                    self.pending.remove(&sid);
                }
                return self.reject(from, &party.hs, code, &format!("streamid {sid:?}: {why}"));
            }
            Admit::Replace(i) => {
                let old_addr = waiting.remove(i).addr;
                self.replaced.insert(old_addr, now);
                log!(
                    self,
                    "[{sid}] {from} replaces {old_addr} (same role {mode:?})"
                );
            }
            Admit::Wait => {}
        }
        let waiting = &self.pending[&sid];
        let what = if waiting.is_empty() {
            "waiting for a peer".into()
        } else if waiting.iter().any(|c| compatible(c, &party)) {
            "waiting; pairs once both have repeated".into()
        } else if let Some((_, why)) = waiting.iter().find_map(|c| crypto_mismatch(c, &party)) {
            format!("waiting; no compatible peer yet ({why})")
        } else {
            "waiting; no compatible peer yet".into()
        };
        self.log_waiting(&party, &what);
        self.pending.get_mut(&sid).unwrap().push(party);
    }

    fn log_waiting(&self, p: &Party, what: &str) {
        log!(
            self,
            "[{}] {} {what} (socket {:#x}, {:?}, {})",
            p.sid,
            p.addr,
            p.hs.socket_id,
            p.mode,
            if p.hs.km().is_some() {
                "encrypted"
            } else {
                "clear"
            }
        );
    }

    fn cookie(&self, a: SocketAddr) -> u32 {
        self.secret.hash_one(a) as u32
    }

    /// Pairs two compatible callers (see `compatible`).
    fn pair(&mut self, a: Party, b: Party) {
        let sid = a.sid.clone();
        let (a, b) = oldest_first(a, b);
        let a_km = a.hs.km();
        let Ok((isn_a, isn_b, how)) = response_isns(&a, &b, self.fingerprint) else {
            log!(self, "[{sid}] both sides m={:?}: rejecting both", a.mode);
            self.reject(a.addr, &a.hs, REJX_BAD_MODE, "same m as peer");
            self.reject(b.addr, &b.hs, REJX_BAD_MODE, "same m as peer");
            return;
        };
        let lat = |p: &Party| {
            let (_, _, w) = p.hs.hsreq().unwrap();
            (w >> 16).max(w & 0xFFFF)
        };
        let latency = lat(&a).max(lat(&b));
        let encrypted = a_km.is_some();
        log!(self, "[{sid}] PAIR {} (socket {:#x}, isn {}) <-> {} (socket {:#x}, isn {}), latency {} ms (asked {} / {}), {}",
            a.addr, a.hs.socket_id, a.hs.isn, b.addr, b.hs.socket_id, b.hs.isn, latency, lat(&a), lat(&b),
            match a_km.and_then(km_params) {
                Some((c, k)) => format!("{} AES-{}", if c == 4 { "GCM" } else { "CTR" }, k * 8),
                None => "unencrypted".into(),
            });
        log!(
            self,
            "[{sid}] ISN: {how} (a {:?}, b {:?}) -> {isn_a} / {isn_b}",
            a.mode,
            b.mode
        );
        // Response and KM injection for each side, in an order that lets
        // each side hold the peer's key before the peer can send data.
        for (x, p, isn) in [(&a, &b, isn_a), (&b, &a, isn_b)] {
            let mut rsp = response_for(x, p, latency);
            rsp.isn = isn;
            let rsp_pkt = handshake_packet(&rsp, p.ts_now(), x.hs.socket_id);
            self.send(x.addr, &rsp_pkt);
            let inject = p.hs.km().map(|km| {
                let pkt = control(CTRL_EXT, CMD_KMREQ, 0, p.ts_now(), x.hs.socket_id, km);
                self.send(x.addr, &pkt);
                Inject {
                    pkt,
                    next: Instant::now() + KM_RETRY,
                    left: KM_TRIES,
                }
            });
            self.legs.insert(
                x.addr,
                Leg {
                    sid: sid.clone(),
                    peer: p.addr,
                    socket_id: x.hs.socket_id,
                    encrypted,
                    response: rsp_pkt,
                    injected_km: p.hs.km().map(<[u8]>::to_vec),
                    inject,
                    last_rx: Instant::now(),
                    stats: Stats::default(),
                },
            );
        }
    }

    fn reject(&self, to: SocketAddr, hs: &Handshake, reason: u32, why: &str) {
        log!(self, "{to}: REJECT {reason} ({why})");
        let rsp = Handshake {
            version: 5,
            hs_type: HS_REJECT_BASE + reason,
            exts: vec![],
            ..hs.clone()
        };
        self.send(to, &handshake_packet(&rsp, 0, hs.socket_id));
    }

    /// Ends the session `addr` belongs to: tells the other side, drops both.
    fn teardown(&mut self, addr: SocketAddr, why: &str) {
        let Some(leg) = self.legs.remove(&addr) else {
            return;
        };
        self.print_stats(addr, &leg);
        if let Some(other) = self.legs.remove(&leg.peer) {
            self.print_stats(leg.peer, &other);
            let bye = control(CTRL_SHUTDOWN, 0, 0, 0, other.socket_id, &[0; 4]);
            self.send(leg.peer, &bye);
            // and the side that is going away, in case it is not.
            let bye = control(CTRL_SHUTDOWN, 0, 0, 0, leg.socket_id, &[0; 4]);
            self.send(addr, &bye);
        }
        log!(self, "[{}] closed: {why}", leg.sid);
    }

    fn print_stats(&self, addr: SocketAddr, l: &Leg) {
        let s = &l.stats;
        log!(self, "[{}] {addr} -> {}: pkts {} ({} kB), data {} (rexmit {}, clear {}), ctrl {}, seq {:?}..{}",
            l.sid, l.peer, s.pkts, s.bytes / 1000, s.data, s.rexmit, s.clear_data, s.ctrl, s.first_seq, s.last_seq);
    }

    fn tick(&mut self) {
        let now = Instant::now();
        // Injection retries.
        let mut sends = Vec::new();
        let mut gave_up = Vec::new();
        for (addr, leg) in self.legs.iter_mut() {
            if let Some(inj) = &mut leg.inject {
                if now >= inj.next {
                    if inj.left == 0 {
                        gave_up.push(*addr);
                    } else {
                        inj.left -= 1;
                        inj.next = now + KM_RETRY;
                        sends.push((*addr, inj.pkt.clone()));
                    }
                }
            }
        }
        for (a, p) in sends {
            self.send(a, &p);
        }
        for a in gave_up {
            log!(self, "{a}: no answer to the injected key");
            self.teardown(a, "key injection unanswered");
        }
        self.replaced.retain(|_, t| now - *t < REPLACED_TTL);
        // Waiting callers that gave up.
        self.pending.retain(|_, w| {
            w.retain(|c| c.alive(now));
            !w.is_empty()
        });
        // Idle sessions.
        let idle: Vec<_> = self
            .legs
            .iter()
            .filter(|(_, l)| now - l.last_rx > IDLE_TTL)
            .map(|(a, _)| *a)
            .collect();
        for a in idle {
            self.teardown(a, "idle");
        }
    }
}

/// The conclusion response for `x`, describing its peer `p`.
fn response_for(x: &Party, p: &Party, latency: u32) -> Handshake {
    let (p_ver, p_flags, _) = p.hs.hsreq().unwrap();
    let mut hsrsp = Vec::with_capacity(12);
    hsrsp.extend(p_ver.to_be_bytes());
    hsrsp.extend(p_flags.to_be_bytes());
    hsrsp.extend(((latency << 16) | latency).to_be_bytes());
    let mut exts = vec![Ext {
        cmd: CMD_HSRSP,
        data: hsrsp,
    }];
    let mut ext_field = EXT_HSREQ;
    if let Some(km) = x.hs.km() {
        // The caller only accepts its own KM back.
        exts.push(Ext {
            cmd: CMD_KMRSP,
            data: km.to_vec(),
        });
        ext_field |= EXT_KMREQ;
    }
    Handshake {
        version: 5,
        enc_field: 0,
        ext_field,
        isn: p.hs.isn,
        mss: x.hs.mss.min(p.hs.mss),
        flow: p.hs.flow,
        hs_type: HS_CONCLUSION,
        socket_id: p.hs.socket_id,
        cookie: x.hs.cookie,
        // As a listener does: the caller's address as we see it.
        peer_ip: peer_ip_field(x.addr),
        exts,
    }
}

/// The handshake's peer IP field as libsrt writes it: the address bytes in
/// 32-bit groups, each group byte-reversed (IPv4 in the first group).
fn peer_ip_field(a: SocketAddr) -> [u8; 16] {
    let mut f = [0u8; 16];
    match a.ip() {
        std::net::IpAddr::V4(v4) => f[..4].copy_from_slice(&v4.octets()),
        std::net::IpAddr::V6(v6) => f.copy_from_slice(&v6.octets()),
    }
    for w in f.chunks_mut(4) {
        w.reverse();
    }
    f
}

fn main() {
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let mut listen = env("SRT_SPLICE_LISTEN").unwrap_or_else(|| "0.0.0.0:9000".into());
    let mut api_listen = env("SRT_SPLICE_API").unwrap_or_else(|| "127.0.0.1:9001".into());
    let mut public = env("SRT_SPLICE_PUBLIC");
    let mut verbose = false;
    let mut fingerprint = true;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-v" | "--verbose" => verbose = true,
            "--no-fingerprint" => fingerprint = false,
            "-l" | "--listen" => listen = args.next().expect("--listen ADDR"),
            "--api" => api_listen = args.next().expect("--api ADDR|off"),
            "--public" => public = Some(args.next().expect("--public HOST:PORT")),
            _ => {
                eprintln!(
                    "usage: srt-splice [--listen ADDR:PORT] [--api ADDR:PORT|off] \
                     [--public HOST:PORT] [--no-fingerprint] [-v]"
                );
                std::process::exit(2);
            }
        }
    }
    let sock = UdpSocket::bind(&listen).expect("bind");
    let srt_port = sock.local_addr().map(|a| a.port()).unwrap_or(0);
    sock.set_read_timeout(Some(TICK)).unwrap();
    let mut r = Relay {
        sock,
        verbose,
        fingerprint,
        t0: Instant::now(),
        secret: RandomState::new(),
        pending: HashMap::new(),
        replaced: HashMap::new(),
        legs: HashMap::new(),
    };
    log!(r, "srt-splice listening on udp {listen}");
    if api_listen != "off" {
        match api::spawn(
            &api_listen,
            api::Info {
                public: public.clone(),
                srt_port,
            },
        ) {
            Ok(addr) => log!(
                r,
                "api on http://{addr} (public address: {})",
                public.as_deref().unwrap_or("not set, use --public")
            ),
            // The API is a convenience: the relay runs on without it.
            Err(e) => log!(
                r,
                "WARNING: api: cannot listen on {api_listen}: {e}; running without the API"
            ),
        }
    }
    // The largest UDP payload, so nothing is ever forwarded truncated.
    let mut buf = vec![0u8; 65536];
    let mut next_tick = Instant::now() + TICK;
    let mut next_stats = Instant::now() + STATS_EVERY;
    loop {
        match r.sock.recv_from(&mut buf) {
            Ok((n, from)) => r.on_packet(from, &buf[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(e) => log!(r, "recv: {e}"),
        }
        // Timers off the per-packet path.
        if Instant::now() >= next_tick {
            next_tick = Instant::now() + TICK;
            r.tick();
        }
        if Instant::now() >= next_stats {
            next_stats += STATS_EVERY;
            if verbose {
                for (a, l) in &r.legs {
                    r.print_stats(*a, l);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streamid_plain_and_access_control() {
        assert_eq!(parse_streamid("cam1"), ("cam1".into(), Mode::Unknown));
        assert_eq!(
            parse_streamid("#!::r=cam1,m=request"),
            ("cam1".into(), Mode::Request)
        );
        assert_eq!(
            parse_streamid("#!::m=publish,u=x,r=pgm"),
            ("pgm".into(), Mode::Publish)
        );
        assert_eq!(
            parse_streamid("#!::m=bidirectional"),
            ("#!::m=bidirectional".into(), Mode::Unknown)
        );
    }

    #[test]
    fn sender_from_modes() {
        use Mode::*;
        assert_eq!(sender(Publish, Unknown), Ok(Some(true)));
        assert_eq!(sender(Unknown, Request), Ok(Some(true)));
        assert_eq!(sender(Request, Publish), Ok(Some(false)));
        assert_eq!(sender(Unknown, Unknown), Ok(None));
        assert_eq!(sender(Publish, Publish), Err(()));
        assert_eq!(sender(Request, Request), Err(()));
    }

    fn party(port: u16, mode: Mode, arrived: Instant, last_seen: Instant) -> Party {
        Party {
            addr: SocketAddr::from(([127, 0, 0, 1], port)),
            hs: Handshake {
                version: 5,
                enc_field: 0,
                ext_field: 0,
                isn: 0,
                mss: 1500,
                flow: 8192,
                hs_type: HS_CONCLUSION,
                socket_id: port as u32,
                cookie: 0,
                peer_ip: [0; 16],
                exts: vec![],
            },
            sid: "s".into(),
            mode,
            start: arrived,
            arrived,
            last_seen,
        }
    }

    #[test]
    fn pairing_needs_a_repeat_from_the_older_caller() {
        let t0 = Instant::now();
        let ms = |n| t0 + Duration::from_millis(n);
        let new = party(2, Mode::Unknown, ms(1000), ms(1000));
        // The older caller last repeated before the new one arrived: it may
        // have given up (or be the new caller's own earlier attempt).
        let stale = party(1, Mode::Unknown, ms(0), ms(900));
        assert!(!both_alive(&stale, &new, ms(1010)));
        // It repeated after the new one arrived: pair.
        let live = party(1, Mode::Unknown, ms(0), ms(1100));
        assert!(both_alive(&live, &new, ms(1110)));
        assert!(both_alive(&new, &live, ms(1110)));
    }

    #[test]
    fn same_role_never_pairs() {
        let t = Instant::now();
        let req = party(1, Mode::Request, t, t);
        let req2 = party(2, Mode::Request, t, t);
        let publ = party(3, Mode::Publish, t, t);
        let any = party(4, Mode::Unknown, t, t);
        assert!(!compatible(&req, &req2));
        assert!(compatible(&req, &publ));
        assert!(compatible(&req, &any));
        assert!(compatible(&any, &party(5, Mode::Unknown, t, t)));
    }

    /// `p` with a KM of this cipher (2 = CTR) and key length in bytes.
    fn enc(mut p: Party, cipher: u8, klen: u8) -> Party {
        let mut km = vec![0u8; 32];
        km[8] = cipher;
        km[15] = klen / 4;
        p.hs.exts.push(Ext {
            cmd: CMD_KMREQ,
            data: km,
        });
        p
    }

    /// `p` calling from another host.
    fn from_host(mut p: Party, last_octet: u8) -> Party {
        p.addr = SocketAddr::from(([127, 0, 0, last_octet], p.addr.port()));
        p
    }

    #[test]
    fn encryption_must_match_to_pair() {
        let t = Instant::now();
        let p = |port| party(port, Mode::Unknown, t, t);
        assert!(compatible(&p(1), &p(2)));
        assert!(compatible(&enc(p(1), 2, 16), &enc(p(2), 2, 16)));
        assert!(!compatible(&enc(p(1), 2, 16), &p(2)));
        assert!(!compatible(&p(1), &enc(p(2), 2, 16)));
        assert!(!compatible(&enc(p(1), 2, 16), &enc(p(2), 2, 32)));
        assert!(!compatible(&enc(p(1), 2, 16), &enc(p(2), 4, 16)));
        assert_eq!(
            crypto_mismatch(&enc(p(1), 2, 16), &enc(p(2), 4, 16))
                .unwrap()
                .0,
            REJ_CRYPTO
        );
        assert_eq!(
            crypto_mismatch(&enc(p(1), 2, 16), &enc(p(2), 2, 32))
                .unwrap()
                .0,
            REJ_BADSECRET
        );
    }

    #[test]
    fn plain_pair_still_meets() {
        let t0 = Instant::now();
        let ms = |n| t0 + Duration::from_millis(n);
        let rcv = party(1, Mode::Unknown, ms(0), ms(0));
        let snd = party(2, Mode::Unknown, ms(1000), ms(1000));
        let mut waiting = vec![rcv];
        assert_eq!(admit(&waiting, &snd, ms(1000)), Admit::Wait);
        waiting.push(snd);
        waiting[0].last_seen = ms(1100);
        assert_eq!(best_peer(&waiting, 0, ms(1100)), Some(1));
    }

    #[test]
    fn stray_clear_caller_first_then_encrypted_pair_meets() {
        let t0 = Instant::now();
        let ms = |n| t0 + Duration::from_millis(n);
        let stray = from_host(party(1, Mode::Unknown, ms(0), ms(0)), 9);
        let rcv = enc(party(2, Mode::Unknown, ms(500), ms(500)), 2, 16);
        let snd = enc(party(3, Mode::Unknown, ms(1000), ms(1000)), 2, 16);
        let mut waiting = vec![stray];
        // The encrypted receiver is not refused because of the stray.
        assert_eq!(admit(&waiting, &rcv, ms(500)), Admit::Wait);
        waiting.push(rcv);
        assert_eq!(admit(&waiting, &snd, ms(1000)), Admit::Wait);
        waiting.push(snd);
        // Everyone repeats; the stray is the most recent, and never chosen.
        waiting[1].last_seen = ms(1100);
        waiting[2].last_seen = ms(1150);
        waiting[0].last_seen = ms(1200);
        assert_eq!(best_peer(&waiting, 0, ms(1200)), None);
        assert_eq!(best_peer(&waiting, 1, ms(1200)), Some(2));
        assert_eq!(best_peer(&waiting, 2, ms(1200)), Some(1));
    }

    #[test]
    fn stray_clear_caller_after_encrypted_receiver_is_refused() {
        let t0 = Instant::now();
        let ms = |n| t0 + Duration::from_millis(n);
        let rcv = enc(party(1, Mode::Unknown, ms(0), ms(400)), 2, 16);
        let stray = from_host(party(2, Mode::Unknown, ms(500), ms(500)), 9);
        let waiting = vec![rcv];
        assert!(matches!(
            admit(&waiting, &stray, ms(500)),
            Admit::Reject(REJ_UNSECURE, _)
        ));
        // An encrypted caller with other settings is never refused: it
        // cannot block a correctly configured one that comes later.
        let other = enc(party(3, Mode::Unknown, ms(500), ms(500)), 2, 32);
        assert_eq!(admit(&waiting, &other, ms(500)), Admit::Wait);
        // Only waiting callers of a compatible role count: a clear m=request
        // next to an encrypted m=request just waits.
        let req = enc(party(4, Mode::Request, ms(0), ms(400)), 2, 16);
        let clear_req = from_host(party(5, Mode::Request, ms(500), ms(500)), 9);
        assert_eq!(admit(&[req], &clear_req, ms(500)), Admit::Wait);
    }

    #[test]
    fn stray_does_not_block_same_role_caller() {
        let t0 = Instant::now();
        let ms = |n| t0 + Duration::from_millis(n);
        // A clear m=request from another host waits, repeating.
        let stray = from_host(party(1, Mode::Request, ms(0), ms(400)), 9);
        let rcv = enc(party(2, Mode::Request, ms(500), ms(500)), 2, 16);
        let mut waiting = vec![stray];
        // Not a 1409: the stray could never pair with the receiver's peer.
        assert_eq!(admit(&waiting, &rcv, ms(500)), Admit::Wait);
        waiting.push(rcv);
        let snd = enc(party(3, Mode::Publish, ms(1000), ms(1000)), 2, 16);
        assert_eq!(admit(&waiting, &snd, ms(1000)), Admit::Wait);
        waiting.push(snd);
        waiting[0].last_seen = ms(1100);
        waiting[1].last_seen = ms(1100);
        assert_eq!(best_peer(&waiting, 1, ms(1100)), Some(2));
        assert_eq!(best_peer(&waiting, 0, ms(1100)), None);
    }

    #[test]
    fn same_role_with_matching_encryption_conflicts_or_replaces() {
        let t0 = Instant::now();
        let ms = |n| t0 + Duration::from_millis(n);
        let rcv = enc(party(1, Mode::Request, ms(0), ms(400)), 2, 16);
        let waiting = vec![rcv];
        let other_host = from_host(enc(party(2, Mode::Request, ms(500), ms(500)), 2, 16), 9);
        assert!(matches!(
            admit(&waiting, &other_host, ms(500)),
            Admit::Reject(REJX_CONFLICT, _)
        ));
        let reconnect = enc(party(3, Mode::Request, ms(500), ms(500)), 2, 16);
        assert_eq!(admit(&waiting, &reconnect, ms(500)), Admit::Replace(0));
    }

    #[test]
    fn peer_ip_field_matches_libsrt() {
        // libsrt sends 127.0.0.1 as 01 00 00 7f, then zeros.
        let f = peer_ip_field("127.0.0.1:9000".parse().unwrap());
        assert_eq!(f[..4], [1, 0, 0, 127]);
        assert!(f[4..].iter().all(|b| *b == 0));
    }

    #[test]
    fn km_params_key_length_does_not_overflow() {
        let mut km = vec![0u8; 32];
        km[8] = 2;
        km[15] = 0xFF;
        assert_eq!(km_params(&km), Some((2, 1020)));
        km[15] = 4;
        assert_eq!(km_params(&km), Some((2, 16)));
        assert_eq!(km_params(&km[..10]), None);
    }
}
