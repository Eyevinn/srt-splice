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
//! handshake sends the other side's KM as an in-band KMREQ (a key update):
//! to the receiver if the direction is known, otherwise to both sides. The
//! KM is wrapped with the passphrase, so the relay neither needs nor learns
//! it.

// Remote input must never be able to stop the relay: no panicking shortcuts
// outside the tests.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

mod health;
mod limit;
mod wire;

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::hash::BuildHasher;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use limit::{net, Limiter};
use wire::*;

/// Callers repeat their conclusion every 250 ms (libsrt, srt-protocol)
/// until answered or timed out. A waiting caller not heard from for this
/// long has given up (one lost repeat is tolerated).
const DEAD_AFTER: Duration = Duration::from_millis(400);
/// Some callers send their conclusion once and wait for the answer without
/// repeating it (gosrt). Such a caller, seen exactly once, counts as alive
/// for this long after it arrived. It must be shorter than its connect
/// timeout, so that a pairing still reaches it: 3 s by default in gosrt
/// (measured from the induction) and libsrt. 2.5 s leaves 500 ms for the
/// induction and the response on a slow path.
const SINGLE_SHOT_ALIVE: Duration = Duration::from_millis(2500);
const IDLE_TTL: Duration = Duration::from_secs(5);
const TICK: Duration = Duration::from_millis(20);
const KM_RETRY: Duration = Duration::from_millis(100);
const KM_TRIES: u32 = 30;
const STATS_EVERY: Duration = Duration::from_secs(5);
/// A leg moves to a new address (NAT rebinding) only after its current
/// address has been silent this long. A healthy leg is never silent that
/// long while media flows: the receiver ACKs every 10 ms, and a sender sends
/// at its bitrate (even a 64 kbit/s audio-only stream sends a packet every
/// ~160 ms). So packets from anyone else who learned the socket id, or late
/// packets from the old address, cannot take over a leg that is still
/// sending. The price: a real rebinding loses up to this much media unless
/// the SRT latency covers it. See docs/DESIGN.md.
const REBIND_QUIET: Duration = Duration::from_millis(500);
/// The smallest and largest MSS `--max-mss` accepts. 76 is libsrt's own
/// minimum; above 1500 there is no cap to speak of on the internet.
const MSS_RANGE: std::ops::RangeInclusive<u32> = 76..=1500;
/// The longest streamid accepted, in bytes: libsrt's own limit
/// (`MAX_SID_LENGTH`).
const MAX_SID_LEN: usize = 512;
/// The largest handshake packet handled. A handshake travels in one packet
/// within the path MTU; anything bigger is not from an SRT caller.
const MAX_HS_LEN: usize = 1500;
/// Callers waiting at a time from one network (an IPv4 address or an IPv6
/// /64, see `limit::net`), over all streamids. Generous: everything behind
/// a cloud NAT gateway or a production cluster can share one address. It
/// only keeps one host from taking all of `MAX_WAITING_TOTAL`.
const MAX_WAITING_PER_NET: usize = 1000;
/// Callers waiting at a time, in total. A waiting caller holds its
/// handshake, at most `MAX_HS_LEN` bytes: some 40 MB when full.
const MAX_WAITING_TOTAL: usize = 20_000;
/// Handshake cookies are valid for one to two of these. Long enough for any
/// caller between its induction and its conclusion; short enough that a
/// cookie seen once does not stay valid for the life of the process.
const COOKIE_PERIOD: Duration = Duration::from_secs(600);
/// How often the limiter forgets networks with nothing to remember.
const PRUNE_EVERY: Duration = Duration::from_secs(1);

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
    /// How often it has repeated its conclusion (0 = seen once).
    repeats: u32,
}

impl Party {
    fn ts_now(&self) -> u32 {
        self.start.elapsed().as_micros() as u32
    }

    /// Whether this caller is still waiting. A caller that repeats its
    /// conclusion (libsrt, srt-protocol: every 250 ms) is gone once it falls
    /// silent for `DEAD_AFTER`. One that has never repeated may be a caller
    /// that sends its conclusion only once (gosrt): it counts as alive for
    /// `SINGLE_SHOT_ALIVE` after it arrived.
    fn alive(&self, now: Instant) -> bool {
        if self.repeats == 0 {
            now.saturating_duration_since(self.arrived) < SINGLE_SHOT_ALIVE
        } else {
            now.saturating_duration_since(self.last_seen) < DEAD_AFTER
        }
    }

    /// Whether this caller sends from the ISN in the conclusion response
    /// (srt-protocol: one ISN for both directions, taken from the response)
    /// rather than from its own (libsrt: sends from its own ISN, expects the
    /// peer from the response's). Against a real listener the two never
    /// differ, since the listener echoes the caller's ISN; here they do.
    /// Fingerprints, from the HSREQ (SRT version, flags):
    /// - srt-protocol 0.4 announces SRT 1.3.1 with exactly
    ///   TSBPDSND|TSBPDRCV|CRYPT|REXMITFLG (0x27); libsrt always adds
    ///   TLPKTDROP and NAKREPORT unless turned off.
    /// - gosrt (datarhei/gosrt, used by Restreamer and MediaMTX; checked in
    ///   v0.13.0, `SRT_VERSION` in config.go and the HSREQ in dial.go)
    ///   announces SRT 1.4.1 with TSBPDSND|TSBPDRCV|CRYPT|TLPKTDROP|
    ///   NAKREPORT|REXMITFLG (0x3F). libsrt 1.4.0 and later always add
    ///   FILTERCAP (0x80), so 1.4.1 with exactly 0x3F is not libsrt. It
    ///   takes its ISN from the response (`cif.InitialPacketSequenceNumber`
    ///   in dial.go), like srt-protocol.
    fn adopts_response_isn(&self) -> bool {
        matches!(
            self.hs.hsreq(),
            Some((0x0001_0301, 0x27, _)) | Some((0x0001_0401, 0x3F, _))
        )
    }

    /// The SRT version this caller announces in its HSREQ (`0x00MMmmpp`).
    fn srt_version(&self) -> u32 {
        self.hs.hsreq().map_or(0, |(v, _, _)| v)
    }
}

/// `0x00010501` as `1.5.1`.
fn version_str(v: u32) -> String {
    format!("{}.{}.{}", (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF)
}

/// Whether this caller's receive buffer starts at its *own* ISN rather than
/// the peer's ISN from the conclusion response. libsrt 1.5.0 to 1.5.2 do
/// that (`CRcvBuffer(m_iISN, ...)` in core.cpp; fixed in 1.5.3 with
/// `m_iPeerISN`). Against a listener the two are equal; through the relay
/// they differ unless the peer sends from it, so such a caller breaks the
/// connection as soon as it receives data ("SEQUENCE DISCREPANCY"). As a
/// sender it works. The relay cannot rewrite sequence numbers instead: they
/// are part of the AES-CTR/GCM IV.
fn rcv_buffer_uses_own_isn(p: &Party) -> bool {
    (0x0001_0500..=0x0001_0502).contains(&p.srt_version())
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

/// Whether side `a` (`x_is_a`) or `b` may receive data, given which side
/// sends (`sender`): only the receiver when the direction is known, both
/// when it is not.
fn may_receive(a_sends: Option<bool>, x_is_a: bool) -> bool {
    a_sends.is_none_or(|a_sends| a_sends != x_is_a)
}

/// Why two callers that met cannot be paired as they are.
#[derive(Debug, PartialEq, Eq)]
enum NoPair {
    /// Both state the same role.
    SameRole,
    /// The receiver (`a` if `a_receives`) cannot receive through the relay
    /// (see `rcv_buffer_uses_own_isn`); the sender may keep waiting.
    Receiver { a_receives: bool, why: String },
}

/// The ISNs to put in the responses to (a, b), so that the data sender
/// sends from what the receiver expects.
///
/// With a known direction, both responses carry the sender's own ISN: the
/// sender gets its ISN echoed, as from any listener, so it sends from it
/// whether it is libsrt (own ISN) or one that adopts the response ISN;
/// every receiver expects the peer's data from the response ISN.
/// Except:
/// - a sender recognised as adopting the response ISN (srt-protocol,
///   gosrt; see `Party::adopts_response_isn`) gets the receiver's own ISN,
///   like the receiver. It uses one ISN for both directions, so its ACKs
///   then also match the receiver's own send sequence; with its own ISN,
///   a libsrt receiver can take those ACKs for an attack and close.
/// - a receiver that expects data from its own ISN (libsrt 1.5.0-1.5.2)
///   works only with such a sender (both get its ISN); otherwise it is
///   refused.
///
/// Without one, fall back to recognising srt-protocol (`fingerprint`), or
/// assume libsrt on both sides.
fn response_isns(a: &Party, b: &Party, fingerprint: bool) -> Result<(u32, u32, String), NoPair> {
    if let Some(a_sends) = sender(a.mode, b.mode).map_err(|()| NoPair::SameRole)? {
        let (s, r) = if a_sends { (a, b) } else { (b, a) };
        let (who, rwho) = if a_sends { ("a", "b") } else { ("b", "a") };
        if rcv_buffer_uses_own_isn(r) && !s.adopts_response_isn() {
            return Err(NoPair::Receiver {
                a_receives: !a_sends,
                why: format!(
                    "libsrt {} cannot receive through the relay (it expects data from its \
                         own ISN); the receiver needs libsrt 1.5.3+ or 1.4.x",
                    version_str(r.srt_version())
                ),
            });
        }
        if s.adopts_response_isn() {
            // Its ACKs (it acknowledges from the same ISN it sends from)
            // must also fit the receiver's own send sequence, or libsrt
            // drops the connection ("ATTACK/IPE: incoming ack seq ...
            // exceeds current"): give both the receiver's own ISN.
            return Ok((
                r.hs.isn,
                r.hs.isn,
                format!("direction: {who} sends from the response ISN: both get {rwho}'s ISN"),
            ));
        }
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
        format!(
            "no direction, fingerprint: takes the response ISN (srt-protocol, gosrt) a={fa} b={fb}"
        )
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
///
/// An older caller that has never repeated (one that sends its conclusion
/// only once, like gosrt) cannot prove it that way; it counts as there
/// while it is recent (see `Party::alive`). A caller that has repeated even
/// once keeps the strict rule, so a dead libsrt attempt (repeats, then
/// silence) is never paired.
fn both_alive(a: &Party, b: &Party, now: Instant) -> bool {
    let (old, new) = oldest_first(a, b);
    let old_still_there = old.repeats == 0 || old.last_seen > new.arrived;
    old_still_there && new.alive(now) && old.alive(now)
}

/// The best peer for `waiting[i]`, which has just arrived or repeated its
/// conclusion: the compatible one, known to be alive, heard from most
/// recently.
fn best_peer(waiting: &[Party], i: usize, now: Instant) -> Option<usize> {
    let x = waiting.get(i)?;
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
    /// It is the waiting caller at this address reconnecting: it takes
    /// that place.
    Replace(SocketAddr),
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
fn admit(waiting: &[&Party], new: &Party, now: Instant) -> Admit {
    if new.mode != Mode::Unknown {
        let same_role = waiting
            .iter()
            .find(|c| c.mode == new.mode && crypto_mismatch(c, new).is_none());
        if let Some(c) = same_role {
            if c.addr.ip() != new.addr.ip() && c.alive(now) {
                return Admit::Reject(
                    REJX_CONFLICT,
                    format!("another m={:?} is waiting", new.mode),
                );
            }
            return Admit::Replace(c.addr);
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
    /// This side is known to receive, so it needs the key: no answer means
    /// it cannot unwrap it (a wrong passphrase), and the session is torn
    /// down. Without a known direction the relay cannot tell, and some
    /// callers never answer an in-band key update (gosrt), so it only warns.
    required: bool,
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
    /// Packets from this caller's address not addressed to its peer
    /// (spoofed or stray), dropped.
    foreign: u64,
}

struct Leg {
    sid: String,
    peer: SocketAddr,
    /// This caller's own socket id: the destination of packets to it.
    socket_id: u32,
    /// The peer's socket id: the destination of every packet this caller
    /// sends. It identifies the leg when the caller's address changes.
    peer_socket_id: u32,
    /// The last address a rebind was refused for (logged once).
    refused_from: Option<SocketAddr>,
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
    /// Callers waiting for a peer, per pairing key. Changed only through
    /// `push_waiting`, `take_waiting` and `tick`, which keep the two
    /// indexes below in step.
    pending: HashMap<String, Vec<Party>>,
    /// The pairing key each waiting caller waits on. An address waits on
    /// one streamid at a time.
    waiting_at: HashMap<SocketAddr, String>,
    /// Waiting callers per network (`limit::net`).
    waiting_per_net: HashMap<IpAddr, usize>,
    /// Attempts replaced by a reconnect of the same caller; ignored a while.
    replaced: HashMap<SocketAddr, Instant>,
    legs: HashMap<SocketAddr, Leg>,
    /// Pairing keys with a session.
    busy: HashSet<String>,
    /// Established legs by the destination socket id of the packets their
    /// caller sends (`Leg::peer_socket_id`), to find a leg whose caller's
    /// address has changed. Usually one address per id.
    by_dest: HashMap<u32, Vec<SocketAddr>>,
    /// Cap on the MSS granted in conclusion responses (`--max-mss`).
    max_mss: Option<u32>,
    /// Handshake rate limits and bans.
    limiter: Limiter,
    next_prune: Instant,
}

macro_rules! log {
    ($r:expr, $($a:tt)*) => {
        eprintln!("[{:8.3}] {}", $r.t0.elapsed().as_secs_f64(), format!($($a)*))
    };
}

impl Relay {
    fn new(
        sock: UdpSocket,
        verbose: bool,
        fingerprint: bool,
        max_mss: Option<u32>,
        rate_limit: bool,
    ) -> Relay {
        let now = Instant::now();
        Relay {
            sock,
            verbose,
            fingerprint,
            t0: now,
            secret: RandomState::new(),
            pending: HashMap::new(),
            waiting_at: HashMap::new(),
            waiting_per_net: HashMap::new(),
            replaced: HashMap::new(),
            legs: HashMap::new(),
            busy: HashSet::new(),
            by_dest: HashMap::new(),
            max_mss,
            limiter: Limiter::new(rate_limit, now),
            next_prune: now + PRUNE_EVERY,
        }
    }

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
        if !self.legs.contains_key(&from) && !self.rebind(from, p) {
            if self.verbose {
                log!(self, "{from}: stray packet ({} bytes), no session", p.len());
            }
            return;
        }
        let Some(leg) = self.legs.get_mut(&from) else {
            return;
        };
        // Every packet a caller sends names its peer's socket id. One that
        // does not was not sent by this caller (a spoofed source address):
        // it neither reaches the peer nor counts as a sign of life.
        let dest = dest_socket_id(p);
        if dest != leg.peer_socket_id {
            leg.stats.foreign += 1;
            if leg.stats.foreign == 1 {
                // Once per leg: if a real caller ever does this, it shows.
                let (sid, peer_id) = (leg.sid.clone(), leg.peer_socket_id);
                log!(
                    self,
                    "[{sid}] {from}: dropped a packet for socket {dest:#x}, not the peer's \
                     {peer_id:#x} (spoofed or stray; counted as foreign)"
                );
            }
            return;
        }
        leg.last_rx = Instant::now();
        leg.stats.pkts += 1;
        leg.stats.bytes += p.len() as u64;
        let peer = leg.peer;
        if is_control(p) {
            leg.stats.ctrl += 1;
            let (ty, sub) = (ctrl_type(p), ctrl_subtype(p));
            if ty == CTRL_EXT && sub == CMD_KMRSP {
                let body = p.get(HDR..).unwrap_or_default();
                if leg.injected_km.as_deref() == Some(body) {
                    // An answer (maybe a duplicate) to our injected key.
                    if leg.inject.take().is_some() {
                        log!(self, "[{}] {from}: peer key accepted (KMRSP)", leg.sid);
                    }
                    return;
                }
                if let (Ok(state), true) = (<[u8; 4]>::try_from(body), leg.inject.is_some()) {
                    // An error state while our key is outstanding.
                    let state = u32::from_be_bytes(state);
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

    /// NAT rebinding: a packet (not a handshake) from an unknown address
    /// whose destination socket id belongs to exactly one established leg
    /// moves that leg to the new address, if `rebind_allowed`. Returns
    /// whether it did.
    fn rebind(&mut self, from: SocketAddr, p: &[u8]) -> bool {
        let dest = dest_socket_id(p);
        let Some(&[old]) = self.by_dest.get(&dest).map(Vec::as_slice) else {
            return false;
        };
        let Some(leg) = self.legs.get_mut(&old) else {
            // An index entry without its leg: a bug, but never a crash.
            log!(
                self,
                "BUG: socket {dest:#x} indexed for {old}, which has no session"
            );
            self.index_leg(old, dest, false);
            return false;
        };
        if let Err(why) = rebind_allowed(old, leg.last_rx, from, p, Instant::now()) {
            // Once per new address, not per packet.
            if self.verbose && leg.refused_from.replace(from) != Some(from) {
                let sid = leg.sid.clone();
                log!(
                    self,
                    "[{sid}] {from}: packet for {old}'s session not taken ({why})"
                );
            }
            return false;
        }
        let Some(mut leg) = self.legs.remove(&old) else {
            return false;
        };
        leg.refused_from = None;
        log!(
            self,
            "[{}] {old} moved to {from} (address changed, socket {:#x})",
            leg.sid,
            leg.socket_id
        );
        if let Some(other) = self.legs.get_mut(&leg.peer) {
            other.peer = from;
        }
        if let Some(addrs) = self.by_dest.get_mut(&dest) {
            for a in addrs.iter_mut().filter(|a| **a == old) {
                *a = from;
            }
        }
        self.legs.insert(from, leg);
        true
    }

    /// Adds or removes a leg in `by_dest`.
    fn index_leg(&mut self, addr: SocketAddr, dest: u32, add: bool) {
        let addrs = self.by_dest.entry(dest).or_default();
        if add {
            addrs.push(addr);
        } else {
            addrs.retain(|a| *a != addr);
            if addrs.is_empty() {
                self.by_dest.remove(&dest);
            }
        }
    }

    /// Adds a caller to the waiting callers of its pairing key.
    fn push_waiting(&mut self, p: Party) {
        self.waiting_at.insert(p.addr, p.sid.clone());
        *self.waiting_per_net.entry(net(p.addr.ip())).or_default() += 1;
        self.pending.entry(p.sid.clone()).or_default().push(p);
    }

    /// Removes the waiting caller at `addr`, if there is one.
    fn take_waiting(&mut self, addr: SocketAddr) -> Option<Party> {
        let sid = self.waiting_at.get(&addr)?.clone();
        let waiting = self.pending.get_mut(&sid)?;
        let i = waiting.iter().position(|c| c.addr == addr)?;
        let p = waiting.remove(i);
        if waiting.is_empty() {
            self.pending.remove(&sid);
        }
        self.forget_waiting(addr);
        Some(p)
    }

    /// Drops `addr` from the waiting indexes.
    fn forget_waiting(&mut self, addr: SocketAddr) {
        if self.waiting_at.remove(&addr).is_none() {
            return;
        }
        let key = net(addr.ip());
        if let Some(n) = self.waiting_per_net.get_mut(&key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.waiting_per_net.remove(&key);
            }
        }
    }

    fn on_handshake(&mut self, from: SocketAddr, p: &[u8]) {
        if p.len() > MAX_HS_LEN {
            if self.verbose {
                log!(
                    self,
                    "{from}: oversized handshake ({} bytes), dropped",
                    p.len()
                );
            }
            return;
        }
        if !self.limiter.allow(from.ip(), Instant::now()) {
            return;
        }
        let Some(hs) = Handshake::parse(p) else {
            // The source may be spoofed: only with -v.
            if self.verbose {
                log!(self, "{from}: malformed handshake");
            }
            return;
        };
        match hs.hs_type {
            HS_INDUCTION => {
                // An induction from the address of an established leg is
                // answered, but does not end the session: the source may be
                // spoofed. A caller that really restarted on the same
                // address follows with a conclusion with a valid cookie and
                // a new socket id, which ends it (see `on_conclusion`).
                // Version 5, the SRT magic, no key length preference.
                let cookie = self.cookie(from);
                let rsp = Handshake {
                    version: 5,
                    enc_field: 0,
                    ext_field: SRT_MAGIC,
                    // Not used after the induction; anything unpredictable.
                    socket_id: (cookie & 0x3FFF_FFFF) | 1,
                    cookie,
                    exts: vec![],
                    ..hs.clone()
                };
                if self.verbose {
                    log!(
                        self,
                        "{from}: induction (socket {:#x}, peer ip field {:02x?})",
                        hs.socket_id,
                        hs.peer_ip.get(..8).unwrap_or_default()
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
            if hs.socket_id == leg.socket_id {
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
            // Another socket on the address of an established leg: the
            // caller restarted on the same port. Only a valid cookie proves
            // the source; then the old session ends and this is a new caller.
            if !self.cookie_ok(from, hs.cookie) {
                if self.verbose {
                    log!(self, "{from}: conclusion with a wrong cookie, dropped");
                }
                return;
            }
            self.teardown(from, "caller restarted on the same address");
        }
        // A waiting caller repeats the conclusion it was admitted with, cookie
        // and all, for as long as it waits, which may outlast the cookie.
        let admitted_cookie = self
            .waiting_at
            .get(&from)
            .and_then(|sid| self.pending.get(sid))
            .and_then(|w| w.iter().find(|c| c.addr == from))
            .map(|c| c.hs.cookie);
        if !self.cookie_ok(from, hs.cookie) && admitted_cookie != Some(hs.cookie) {
            // No recent induction from this address: spoofed or stale. Drop
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
        if raw_sid.len() > MAX_SID_LEN {
            let why = format!("streamid longer than {MAX_SID_LEN} bytes");
            return self.reject(from, &hs, REJX_BAD_REQUEST, &why);
        }
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
        if self.busy.contains(&sid) {
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
            repeats: 0,
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
        match self.waiting_at.get(&from) {
            Some(s) if *s == sid => {
                // A repeat: refresh it, then pair with the best live peer.
                let Some(waiting) = self.pending.get_mut(&sid) else {
                    return;
                };
                let Some(i) = waiting.iter().position(|c| c.addr == from) else {
                    return;
                };
                if let Some(old) = waiting.get_mut(i) {
                    party.arrived = old.arrived;
                    party.repeats = old.repeats.saturating_add(1);
                    *old = party;
                }
                self.try_pair(&sid, i, now);
                return;
            }
            Some(other) => {
                // One address waits on one streamid at a time: this attempt
                // replaces its earlier one.
                if self.verbose {
                    log!(self, "[{sid}] {from}: was waiting on {other:?}, moved");
                }
                self.take_waiting(from);
            }
            None => {}
        }
        let key = net(from.ip());
        if self.waiting_per_net.get(&key).copied().unwrap_or(0) >= MAX_WAITING_PER_NET {
            let why = format!("too many callers waiting from {key}");
            return self.reject(from, &party.hs, REJX_CONFLICT, &why);
        }
        if self.waiting_at.len() >= MAX_WAITING_TOTAL {
            return self.reject(from, &party.hs, REJX_CONFLICT, "too many callers waiting");
        }
        let waiting: Vec<&Party> = self.pending.get(&sid).into_iter().flatten().collect();
        match admit(&waiting, &party, now) {
            Admit::Reject(code, why) => {
                return self.reject(from, &party.hs, code, &format!("streamid {sid:?}: {why}"));
            }
            Admit::Replace(old_addr) => {
                self.take_waiting(old_addr);
                self.replaced.insert(old_addr, now);
                log!(
                    self,
                    "[{sid}] {from} replaces {old_addr} (same role {mode:?})"
                );
            }
            Admit::Wait => {}
        }
        let waiting: &[Party] = self.pending.get(&sid).map_or(&[], Vec::as_slice);
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
        self.push_waiting(party);
        // An older caller that never repeats (gosrt) pairs right away.
        let i = self
            .pending
            .get(&sid)
            .map_or(0, |w| w.len().saturating_sub(1));
        self.try_pair(&sid, i, now);
    }

    /// Pairs `pending[sid][i]` with its best live peer, if there is one.
    fn try_pair(&mut self, sid: &str, i: usize, now: Instant) {
        let Some(waiting) = self.pending.get(sid) else {
            return;
        };
        let (Some(j), Some(x)) = (best_peer(waiting, i, now), waiting.get(i)) else {
            return;
        };
        let (xa, ya) = (x.addr, waiting.get(j).map(|y| y.addr));
        let Some(ya) = ya else {
            return;
        };
        if let (Some(a), Some(b)) = (self.take_waiting(xa), self.take_waiting(ya)) {
            self.pair(a, b);
        }
    }

    fn log_waiting(&self, p: &Party, what: &str) {
        log!(
            self,
            "[{}] {} {what} (socket {:#x}, {:?}, SRT {} flags {:#x}, {})",
            p.sid,
            p.addr,
            p.hs.socket_id,
            p.mode,
            version_str(p.srt_version()),
            p.hs.hsreq().map_or(0, |(_, f, _)| f),
            if p.hs.km().is_some() {
                "encrypted"
            } else {
                "clear"
            }
        );
    }

    /// The cookie period `now` is in.
    fn cookie_period(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.t0).as_secs() / COOKIE_PERIOD.as_secs()
    }

    fn cookie_at(&self, a: SocketAddr, period: u64) -> u32 {
        self.secret.hash_one((a, period)) as u32
    }

    /// The cookie for `a` in this period. It changes every
    /// `COOKIE_PERIOD`, so one seen once does not stay valid.
    fn cookie(&self, a: SocketAddr) -> u32 {
        self.cookie_at(a, self.cookie_period(Instant::now()))
    }

    /// Whether `c` is `a`'s cookie for this period or the one before.
    fn cookie_ok(&self, a: SocketAddr, c: u32) -> bool {
        let now = self.cookie_period(Instant::now());
        c == self.cookie_at(a, now) || (now > 0 && c == self.cookie_at(a, now - 1))
    }

    /// Pairs two compatible callers (see `compatible`).
    fn pair(&mut self, a: Party, b: Party) {
        let sid = a.sid.clone();
        if self.busy.contains(&sid)
            || self.legs.contains_key(&a.addr)
            || self.legs.contains_key(&b.addr)
        {
            // Admission rules out all three; never overwrite a session.
            log!(
                self,
                "BUG: [{sid}] {} / {} already in a session, not paired",
                a.addr,
                b.addr
            );
            return;
        }
        let (a, b) = oldest_first(a, b);
        let a_km = a.hs.km();
        let (isn_a, isn_b, how) = match response_isns(&a, &b, self.fingerprint) {
            Ok(r) => r,
            Err(NoPair::SameRole) => {
                log!(self, "[{sid}] both sides m={:?}: rejecting both", a.mode);
                self.reject(a.addr, &a.hs, REJX_BAD_MODE, "same m as peer");
                self.reject(b.addr, &b.hs, REJX_BAD_MODE, "same m as peer");
                return;
            }
            Err(NoPair::Receiver { a_receives, why }) => {
                let (r, s) = if a_receives { (a, b) } else { (b, a) };
                self.reject(r.addr, &r.hs, REJX_UNACCEPTABLE, &format!("[{sid}] {why}"));
                // The sender was fine: it keeps waiting for another receiver.
                self.log_waiting(&s, "waiting for a peer");
                self.push_waiting(s);
                return;
            }
        };
        if sender(a.mode, b.mode) == Ok(None) {
            for p in [&a, &b] {
                if rcv_buffer_uses_own_isn(p) {
                    log!(
                        self,
                        "[{sid}] WARNING: {} is libsrt {}, which can only send through the \
                         relay; if it receives, it breaks the connection (needs 1.5.3+ or 1.4.x)",
                        p.addr,
                        version_str(p.srt_version())
                    );
                }
            }
        }
        // Admission requires an HSREQ, so the 0 never applies.
        let lat = |p: &Party| {
            p.hs.hsreq()
                .map_or(0, |(_, _, w)| (w >> 16).max(w & 0xFFFF))
        };
        let latency = lat(&a).max(lat(&b));
        let encrypted = a_km.is_some();
        let mss = a.hs.mss.min(b.hs.mss).min(self.max_mss.unwrap_or(u32::MAX));
        log!(self, "[{sid}] PAIR {} (socket {:#x}, isn {}) <-> {} (socket {:#x}, isn {}), latency {} ms (asked {} / {}), mss {mss}, {}",
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
        // Which side needs the peer's key: only the receiver, if the
        // direction is known (some callers do not take an in-band key update
        // while they send, e.g. gosrt); both, if it is not.
        let direction = sender(a.mode, b.mode).ok().flatten();
        // Response and KM injection for each side, in an order that lets
        // each side hold the peer's key before the peer can send data.
        for (x, p, isn, x_is_a) in [(&a, &b, isn_a, true), (&b, &a, isn_b, false)] {
            let mut rsp = response_for(x, p, latency, self.max_mss);
            rsp.isn = isn;
            let rsp_pkt = handshake_packet(&rsp, p.ts_now(), x.hs.socket_id);
            self.send(x.addr, &rsp_pkt);
            let km = p.hs.km().filter(|_| may_receive(direction, x_is_a));
            let inject = km.map(|km| {
                let pkt = control(CTRL_EXT, CMD_KMREQ, 0, p.ts_now(), x.hs.socket_id, km);
                self.send(x.addr, &pkt);
                Inject {
                    pkt,
                    next: Instant::now() + KM_RETRY,
                    left: KM_TRIES,
                    required: direction.is_some(),
                }
            });
            self.index_leg(x.addr, p.hs.socket_id, true);
            self.legs.insert(
                x.addr,
                Leg {
                    sid: sid.clone(),
                    peer: p.addr,
                    socket_id: x.hs.socket_id,
                    peer_socket_id: p.hs.socket_id,
                    refused_from: None,
                    encrypted,
                    response: rsp_pkt,
                    injected_km: km.map(<[u8]>::to_vec),
                    inject,
                    last_rx: Instant::now(),
                    stats: Stats::default(),
                },
            );
        }
        self.busy.insert(sid);
    }

    /// Refuses a caller. Only callers that passed the cookie check are
    /// refused, so the relay never sends this to a spoofed address.
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
        self.index_leg(addr, leg.peer_socket_id, false);
        self.busy.remove(&leg.sid);
        self.print_stats(addr, &leg);
        if let Some(other) = self.legs.remove(&leg.peer) {
            self.index_leg(leg.peer, other.peer_socket_id, false);
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
        log!(self, "[{}] {addr} -> {}: pkts {} ({} kB), data {} (rexmit {}, clear {}), ctrl {}, seq {:?}..{}, foreign {}",
            l.sid, l.peer, s.pkts, s.bytes / 1000, s.data, s.rexmit, s.clear_data, s.ctrl, s.first_seq, s.last_seq, s.foreign);
    }

    /// Logs what the rate limit dropped since the last call, if anything.
    fn log_dropped(&mut self) {
        let n = self.limiter.take_dropped();
        if n > 0 {
            log!(self, "rate limit: dropped {n} handshakes in the last 5 s");
        }
    }

    fn tick(&mut self) {
        let now = Instant::now();
        // Injection retries.
        let mut sends = Vec::new();
        let mut gave_up = Vec::new();
        let mut unsure = Vec::new();
        for (addr, leg) in self.legs.iter_mut() {
            if let Some(inj) = &mut leg.inject {
                if now >= inj.next {
                    if inj.left == 0 {
                        if inj.required {
                            gave_up.push(*addr);
                        } else {
                            // Stop retrying; a late KMRSP is still consumed.
                            leg.inject = None;
                            unsure.push((*addr, leg.sid.clone()));
                        }
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
            log!(
                self,
                "{a}: no answer to the injected key (receiver): passphrase mismatch?"
            );
            self.teardown(a, "key injection unanswered");
        }
        for (a, sid) in unsure {
            log!(
                self,
                "[{sid}] WARNING: {a}: no answer to the injected key; if this side \
                 receives, check the passphrase (state the direction to have the relay \
                 detect it)"
            );
        }
        self.replaced
            .retain(|_, t| now.saturating_duration_since(*t) < REPLACED_TTL);
        // Waiting callers that gave up.
        let mut gone = Vec::new();
        self.pending.retain(|_, w| {
            w.retain(|c| {
                let alive = c.alive(now);
                if !alive {
                    gone.push(c.addr);
                }
                alive
            });
            !w.is_empty()
        });
        for a in gone {
            self.forget_waiting(a);
        }
        // Idle sessions.
        let idle: Vec<_> = self
            .legs
            .iter()
            .filter(|(_, l)| now.saturating_duration_since(l.last_rx) > IDLE_TTL)
            .map(|(a, _)| *a)
            .collect();
        for a in idle {
            self.teardown(a, "idle");
        }
        if now >= self.next_prune {
            self.next_prune = now + PRUNE_EVERY;
            self.limiter.prune(now);
        }
    }
}

/// Whether a packet from `from`, an unknown address, may take over the
/// established leg at `old` (last heard from at `last_rx`) whose session its
/// destination socket id names. Socket ids are the callers' own random
/// 32-bit values, so an off-path sender has to guess one; on top of that:
/// - only a plausible SRT packet: data, or a known control type other than
///   a handshake (a handshake from a new address is a new caller);
/// - the same IP family as before;
/// - the old address has been silent for `REBIND_QUIET`, so a leg in use
///   cannot be taken over, and late packets from the old address cannot
///   take it back.
fn rebind_allowed(
    old: SocketAddr,
    last_rx: Instant,
    from: SocketAddr,
    p: &[u8],
    now: Instant,
) -> Result<(), &'static str> {
    if p.len() < HDR {
        return Err("too short");
    }
    if is_control(p) && !matches!(ctrl_type(p), 1..=8 | CTRL_EXT) {
        return Err("not a session packet");
    }
    if old.is_ipv4() != from.is_ipv4() {
        return Err("other IP family");
    }
    if now.saturating_duration_since(last_rx) < REBIND_QUIET {
        return Err("the current address is still active");
    }
    Ok(())
}

/// `--max-mss`: a number in `MSS_RANGE`.
fn parse_max_mss(s: &str) -> Result<u32, String> {
    match s.trim().parse::<u32>() {
        Ok(n) if MSS_RANGE.contains(&n) => Ok(n),
        _ => Err(format!(
            "max MSS must be a number from {} to {}, got {s:?}",
            MSS_RANGE.start(),
            MSS_RANGE.end()
        )),
    }
}

/// The conclusion response for `x`, describing its peer `p`. The MSS is the
/// smaller of the two callers', capped at `max_mss`.
fn response_for(x: &Party, p: &Party, latency: u32, max_mss: Option<u32>) -> Handshake {
    // Admission requires an HSREQ, so the zeros never apply.
    let (p_ver, p_flags, _) = p.hs.hsreq().unwrap_or((0, 0, 0));
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
        mss: x.hs.mss.min(p.hs.mss).min(max_mss.unwrap_or(u32::MAX)),
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

/// Prints `msg` and exits with `code`.
fn die(code: i32, msg: &str) -> ! {
    eprintln!("srt-splice: {msg}");
    std::process::exit(code);
}

const USAGE: &str = "usage: srt-splice [--listen ADDR:PORT] [--health ADDR:PORT|off] \
                     [--max-mss N] [--no-fingerprint] [--no-rate-limit] [-v]";

fn main() {
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let mut listen = env("SRT_SPLICE_LISTEN").unwrap_or_else(|| "0.0.0.0:9000".into());
    // Removed in 0.2.0. Refuse them instead of silently ignoring them.
    let removed = |old: &str| -> ! {
        let hint = match old {
            "--api" | "SRT_SPLICE_API" => "use --health / SRT_SPLICE_HEALTH",
            _ => "configure clients with the relay's public address directly",
        };
        die(2, &format!("{old} was removed in 0.2.0: {hint}"));
    };
    for old in ["SRT_SPLICE_API", "SRT_SPLICE_PUBLIC"] {
        if env(old).is_some() {
            removed(old);
        }
    }
    let mut health_listen = env("SRT_SPLICE_HEALTH").unwrap_or_else(|| "127.0.0.1:9001".into());
    let mut max_mss = env("SRT_SPLICE_MAX_MSS");
    let mut rate_limit = !matches!(
        env("SRT_SPLICE_NO_RATE_LIMIT").as_deref(),
        Some("1" | "true" | "yes")
    );
    let mut verbose = false;
    let mut fingerprint = true;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut value = |what: &str| {
            args.next()
                .unwrap_or_else(|| die(2, &format!("{a} needs {what}\n{USAGE}")))
        };
        match a.as_str() {
            "-v" | "--verbose" => verbose = true,
            "--no-fingerprint" => fingerprint = false,
            "--no-rate-limit" => rate_limit = false,
            "-l" | "--listen" => listen = value("ADDR:PORT"),
            "--health" => health_listen = value("ADDR:PORT or off"),
            "--max-mss" => max_mss = Some(value("N")),
            "--api" | "--public" => removed(&a),
            _ => die(2, USAGE),
        }
    }
    let max_mss = max_mss.map(|s| parse_max_mss(&s).unwrap_or_else(|e| die(2, &e)));
    let sock = UdpSocket::bind(&listen)
        .unwrap_or_else(|e| die(1, &format!("cannot listen on udp {listen}: {e}")));
    if let Err(e) = sock.set_read_timeout(Some(TICK)) {
        die(1, &format!("socket timeout: {e}"));
    }
    let mut r = Relay::new(sock, verbose, fingerprint, max_mss, rate_limit);
    log!(r, "srt-splice listening on udp {listen}");
    if let Some(m) = max_mss {
        log!(r, "MSS capped at {m}");
    }
    if !rate_limit {
        log!(r, "WARNING: handshake rate limiting is off");
    }
    if health_listen != "off" {
        match health::spawn(&health_listen) {
            Ok(addr) => log!(r, "health on http://{addr}/healthz"),
            // Only probes need it: the relay runs on without it.
            Err(e) => log!(
                r,
                "WARNING: health: cannot listen on {health_listen}: {e}; running without it"
            ),
        }
    }
    // The largest UDP payload, so nothing is ever forwarded truncated.
    let mut buf = vec![0u8; 65536];
    let mut next_tick = Instant::now() + TICK;
    let mut next_stats = Instant::now() + STATS_EVERY;
    loop {
        match r.sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                if let Some(p) = buf.get(..n) {
                    r.on_packet(from, p);
                }
            }
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
            r.log_dropped();
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

    /// `admit` on a list of owned callers.
    fn admit_v(waiting: &[Party], new: &Party, now: Instant) -> Admit {
        admit(&waiting.iter().collect::<Vec<_>>(), new, now)
    }

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

    /// A caller; one heard from after it arrived has repeated its conclusion.
    fn party(port: u16, mode: Mode, arrived: Instant, last_seen: Instant) -> Party {
        Party {
            addr: SocketAddr::from(([127, 0, 0, 1], port)),
            hs: Handshake {
                version: 5,
                enc_field: 0,
                ext_field: 0,
                // A distinct ISN per caller.
                isn: 1000 * port as u32,
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
            repeats: u32::from(last_seen > arrived),
        }
    }

    /// `p` after repeating its conclusion at `t`.
    fn repeat(p: &mut Party, t: Instant) {
        p.last_seen = t;
        p.repeats += 1;
    }

    #[test]
    fn single_shot_caller_counts_as_alive_while_recent() {
        let t0 = Instant::now();
        let ms = |n| t0 + Duration::from_millis(n);
        // gosrt: one conclusion, never repeated.
        let once = party(1, Mode::Request, ms(0), ms(0));
        assert!(once.alive(ms(400)) && once.alive(ms(2400)));
        assert!(!once.alive(ms(2500)));
        // It is the older one: pairs with a newer caller on its arrival.
        let snd = party(2, Mode::Unknown, ms(2000), ms(2000));
        assert!(both_alive(&once, &snd, ms(2000)));
        assert!(!both_alive(&once, &snd, ms(2600)));
        let mut waiting = vec![once];
        assert_eq!(admit_v(&waiting, &snd, ms(2000)), Admit::Wait);
        waiting.push(snd);
        assert_eq!(best_peer(&waiting, 1, ms(2000)), Some(0));
        // Two single-shot callers pair on the second's arrival.
        let a = party(3, Mode::Publish, ms(0), ms(0));
        let b = party(4, Mode::Unknown, ms(1000), ms(1000));
        assert!(both_alive(&a, &b, ms(1000)));
    }

    #[test]
    fn repeating_caller_keeps_the_strict_rule() {
        let t0 = Instant::now();
        let ms = |n| t0 + Duration::from_millis(n);
        // A libsrt attempt that repeated, then fell silent: dead after 400 ms,
        // and never paired with a caller that arrived after its last repeat.
        let mut old = party(1, Mode::Unknown, ms(0), ms(0));
        repeat(&mut old, ms(250));
        assert!(old.alive(ms(600)) && !old.alive(ms(650)));
        let new = party(2, Mode::Unknown, ms(300), ms(300));
        assert!(!both_alive(&old, &new, ms(300)));
        // It repeats after the newer one arrived: pair.
        repeat(&mut old, ms(500));
        assert!(both_alive(&old, &new, ms(500)));
        // The newer one may be single-shot: alive while recent, not after
        // the 400 ms a repeating caller gets.
        repeat(&mut old, ms(1250));
        assert_eq!(new.repeats, 0);
        assert!(both_alive(&old, &new, ms(1250)));
    }

    #[test]
    fn key_injected_only_into_the_receiver() {
        use Mode::*;
        let dir = |a, b| sender(a, b).unwrap();
        // a sends: only b gets a's key.
        assert!(!may_receive(dir(Publish, Unknown), true));
        assert!(may_receive(dir(Publish, Unknown), false));
        // b sends (a states m=request): only a.
        assert!(may_receive(dir(Request, Unknown), true));
        assert!(!may_receive(dir(Request, Unknown), false));
        // No direction: both ways.
        assert!(may_receive(dir(Unknown, Unknown), true));
        assert!(may_receive(dir(Unknown, Unknown), false));
    }

    #[test]
    fn gosrt_fingerprint() {
        let t = Instant::now();
        let p = |v, f| srt(party(1, Mode::Unknown, t, t), v, f).adopts_response_isn();
        assert!(p(0x0001_0401, 0x3F), "gosrt");
        assert!(p(0x0001_0301, 0x27), "srt-protocol");
        // libsrt always adds FILTERCAP (0x80).
        assert!(!p(0x0001_0401, 0xBF));
        assert!(!p(0x0001_0400, 0xBF) && !p(0x0001_0402, 0xBF) && !p(0x0001_0506, 0xBF));
        // gosrt sender, libsrt receiver, no direction: both get the receiver's ISN.
        let go = srt(party(1, Mode::Unknown, t, t), 0x0001_0401, 0x3F);
        let rcv = libsrt(party(2, Mode::Unknown, t, t), 0x0001_0506);
        let (ia, ib, _) = response_isns(&go, &rcv, true).unwrap();
        assert_eq!((ia, ib), (rcv.hs.isn, rcv.hs.isn));
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

    /// `p` with an HSREQ announcing this SRT version and these flags.
    fn srt(mut p: Party, version: u32, flags: u32) -> Party {
        p.hs.exts.retain(|e| e.cmd != CMD_HSREQ);
        let mut data = Vec::new();
        for w in [version, flags, (120 << 16) | 120] {
            data.extend(w.to_be_bytes());
        }
        p.hs.exts.push(Ext {
            cmd: CMD_HSREQ,
            data,
        });
        p
    }

    /// `p` as libsrt of this version (its usual flags).
    fn libsrt(p: Party, version: u32) -> Party {
        srt(p, version, 0xBF)
    }

    /// `p` as srt-protocol 0.4 (adopts the response ISN).
    fn srt_protocol(p: Party) -> Party {
        srt(p, 0x0001_0301, 0x27)
    }

    #[test]
    fn affected_libsrt_versions() {
        let t = Instant::now();
        let v = |v| rcv_buffer_uses_own_isn(&libsrt(party(1, Mode::Unknown, t, t), v));
        assert!(v(0x0001_0500) && v(0x0001_0501) && v(0x0001_0502));
        assert!(!v(0x0001_0402) && !v(0x0001_0400) && !v(0x0001_0503) && !v(0x0001_0506));
        assert_eq!(version_str(0x0001_0501), "1.5.1");
    }

    #[test]
    fn affected_receiver_refused_when_sender_is_libsrt() {
        let t = Instant::now();
        let rcv = libsrt(party(1, Mode::Unknown, t, t), 0x0001_0501);
        let snd = libsrt(party(2, Mode::Publish, t, t), 0x0001_0506);
        // Refused with 1406 in pair(); only the receiver.
        assert!(matches!(
            response_isns(&rcv, &snd, true),
            Err(NoPair::Receiver {
                a_receives: true,
                ..
            })
        ));
        assert!(matches!(
            response_isns(&snd, &rcv, true),
            Err(NoPair::Receiver {
                a_receives: false,
                ..
            })
        ));
        // The same with the direction stated by the receiver.
        let rcv = libsrt(party(1, Mode::Request, t, t), 0x0001_0502);
        let snd = libsrt(party(2, Mode::Unknown, t, t), 0x0001_0501);
        assert!(matches!(
            response_isns(&snd, &rcv, false),
            Err(NoPair::Receiver {
                a_receives: false,
                ..
            })
        ));
    }

    #[test]
    fn affected_receiver_with_adopting_sender_gets_its_own_isn() {
        let t = Instant::now();
        let rcv = libsrt(party(1, Mode::Request, t, t), 0x0001_0500);
        let snd = srt_protocol(party(2, Mode::Unknown, t, t));
        let (ia, ib, _) = response_isns(&rcv, &snd, true).unwrap();
        assert_eq!((ia, ib), (rcv.hs.isn, rcv.hs.isn));
        let (ia, ib, _) = response_isns(&snd, &rcv, false).unwrap();
        assert_eq!((ia, ib), (rcv.hs.isn, rcv.hs.isn));
    }

    #[test]
    fn affected_sender_works() {
        let t = Instant::now();
        let snd = libsrt(party(1, Mode::Publish, t, t), 0x0001_0501);
        let rcv = libsrt(party(2, Mode::Unknown, t, t), 0x0001_0506);
        let (ia, ib, _) = response_isns(&snd, &rcv, true).unwrap();
        assert_eq!((ia, ib), (snd.hs.isn, snd.hs.isn));
    }

    #[test]
    fn adopting_sender_with_direction_gets_the_receivers_isn() {
        let t = Instant::now();
        let rcv = libsrt(party(1, Mode::Request, t, t), 0x0001_0507);
        for snd in [
            srt(party(2, Mode::Unknown, t, t), 0x0001_0401, 0x3F),
            srt_protocol(party(2, Mode::Unknown, t, t)),
        ] {
            let (ia, ib, _) = response_isns(&rcv, &snd, false).unwrap();
            assert_eq!((ia, ib), (rcv.hs.isn, rcv.hs.isn));
        }
        // A libsrt sender gets its own ISN, whatever the receiver is.
        let go_rcv = srt(party(1, Mode::Request, t, t), 0x0001_0401, 0x3F);
        let snd = libsrt(party(2, Mode::Unknown, t, t), 0x0001_0507);
        let (ia, ib, _) = response_isns(&go_rcv, &snd, true).unwrap();
        assert_eq!((ia, ib), (snd.hs.isn, snd.hs.isn));
    }

    #[test]
    fn unknown_direction_is_never_refused() {
        let t = Instant::now();
        let a = libsrt(party(1, Mode::Unknown, t, t), 0x0001_0501);
        let b = libsrt(party(2, Mode::Unknown, t, t), 0x0001_0506);
        // Not refused: libsrt both, each gets the other's ISN (warned in pair()).
        let (ia, ib, _) = response_isns(&a, &b, true).unwrap();
        assert_eq!((ia, ib), (b.hs.isn, a.hs.isn));
        // Both affected: still paired (one of them may only send).
        let b = libsrt(party(2, Mode::Unknown, t, t), 0x0001_0502);
        assert!(response_isns(&a, &b, true).is_ok());
        assert!(response_isns(&a, &b, false).is_ok());
    }

    #[test]
    fn unaffected_versions_pair_as_before() {
        let t = Instant::now();
        for v in [0x0001_0400, 0x0001_0402, 0x0001_0503, 0x0001_0506] {
            let rcv = libsrt(party(1, Mode::Request, t, t), v);
            let snd = libsrt(party(2, Mode::Unknown, t, t), 0x0001_0506);
            let (ia, ib, _) = response_isns(&rcv, &snd, true).unwrap();
            assert_eq!((ia, ib), (snd.hs.isn, snd.hs.isn));
        }
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
        assert_eq!(admit_v(&waiting, &snd, ms(1000)), Admit::Wait);
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
        assert_eq!(admit_v(&waiting, &rcv, ms(500)), Admit::Wait);
        waiting.push(rcv);
        assert_eq!(admit_v(&waiting, &snd, ms(1000)), Admit::Wait);
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
            admit_v(&waiting, &stray, ms(500)),
            Admit::Reject(REJ_UNSECURE, _)
        ));
        // An encrypted caller with other settings is never refused: it
        // cannot block a correctly configured one that comes later.
        let other = enc(party(3, Mode::Unknown, ms(500), ms(500)), 2, 32);
        assert_eq!(admit_v(&waiting, &other, ms(500)), Admit::Wait);
        // Only waiting callers of a compatible role count: a clear m=request
        // next to an encrypted m=request just waits.
        let req = enc(party(4, Mode::Request, ms(0), ms(400)), 2, 16);
        let clear_req = from_host(party(5, Mode::Request, ms(500), ms(500)), 9);
        assert_eq!(admit_v(&[req], &clear_req, ms(500)), Admit::Wait);
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
        assert_eq!(admit_v(&waiting, &rcv, ms(500)), Admit::Wait);
        waiting.push(rcv);
        let snd = enc(party(3, Mode::Publish, ms(1000), ms(1000)), 2, 16);
        assert_eq!(admit_v(&waiting, &snd, ms(1000)), Admit::Wait);
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
            admit_v(&waiting, &other_host, ms(500)),
            Admit::Reject(REJX_CONFLICT, _)
        ));
        let reconnect = enc(party(3, Mode::Request, ms(500), ms(500)), 2, 16);
        assert_eq!(
            admit_v(&waiting, &reconnect, ms(500)),
            Admit::Replace(waiting[0].addr)
        );
    }

    /// A relay on loopback with a paired session between two real sockets
    /// (socket ids 0x111 and 0x222), their conclusion responses drained.
    fn session() -> (Relay, UdpSocket, UdpSocket) {
        let sock = |_| {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            s.set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            s
        };
        let (ca, cb) = (sock(0), sock(1));
        let mut r = Relay::new(sock(2), false, true, None, true);
        let t = Instant::now();
        let mut a = libsrt(party(1, Mode::Publish, t, t), 0x0001_0506);
        let mut b = libsrt(party(2, Mode::Unknown, t, t), 0x0001_0506);
        a.addr = ca.local_addr().unwrap();
        b.addr = cb.local_addr().unwrap();
        a.hs.socket_id = 0x111;
        b.hs.socket_id = 0x222;
        r.pair(a, b);
        let mut buf = [0u8; 2048];
        ca.recv(&mut buf).unwrap();
        cb.recv(&mut buf).unwrap();
        (r, ca, cb)
    }

    /// A data packet to socket `dest` with sequence number `seq`.
    fn data_to(dest: u32, seq: u32) -> Vec<u8> {
        let mut p = vec![0u8; HDR + 8];
        p[..4].copy_from_slice(&seq.to_be_bytes());
        p[12..16].copy_from_slice(&dest.to_be_bytes());
        p
    }

    /// The sequence number of the next packet `s` receives, if any.
    fn recv_seq(s: &UdpSocket) -> Option<u32> {
        let mut buf = [0u8; 2048];
        let n = s.recv(&mut buf).ok()?;
        Some(data_seq(&buf[..n]))
    }

    /// Makes the leg at `addr` look silent since `ago`.
    fn silent_for(r: &mut Relay, addr: SocketAddr, ago: Duration) {
        r.legs.get_mut(&addr).unwrap().last_rx = Instant::now() - ago;
    }

    #[test]
    fn rebind_moves_the_leg_and_both_directions_keep_working() {
        let (mut r, ca, cb) = session();
        let (a, b) = (ca.local_addr().unwrap(), cb.local_addr().unwrap());
        r.on_packet(a, &data_to(0x222, 1));
        assert_eq!(recv_seq(&cb), Some(1));
        // A's NAT mapping changes: the same caller, a new port.
        let ca2 = UdpSocket::bind("127.0.0.1:0").unwrap();
        ca2.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let a2 = ca2.local_addr().unwrap();
        // While the old address is in use, the leg stays where it is.
        r.on_packet(a2, &data_to(0x222, 2));
        assert!(r.legs.contains_key(&a) && !r.legs.contains_key(&a2));
        silent_for(&mut r, a, REBIND_QUIET * 2);
        r.on_packet(a2, &data_to(0x222, 3));
        assert_eq!(recv_seq(&cb), Some(3));
        assert!(r.legs.contains_key(&a2) && !r.legs.contains_key(&a));
        assert_eq!(r.legs[&b].peer, a2);
        assert_eq!(r.legs[&a2].peer, b);
        assert_eq!(r.by_dest[&0x222], vec![a2]);
        // B to A goes to the new address.
        r.on_packet(b, &data_to(0x111, 7));
        assert_eq!(recv_seq(&ca2), Some(7));
        // A late packet from the old address cannot take it back.
        r.on_packet(a, &data_to(0x222, 4));
        assert!(r.legs.contains_key(&a2) && !r.legs.contains_key(&a));
        // Teardown cleans the index.
        r.teardown(a2, "test");
        assert!(r.legs.is_empty() && r.by_dest.is_empty());
    }

    #[test]
    fn rebind_needs_one_unambiguous_dest_id_and_a_session_packet() {
        let (mut r, ca, cb) = session();
        let a = ca.local_addr().unwrap();
        silent_for(&mut r, a, Duration::from_secs(1));
        let x: SocketAddr = "127.0.0.1:1".parse().unwrap();
        // Unknown destination id: a stray.
        r.on_packet(x, &data_to(0x333, 1));
        assert!(!r.legs.contains_key(&x));
        // A handshake from a new address is a new caller, never a rebind.
        let hs = control(CTRL_HANDSHAKE, 0, 0, 0, 0x222, &[0; HS_CIF]);
        r.on_packet(x, &hs);
        assert!(!r.legs.contains_key(&x) && r.legs.contains_key(&a));
        // Nor an unknown control type, or another IP family.
        let t = Instant::now();
        let odd = control(0x0042, 0, 0, 0, 0x222, &[]);
        assert!(rebind_allowed(a, t - Duration::from_secs(1), x, &odd, t).is_err());
        let v6: SocketAddr = "[::1]:5000".parse().unwrap();
        let p = data_to(0x222, 1);
        assert!(rebind_allowed(a, t - Duration::from_secs(1), v6, &p, t).is_err());
        assert!(rebind_allowed(a, t - Duration::from_secs(1), x, &p, t).is_ok());
        let ack = control(2, 0, 0, 0, 0x222, &[0; 4]);
        assert!(rebind_allowed(a, t - Duration::from_secs(1), x, &ack, t).is_ok());
        // Ambiguous ids (two legs expect the same one) never rebind.
        r.by_dest
            .get_mut(&0x222)
            .unwrap()
            .push(cb.local_addr().unwrap());
        r.on_packet(x, &data_to(0x222, 1));
        assert!(!r.legs.contains_key(&x));
    }

    #[test]
    fn still_sending_leg_is_not_taken() {
        let (mut r, ca, cb) = session();
        let (a, b) = (ca.local_addr().unwrap(), cb.local_addr().unwrap());
        let x: SocketAddr = "127.0.0.1:1".parse().unwrap();
        // Heard from 400 ms ago (a low-bitrate sender between packets): kept.
        silent_for(&mut r, a, Duration::from_millis(400));
        r.on_packet(x, &data_to(0x222, 1));
        assert!(r.legs.contains_key(&a) && !r.legs.contains_key(&x));
        assert_eq!(r.legs[&b].peer, a);
        let t = Instant::now();
        let p = data_to(0x222, 1);
        assert!(rebind_allowed(a, t - REBIND_QUIET + Duration::from_millis(1), x, &p, t).is_err());
        assert!(rebind_allowed(a, t - REBIND_QUIET, x, &p, t).is_ok());
    }

    #[test]
    fn max_mss_caps_the_granted_mss() {
        let t = Instant::now();
        let mut a = libsrt(party(1, Mode::Publish, t, t), 0x0001_0506);
        let b = libsrt(party(2, Mode::Unknown, t, t), 0x0001_0506);
        assert_eq!(response_for(&a, &b, 120, None).mss, 1500);
        assert_eq!(response_for(&a, &b, 120, Some(1400)).mss, 1400);
        a.hs.mss = 1300;
        assert_eq!(response_for(&a, &b, 120, None).mss, 1300);
        assert_eq!(response_for(&b, &a, 120, Some(1400)).mss, 1300);
        assert_eq!(parse_max_mss("1400"), Ok(1400));
        assert_eq!(parse_max_mss("76"), Ok(76));
        assert_eq!(parse_max_mss("1500"), Ok(1500));
        for bad in ["75", "1501", "0", "-1", "x", ""] {
            assert!(parse_max_mss(bad).is_err(), "{bad}");
        }
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

    // ---- Hardening against hostile callers ----

    /// A conclusion from `from` with a valid cookie, as libsrt 1.5.6 sends it.
    fn conclusion(
        r: &Relay,
        from: SocketAddr,
        socket_id: u32,
        sid: &str,
        km: Option<(u8, u8)>,
    ) -> Vec<u8> {
        let mut b = sid.as_bytes().to_vec();
        while b.len() % 4 != 0 {
            b.push(0);
        }
        // libsrt's byte order: each 4-byte group reversed.
        let sid_data = b.chunks(4).flat_map(|w| w.iter().rev().copied()).collect();
        let mut hsreq = Vec::new();
        for w in [0x0001_0506u32, 0xBF, (120 << 16) | 120] {
            hsreq.extend(w.to_be_bytes());
        }
        let mut exts = vec![
            Ext {
                cmd: CMD_HSREQ,
                data: hsreq,
            },
            Ext {
                cmd: CMD_SID,
                data: sid_data,
            },
        ];
        if let Some((cipher, klen_words)) = km {
            let mut k = vec![0u8; 32];
            k[8] = cipher;
            k[15] = klen_words;
            exts.push(Ext {
                cmd: CMD_KMREQ,
                data: k,
            });
        }
        let hs = Handshake {
            version: 5,
            enc_field: 0,
            ext_field: SRT_MAGIC,
            isn: 1,
            mss: 1500,
            flow: 8192,
            hs_type: HS_CONCLUSION,
            socket_id,
            cookie: r.cookie(from),
            peer_ip: [0; 16],
            exts,
        };
        handshake_packet(&hs, 0, 0)
    }

    fn induction(socket_id: u32) -> Vec<u8> {
        let hs = Handshake {
            version: 4,
            enc_field: 0,
            ext_field: 2,
            isn: 0,
            mss: 1500,
            flow: 8192,
            hs_type: HS_INDUCTION,
            socket_id,
            cookie: 0,
            peer_ip: [0; 16],
            exts: vec![],
        };
        handshake_packet(&hs, 0, 0)
    }

    fn at(ip: &str, port: u16) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), port)
    }

    fn relay() -> Relay {
        Relay::new(
            UdpSocket::bind("127.0.0.1:0").unwrap(),
            false,
            true,
            None,
            true,
        )
    }

    /// The relay's indexes agree with its sessions and waiting callers.
    fn assert_consistent(r: &Relay) {
        for (dest, addrs) in &r.by_dest {
            for a in addrs {
                let leg = r
                    .legs
                    .get(a)
                    .expect("by_dest names a leg that does not exist");
                assert_eq!(leg.peer_socket_id, *dest);
            }
        }
        for (a, leg) in &r.legs {
            assert_eq!(r.legs[&leg.peer].peer, *a, "legs pair up");
            assert!(r.busy.contains(&leg.sid));
        }
        let sids: HashSet<_> = r.legs.values().map(|l| l.sid.clone()).collect();
        assert_eq!(sids, r.busy);
        let mut per_net: HashMap<IpAddr, usize> = HashMap::new();
        let mut n = 0;
        for (sid, w) in &r.pending {
            assert!(!w.is_empty());
            for c in w {
                assert_eq!(r.waiting_at.get(&c.addr), Some(sid));
                assert!(!r.legs.contains_key(&c.addr));
                *per_net.entry(net(c.addr.ip())).or_default() += 1;
                n += 1;
            }
        }
        assert_eq!(n, r.waiting_at.len());
        assert_eq!(per_net, r.waiting_per_net);
    }

    #[test]
    fn one_address_waits_on_one_streamid_and_cannot_crash_the_relay() {
        let mut r = relay();
        let (a, b, c, d) = (
            at("127.0.0.1", 40001),
            at("127.0.0.1", 40002),
            at("127.0.0.1", 40003),
            at("127.0.0.1", 40004),
        );
        r.on_packet(a, &conclusion(&r, a, 0xA, "s1", None));
        r.on_packet(a, &conclusion(&r, a, 0xA, "s2", None));
        // It moved to s2.
        assert!(!r.pending.contains_key("s1"));
        assert_eq!(r.waiting_at[&a], "s2");
        assert_consistent(&r);
        r.on_packet(b, &conclusion(&r, b, 0xB, "s1", None));
        r.on_packet(c, &conclusion(&r, c, 0xC, "s2", None));
        assert_eq!(r.legs[&a].peer, c);
        assert!(!r.legs.contains_key(&b));
        assert_consistent(&r);
        r.on_packet(a, &control(CTRL_SHUTDOWN, 0, 0, 0, 0xC, &[0; 4]));
        assert_consistent(&r);
        r.on_packet(d, &data_to(0xB, 1));
        r.on_packet(d, &data_to(0xA, 1));
        assert_consistent(&r);
    }

    #[test]
    fn a_stale_index_entry_is_dropped_not_unwrapped() {
        let (mut r, ca, _cb) = session();
        let a = ca.local_addr().unwrap();
        r.legs.remove(&a);
        r.on_packet(at("127.0.0.1", 1), &data_to(0x222, 1));
        assert!(!r.by_dest.contains_key(&0x222));
    }

    #[test]
    fn waiting_callers_are_capped_per_network() {
        let mut r = relay();
        for i in 0..MAX_WAITING_PER_NET as u16 + 5 {
            let x = at("192.0.2.1", 1000 + i);
            r.on_packet(x, &conclusion(&r, x, 1, &format!("sid{i}"), None));
        }
        assert_eq!(r.waiting_at.len(), MAX_WAITING_PER_NET);
        // An IPv6 host cannot get around it with more addresses in its /64.
        for i in 0..MAX_WAITING_PER_NET as u16 + 5 {
            let x = at(&format!("2001:db8::{i:x}"), 1000);
            r.on_packet(x, &conclusion(&r, x, 1, &format!("v6-{i}"), None));
        }
        assert_eq!(r.waiting_at.len(), 2 * MAX_WAITING_PER_NET);
        assert_consistent(&r);
    }

    #[test]
    fn long_streamids_and_oversized_handshakes_are_refused() {
        let mut r = relay();
        let a = at("127.0.0.1", 40001);
        r.on_packet(a, &conclusion(&r, a, 1, &"x".repeat(MAX_SID_LEN), None));
        assert_eq!(r.waiting_at.len(), 1);
        let b = at("127.0.0.1", 40002);
        r.on_packet(b, &conclusion(&r, b, 1, &"x".repeat(MAX_SID_LEN + 1), None));
        assert_eq!(r.waiting_at.len(), 1);
        let mut big = conclusion(&r, b, 1, "ok", None);
        big.resize(MAX_HS_LEN + 1, 0);
        r.on_packet(b, &big);
        assert_eq!(r.waiting_at.len(), 1);
    }

    #[test]
    fn spoofed_packets_from_a_leg_address_do_not_end_the_session() {
        let (mut r, ca, cb) = session();
        let a = ca.local_addr().unwrap();
        // An induction: answered, the session stays.
        r.on_packet(a, &induction(7));
        assert_eq!(r.legs.len(), 2);
        // A shutdown not addressed to the peer: dropped, not forwarded.
        r.on_packet(a, &control(CTRL_SHUTDOWN, 0, 0, 0, 0xDEAD, &[0; 4]));
        assert_eq!(r.legs.len(), 2);
        assert_eq!(r.legs[&a].stats.foreign, 1);
        // Nor data.
        r.on_packet(a, &data_to(0xDEAD, 5));
        assert_eq!(recv_seq(&cb), None);
        // A conclusion with a new socket id but no valid cookie: dropped.
        let mut c = conclusion(&r, a, 0x999, "s", None);
        c[HDR + 28..HDR + 32].copy_from_slice(&0u32.to_be_bytes());
        r.on_packet(a, &c);
        assert_eq!(r.legs.len(), 2);
        // The real shutdown ends it.
        r.on_packet(a, &control(CTRL_SHUTDOWN, 0, 0, 0, 0x222, &[0; 4]));
        assert!(r.legs.is_empty() && r.busy.is_empty());
        assert_consistent(&r);
    }

    #[test]
    fn caller_restarting_on_the_same_address_replaces_its_session() {
        let (mut r, ca, _cb) = session();
        let a = ca.local_addr().unwrap();
        // The same socket id: a lost response, resent; the session stays.
        r.on_packet(a, &conclusion(&r, a, 0x111, "s", None));
        assert_eq!(r.legs.len(), 2);
        // A new socket with a valid cookie: the old session ends, it waits.
        r.on_packet(a, &conclusion(&r, a, 0x333, "s", None));
        assert!(r.legs.is_empty());
        assert_eq!(r.waiting_at[&a], "s");
        assert_consistent(&r);
    }

    #[test]
    fn cookies_expire_but_a_waiting_caller_keeps_its_own() {
        let mut r = relay();
        let a = at("127.0.0.1", 40001);
        r.on_packet(a, &conclusion(&r, a, 1, "s", None));
        // Three cookie periods later.
        let Some(t0) = r.t0.checked_sub(COOKIE_PERIOD * 3) else {
            return; // the machine has not been up that long
        };
        let old = r.cookie(a);
        r.t0 = t0;
        assert!(!r.cookie_ok(a, old));
        assert!(r.cookie_ok(a, r.cookie_at(a, 2)) && r.cookie_ok(a, r.cookie_at(a, 3)));
        assert!(!r.cookie_ok(a, r.cookie_at(a, 1)));
        // The caller repeats the conclusion it was admitted with: still counts.
        let mut c = conclusion(&r, a, 1, "s", None);
        c[HDR + 28..HDR + 32].copy_from_slice(&old.to_be_bytes());
        r.pending.get_mut("s").unwrap()[0].last_seen = Instant::now();
        r.on_packet(a, &c);
        assert_eq!(r.pending["s"][0].repeats, 1);
        // A new address with that cookie gets nowhere.
        let b = at("127.0.0.1", 40002);
        c[HDR + 28..HDR + 32].copy_from_slice(&r.cookie_at(b, 0).to_be_bytes());
        r.on_packet(b, &c);
        assert!(!r.waiting_at.contains_key(&b));
    }

    #[test]
    fn a_caller_refused_again_and_again_is_not_locked_out() {
        // A second receiver on a busy 1:1 stream, retrying in a tight loop.
        let (mut r, _ca, _cb) = session();
        for port in 0..500 {
            let x = at("192.0.2.1", 1000 + port);
            r.on_packet(x, &induction(1));
            r.on_packet(x, &conclusion(&r, x, 1, "s", None));
        }
        assert!(r.waiting_at.is_empty());
        // Once the stream is free, it gets in, and so does everyone behind
        // the same address.
        let a = *r.legs.keys().next().unwrap();
        r.teardown(a, "test");
        let x = at("192.0.2.1", 2000);
        r.on_packet(x, &conclusion(&r, x, 1, "s", None));
        let y = at("192.0.2.1", 2001);
        r.on_packet(y, &conclusion(&r, y, 2, "other", None));
        assert_eq!(r.waiting_at.len(), 2);
        assert_consistent(&r);
    }
}
