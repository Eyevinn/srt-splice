# Design

> Code is the source of truth: this may have drifted. Read the code for the
> current implementation.

srt-splice pairs two SRT callers on one UDP port and forwards their packets
unchanged. It does not terminate SRT. This document explains how that
works and why it is built this way.

## Why not terminate?

A terminating relay (srtrelay, srt-live-server, MediaMTX, SRT gateways) runs
a full SRT session to each side and copies the media between them. That
gives two ARQ loops, two latency budgets, and the passphrase on the relay.

srt-splice instead makes the two callers believe they are connected
straight to each other:
- one ARQ loop and one latency, end to end;
- no media buffering in the relay;
- the relay never needs or learns the passphrase.

The price is that the relay has to answer each caller's handshake with the
other caller's parameters, which is described below.

## The handshake

1. **Induction.** The relay answers by itself: HSv5, the SRT magic, and a
   cookie keyed with a per-process random secret.
2. **Conclusion.** The relay reads the streamid (the SID extension) and
   *holds* the conclusion without answering. libsrt and srt-protocol repeat
   it every 250 ms until their connect timeout; gosrt sends it once and
   waits (see [Pairing rules](#pairing-rules)).
   - A conclusion whose cookie does not match its source address is dropped,
     so a spoofed source cannot hold a streamid or make the relay send to it.
   - A waiting caller that repeats and is then not heard from for 400 ms is
     treated as gone. One that has never repeated is kept for 2.5 s.
3. **Pairing.** When a second caller with the same streamid is waiting, the
   relay answers both conclusions. Each side gets the **other side's**
   values:
   - **socket id**, so the destination socket id in every later packet is
     already right and no header field is rewritten. AES-GCM authenticates
     the whole 16-byte header, so this matters.
   - **ISN**, so sequence numbers, and with them the AES counter, need no
     rewriting. See [ISN and direction](#isn-and-direction).
   - SRT version and flags, the flow window, and the smaller MSS, capped
     at `--max-mss` if set (see [MSS](#mss)).
   - **latency**: the largest of the four values both sides asked for, in
     both fields.
   - **the handshake timestamp on the other side's clock**, so TSBPD gets
     the right peer start time.
4. **Keys.** See [Encryption](#encryption).
5. **Forwarding.** After that, data, ACK, NAK, keepalive, key refresh and
   shutdown are forwarded as they are. Only the UDP address changes.

## Pairing rules

- Up to four callers can wait on one streamid.
- **Liveness:** two callers are paired only once the older one has repeated
  its conclusion after the newer one arrived (at most about 250 ms later).
  This proves both are still there. A caller that gave up, or a caller's own
  earlier attempt before it reconnected from a new port, is never paired.
- **Callers that do not repeat:** gosrt sends its conclusion once and waits
  for the answer. A caller seen exactly once counts as alive for 2.5 s
  after it arrived, and is paired as soon as a compatible peer arrives in
  that time (or repeats). 2.5 s is below the 3 s default connect timeout of
  gosrt (counted from its induction) and libsrt, so the answer still finds
  it waiting. A caller that has repeated even once keeps the strict rule
  above, so a dead libsrt attempt (repeats, then silence) is never paired.
  A libsrt attempt that dies within its first 250 ms looks like a gosrt
  caller for those 2.5 s; that is the price.
- **Roles:** two callers that state the same role (`m=publish` or
  `m=request`) are never paired.
  - From the same host, the newer one is that caller reconnecting (callers
    retry from a new port after their connect timeout; Strom's SRT blocks do
    it every 3 s). It replaces the older attempt, and the old attempt is
    ignored while it keeps repeating.
  - From another host while the first is still waiting, it is refused with
    `SRT_REJX_CONFLICT` (1409).
- **Encryption** must match: a key exchange (KM) on both sides with the same
  cipher and key length, or no encryption on either.
  - A caller with other settings is ignored for everyone else: it cannot
    pair with them, and it does not count against them in the role rule.
  - A clear caller that finds only encrypted callers of a matching role is
    refused with `SRT_REJ_UNSECURE`.
  - Encrypted callers are never refused for a mismatch. The relay cannot
    tell which side is the stray, and refusing the later one would let
    whoever came first block the session.
  - A wrong *passphrase* cannot be seen in the handshake at all; see
    [Findings](#findings).
- **1:1:** while a session is up, another caller on its streamid is refused
  with 1409.

## Address changes (NAT rebinding)

The relay knows each leg by its caller's UDP address. Some NATs (mobile
networks, some home and carrier-grade NATs) give a long-running flow a new
public port, or address, mid-session. The caller does not notice, but its
packets now come from an address the relay does not know.

Every SRT packet carries the destination socket id in its header (bytes
12..16), and every packet a caller sends is addressed to its peer's socket
id, which the relay put in that caller's conclusion response. So a packet
from an unknown address whose destination socket id belongs to an
established leg is most likely that leg's caller from its new address. The
relay then moves the leg: the leg's address and the peer's return address
both change, it logs `<old> moved to <new>`, and forwards the packet. The
peer's packets go to the new address from then on.

Conditions, all required:
- **Not a handshake.** A handshake from a new address is a new caller, and
  goes through the normal handshake (cookie, pairing, `1409` while the
  session is up).
- **A plausible session packet:** data, or a known control type.
- **Exactly one leg** expects that destination socket id. If several do
  (see [Socket id collisions](#socket-id-collisions)), none is moved and the
  packet is dropped as a stray.
- **The same IP family** as before.
- **The old address has been silent for 500 ms.** A healthy leg is never
  silent that long while media flows: the receiver ACKs every 10 ms, and
  the sender sends at its bitrate (a packet every ~160 ms even for 64 kbit/s
  audio alone). After a real rebinding the old address goes silent at once,
  so this costs at most 500 ms. Moving at once would have no gap, but then
  any packet with the right socket id would take over a leg that is still
  sending, and packets still in flight from the old address would move it
  back and forth.

**The cost** is a stall of about 500 ms. In the tests (see
[TESTING.md](TESTING.md)) libsrt recovered every packet even at the
default 120 ms latency, delivering them up to about 1 s late; a latency
above about 500 ms plus the round trip hides it completely. A shorter
threshold (50 ms worked in tests too) would shorten the stall, but would
let a guessed socket id take over a low-bitrate leg between its packets.

**Residual risk.** The socket ids are the callers' own random values, not
assigned by the relay (libsrt draws about 30 random bits), and the relay
never sends them anywhere but to the two callers. An off-path attacker has
to guess one, and a guess only works on a leg that has been silent for
500 ms: one with no media flowing (only a keepalive every second), or one
whose caller really is gone (until the 5 s idle timeout). An attacker who succeeds receives that leg's packets, which
are encrypted with a passphrase, and the session breaks, as it would
anyway if they could spoof the caller's address. When the real caller sends
again, its packets come from an address the relay does not know, and take
the leg back once the attacker has been silent for 500 ms. Someone who can
see the traffic (on the path) learns the socket ids and can move a silent
leg; they could also drop or spoof the packets. The relay does not
authenticate packets; the passphrase protects the content end to end.

### Socket id collisions

libsrt draws a random start value in about 2^30 once per process and
counts down for each new socket, so two sockets of one process never share
an id; ids can only collide between processes. For N legs at a time on one
relay, the chance that any two expect the same id is about
N² / (2 · 2^30): about 1 in 2,000 for 1,000 legs (500 sessions).

A collision does not matter for forwarding, which is keyed by the callers'
addresses. It only matters if one of the colliding legs also changes its
address: the id is then ambiguous, the relay does not move either leg, and
that session is lost as it was before rebinding was supported. Media is
never sent to the wrong session.

## MSS

The relay grants each caller the smaller of the two MSS values (the
largest IP packet SRT will send, including the 28-byte IP/UDP and 16-byte
SRT headers; libsrt asks for 1500). `--max-mss N` caps it, for a path
with a smaller MTU than the callers know about, such as an overlay network
inside a cluster (VXLAN: 1450). By default there is no cap: the callers'
own values stand, as with a direct connection. See
[DEPLOYMENT.md](DEPLOYMENT.md#mtu).

## Encryption

A libsrt caller only accepts its *own* key material back in the KMRSP, so
the relay echoes it. Each caller has generated its own key, so right after
the handshake the relay sends the *other* side's KM as an in-band key
update (`UMSG_EXT` / `KMREQ`):
- **direction known:** only to the receiver. The sender does not need the
  peer's key, and some implementations do not take a key update while they
  send (gosrt).
- **no direction:** to both sides, since either may receive.

The KM is wrapped with a key derived from the passphrase and a salt, and the
salt travels in the KM. So the receiver unwraps it with its own passphrase;
the relay neither needs nor learns it. The relay repeats the update every
100 ms until a KMRSP arrives (for 3 s), and consumes that KMRSP. After
that, key refreshes from the sender go end to end like everything else.

**A wrong passphrase.** libsrt does not answer a key update it cannot
unwrap. So:
- **direction known:** no answer from the receiver within 3 s means it
  cannot decrypt, and the relay tears the session down.
- **no direction:** the relay cannot tell whether that side needs the key
  (a gosrt sender never answers either), so it stops retrying and logs a
  warning; the session stays up.
- An explicit error answer (a KMRSP with only a KM state) tears the session
  down either way: the passphrases differ, so neither side can decrypt.

## ISN and direction

Every SRT session has an initial sequence number (ISN). A normal listener
echoes the caller's own ISN, so implementations never notice that they read
the response's ISN differently:
- **libsrt** sends from its *own* ISN and expects the peer's data from the
  ISN in the response.
- **srt-protocol** (Rust) uses the response's ISN for *both* directions.

The relay has to answer with the peer's ISN, so the difference matters. With
a known direction it goes away: **both sides get the sender's own ISN.** The
sender sees exactly what any listener would send it (its own ISN echoed),
and every receiver expects the peer's data from the response's ISN, whatever
the implementation.

One exception: a sender recognised as taking its ISN from the response
(srt-protocol or gosrt, by the fingerprint below) gets the *receiver's* own
ISN, and so does the receiver. Such a sender uses one ISN for both
directions, also in the ACKs it sends back. With its own ISN those ACKs do
not fit the receiver's own send sequence, and libsrt can close the
connection ("ATTACK/IPE: incoming ack seq ... exceeds current"), depending
on which of the two random ISNs is larger. With the receiver's ISN
everything lines up, as in the no-direction case.

The direction comes from the streamid in the SRT access-control syntax:
- `#!::r=<id>,m=publish` means this caller sends.
- `#!::r=<id>,m=request` means this caller receives.

It pairs on `r`, so either side can state it and the other can use a plain
`<id>`. Strom always states it.

Without a direction (plain streamids on both sides, or `m=bidirectional`),
the relay falls back to recognising the implementations that take their ISN
from the response by their HSREQ, and otherwise assumes libsrt:
- srt-protocol 0.4: SRT 1.3.1, flags exactly `0x27`;
- gosrt 0.13: SRT 1.4.1, flags exactly `0x3F`. libsrt 1.4.0 and later
  always set FILTERCAP (`0x80`), so libsrt never sends this.

That fingerprint is fragile (a new gosrt release may announce another
version), so give the direction where you can. `--no-fingerprint` turns
the fallback off.

### gosrt

gosrt (github.com/datarhei/gosrt, the SRT stack of Restreamer and MediaMTX)
differs from libsrt in three ways that matter here, checked in v0.13.0:
- It takes its ISN from the conclusion response, for both directions, like
  srt-protocol (see above).
- It sends its conclusion once and does not repeat it (see
  [Pairing rules](#pairing-rules)).
- It refuses an in-band key update for the key slot it already uses
  ("wants to reset the key that is already in use"), and does not answer.
  Both callers start on the even key, so gosrt never takes the sender's key
  the relay injects. As a sender that does not matter (it gets no
  injection when the direction is known); as an encrypted receiver it
  cannot decrypt. The relay cannot fix that without the passphrase.

### libsrt 1.5.0 to 1.5.2 as receiver

libsrt 1.5.0, 1.5.1 and 1.5.2 create the receive buffer from the caller's
*own* ISN (`CRcvBuffer(m_iISN, ...)` in core.cpp), not from the peer's ISN
in the conclusion response. 1.5.3 fixed this (`m_iPeerISN`); 1.4.x uses the
old buffer and is not affected. Against a listener the two ISNs are equal.
Through the relay they differ, so such a caller breaks the connection as
soon as it receives data ("SEQUENCE DISCREPANCY ... past max"). As a sender
it works. The relay cannot rewrite sequence numbers instead: they are part
of the AES-CTR/GCM IV.

The relay reads the version from the HSREQ:
- **Direction known, affected receiver:** if the sender adopts the response
  ISN (srt-protocol, gosrt), both responses carry the *receiver's* ISN, and it
  works. Otherwise the receiver is refused with `SRT_REJX_UNACCEPTABLE`
  (1406) and a log line naming its version. The sender keeps waiting.
- **No direction:** never refused, since an affected caller that only sends
  works. The relay logs a warning at pairing.

## Abuse protection

The relay is a public UDP port without authentication: the streamid is the
only key. These limits keep one host from exhausting the relay, and spoofed
packets from disturbing a session. They do not stop someone who knows a
streamid from taking or blocking that session (see *What remains* below).

**Legitimate callers come first.** Many of them can share one source
address: everything behind a cloud NAT gateway, a production cluster with
dozens of outputs, a venue, a carrier-grade NAT, or a cluster that SNATs
(`externalTrafficPolicy: Cluster`). And callers misbehave without malice: a
second receiver on a 1:1 stream retries in a loop, a caller with a long
connect timeout waits for minutes. So every limit is far above what such
callers do, nothing that is legitimate leads to a refusal, and there are no
bans: a host that keeps getting refused is most likely a caller retrying,
and a ban would lock out everyone behind its address.

**Handshake rate** (`src/limit.rs`). Handshakes are limited per source
network, counting an IPv4 address or an IPv6 /56 as one (the usual
allocation for one customer site; one host may hold many addresses): 1000
a second, bursts of 2000. A waiting caller sends about 4 a
second (a conclusion every 250 ms) and reconnects about every 3 s, so that
is room for some 200 callers waiting at once behind one address. In total,
20,000 a second (bursts of 40,000) for handshakes whose source is not
proven, so a flood cannot take the forwarding thread. Conclusions with a
valid cookie do not count against that, so a spoofed flood cannot starve
callers that have already proven their address. Over the limit, handshakes are dropped, not refused: a caller loses
a few repeats and keeps trying, as on a lossy path. Established sessions
are never limited. What is dropped is logged once every 5 s.
`--no-rate-limit` turns it off.

**Waiting callers.**
- An address (IP and port: one caller socket) waits on one streamid at a
  time; a conclusion for another streamid moves it. A caller socket makes
  one connection at a time anyway. Without this rule, one address paired on
  two streamids corrupted the session table, and a later packet crashed the
  relay.
- At most 1000 waiting callers per network and 20,000 in total (each holds
  at most a 1500-byte handshake: some 40 MB when full). A caller that takes
  over its own earlier attempt (same role, same host) is never refused by
  these caps.
- A waiting caller's address never becomes a session leg through NAT
  rebinding.
- Streamids longer than 512 bytes on the wire (libsrt's and gosrt's own
  limit) are refused, and handshake packets over 1500 bytes (more than fits in one
  packet) are dropped.

**Cookies** change every 10 minutes; one is valid for 10 to 20 minutes.
A waiting caller repeats the conclusion it was admitted with, cookie and
all, for as long as it waits, so that one stays valid for it however long it
waits.

**Spoofed packets from a session's address.** Every packet a caller sends
names its peer's socket id: libsrt does (tested: no packet dropped in
an AES session), and gosrt (`pop()` in connection.go, v0.9.0) and
srt-protocol (`output` and `encapsulate`, 0.4.4) do in their source.
srt-protocol itself drops packets with another socket id. A packet that does not is dropped and
counted as `foreign` in the stats. The first one per session is logged, so
that a caller that ever did this would show. A spoofed source then also has
to guess the 32-bit socket id, as with a direct SRT connection. An
induction from a session's address is answered but does not end the
session; a caller that really restarted on the same port follows with a
conclusion with a valid cookie and a new socket id, and only that ends the
old session.

**No panics.** The relay is one process and one thread for all sessions,
so a panic would end all of them. Clippy denies `unwrap`, `expect`,
`panic!` and indexing outside the tests.

**What remains:**
- **Whoever knows a streamid can take or block it.** They can pair first and
  answer the key update by echoing it (which is all a KMRSP is), so the
  relay cannot tell that they cannot decrypt. Or they pair two sockets of
  their own on it and keep that session up. A passphrase keeps the media
  unreadable, not the session available. Signed streamids (a token the
  relay can verify, bound to the role and with an expiry) would fix this,
  but need support in the callers' tooling.
- **Floods from many networks, or with spoofed sources,** can use up the
  global handshake budget while they last: new sessions cannot start, but
  established ones run on. A network's own budget can also be used up by
  spoofing its address.
- **Someone with 20 networks** (IPv4 addresses or IPv6 /56s) can fill the
  20,000 waiting places with callers on made-up streamids, and new callers
  are refused while they keep repeating. Running sessions are not
  affected.
- **Volume.** One thread reads every packet, also those it drops. A flood
  above what it can read fills the socket's receive buffer, and the kernel
  then drops packets of every session alike. Against that, only filtering
  in front of the relay helps (the cloud provider's DDoS protection, a
  firewall).

## What the relay sees

What SRT carries in clear text: sequence numbers, retransmit flags, the key
slot (KK), packet and byte counts, and the streamid. The relay logs these
per session with `-v`.

## Findings

- **The waiting caller sits in the handshake.** Its connect timeout is how
  long it can wait for its peer. The alternative, finishing the handshake
  early, would mean rewriting socket ids and sequence numbers later. That
  breaks the AES counter (CTR uses the sequence number) and the GCM tag.
- **A passphrase does not protect availability.** See
  [Abuse protection](#abuse-protection).
- **A wrong passphrase gives no KMRSP from libsrt** for an in-band KMREQ it
  cannot unwrap. The relay only notices by timeout (3 s), and only when the
  direction is known (see [Encryption](#encryption)).
- **colima / Docker on macOS:** the UDP port forward to `localhost` can stop
  working when the container is recreated. Use the VM's address instead.

## Not supported, and ideas

- **Fan-out** (one source, several receivers) needs a *terminating* mode:
  a full SRT stack, separate ARQ legs and the passphrase in the relay. Only
  the streamid travels in the handshake, so such a mode would have to be
  chosen in the streamid. Today: one session per receiver.
- **Packet filter (FEC), bonding groups and rendezvous mode** are refused.
- **Dialling a listener on behalf of a caller** (the relay as the
  initiator) would be simpler than pairing two callers, because the relay
  could send the caller's own KM, ISN and socket id.
- **Throughput:** one thread with one syscall per packet. Batching with
  `recvmmsg` / `sendmmsg` and several threads are the next steps if needed;
  several relays with their own public addresses scale out.
