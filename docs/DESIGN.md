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

## What the relay sees

What SRT carries in clear text: sequence numbers, retransmit flags, the key
slot (KK), packet and byte counts, and the streamid. The relay logs these
per session with `-v`.

## Findings

- **The waiting caller sits in the handshake.** Its connect timeout is how
  long it can wait for its peer. The alternative, finishing the handshake
  early, would mean rewriting socket ids and sequence numbers later. That
  breaks the AES counter (CTR uses the sequence number) and the GCM tag.
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
