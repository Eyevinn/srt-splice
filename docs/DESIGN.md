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
   *holds* the conclusion without answering. The caller repeats it every
   250 ms until its connect timeout.
   - A conclusion whose cookie does not match its source address is dropped,
     so a spoofed source cannot hold a streamid or make the relay send to it.
   - A waiting caller not heard from for 400 ms is treated as gone.
3. **Pairing.** When a second caller with the same streamid is waiting, the
   relay answers both conclusions. Each side gets the **other side's**
   values:
   - **socket id**, so the destination socket id in every later packet is
     already right and no header field is rewritten. AES-GCM authenticates
     the whole 16-byte header, so this matters.
   - **ISN**, so sequence numbers, and with them the AES counter, need no
     rewriting. See [ISN and direction](#isn-and-direction).
   - SRT version and flags, the flow window, and the smaller MSS.
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

## Encryption

A libsrt caller only accepts its *own* key material back in the KMRSP, so
the relay echoes it. Each caller has generated its own key, so right after
the handshake the relay sends each side the *other* side's KM as an in-band
key update (`UMSG_EXT` / `KMREQ`).

The KM is wrapped with a key derived from the passphrase and a salt, and the
salt travels in the KM. So the receiver unwraps it with its own passphrase;
the relay neither needs nor learns it. The relay repeats the update until a
KMRSP arrives, and consumes that KMRSP. After that, key refreshes from the
sender go end to end like everything else.

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

The direction comes from the streamid in the SRT access-control syntax:
- `#!::r=<id>,m=publish` means this caller sends.
- `#!::r=<id>,m=request` means this caller receives.

It pairs on `r`, so either side can state it and the other can use a plain
`<id>`. Strom always states it.

Without a direction (plain streamids on both sides, or `m=bidirectional`),
the relay falls back to recognising srt-protocol by its HSREQ (SRT 1.3.1,
flags exactly `0x27`), and otherwise assumes libsrt. That fingerprint is
fragile, so give the direction where you can. `--no-fingerprint` turns the
fallback off.

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
  ISN (srt-protocol), both responses carry the *receiver's* ISN, and it
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
  cannot unwrap. The relay only notices by timeout (3 s) and then tears the
  session down.
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
