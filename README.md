# srt-splice

A forwarding SRT relay on **one UDP port**. Think of it as a TURN relay, but
for SRT: two SRT callers that use the same `streamid` are paired, and the
relay splices their handshakes so that one SRT session runs end to end.

The relay never terminates SRT. After the handshake it forwards every packet
untouched, so there is one ARQ loop, one negotiated latency and one
encryption context. The relay does not need the passphrase and never learns
it.

```
caller A ──srt://relay:9000?streamid=cam1──┐
                                           ├─ relay (UDP 9000) ─ forwards packets A⇄B
caller B ──srt://relay:9000?streamid=cam1──┘
```

It is meant as a helper service for [Strom](https://github.com/Eyevinn/strom),
the GStreamer flow engine: a single public UDP port in front of Strom in
Kubernetes, so that both Strom and the outside world connect *out* as SRT
callers and neither needs its own public listener. It does not depend on
Strom and works with any SRT caller, in a local Docker Compose stack or
anywhere else.

> **Status: experimental.** This is a research spike: std-only Rust (no
> dependencies), about 800 lines, one thread. It has been tested on loopback
> with libsrt and the Rust `srt-protocol` crate (see [Results](#results)). It
> is not production code yet. Feedback and interop reports are welcome.

## Quick start

The relay listens on `0.0.0.0:9000` by default.

```sh
# From source
cargo build --release
./target/release/srt-splice --listen 0.0.0.0:9000 -v

# Released image (multi-arch, published to ghcr.io on version tags)
docker run --rm -p 9000:9000/udp ghcr.io/eyevinn/srt-splice:latest

# Or build it (static binary on an empty base, runs as nobody)
docker build -t srt-splice .
docker run --rm -p 9000:9000/udp srt-splice

# Docker Compose
docker compose -f examples/docker-compose.yml up --build
```

Options (environment variable in brackets):

| Option | Default | |
|---|---|---|
| `--listen ADDR:PORT`, `-l` (`SRT_SPLICE_LISTEN`) | `0.0.0.0:9000` | The SRT UDP port, the one exposed publicly. |
| `--api ADDR:PORT\|off` (`SRT_SPLICE_API`) | `0.0.0.0:9001` | Read-only HTTP API, **internal network only**. |
| `--public HOST:PORT` (`SRT_SPLICE_PUBLIC`) | unset | The address the outside world dials, reported by the API. |
| `--no-fingerprint` | off | See [Direction](#direction-mpublish--mrequest). |
| `-v` | off | Log per-session stats every 5 s. |

### HTTP API

For services next to the relay, for example Strom asking which public
address to show its users. Nothing in it is secret, but keep it off the
public network.

- `GET /v1/info` → `{"version":"0.0.1","public":"srt.example.com:9000","srt_port":9000}`
  (`public` is `null` when `--public` is not set)
- `GET /healthz` → `ok`

Then start a receiver and a sender in either order, with the same streamid.
Use a long random streamid and a passphrase (see [Security](#security)):

```sh
SID=$(openssl rand -hex 16)
srt-live-transmit "srt://HOST:9000?streamid=$SID&passphrase=$SRT_PASSPHRASE" file://con | ffplay -
ffmpeg -re -i in.ts -c copy -f mpegts "srt://HOST:9000?streamid=$SID&passphrase=$SRT_PASSPHRASE"
```

A Kubernetes example (Deployment + `LoadBalancer` Service) is in
[examples/kubernetes/](examples/kubernetes/). Run a **single replica** and
use `externalTrafficPolicy: Local`: the two callers of a session are paired
inside one process, and the relay tells the legs apart by their UDP source
address, so it must see the real client addresses.

## Pairing rule: one streamid = one session (1:1)

A streamid pairs exactly two callers. A third caller with the same streamid
while the session is up is rejected with `SRT_REJX_CONFLICT` (1409). It can
connect again once the session has ended. This holds in both directions: two
senders cannot share a streamid either.

The relay does not split streams. One source to several receivers needs a
session per receiver, all the way to the source:

- **Today:** the source makes one output per receiver from the same signal,
  each with its own streamid (`pgm-1`, `pgm-2`, …). In Strom that is one SRT
  output per receiver.
- **Later, if needed:** a separate, *terminating* fan-out mode, chosen per
  session. Only the streamid travels in the SRT handshake. The other URI
  parameters are local socket options and never reach the relay. So a mode
  has to be signalled in the streamid itself, for example with the SRT
  access-control syntax (`#!::r=pgm,m=request,…`) or a prefix. That mode
  needs a full SRT stack, separate ARQ legs and the passphrase in the relay.
  It is a bigger question and not part of this spike.

## Direction: `m=publish` / `m=request`

A streamid in the SRT access-control syntax (`#!::r=cam1,m=request`) pairs
on `r`, so it pairs with a plain `cam1` from the other side. `m` gives the
caller's **own** role, as the SRT spec defines it: `publish` = I send,
`request` = I receive.

The relay uses the direction to choose the ISN in the conclusion responses.
**Both sides get the sender's own ISN.** The sender then sees exactly what
any listener would send it (its own ISN echoed), and every receiver expects
the peer's data from the response's ISN, whatever the implementation. So no
fingerprinting is needed.

- Ingest into Strom: Strom connects with `#!::r=<id>,m=request`, and the
  outside sends to plain `<id>`.
- Output from Strom: Strom connects with `#!::r=<id>,m=publish`, and the
  outside pulls from plain `<id>`.
- Either side may state it. Two callers that state the same role are never
  paired. From the same host, the newer one is that caller reconnecting
  (callers retry from a new port after their connect timeout, as Strom's
  SRT blocks do every 3 s) and replaces the older attempt. From another
  host while the first is still waiting, it is rejected with
  `SRT_REJX_CONFLICT` (1409).
- No direction (plain streamids on both sides, or `m=bidirectional`):
  **fallback:** recognize srt-protocol by its HSREQ (see
  [Findings](#findings)), otherwise assume libsrt on both sides.
  `--no-fingerprint` turns the fallback off.

In a URI the streamid must be URL-encoded:
`srt://relay:9000?streamid=%23!%3A%3Ar%3Dcam1%2Cm%3Drequest`.

## How it works

1. **Induction:** the relay answers itself (HSv5, the SRT magic, and a
   cookie keyed with a per-process random secret). A conclusion whose cookie
   does not match its source address is dropped, so a spoofed source cannot
   hold a streamid or make the relay send to it.
2. **Conclusion:** the relay reads the streamid (SID extension) and *holds*
   the conclusion without answering. The caller resends it every 250 ms
   until its connect timeout. A waiting caller not heard from for 400 ms is
   treated as gone.
3. Up to four callers can wait on one streamid. Two of them are paired
   once the older one has repeated its conclusion after the newer one
   arrived (at most about 250 ms), as proof that both are still there. So a
   caller that gave up, or a caller's own earlier attempt before it
   reconnected from a new port, is never paired. Each side gets the
   **other side's** values:
   - socket id, so `dest socket id` in every later packet is already right
     and nothing in the header is rewritten. That matters for AES-GCM,
     which authenticates the whole 16-byte header.
   - ISN, so sequence numbers (and with them the AES IV) need no rewriting.
     See the ISN finding below.
   - SRT version and flags, the flow window, and min(MSS).
   - latency = max of the four values both sides asked for, in both fields.
   - the handshake timestamp on the *other side's* clock, so TSBPD gets the
     right peer start time.
4. **Keys:** a libsrt caller only accepts its *own* KM back in the KMRSP,
   so the relay echoes it. Right after that it sends each side the other
   side's KM as an in-band key update (`UMSG_EXT`/`KMREQ`). The KM is
   wrapped with a KEK derived from the passphrase and the salt, and the
   salt travels in the KM, so the receiver unwraps it with its own
   passphrase. The relay retransmits it until a KMRSP arrives, and consumes
   that KMRSP.
5. After that, data, ACK, NAK, keepalive, key refresh and shutdown are
   forwarded as they are. Only the UDP address changes.

## Security

- **The streamid is the pairing key.** Anyone who can reach the port and
  guesses a streamid that is waiting for a peer can take the other end of
  that session. Use long random streamids (for example 128 bits from
  `openssl rand -hex 16`), not names like `cam1`.
- **Use a passphrase.** Encryption runs end to end between the two callers.
  The relay never sees the passphrase, so an intruder with the right
  streamid but the wrong passphrase gets no usable data (see
  [Results](#results)). Keep passphrases in environment variables or
  secrets, not in files you commit.
- The relay can still see everything that is in clear text in SRT:
  sequence numbers, retransmit flags, the key slot (KK), packet and byte
  counts, and the streamid.
- There is no authentication, access policy, rate limit or handshake
  flood protection yet. Do not expose it to the internet for anything that
  matters without those in front of it.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Limits

- **1:1 only:** one streamid pairs exactly two callers (see above).
- **AES-GCM is untested.** Homebrew's libsrt is built without
  `ENABLE_AEAD_API_PREVIEW` and silently falls back to CTR. In theory it
  works, since no header field is rewritten.
- **Not supported:** packet filter (FEC) and bonding groups (both are
  rejected), and rendezvous mode.
- **Not tested:** bidirectional data (both sides sending), IPv6, NAT
  rebinding (a peer's port changes mid-session), libsrt 1.4.x and pre-1.3
  HSv4 callers, hardware encoders, srt-protocol as the *receiver*.
- **One process holds all sessions,** so it scales up, not out: both
  callers of a session must reach the same instance.

## Results

macOS, loopback, libsrt 1.5.6 `srt-live-transmit` and the Rust
`srt-protocol` 0.4.4 crate.

| Case | Result |
|---|---|
| Unencrypted | ✅ 0 lost, p50 133.7 ms (direct without relay: 133.4) |
| AES-128 / AES-256 (CTR) | ✅ 0 lost, keys injected and accepted both ways, no clear packets |
| Key refresh mid-stream (`kmrefreshrate=2000`) | ✅ in-band KMREQ/KMRSP forwarded, 0 lost |
| Latency 500 (sender) vs 120 (receiver) | ✅ both get 500, measured p50 513 ms |
| 5 % loss + 20 ms each way (lossy proxy), latency 300 | ✅ 0 lost, 131 retransmits end to end. Same as direct through the same proxy (0 lost, p50 337 ms) |
| Sender connects first, receiver 1.5 s later | ✅ |
| Receiver with `conntimeo=1500` and auto-reconnect, sender joins after 4 s (the receiver has reconnected from new ports twice) | ✅ stale attempts are not paired, 0 lost |
| **Strom 0.7.2** (Docker) in a loop: `ffmpeg` → relay `cam1` → Strom MPEG-TS/SRT Input (caller, `m=request`, passthrough) → Strom MPEG-TS/SRT Output (caller, `m=publish`) → relay `pgm` → receiver; AES-128, H.264 720p 4 Mbit/s | ✅ decodable H.264 out, 348 frames of 375. Strom's 3 s reconnects replace their own earlier attempts |
| Wrong passphrase on one side | ✅ no data reaches the receiver. The injected key gets no KMRSP and the relay tears down after 3 s (could be faster) |
| One side encrypted, other not | ✅ the newer caller is refused with `SRT_REJ_UNSECURE`; the one already waiting keeps its place, so a stray or hostile caller that knows the id cannot knock it out |
| Rust `srt-protocol` 0.4.4 sender → libsrt receiver, plain + AES | ✅ after the ISN fix below |
| Direction, `--no-fingerprint`: Rust sender → libsrt receiver `m=request` (Strom ingest) | ✅ |
| Direction: libsrt ingest (`m=request`) / egress (`m=publish`), AES | ✅ / ✅ |
| Direction: Rust sender declares `m=publish` itself | ✅ |
| No direction, `--no-fingerprint`: Rust sender → libsrt | ❌ as expected: 0 packets. This is the case the fallback covers |
| No direction, fingerprint on: Rust sender → libsrt | ✅ |
| Both `m=publish` (same host) | ✅ never paired; the newer replaces the older |
| AES-GCM | ⚠️ **untested**, see [Limits](#limits) |

The `max=5000 ms` in the measurements is an artifact of the tools at
shutdown. A direct connection without the relay shows the same.

### How the cases were run

[scripts/case.sh](scripts/case.sh) runs one case against a running relay: a
libsrt receiver (`srt-live-transmit`) connects first, then a sender joins
with the same streamid, and a measuring tool reports loss, duplicates and
latency at the receiver. The measuring tool (test stream generator, latency
meter, Rust `srt-protocol` sender and lossy UDP proxy) is an **external**
tool that is not part of this repository; point `SPIKE` at a compatible
binary. The header of the script describes the interface it expects.

```sh
./target/release/srt-splice &
SPIKE=/path/to/measuring-tool \
  ./scripts/case.sh aes128 "passphrase=$SRT_PASSPHRASE" "passphrase=$SRT_PASSPHRASE" 5
```

## Findings

- **The ISN differs per implementation.** libsrt sends from its *own* ISN
  and expects the peer's data from the ISN in the response. srt-protocol
  takes the response's ISN for *both* directions. A normal listener echoes
  the caller's ISN, so the difference never shows there. With a known
  direction (`m=`, see above) it does not matter. Without one, the relay
  falls back to recognizing srt-protocol (SRT 1.3.1, flags exactly `0x27`).
  That fingerprint is fragile: other implementations (gosrt, hardware
  encoders) need checking, so give the direction wherever possible.
- **The waiting party sits in the handshake.** The first caller's connect
  timeout (default 3 s) is how long it can wait. Encoders with
  auto-reconnect (OBS, vMix, srt-live-transmit `-a`) just try again. Without
  that, raise `conntimeo`. The alternative, finishing the handshake early,
  would mean rewriting socket id and ISN: that breaks the AES IV (CTR uses
  the seqno) and the GCM AAD.
- **Wrong passphrase gives no KMRSP from libsrt** for an in-band KMREQ it
  cannot unwrap, so the relay only detects it by timeout.

## Possible next steps

- GCM test (build libsrt with `-DENABLE_AEAD_API_PREVIEW=ON`), and
  bidirectional data.
- Interop matrix: OBS, vMix, ffmpeg, GStreamer `srtsrc`/`srtsink`, gosrt,
  hardware encoders.
- Forwarding to a URI: the relay calls a listener itself (for example a
  Strom SRT input) on behalf of a caller. That case is simpler, because the
  relay is the initiator and can send the caller's own KM, ISN and socket id.
- Policy and access per streamid (tokens), metrics, idle timeouts,
  multithreading or `recvmmsg`, and a rate limit on handshakes.

## Contributing

Issues are the best way to contribute: say what is broken or missing, how
you would solve it, and how we would test it. Interop reports (which
encoder or decoder, which version, what happened) are especially welcome.
Pull requests are welcome too; CI runs `cargo fmt --check`, `cargo clippy
-- -D warnings`, `cargo build` and `cargo test`.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
