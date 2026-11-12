# srt-splice

An SRT relay on **one UDP port**. Two SRT callers that use the same
`streamid` are paired, and the relay splices their handshakes so that one
SRT session runs end to end. Think of it as a TURN relay, but for SRT.

```
caller A ──srt://relay:9000?streamid=cam1──┐
                                           ├─ srt-splice (UDP 9000) ─ forwards packets A⇄B
caller B ──srt://relay:9000?streamid=cam1──┘
```

The relay does not terminate SRT. After the handshake it forwards every
packet as it is, so there is one ARQ loop, one negotiated latency and one
encryption context between the two callers. The relay never needs, or
sees, the passphrase.

It was built as a public front for [Strom](https://github.com/Eyevinn/strom)
in Kubernetes: Strom and the outside world both connect *out* to one public
UDP port, and Strom needs no listener port of its own. It does not depend
on Strom.

**Tested with:** libsrt 1.4 and 1.5 (`srt-live-transmit`, GStreamer
`srtsrc`/`srtsink` in Strom, ffmpeg/ffplay, VLC 3.0.24), the Rust
`srt-protocol` crate and gosrt 0.13 (the Go SRT stack in Restreamer and
MediaMTX). gosrt works as a sender, clear and encrypted, and as a receiver
without encryption, but not as an encrypted receiver (see [Limits](#limits)).
Other implementations (OBS, vMix, hardware encoders, libsrt 1.3 and older)
have not been tested yet. SRT implementations differ in how they read the
handshake, so interop reports are welcome. See
[docs/TESTING.md](docs/TESTING.md).

## Quick start

```sh
docker run --rm -p 9000:9000/udp ghcr.io/eyevinn/srt-splice:latest
```

Then connect a receiver and a sender, in either order, with the same
streamid:

```sh
SID=$(openssl rand -hex 16)
ffplay "srt://relay.example.com:9000?streamid=$SID&passphrase=$SRT_PASSPHRASE"
ffmpeg -re -i in.ts -c copy -f mpegts "srt://relay.example.com:9000?streamid=$SID&passphrase=$SRT_PASSPHRASE"
```

To build from source: `cargo build --release` (std only, no dependencies).
[examples/](examples/) has a Docker Compose file and a Kubernetes manifest.

## How callers pair

- **One streamid is one session, 1:1.** It pairs exactly two callers. A
  third caller with the same streamid while the session is up is refused
  with `SRT_REJX_CONFLICT` (1409). The relay does not split one source to
  several receivers: give each receiver its own streamid.
- **Encryption must match:** a passphrase on both sides, with the same key
  length, or on neither. A caller with other settings is never paired and
  cannot block a correctly configured pair.
- **The waiting caller sits in the handshake** until its peer arrives. Its
  connect timeout (3 s by default in libsrt) is how long it waits. Callers
  that reconnect automatically (OBS, vMix, Strom) just try again; otherwise
  raise the timeout (`conntimeo` in libsrt URIs). gosrt sends its handshake
  only once, so a gosrt caller that waits pairs only with a peer that
  arrives within 2.5 s.
- **Direction (recommended):** a caller may state its role with the SRT
  access-control syntax, `#!::r=<id>,m=publish` (I send) or
  `#!::r=<id>,m=request` (I receive). It pairs on `r`, so it pairs with a
  plain `<id>` from the other side. With a direction, the relay knows which
  side needs which sequence number and key, so it depends much less on how
  a particular implementation reads the handshake, and it can detect a
  wrong passphrase (see
  [docs/DESIGN.md](docs/DESIGN.md#isn-and-direction)). In a URI, encode it:
  `streamid=%23!%3A%3Ar%3Dcam1%2Cm%3Drequest`. Newer libsrt, GStreamer and
  ffmpeg decode that. Older `srt-live-transmit` (tested: libsrt 1.4.2 and
  1.5.1) does not: give it the raw form, quoted in the shell:
  `"srt://relay:9000?streamid=#!::r=cam1,m=request"`.

How this works in detail: [docs/DESIGN.md](docs/DESIGN.md).

### Streamid

- **Every caller must be able to set a streamid**: it is the pairing key.
  libsrt supports it since 1.3.0 (2018), and so do the common tools:
  `streamid=` in ffmpeg and OBS URLs, GStreamer `srtsrc`/`srtsink`, VLC
  3.0.24, and a Stream ID field in vMix and Larix. Some older or low-end
  hardware encoders have no streamid field and cannot use the relay.
- **Length:** the protocol allows 512 characters, but some devices cap the
  field (at 32 or 64, for example). The 22-character ids that Strom and
  Open Live generate fit.
- **Characters:** the outside party only needs the plain id. Use URL-safe
  characters (`[A-Za-z0-9_-]`). Some devices reject `#`, `!`, `:` or `,`,
  and some tools do not URL-decode the streamid, so only the side that can
  (Strom, for example) should use the `#!::r=…,m=…` form.

## Configuration

| Option (env) | Default | |
|---|---|---|
| `--listen`, `-l` (`SRT_SPLICE_LISTEN`) | `0.0.0.0:9000` | The SRT UDP port, the one exposed publicly. |
| `--health` (`SRT_SPLICE_HEALTH`) | `127.0.0.1:9001` (image: `0.0.0.0:9001`) | HTTP health endpoint for probes, `off` to disable. Internal network only. |
| `--no-fingerprint` | off | Without a stated direction, do not guess the caller's SRT implementation. |
| `-v` | off | Log per-session stats every 5 s. |

A command-line option wins over its environment variable.

The health endpoint serves only `GET /healthz`, which returns `ok`. Nothing
needs the relay's HTTP port to use it: clients are configured with the
relay's public address directly. `--api`, `--public` and their environment
variables were removed in 0.2.0; the relay refuses to start if they are set.

Running it in Kubernetes, Docker and behind NAT: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## With Strom

Strom dials the relay itself when an SRT block's `srt_uri` is
`srt+relay://<id>?passphrase=…` and Strom is started with
`STROM_SRT_RELAY=<public host>:9000`, the relay's public address. Strom dials
it and shows it to the outside party as the place to connect. When Strom runs
next to the relay (same cluster or network), also set
`STROM_SRT_RELAY_INTERNAL=<internal host>:9000`: Strom then dials that
address instead, and still shows the public one. This avoids hairpin NAT
through the load balancer. The GUI has a
"Publish via SRT relay" button that generates the id and the passphrase.
This is added in [Eyevinn/strom#1258](https://github.com/Eyevinn/strom/pull/1258).

## Security

- **The streamid is the pairing key.** Anyone who reaches the port and knows
  a waiting streamid can take the other end of that session. Use long random
  streamids (`openssl rand -hex 16`), not names like `cam1`.
- **Use a passphrase.** Encryption runs end to end between the two callers.
  Without the passphrase, an intruder with the right streamid gets no usable
  data.
- The relay sees what SRT carries in clear text: sequence numbers, packet
  and byte counts, and the streamid.
- There is no authentication, access policy or rate limit in the relay.
  Keep the health port off the public network.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Limits

- 1:1 pairing only, no fan-out.
- Not supported: packet filter (FEC), bonding groups and rendezvous mode.
  Callers that ask for them are refused.
- One process holds all sessions, so both callers of a session must reach
  the same instance. Scale out with several relays, each with its own public
  address.
- AES-GCM is untested, though nothing it authenticates is rewritten.
- libsrt 1.5.0–1.5.2 can send through the relay but not receive; a receiver
  on those versions needs 1.5.3+ or 1.4.x
  ([why](docs/DESIGN.md#libsrt-150-to-152-as-receiver)).
- gosrt cannot receive encrypted streams through the relay: it does not
  take the sender's key as an in-band key update
  ([why](docs/DESIGN.md#gosrt)). Clear streams, and gosrt as a sender, work.
- A wrong passphrase is detected (and the session closed) only when the
  direction is stated; without it the relay just logs a warning.

What has been tested, and how: [docs/TESTING.md](docs/TESTING.md).

## Contributing

Issues are the best way to contribute: what is broken or missing, how you
would solve it, and how we would test it. Interop reports (which encoder or
decoder, which version, what happened) are especially welcome. CI runs
`cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo build` and
`cargo test`.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
