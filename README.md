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
`srtsrc`/`srtsink` in Strom, ffmpeg/ffplay, VLC 3.0.24) and the Rust
`srt-protocol` crate. Other implementations (OBS, vMix, hardware encoders,
gosrt, libsrt 1.3 and older) have not been tested yet. SRT implementations differ in how they read
the handshake, so interop reports are welcome. See
[docs/TESTING.md](docs/TESTING.md).

## Quick start

```sh
docker run --rm -p 9000:9000/udp -e SRT_SPLICE_PUBLIC=relay.example.com:9000 \
  ghcr.io/eyevinn/srt-splice:latest
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
  raise the timeout (`conntimeo` in libsrt URIs).
- **Direction (recommended):** a caller may state its role with the SRT
  access-control syntax, `#!::r=<id>,m=publish` (I send) or
  `#!::r=<id>,m=request` (I receive). It pairs on `r`, so it pairs with a
  plain `<id>` from the other side. With a direction, the sender sees the
  same handshake answer a normal listener would give it, so the relay does
  not depend on how a particular implementation reads it (see
  [docs/DESIGN.md](docs/DESIGN.md#isn-and-direction)). In a URI, encode it:
  `streamid=%23!%3A%3Ar%3Dcam1%2Cm%3Drequest`.

How this works in detail: [docs/DESIGN.md](docs/DESIGN.md).

## Configuration

| Option (env) | Default | |
|---|---|---|
| `--listen`, `-l` (`SRT_SPLICE_LISTEN`) | `0.0.0.0:9000` | The SRT UDP port, the one exposed publicly. |
| `--public` (`SRT_SPLICE_PUBLIC`) | unset | The address the outside world dials. Reported by the API. |
| `--api` (`SRT_SPLICE_API`) | `127.0.0.1:9001` (image: `0.0.0.0:9001`) | Read-only HTTP API, `off` to disable. Internal network only. |
| `--no-fingerprint` | off | Without a stated direction, do not guess the caller's SRT implementation. |
| `-v` | off | Log per-session stats every 5 s. |

A command-line option wins over its environment variable.

The HTTP API is for services next to the relay:
- `GET /v1/info` returns `{"version":"0.1.1","public":"relay.example.com:9000","srt_port":9000}`.
- `GET /healthz` returns `ok`.

Running it in Kubernetes, Docker and behind NAT: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## With Strom

Strom dials the relay itself when an SRT block's `srt_uri` is
`srt+relay://<id>?passphrase=…` and Strom is started with
`STROM_SRT_RELAY=<relay host>:9000`. Strom reads the public address from the
relay's API and shows the outside party where to connect. The GUI has a
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
  Keep the HTTP API off the public network.

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
