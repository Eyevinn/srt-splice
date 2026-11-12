# Testing

## Unit tests

`cargo test` covers the wire format, the pairing rules (liveness, callers
that do not repeat their conclusion, roles, encryption compatibility,
reconnects, the libsrt 1.5.0–1.5.2 receiver guard), the fingerprints,
which side gets the key update, the streamid parsing and the HTTP API.

## Interop and end-to-end results

macOS, loopback, libsrt 1.5.6 `srt-live-transmit` and the Rust
`srt-protocol` 0.4.4 crate, unless noted.

| Case | Result |
|---|---|
| Unencrypted | ✅ 0 lost, p50 133.7 ms (133.4 ms direct, without the relay) |
| AES-128 and AES-256 (CTR) | ✅ 0 lost, keys exchanged both ways, no clear packets |
| Key refresh mid-stream (`kmrefreshrate=2000`) | ✅ in-band KMREQ/KMRSP forwarded, 0 lost |
| Latency 500 ms (sender) vs 120 ms (receiver) | ✅ both get 500, measured p50 513 ms |
| 5 % loss and 20 ms delay each way, latency 300 ms | ✅ 0 lost, 131 retransmits end to end; the same as direct through the same lossy proxy |
| Sender connects first, receiver 1.5 s later | ✅ |
| Receiver with `conntimeo=1500` and auto-reconnect, sender after 4 s | ✅ stale attempts are not paired, 0 lost |
| Wrong passphrase on one side | ✅ no data reaches the receiver; with a direction, the relay tears down after 3 s; without one, it logs a warning |
| One side encrypted, the other not | ✅ never paired; the clear caller is refused with `SRT_REJ_UNSECURE` |
| Stray clear caller on the id of an encrypted pair, before or between them | ✅ the pair meets with 0 lost; the stray neither pairs nor blocks |
| Rust `srt-protocol` sender to a libsrt receiver, clear and AES | ✅ |
| Direction with `m=request` / `m=publish`, libsrt and srt-protocol | ✅ |
| No direction, `--no-fingerprint`, srt-protocol sender to libsrt | ❌ as expected, no data: the case the fingerprint fallback covers |
| No direction, fingerprint on | ✅ |
| Two callers with the same role from one host | ✅ never paired; the newer replaces the older |
| **Strom**: ffmpeg → relay → Strom SRT input (`m=request`) → vision mixer → Strom SRT output (`m=publish`) → relay → receiver, AES-128, H.264 720p and AAC | ✅ video and sound end to end; Strom's 3 s reconnects replace their own earlier attempts |
| **Open Live** on that Strom: relay source and output with a generated id; deactivate and reactivate | ✅ media end to end, the same ids after reactivation |
| VLC 3.0.24 and ffplay (`ffmpeg-full`) pulling a relay output | ✅ |
| libsrt 1.4.0 (Ubuntu focal) and 1.4.2 (Debian bullseye), as sender and as receiver, AES and clear, with and without `m=` on the other side | ✅ 0 lost |
| libsrt 1.5.1 (Debian bookworm) as sender, AES and clear, with and without `m=` | ✅ 0 lost |
| libsrt 1.5.1 as receiver | ❌ "SEQUENCE DISCREPANCY" before the guard: 1.5.0–1.5.2 expect data from their own ISN (see [DESIGN.md](DESIGN.md#libsrt-150-to-152-as-receiver)). Now, with a direction, refused with 1406 right at pairing (about 150 ms); without one, paired with a warning |
| gosrt 0.13 sender to libsrt, clear and AES, with and without `m=request` on the other side | ✅ 0 lost (without a direction by the fingerprint, SRT 1.4.1 flags `0x3F`). Before, with `m=request`, libsrt could close on gosrt's ACKs ("incoming ack seq ... exceeds current"); the sender now gets the receiver's ISN (see [DESIGN.md](DESIGN.md#isn-and-direction)) |
| gosrt 0.13 receiver from libsrt, clear, with and without `m=publish`, gosrt waiting first or arriving second | ✅ 0 lost; waiting first, it is paired when the sender arrives (gosrt does not repeat its conclusion) |
| gosrt 0.13 to gosrt 0.13, clear, no direction | ✅ 0 lost; neither repeats its conclusion, so they pair when the second arrives |
| gosrt 0.13 receiver, AES | ❌ as expected: gosrt does not take the injected key (see [DESIGN.md](DESIGN.md#gosrt)); with a direction the relay tears down after 3 s |
| AES-GCM | ⚠️ untested: Homebrew's libsrt is built without `ENABLE_AEAD_API_PREVIEW` and silently uses CTR |

The libsrt 1.4 and 1.5.1 cases ran in Docker (colima) on macOS against the
relay on the host, with the distro packages (GnuTLS flavour on Debian) and
libsrt 1.5.7 on the other side. Their `srt-live-transmit` does not
URL-decode the streamid: pass `#!::r=…,m=…` unencoded there. gosrt ran the
same way, as its `client` example (`-from`/`-to`) from v0.13.0. libsrt 1.3.x is
not tested (no distro package).

The `max=5000 ms` latency some measurements show is an artifact of the
tools at shutdown. A direct connection without the relay shows the same.

## How the cases are run

[scripts/case.sh](../scripts/case.sh) runs one case against a running relay:
1. A libsrt receiver (`srt-live-transmit`) connects first.
2. A sender joins with the same streamid.
3. A measuring tool reports loss, duplicates and latency at the receiver.

The measuring tool is a separate program and not part of this repository: a
test stream generator, a latency meter, a Rust `srt-protocol` sender, and a
UDP proxy that drops and delays packets. Point `MEASURE_TOOL` at a
compatible binary; the header of the script describes the interface it
expects.

```sh
./target/release/srt-splice -l 127.0.0.1:9900 &
RELAY=127.0.0.1:9900 MEASURE_TOOL=/path/to/tool \
  ./scripts/case.sh aes128 "passphrase=$SRT_PASSPHRASE" "passphrase=$SRT_PASSPHRASE" 5
```

## Not tested yet

- AES-GCM.
- Bidirectional data (both sides sending).
- IPv6.
- A peer whose port changes mid-session (NAT rebinding).
- libsrt 1.3 and older, hardware encoders.
- srt-protocol as the receiver.
- Load: many sessions and high bitrates on one relay.
