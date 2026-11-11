# Deployment

## The two ports

- **9000/udp: SRT.** This is the one port to expose publicly.
- **9001/tcp: the HTTP API.** Internal network only. It is read-only and
  holds nothing secret, but it is meant for the services next to the relay
  (such as Strom), not for the internet.

Set the public address the outside world dials with `SRT_SPLICE_PUBLIC`
(for example the load balancer's DNS name and port). The relay cannot know
it by itself. It is reported on `GET /v1/info`, so a service like Strom
reads it from there and the address is configured in one place.

The image runs a static binary on an empty base, as user `nobody`. It sets
`SRT_SPLICE_LISTEN=0.0.0.0:9000` and `SRT_SPLICE_API=0.0.0.0:9001`.

## Kubernetes

[examples/kubernetes/srt-splice.yaml](../examples/kubernetes/srt-splice.yaml)
has a Deployment, a public `LoadBalancer` Service for 9000/udp, and an
internal `ClusterIP` Service for the SRT port and the API.

- **One replica per relay.** The two callers of a session are paired inside
  one process. If they reached different pods they would never meet.
- **`externalTrafficPolicy: Local`.** The relay tells the legs of a session
  apart by their UDP source address, so it must see the real client
  addresses. With the default policy, nodes may SNAT incoming packets. Check
  your cloud provider's documentation for UDP load balancers.
- **Readiness:** `GET /healthz` on the API port.
- **Strom in the same cluster:** `STROM_SRT_RELAY=srt-splice-internal:9000`.
  Strom finds the API on port 9001 of the same host by default, and reads
  the public address from it.

**Scaling out:** run several relays, each with its own public address, and
have the service that hands out addresses (for example Strom) choose one per
session. A load balancer cannot route on the streamid: it is inside the SRT
handshake, not in the UDP header.

## Docker Compose

[examples/docker-compose.yml](../examples/docker-compose.yml) runs the relay
with the API bound to loopback on the host.

On macOS with colima or Docker Desktop, the UDP port forward to `localhost`
can stop working when the container is recreated. If callers on the Mac
cannot reach the relay, use the VM's address instead (`colima ls` shows it
with `--network-address`). It also shows the callers' real addresses in the
relay log.

## Callers

- Use long random streamids and a passphrase (see the README's Security
  section).
- The first caller waits in the SRT handshake until its peer arrives. Its
  connect timeout (3 s by default in libsrt) is how long. Encoders with
  auto-reconnect retry by themselves; otherwise raise `conntimeo`.
- Quote SRT URIs in shells: `?` and `&` are special in zsh and bash.
- Players need SRT support with `streamid`: VLC 3.0.24 works, with
  `streamid` and `passphrase` in the URI. Homebrew's plain `ffmpeg` has no
  SRT; `ffmpeg-full` does.
