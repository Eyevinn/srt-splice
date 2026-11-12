# Deployment

## The two ports

- **9000/udp: SRT.** This is the one port to expose publicly.
- **9001/tcp: health.** `GET /healthz` returns `ok`, for orchestrator
  probes. Internal network only; nothing else uses it.

The relay does not know its public address (for example the load
balancer's DNS name and port), and nothing asks it: configure the services
that hand out the address, such as Strom, with it directly.

The image runs a static binary on an empty base, as user `nobody`. It sets
`SRT_SPLICE_LISTEN=0.0.0.0:9000` and `SRT_SPLICE_HEALTH=0.0.0.0:9001`.

## Kubernetes

[examples/kubernetes/srt-splice.yaml](../examples/kubernetes/srt-splice.yaml)
has a Deployment, a public `LoadBalancer` Service for 9000/udp, and an
internal `ClusterIP` Service for the SRT port. The health port is only on
the container, for the readiness probe.

- **One replica per relay.** The two callers of a session are paired inside
  one process. If they reached different pods they would never meet.
- **`externalTrafficPolicy: Local`.** The relay tells the legs of a session
  apart by their UDP source address, so it must see the real client
  addresses. With the default policy, nodes may SNAT incoming packets. Check
  your cloud provider's documentation for UDP load balancers.
- **Readiness:** `GET /healthz` on the health port.
- **Strom in the same cluster:** `STROM_SRT_RELAY=<public host:port>` (the
  load balancer's address, shown to the outside party) and
  `STROM_SRT_RELAY_INTERNAL=srt-splice-internal:9000` (what Strom dials,
  avoiding hairpin NAT). With a relay elsewhere, for example a managed
  service, only `STROM_SRT_RELAY=<public host:port>` is needed.

**Scaling out:** run several relays, each with its own public address, and
have the service that hands out addresses (for example Strom) choose one per
session. A load balancer cannot route on the streamid: it is inside the SRT
handshake, not in the UDP header.

## Docker Compose

[examples/docker-compose.yml](../examples/docker-compose.yml) runs the relay
with the health endpoint bound to loopback on the host.

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
