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
- **`externalTrafficPolicy: Local` (recommended).** It keeps the real
  client addresses. With the default (`Cluster`) policy, nodes may SNAT
  incoming packets to a node address. That still works: each leg keeps its
  own address and port after SNAT, and that is all the relay needs to tell
  the legs apart. What you lose:
  - the logs show node addresses, not the real callers;
  - the role rule's "same host = the caller reconnecting" (see
    [DESIGN.md](DESIGN.md#pairing-rules)) sees every caller behind one SNAT
    address as one host. A second caller with the same role on a waiting
    streamid then *replaces* the first instead of being refused with 1409.
    With long random streamids that only matters if one leaks.
  - the per-network limits (handshake rate, waiting callers; see
    [DESIGN.md](DESIGN.md#abuse-protection)) apply to all callers behind
    one SNAT address together. They leave room for some 200 callers
    waiting at once per address.
  See also [Load balancer](#load-balancer).
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

## Load balancer

The load balancer (or whatever forwards the public port) must:
- **support UDP**, and keep each flow (client address and port) on the
  same backend for as long as it sends;
- **pass the packets through** (layer 4). The relay changes nothing in
  them, and needs nothing from the load balancer but the packets.

Ideally it also **preserves the client address**. A load balancer that
proxies UDP (one that re-sends each flow from its own address) still
works, for the same reason as SNAT above, with the same caveats: the logs
show the load balancer, and callers look like one host to the role rule.

**OpenStack** (for example managed Kubernetes on OpenStack, with Octavia
as the load balancer): check what your Octavia provider does. Octavia has
UDP listeners, but whether the client address reaches the pod depends on
the provider (the OVN provider forwards at layer 4 with DNAT; the amphora
provider uses LVS for UDP) and on `externalTrafficPolicy`. Check it: with
`-v`, the relay logs the address of every caller. If the load balancer does
not fit, expose the relay on a NodePort, or run it with `hostNetwork`, and
give that node a floating IP: the relay then sees the callers directly.

## MTU

A typical MPEG-TS stream over SRT sends 1316-byte payloads (7 TS packets),
which are 1360-byte IP packets with the SRT, UDP and IP headers. That fits an overlay
network with a 1450-byte MTU (VXLAN), as most Kubernetes pod networks are.
Larger payloads may not: a larger `payloadsize`, file mode, or
`srt-live-transmit`, whose default chunk is 1456 bytes (1500-byte
packets): the relay
cannot forward a packet larger than the pod's MTU (it logs
`Message too long`), or it is fragmented on the way. Set `--max-mss` (`SRT_SPLICE_MAX_MSS`), for example
to 1450 on VXLAN, to grant the callers a smaller MSS in the handshake, so
they never send larger packets (the MSS counts the whole IP packet,
like the MTU). A caller whose payload size does not fit
the granted MSS then fails visibly when it connects or sends, instead of
losing packets on the way. Valid values: 76 to 1500.

## IPv4 only

The relay listens on IPv4 (`0.0.0.0:9000` by default) and has only been
tested on IPv4. Callers that only have IPv6, for example IPv6 clients of a dual-stack cluster or load
balancer, cannot reach it. Give the Service an IPv4 address
(`ipFamilies: [IPv4]`, the default in single-stack clusters).

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
