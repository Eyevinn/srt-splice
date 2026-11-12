# Build stage: std-only Rust, no system libraries needed.
FROM rust:1-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked \
 && strip target/release/srt-splice

# Runtime stage: a static musl binary on an empty base.
FROM scratch
COPY --from=builder /src/target/release/srt-splice /srt-splice
USER 65534:65534
# 9000/udp: SRT, the public port. 9001/tcp: the health endpoint (GET /healthz)
# for orchestrator probes, internal network only.
EXPOSE 9000/udp 9001/tcp
# Defaults, overridable with -e or CLI args. The binary's own health default is
# loopback; in a container it has to listen on all interfaces to be reachable.
ENV SRT_SPLICE_LISTEN=0.0.0.0:9000 \
    SRT_SPLICE_HEALTH=0.0.0.0:9001
# The relay keeps no state worth saving and has no signal handler. As PID 1 it
# would ignore SIGTERM, so stop it with SIGKILL instead of waiting for a timeout.
STOPSIGNAL SIGKILL
ENTRYPOINT ["/srt-splice"]
