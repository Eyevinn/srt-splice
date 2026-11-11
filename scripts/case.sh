#!/usr/bin/env bash
# One end-to-end case through a running relay:
#   receiver (libsrt caller) waits on the relay, then a sender (libsrt caller,
#   or the Rust srt-protocol caller with SENDER=rust) joins with the same
#   streamid. A measuring tool (SPIKE) generates a test stream and measures
#   loss, duplicates and latency at the receiver.
#
# Needs: srt-live-transmit (libsrt) on PATH, and SPIKE: an external measuring
# tool with the subcommands `gen --duration-s N` (write a test stream to
# stdout), `measure --quiet` (read it on stdin and print loss/latency) and,
# for SENDER=rust, `send SRT_URI --duration-s N`. It is not part of this repo.
#
# usage: scripts/case.sh NAME "SENDER_QUERY" "RECEIVER_QUERY" [SECONDS]
# env:   SPIKE=/path/to/measuring-tool (or `srt-spike` on PATH)
#        RELAY=127.0.0.1:9000  SID=<name>  SENDER=libsrt|rust
#        SEND_VIA=host:port (e.g. a loss/delay proxy in front of the relay)
#        GAP=1 (seconds between receiver and sender start)
#        SND_SID / RCV_SID: per-side streamid (URL-encoded), default SID
set -u
NAME=$1; SQ=$2; RQ=$3; SECS=${4:-8}
RELAY=${RELAY:-127.0.0.1:9000}
SEND_VIA=${SEND_VIA:-$RELAY}
SID=${SID:-$NAME}
SPIKE=$(command -v "${SPIKE:-srt-spike}" || true)
if [ -z "$SPIKE" ]; then
  echo "error: set SPIKE to the measuring tool (see the header of $0)" >&2
  exit 2
fi
command -v srt-live-transmit >/dev/null || { echo "error: srt-live-transmit not on PATH" >&2; exit 2; }
OUT=${OUT:-${TMPDIR:-/tmp}/srt-cases}
mkdir -p "$OUT"
amp() { [ -n "$1" ] && echo "&$1"; }

echo "=== $NAME"
srt-live-transmit -a:no -t:$((SECS + 6)) -ll:error \
  "srt://$RELAY?streamid=${RCV_SID:-$SID}&conntimeo=10000$(amp "$RQ")" file://con 2>"$OUT/$NAME.rcv.log" \
  | "$SPIKE" measure --quiet >"$OUT/$NAME.measure" &
RCV=$!
sleep "${GAP:-1}"
if [ "${SENDER:-libsrt}" = rust ]; then
  "$SPIKE" send "srt://$SEND_VIA?streamid=${SND_SID:-$SID}$(amp "$SQ")" --duration-s "$SECS" >"$OUT/$NAME.snd.log" 2>&1
else
  "$SPIKE" gen --duration-s "$SECS" \
    | srt-live-transmit -a:no -ll:error file://con "srt://$SEND_VIA?streamid=${SND_SID:-$SID}&conntimeo=10000$(amp "$SQ")" \
      2>"$OUT/$NAME.snd.log"
fi
wait $RCV
cat "$OUT/$NAME.measure"
grep -hiE "error|reject|fail|decrypt" "$OUT/$NAME.rcv.log" "$OUT/$NAME.snd.log" | sort | uniq -c | head -5
