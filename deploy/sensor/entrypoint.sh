#!/bin/sh
# Tarsier sensor entrypoint.
#
# Everything is built in. The host needs no Suricata, no Python, no packages —
# only Docker and a network interface receiving mirrored traffic.
#
# Two jobs beyond starting Suricata:
#   1. pick a capture interface without the user having to know one
#   2. guarantee the sensor can never fill its own disk
set -eu

LOG_DIR=/var/log/suricata
RUN_DIR=/var/run/suricata
mkdir -p "$LOG_DIR" "$RUN_DIR"

# --- capture interface ------------------------------------------------------
# If the user did not name one, choose the interface carrying traffic. A mirror
# port often has no IP address at all, so "the one with a default route" is the
# wrong heuristic here — prefer an interface that is up and not loopback.
if [ -z "${TARSIER_INTERFACE:-}" ]; then
    TARSIER_INTERFACE=$(
        ip -o link show up 2>/dev/null \
        | awk -F': ' '$2 != "lo" && $2 !~ /^(docker|veth|br-)/ {print $2; exit}'
    )
fi
if [ -z "${TARSIER_INTERFACE:-}" ]; then
    echo "tarsier-sensor: no capture interface found." >&2
    echo "  Set TARSIER_INTERFACE=<name> and run with --net=host." >&2
    exit 1
fi
export TARSIER_INTERFACE
echo "tarsier-sensor: capturing on ${TARSIER_INTERFACE}"

# Promiscuous mode is required to see mirrored traffic addressed to other hosts.
ip link set "$TARSIER_INTERFACE" promisc on 2>/dev/null || \
    echo "tarsier-sensor: could not enable promiscuous mode (need --cap-add=NET_ADMIN)" >&2

# Offloading hides the true packet boundaries from the capture engine, which
# corrupts protocol parsing. Disable it where we are permitted to.
for feature in gro lro tso gso; do
    ethtool -K "$TARSIER_INTERFACE" "$feature" off >/dev/null 2>&1 || true
done

# --- disk guard -------------------------------------------------------------
# A sensor that fills its own disk stops capturing and, on a shared host, can
# take other things down with it. Suricata rotates hourly; this reaps what
# rotation leaves behind and hard-stops growth if shipping falls behind.
#
# Deleting the oldest data is the correct failure mode: recent events matter
# more than old ones, and the alternative is losing everything.
MAX_LOG_MB="${TARSIER_MAX_LOG_MB:-2048}"
RETAIN_DAYS="${TARSIER_RETAIN_DAYS:-7}"
echo "tarsier-sensor: keeping ${RETAIN_DAYS} days of logs, capped at ${MAX_LOG_MB}MB"

disk_guard() {
    while true; do
        sleep 60

        # Compress rotated files first. EVE is highly repetitive JSON and gzips
        # around 10:1, so this is the cheapest possible answer to "the files got
        # to 5 GB" — it turns a week of logs into roughly a day's worth of disk.
        # Never touch the file Suricata currently holds open.
        for f in "$LOG_DIR"/eve.json.*; do
            case "$f" in
                *.gz|*'*') continue ;;
            esac
            [ -f "$f" ] && gzip -q "$f" 2>/dev/null || true
        done

        # Age next. Seven days is the default because the agent has long since
        # shipped these events onward — the local file is a replay buffer for
        # outages, not an archive. The server holds the real history.
        if [ "$RETAIN_DAYS" -gt 0 ]; then
            find "$LOG_DIR" -name 'eve.json.*' -type f -mtime "+${RETAIN_DAYS}" \
                -exec rm -f {} \; 2>/dev/null || true
        fi

        # Then size, as the hard backstop. A week of traffic on a busy link can
        # exceed the cap well before it ages out, and a full disk stops capture
        # entirely — so the cap wins over the retention period.
        used=$(du -sm "$LOG_DIR" 2>/dev/null | cut -f1)
        [ -z "$used" ] && continue
        if [ "$used" -gt "$MAX_LOG_MB" ]; then
            echo "tarsier-sensor: ${used}MB exceeds ${MAX_LOG_MB}MB cap, reaping oldest" >&2
            # Never touch the file Suricata is currently writing.
            ls -1t "$LOG_DIR"/eve.json.* 2>/dev/null | tail -n +2 | while read -r f; do
                rm -f "$f"
                used=$(du -sm "$LOG_DIR" 2>/dev/null | cut -f1)
                [ "$used" -le "$MAX_LOG_MB" ] && break
            done
        fi
    done
}
disk_guard &

# --- rules (optional) -------------------------------------------------------
# Tarsier produces a full inventory with no ruleset at all. Threat detection
# is a bonus, so a failed rule download must never stop the sensor.
if [ "${TARSIER_ENABLE_RULES:-yes}" = "yes" ]; then
    if [ ! -f /var/lib/suricata/rules/suricata.rules ]; then
        echo "tarsier-sensor: fetching ruleset (optional)"
        suricata-update --no-test 2>&1 | tail -3 || \
            echo "tarsier-sensor: ruleset unavailable — continuing without it" >&2
    fi
fi
mkdir -p /var/lib/suricata/rules
touch /var/lib/suricata/rules/suricata.rules

# --- validate before starting ----------------------------------------------
# Fail loudly here rather than half-starting with a broken config.
if ! suricata -T -c /etc/suricata/suricata.yaml -v 2>&1 | tail -5; then
    echo "tarsier-sensor: configuration failed validation" >&2
    exit 1
fi

# --- agent ------------------------------------------------------------------
# Started before Suricata so no events are missed at the head of the file.
if [ -n "${TARSIER_SERVER:-}" ] && [ -n "${TARSIER_TOKEN:-}" ]; then
    echo "tarsier-sensor: enrolling with ${TARSIER_SERVER}"
    /usr/local/bin/tarsier-agent enroll \
        --server "$TARSIER_SERVER" --token "$TARSIER_TOKEN" || \
        echo "tarsier-sensor: enrolment failed — will retry" >&2
    /usr/local/bin/tarsier-agent run --eve "$LOG_DIR/eve.json" &
else
    echo "tarsier-sensor: no server configured — running standalone."
    echo "tarsier-sensor: inspect locally with: tarsier-scan $LOG_DIR/eve.json"
fi

exec suricata -c /etc/suricata/suricata.yaml --af-packet="$TARSIER_INTERFACE" \
    --set logging.outputs.0.console.enabled=yes
