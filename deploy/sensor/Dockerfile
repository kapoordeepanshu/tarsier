# Tarsier sensor — Suricata, configuration and agent in one image.
#
# The point of this image: a company with no Suricata, no security tooling and
# nobody to maintain it can get a full network inventory by plugging a machine
# into a mirror port and running one command. Nothing is installed on the host
# and nothing sits in the path of their traffic.

FROM ubuntu:24.04 AS build

ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends \
        golang-go ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
# Static binaries so the runtime image needs no Go and no shared libraries.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/tarsier-scan  ./cmd/tarsier-scan

# ---------------------------------------------------------------------------

FROM ubuntu:24.04

# Suricata comes from OISF's own stable repository, NOT from the distribution.
#
# This matters more than it looks. Distribution packages lag badly — Debian
# bookworm ships Suricata 6.0, which has no ARP events (8.0+) and no JA4
# (7.0.7+). Both are features this sensor's config enables and the README
# advertises, and 6.0 would reject the config outright for referencing sections
# it has never heard of. Shipping the distro package would mean promising
# capabilities the sensor could not deliver.
RUN apt-get update && apt-get install -y --no-install-recommends \
        software-properties-common gpg-agent ca-certificates \
    && add-apt-repository -y ppa:oisf/suricata-stable \
    && apt-get update && apt-get install -y --no-install-recommends \
        suricata suricata-update \
        iproute2 ethtool \
    && apt-get purge -y software-properties-common gpg-agent \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/log/suricata /var/run/suricata /var/lib/suricata/rules \
    && suricata -V

COPY --from=build /out/tarsier-scan /usr/local/bin/tarsier-scan
COPY deploy/sensor/suricata.yaml /etc/suricata/suricata.yaml
COPY deploy/sensor/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Interface to capture from. Left empty so the entrypoint can auto-detect.
ENV TARSIER_INTERFACE=""
# Hard ceiling on local log storage. The sensor deletes its oldest data rather
# than ever filling the disk it runs on.
ENV TARSIER_MAX_LOG_MB="2048"
ENV TARSIER_ENABLE_RULES="yes"

# Reports unhealthy if Suricata stops writing, which is the failure that would
# otherwise go unnoticed.
HEALTHCHECK --interval=60s --timeout=10s --start-period=90s \
    CMD test -s /var/log/suricata/eve.json || exit 1

ENTRYPOINT ["/entrypoint.sh"]
