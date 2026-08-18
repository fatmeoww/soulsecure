#!/usr/bin/env bash
# Detect the right LAB_IP for this host and write /opt/soulsecure-labs/.env,
# which docker-compose reads automatically. All services (including dns/
# CoreDNS) bind 0.0.0.0 -- this only matters for what DNS *answers* point at.
#
# NOTE: this requires systemd-resolved to be disabled on the host (it binds
# 127.0.0.53:53, which blocks Docker's wildcard 0.0.0.0:53 publish for the
# dns container at the kernel level). See InstructorKey for the one-time
# setup command. CoreDNS was chosen specifically because, unlike dnsmasq, it
# has no additional "refuse non-local-subnet queries" default to work around.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$DIR/.env"
OVERRIDE_FILE="$DIR/lab.override"

if [ -f "$OVERRIDE_FILE" ]; then
    LAB_IP="$(tr -d '[:space:]' < "$OVERRIDE_FILE")"
else
    TOKEN="$(curl -s -m 1 -X PUT "http://169.254.169.254/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null || true)"
    if [ -n "$TOKEN" ]; then
        LAB_IP="$(curl -s -m 1 -H "X-aws-ec2-metadata-token: $TOKEN" \
            http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || true)"
    fi
    if [ -z "${LAB_IP:-}" ]; then
        LAB_IP="$(hostname -I | awk '{print $1}')"
    fi
fi

LAB_CIDR="$(echo "$LAB_IP" | awk -F. '{print $1"."$2"."$3".0/24"}')"

cat > "$ENV_FILE" <<EOF
LAB_IP=$LAB_IP
LAB_CIDR=$LAB_CIDR
EOF

echo "detect-ip: LAB_IP=$LAB_IP LAB_CIDR=$LAB_CIDR"
