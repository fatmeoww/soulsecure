#!/bin/sh
set -e
LAB_MODULE="${LAB_MODULE:-2}"
LAB_LEVEL="${LAB_LEVEL:-5}"
LAB_IP="${LAB_IP:?LAB_IP env var is required}"

# Same "same tenant, doesn't reset" rule as nginx's entrypoint -- once
# LAB_MODULE moves past 2, Module 2's DNS zone content stays fully unlocked.
if [ "$LAB_MODULE" -gt 2 ]; then
    M2_LEVEL=5
else
    M2_LEVEL="$LAB_LEVEL"
fi

# Same M{N}_LEVEL pattern as nginx/entrypoint.sh -- kept in sync with that
# file's SAN-list gating (M4_LEVEL>=1 -> iam, M5_LEVEL>=2 -> bastion,
# M6_LEVEL>=1 -> module6). Bug found 2026-08-13: this file only ever
# tracked Module 2's zone content -- iam.soulsecure.lab, bastion.soulsecure.lab,
# and module6.soulsecure.lab all had live nginx vhosts + TLS SAN entries but
# NO DNS A record at all, so a student who set up DNS the normal way (per
# every module's own "ตั้งค่า DNS" setup step) got a hard
# "Could not resolve host" the moment they reached Module 4 -- the vhost was
# only ever reachable via `curl --resolve`, silently, which nothing told
# students to expect for these specific hostnames (unlike Module 2 Lab 2/5's
# *intentionally* DNS-less vhosts, which are a deliberate "found via vhost
# brute force" teaching point -- these three are not that, they're meant to
# resolve normally like any Module 3 hostname does).
if [ "$LAB_MODULE" -gt 4 ]; then
    M4_LEVEL=5
elif [ "$LAB_MODULE" -eq 4 ]; then
    M4_LEVEL="$LAB_LEVEL"
else
    M4_LEVEL=0
fi

if [ "$LAB_MODULE" -gt 5 ]; then
    M5_LEVEL=5
elif [ "$LAB_MODULE" -eq 5 ]; then
    M5_LEVEL="$LAB_LEVEL"
else
    M5_LEVEL=0
fi

if [ "$LAB_MODULE" -gt 6 ]; then
    M6_LEVEL=5
elif [ "$LAB_MODULE" -eq 6 ]; then
    M6_LEVEL="$LAB_LEVEL"
else
    M6_LEVEL=0
fi

mkdir -p /etc/coredns
ZONE=/etc/coredns/soulsecure.lab.zone

sed "s/__ANSWER_IP__/$LAB_IP/g" /opt/dns-src/zone-lab1.tmpl > "$ZONE"

if [ "$M2_LEVEL" -ge 2 ]; then
    sed "s/__ANSWER_IP__/$LAB_IP/g" /opt/dns-src/zone-lab2.tmpl >> "$ZONE"
fi

if [ "$M4_LEVEL" -ge 1 ]; then
    echo "iam     IN A    $LAB_IP" >> "$ZONE"
fi
if [ "$M5_LEVEL" -ge 2 ]; then
    echo "bastion IN A    $LAB_IP" >> "$ZONE"
fi
if [ "$M6_LEVEL" -ge 1 ]; then
    echo "module6 IN A    $LAB_IP" >> "$ZONE"
fi

cp /opt/dns-src/Corefile.tmpl /etc/coredns/Corefile

echo "soulsecure-dns (coredns): LAB_MODULE=$LAB_MODULE LAB_LEVEL=$LAB_LEVEL LAB_IP=$LAB_IP (M4=$M4_LEVEL M5=$M5_LEVEL M6=$M6_LEVEL)"
cat "$ZONE"

exec coredns -conf /etc/coredns/Corefile
