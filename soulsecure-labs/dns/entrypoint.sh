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

mkdir -p /etc/coredns
ZONE=/etc/coredns/soulsecure.lab.zone

sed "s/__ANSWER_IP__/$LAB_IP/g" /opt/dns-src/zone-lab1.tmpl > "$ZONE"

if [ "$M2_LEVEL" -ge 2 ]; then
    sed "s/__ANSWER_IP__/$LAB_IP/g" /opt/dns-src/zone-lab2.tmpl >> "$ZONE"
fi

cp /opt/dns-src/Corefile.tmpl /etc/coredns/Corefile

echo "soulsecure-dns (coredns): LAB_MODULE=$LAB_MODULE LAB_LEVEL=$LAB_LEVEL LAB_IP=$LAB_IP"
cat "$ZONE"

exec coredns -conf /etc/coredns/Corefile
