#!/bin/bash
# check-remediation.sh -- run against your edited network.tf
set -euo pipefail
FILE="${1:-network.tf}"
if [ ! -f "$FILE" ]; then
  echo "usage: ./check-remediation.sh [path/to/network.tf]"
  exit 2
fi
if grep -q '0.0.0.0/0' "$FILE"; then
  echo "Still open to the world -- not remediated."
  exit 1
fi
if ! grep -q 'cidr_blocks' "$FILE"; then
  echo "Rule removed entirely rather than scoped -- not a real fix."
  exit 1
fi
echo "Remediated correctly. flag{8151a3e59ed6cc9709a8f5c910b51ec3}"
