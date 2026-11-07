#!/usr/bin/env bash
# Three serial short S-4 KVM campaigns; total guest time defaults to 15 minutes.
set -euo pipefail
cd "$(dirname "$0")/.."
seconds=${S4_SECONDS_PER_RUN:-300}
for run in 1 2 3; do
  printf '[S4-HOST] run=%s seconds=%s\n' "$run" "$seconds"
  bash scripts/s4-soak.sh "$seconds"
done
