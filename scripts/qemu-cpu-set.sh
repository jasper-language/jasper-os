#!/usr/bin/env bash
# Select a non-desktop CPU set for local TCG runs.
#
# The development host reserves 4-11 for Jasper guests. CI runners with a
# smaller cpuset fall back explicitly instead of failing taskset or sharing the
# first cores with the desktop/runner.
set -eu

preferred="${JASPER_QEMU_PREFERRED_CPUS:-4-11}"
for candidate in "$preferred" 4-7 0-1; do
  if taskset -c "$candidate" true 2>/dev/null; then
    printf '%s\n' "$candidate"
    exit 0
  fi
done

allowed="$(taskset -pc "$$" | sed -n 's/^current affinity list: //p')"
[ -n "$allowed" ] || exit 69
printf '%s\n' "$allowed"
