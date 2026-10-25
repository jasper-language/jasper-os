#!/usr/bin/env bash
# Author: chatgpt. Host entry point: VM builds; generic ARM runs userspace tests.
# No boot, flash, root, reboot, account or system-setting changes.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo"
vmrun=/home/auth/Documents/jasper/jasper-os-build/vm-run.sh
serial=${PDA_SERIAL:-dbaccec1}
label=${1:-arm-core-$(date -u +%Y%m%dT%H%M%SZ)}
[[ "$label" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]]
[[ ${#label} -le 80 ]]
out="evidence/krn2/$label"
adb -s "$serial" get-state >/dev/null
mkdir -p evidence/krn2
mkdir "$out"
VM_KEEP_AWAKE=0 VM_NICE=15 "$vmrun" "$repo" env CARGO_BUILD_JOBS=1 PDA_OUT="$out" bash tools/krn2/arm-tests-build.sh
remote="/data/local/tmp/jasper-$label"
adb -s "$serial" shell "mkdir $remote"
{ adb -s "$serial" shell uname -m; adb -s "$serial" shell getprop ro.product.cpu.abi; } > "$out/device.txt"
mkdir "$out/results"
for binary in "$out"/bin/*; do
  name="$(basename "$binary")"
  adb -s "$serial" push "$binary" "$remote/$name" >/dev/null
  adb -s "$serial" shell "chmod 700 $remote/$name"
  for round in 1 2 3; do
    set +e
    adb -s "$serial" shell "$remote/$name --test-threads=8" > "$out/results/$name-$round.log" 2>&1
    result=$?
    set -e
    printf '%s\n' "$result" > "$out/results/$name-$round.exit"
    [[ "$result" == 0 ]]
    grep -aEq 'test result: ok\. [1-9][0-9]* passed; 0 failed;' "$out/results/$name-$round.log"
  done
done
(cd "$repo"; sha256sum -c "$out/source-before.sha256") > "$out/source-after-run-check.log"
sha256sum -c "$out/binaries.sha256" > "$out/binaries-after-run-check.log"
printf 'ARM userspace mechanisms passed three rounds each; no native Jasper boot or performance claim\n'
