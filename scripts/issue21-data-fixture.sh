#!/usr/bin/env bash
# Install or verify a real payload in the shared P0 Data ext4 partition.
# 在 P0 共享 Data ext4 分区安装或核验真实用户载荷。
set -euo pipefail

MODE="${1:?install or verify}"
IMAGE="${2:?p0 image}"
WORK="${3:?work directory}"
TOTAL="${4:?total image bytes}"
DATA_START_LBA=39061504
TOTAL_SECTORS=$((TOTAL / 512))
DATA_SECTORS=$((TOTAL_SECTORS - DATA_START_LBA))
mkdir -p "$WORK"

PARTITION="$WORK/data-partition.img"
PAYLOAD="$WORK/data-payload.bin"
EXTRACTED="$WORK/data-payload-verified.bin"

case "$MODE" in
  install)
    dd if="$IMAGE" of="$PARTITION" bs=512 skip="$DATA_START_LBA" \
      count="$DATA_SECTORS" conv=sparse status=none
    head -c 65536 /dev/urandom >"$PAYLOAD"
    debugfs -w -R 'mkdir /user-data' "$PARTITION"
    debugfs -w -R "write $PAYLOAD /user-data/preserved.bin" "$PARTITION"
    e2fsck -fy "$PARTITION"
    e2fsck -fn "$PARTITION"
    dd if="$PARTITION" of="$IMAGE" bs=512 seek="$DATA_START_LBA" \
      conv=notrunc,sparse status=none
    sync
    sha256sum "$PAYLOAD" | awk '{print $1}' >"$WORK/data-payload.sha256"
    echo "data-fixture: installed bytes=$(stat -c %s "$PAYLOAD") sha256=$(cat "$WORK/data-payload.sha256")"
    ;;
  verify)
    dd if="$IMAGE" of="$PARTITION" bs=512 skip="$DATA_START_LBA" \
      count="$DATA_SECTORS" conv=sparse status=none
    e2fsck -fn "$PARTITION"
    rm -f -- "$EXTRACTED"
    debugfs -R "dump /user-data/preserved.bin $EXTRACTED" "$PARTITION"
    cmp "$PAYLOAD" "$EXTRACTED"
    sha256sum "$EXTRACTED" | awk '{print $1}' >"$WORK/data-verified.sha256"
    cmp "$WORK/data-payload.sha256" "$WORK/data-verified.sha256"
    echo "data-fixture: verified bytes=$(stat -c %s "$EXTRACTED") sha256=$(cat "$WORK/data-verified.sha256")"
    ;;
  *)
    echo "data-fixture: unknown mode $MODE" >&2
    exit 2
    ;;
esac
