#!/usr/bin/env bash
# Install a minimal root profile marker into one P0 System A/B ext4 partition.
# 向 P0 System A/B 的一个 ext4 槽写入最小根系统标识，供真实健康门挂载校验。
set -euo pipefail

IMAGE="${1:?p0 image}"
WORK="${2:?work directory}"
START_LBA="${3:?system partition LBA}"
SLOT="${4:?A or B}"
RELEASE="${5:?release}"
[[ "$SLOT" == A || "$SLOT" == B ]]
[[ "$RELEASE" =~ ^[1-9][0-9]*$ ]]
mkdir -p "$WORK"

PARTITION="$WORK/system-$SLOT.img"
MARKER="$WORK/system-$SLOT.jasper-root"
dd if="$IMAGE" of="$PARTITION" bs=512 skip="$START_LBA" count=16777216 \
  conv=sparse status=none
printf 'slot=%s\nrelease=%s\nschema=1\n' "$SLOT" "$RELEASE" >"$MARKER"
debugfs -w -R 'mkdir /etc' "$PARTITION"
debugfs -w -R "write $MARKER /etc/jasper-root" "$PARTITION"
e2fsck -fy "$PARTITION"
e2fsck -fn "$PARTITION"
dd if="$PARTITION" of="$IMAGE" bs=512 seek="$START_LBA" \
  conv=notrunc,sparse status=none
sync
echo "system-root-fixture: PASS slot=$SLOT release=$RELEASE start_lba=$START_LBA"
