#!/usr/bin/env bash
# Verify a stock Pixel boot image and its AVB signature without flashing.
# 只读验证 stock Pixel 启动镜像与 AVB 签名，不进行刷写。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="$HOME/.cargo/bin:$PATH"

IMAGE="${PIXEL6A_BOOT_IMAGE:?set PIXEL6A_BOOT_IMAGE to the matching stock boot.img}"
OUT="${PIXEL6A_AVB_OUT:-$ROOT/evidence/pixel6a-avb-$(date '+%Y%m%d-%H%M%S')}"
mkdir -p "$OUT"

run_example() {
  local image=$1
  local partition=$2
  env -u CARGO_TARGET_DIR \
    cargo run --locked --quiet -p jasper-lifecycle-model \
    --example avb_verify -- "$image" "$partition"
}

run_example "$IMAGE" boot >"$OUT/positive.log" 2>&1
grep -q '^avb-verify: PASS partition=boot version=4 ' "$OUT/positive.log"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/jasper-avb.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
cp --reflink=auto "$IMAGE" "$tmp/tampered.img"
python3 - "$tmp/tampered.img" <<'PY'
from pathlib import Path
import struct
import sys

path = Path(sys.argv[1])
data = bytearray(path.read_bytes())
original_size, meta_offset, _ = struct.unpack_from(">QQQ", data, len(data) - 44)
kernel_size = struct.unpack_from("<I", data, 8)[0]
if original_size <= 4096 or kernel_size == 0 or meta_offset >= len(data):
    raise SystemExit("invalid stock boot image layout")
data[4096 + kernel_size // 2] ^= 1
path.write_bytes(data)
PY
if run_example "$tmp/tampered.img" boot >"$OUT/tampered.log" 2>&1; then
  echo "pixel6a-avb: tampered payload was accepted" >&2
  exit 1
fi
grep -q 'protected content hash does not match' "$OUT/tampered.log"
if run_example "$IMAGE" vendor_boot >"$OUT/wrong-partition.log" 2>&1; then
  echo "pixel6a-avb: wrong partition was accepted" >&2
  exit 1
fi
grep -q 'partition descriptor is missing' "$OUT/wrong-partition.log"

cp --reflink=auto "$IMAGE" "$tmp/bad-signature.img"
python3 - "$tmp/bad-signature.img" <<'PY'
from pathlib import Path
import struct
import sys

path = Path(sys.argv[1])
data = bytearray(path.read_bytes())
_, _, _, _, meta_offset, _, _ = struct.unpack_from(">4sIIQQQ28s", data, len(data) - 64)
if data[meta_offset : meta_offset + 4] != b"AVB0":
    raise SystemExit("invalid embedded AVB metadata")
authentication_size = struct.unpack_from(">Q", data, meta_offset + 12)[0]
signature_offset = struct.unpack_from(">Q", data, meta_offset + 48)[0]
signature_size = struct.unpack_from(">Q", data, meta_offset + 56)[0]
if authentication_size == 0 or signature_size == 0:
    raise SystemExit("stock AVB metadata is not signed")
position = meta_offset + 256 + signature_offset
if signature_offset + signature_size > authentication_size:
    raise SystemExit("AVB signature range is invalid")
data[position] ^= 1
path.write_bytes(data)
PY
if run_example "$tmp/bad-signature.img" boot >"$OUT/bad-signature.log" 2>&1; then
  echo "pixel6a-avb: tampered signature was accepted" >&2
  exit 1
fi
grep -q 'RSA signature is invalid' "$OUT/bad-signature.log"

sha256sum "$IMAGE" >"$OUT/input.sha256"
echo "pixel6a-avb: PASS signature=true content=true tamper_rejected=true signature_rejected=true partition_bound=true evidence=$OUT"
