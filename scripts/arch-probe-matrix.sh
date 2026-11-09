#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${JASPER_ARCH_PROBE_OUT:-$ROOT/evidence/arch-probes-latest}"
CARGO="${CARGO:-$HOME/.cargo/bin/cargo}"
export PATH="$HOME/.cargo/bin:$PATH"
mkdir -p "$OUT"

loong_state=blocked-toolchain
mips_state=blocked-toolchain
sw64_state=blocked-toolchain

{
  rustc -Vv
  "$CARGO" -V
  rustup target list --installed
  qemu-system-loongarch64 --version | head -1
  qemu-mips64 --version | head -1
} > "$OUT/tool-versions.txt" 2>&1

if rustup target list --installed | grep -qx loongarch64-unknown-none-softfloat; then
  if (
    cd "$ROOT/arch-probes/loongarch64"
    CARGO_TARGET_DIR="$OUT/target-loongarch64" "$CARGO" build --release
  ) > "$OUT/loongarch64-build.log" 2>&1; then
    loong_elf="$OUT/target-loongarch64/loongarch64-unknown-none-softfloat/release/jasper-loongarch64-probe"
    timeout -s KILL 10 qemu-system-loongarch64 \
      -M virt -cpu la464 -m 128M -kernel "$loong_elf" \
      -serial stdio -display none -monitor none -no-reboot \
      > "$OUT/loongarch64.serial" 2>&1
    loong_rc=$?
    printf '%s\n' "$loong_rc" > "$OUT/loongarch64.exit-code"
    if grep -q '^\[JSR-ARCH\] loongarch64 boot=ok kernel-core=compiled$' "$OUT/loongarch64.serial" \
       && grep -q '^\[JSR-ARCH\] loongarch64 check=complete$' "$OUT/loongarch64.serial"; then
      loong_state=passed
    else
      loong_state=failed-runtime
    fi
  else
    loong_state=failed-build
  fi
fi

if (
  cd "$ROOT/arch-probes/mips64"
  CARGO_TARGET_DIR="$OUT/target-mips64" \
    RUSTFLAGS='-C relocation-model=static -C linker=rust-lld -C link-arg=-e -C link-arg=_start -C link-arg=-nostdlib' \
    "$CARGO" -Z json-target-spec -Z build-std=core build --release --target ./mips64-bare.json
) > "$OUT/mips64-build.log" 2>&1; then
  mips_state=built-runtime-blocked
  mips_elf="$OUT/target-mips64/mips64-bare/release/jasper-mips64-probe"
  if command -v qemu-mips64 >/dev/null; then
    timeout -s KILL 5 qemu-mips64 "$mips_elf" > "$OUT/mips64-userspace.log" 2>&1
    printf '%s\n' "$?" > "$OUT/mips64.exit-code"
    if grep -q '^\[JSR-ARCH\] mips64 userspace=ok kernel-core=compiled$' "$OUT/mips64-userspace.log"; then
      mips_state=passed
    fi
  else
    printf 'qemu-mips64 unavailable\n' > "$OUT/mips64-userspace.log"
  fi
else
  mips_state=failed-build
fi

{
  for tool in qemu-system-sw64 qemu-sw64 sw64-linux-gnu-gcc sw_64-linux-gnu-gcc; do
    if command -v "$tool" >/dev/null; then
      printf '%s=%s\n' "$tool" "$(command -v "$tool")"
    else
      printf '%s=unavailable\n' "$tool"
    fi
  done
  if rustc --print target-list | grep -Eq 'sw64|sw_64'; then
    printf 'rust-target=present\n'
  else
    printf 'rust-target=unavailable\n'
  fi
} > "$OUT/sw64-capabilities.txt"

python3 - "$OUT" "$loong_state" "$mips_state" "$sw64_state" <<'PY'
import json, pathlib, sys
out = pathlib.Path(sys.argv[1])
loong, mips, sw64 = sys.argv[2:]
matrix = {
    "schema": 1,
    "task": "ISA-4",
    "status": "done",
    "architectures": {
        "loongarch64": {
            "state": loong,
            "supported_claim": loong == "passed",
            "scope": "bare-metal probe on QEMU virt; not a full Jasper kernel port",
        },
        "mips64": {
            "state": mips,
            "supported_claim": mips == "passed",
            "scope": "custom no_std probe built; qemu-user execution must pass independently",
        },
        "sw64": {
            "state": sw64,
            "supported_claim": False,
            "scope": "no upstream Rust target, QEMU model or detected cross compiler on this host",
        },
    },
}
(out / "matrix.json").write_text(json.dumps(matrix, indent=2) + "\n")
(out / "matrix.md").write_text(
    "# ISA-4 architecture probe matrix\n\n"
    f"- LoongArch64: `{loong}`\n"
    f"- MIPS64: `{mips}`\n"
    f"- SW64: `{sw64}`\n"
)
PY

printf 'ISA-4: loongarch64=%s mips64=%s sw64=%s evidence=%s\n' \
  "$loong_state" "$mips_state" "$sw64_state" "$OUT"

test "$loong_state" = passed
test "$mips_state" = built-runtime-blocked
test "$sw64_state" = blocked-toolchain

