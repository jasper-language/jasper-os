#!/usr/bin/env bash
# Verify that the UEFI PXE/TFTP artifacts boot without a local disk and that
# Secure Boot rejects the current unsigned bootloader instead of reaching the
# kernel. This is a protocol regression, not physical-hardware acceptance.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KERNEL="${1:?usage: uefi-pxe-qemu-check.sh <kernel-elf> [out-dir] [bootloader-efi]}"
OUT="${2:-$ROOT/evidence/uefi-pxe-qemu-$(date -u +%Y%m%dT%H%M%SZ)}"
BOOTLOADER="${3:-}"

OVMF_CODE="${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
OVMF_CODE_SECBOOT="${OVMF_CODE_SECBOOT:-/usr/share/OVMF/OVMF_CODE_4M.secboot.fd}"
OVMF_VARS="${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"
OVMF_VARS_MS="${OVMF_VARS_MS:-/usr/share/OVMF/OVMF_VARS_4M.ms.fd}"
QEMU="${QEMU:-qemu-system-x86_64}"
XTASK_BIN="${XTASK_BIN:-$ROOT/target/release/xtask}"

for command in timeout sha256sum; do
  command -v "$command" >/dev/null || {
    echo "uefi-pxe-qemu-check: missing command: $command" >&2
    exit 69
  }
done
for path in "$KERNEL" "$OVMF_CODE" "$OVMF_CODE_SECBOOT" "$OVMF_VARS" "$OVMF_VARS_MS"; do
  [ -f "$path" ] || {
    echo "uefi-pxe-qemu-check: missing file: $path" >&2
    exit 66
  }
done
if [ -n "$BOOTLOADER" ]; then
  [ -f "$BOOTLOADER" ] || {
    echo "uefi-pxe-qemu-check: missing file: $BOOTLOADER" >&2
    exit 66
  }
fi

if [ ! -x "$XTASK_BIN" ]; then
  PATH="$HOME/.cargo/bin:$PATH" cargo build --locked --release -p xtask \
    --manifest-path "$ROOT/Cargo.toml"
fi

mkdir -p "$OUT/normal" "$OUT/secureboot"
TFTP_ROOT="$OUT/tftp"
if [ -n "$BOOTLOADER" ]; then
  "$XTASK_BIN" uefi-tftp "$KERNEL" "$TFTP_ROOT" "$BOOTLOADER" >"$OUT/tftp.log"
else
  "$XTASK_BIN" uefi-tftp "$KERNEL" "$TFTP_ROOT" >"$OUT/tftp.log"
fi
cp "$TFTP_ROOT/bootloader" "$TFTP_ROOT/bootloader.efi"

run_qemu() {
  local code=$1
  local vars=$2
  local serial=$3
  local seconds=$4
  local status

  set +e
  timeout "$seconds" "$QEMU" \
    -machine q35 -cpu max -m 1024 -smp 2 \
    -drive "if=pflash,format=raw,readonly=on,file=$code" \
    -drive "if=pflash,format=raw,file=$vars" \
    -netdev "user,id=net0,tftp=$TFTP_ROOT,bootfile=bootloader.efi" \
    -device virtio-net-pci,netdev=net0 \
    -boot order=n -display none -serial "file:$serial" \
    -monitor none -no-reboot
  status=$?
  set -e
  case "$status" in
    0|124) ;;
    *)
      echo "uefi-pxe-qemu-check: QEMU failed with status $status" >&2
      exit "$status"
      ;;
  esac
}

cp "$OVMF_VARS" "$OUT/normal/OVMF_VARS.fd"
run_qemu "$OVMF_CODE" "$OUT/normal/OVMF_VARS.fd" "$OUT/normal/serial.log" 20
grep -Fq "NBP file downloaded successfully." "$OUT/normal/serial.log"
grep -Fq "INFO : UEFI bootloader started" "$OUT/normal/serial.log"
grep -Fq "[JSR-EARLY] stage=entry" "$OUT/normal/serial.log"
grep -Fq "[JSR-BOOT] jasper-os rust kernel" "$OUT/normal/serial.log"

cp "$OVMF_VARS_MS" "$OUT/secureboot/OVMF_VARS.fd"
run_qemu "$OVMF_CODE_SECBOOT" "$OUT/secureboot/OVMF_VARS.fd" \
  "$OUT/secureboot/serial.log" 15
grep -Fq "Access Denied -- rejected probably by Secure Boot" \
  "$OUT/secureboot/serial.log"
if grep -Fq "[JSR-BOOT]" "$OUT/secureboot/serial.log"; then
  echo "uefi-pxe-qemu-check: unsigned kernel unexpectedly crossed Secure Boot" >&2
  exit 1
fi

sha256sum "$TFTP_ROOT/bootloader.efi" "$KERNEL" >"$OUT/artifacts.sha256"
{
  printf '%s\n' \
    'uefi_pxe_normal_boot=true' \
    'uefi_pxe_secureboot_rejected=true' \
    'physical_hardware=false' \
    "normal_serial=$OUT/normal/serial.log" \
    "secureboot_serial=$OUT/secureboot/serial.log"
} >"$OUT/summary.txt"
printf 'UEFI PXE QEMU contract PASS: %s\n' "$OUT"
