#!/bin/bash
# =============================================================================
# abi-freeze.sh —— 把登记表中尚未冻结的接口追加进 abi/system-ids.lock（发布前运行）
#
# 只追加、不修改：已在锁文件中的条目原样保留；构建期 build.rs 会检查登记表没有删除或改动它们。
# 用法：bash scripts/abi-freeze.sh        （打印新冻结的条目）
# =============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REG="$ROOT/abi/system-ids.txt"; LOCK="$ROOT/abi/system-ids.lock"; VER="$ROOT/abi/abi-version.txt"
# ABI-R read-only shape gate; never append IDs in this mode.
if [[ "${1:-}" == --check-reservations ]]; then
  python3 "$ROOT/verification/check-abi-reservations.py"
  exit
fi
value() { awk -F= -v key="$1" '$1 ~ ("^[[:space:]]*" key "[[:space:]]*$") {gsub(/[[:space:]]/, "", $2); print $2}' "$VER"; }
NATIVE_MAJOR="$(value major)"; NATIVE_MINOR="$(value minor)"; NATIVE_PATCH="$(value patch)"
[[ "$NATIVE_MAJOR" =~ ^[0-9]+$ && "$NATIVE_MINOR" =~ ^[0-9]+$ && "$NATIVE_PATCH" =~ ^[0-9]+$ ]] \
  || { echo "✗ abi/abi-version.txt 不合法"; exit 1; }
read -r LOCK_MAJOR LOCK_MINOR LOCK_PATCH <<<"$(awk '/^# abi-generation:/{print $3; exit}' "$LOCK" | awk -F. '{print $1, $2, $3}')" || true
if [[ -z "${LOCK_MAJOR:-}" ]]; then
  echo "✗ abi/system-ids.lock 缺少 '# abi-generation: Major.Minor.Patch' 头"; exit 1
fi
if [[ ! "$LOCK_MAJOR" =~ ^[0-9]+$ || ! "${LOCK_MINOR:-}" =~ ^[0-9]+$ || ! "${LOCK_PATCH:-}" =~ ^[0-9]+$ ]]; then
  echo "✗ abi/system-ids.lock 的世代头不是 Major.Minor.Patch：$LOCK_MAJOR.${LOCK_MINOR:-?}.${LOCK_PATCH:-?}"; exit 1
fi
if [[ "$LOCK_MAJOR" != "$NATIVE_MAJOR" ]]; then
  echo "✗ ABI 主版本换代：锁文件是 $LOCK_MAJOR，原生是 $NATIVE_MAJOR"
  echo "  跨主版本必须随新内核生成新快照：归档旧锁、把锁头改为 $NATIVE_MAJOR.0.0，再重新冻结。"
  exit 1
fi
if (( NATIVE_MINOR < LOCK_MINOR || (NATIVE_MINOR == LOCK_MINOR && NATIVE_PATCH < LOCK_PATCH) )); then
  echo "✗ 原生 ABI $NATIVE_MAJOR.$NATIVE_MINOR.$NATIVE_PATCH 低于锁文件的 $LOCK_MAJOR.$LOCK_MINOR.$LOCK_PATCH（同主版本内不得回退）"
  exit 1
fi
added=0
# 新条目仍按发布顺序追加；锁头保留它首次冻结时的世代。
while IFS= read -r line; do
  case "$line" in ''|\#*) continue;; esac
  id="$(printf '%s' "$line" | awk '{print $1}')"
  if ! grep -v '^#' "$LOCK" | awk '{print $1}' | grep -qx "$id"; then
    printf '%s\n' "$line" >> "$LOCK"; echo "  冻结：$line"; added=$((added+1))
  fi
done < "$REG"
echo "新冻结 $added 条"
