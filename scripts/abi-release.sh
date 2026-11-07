#!/bin/bash
# =============================================================================
# abi-release.sh —— 建立一个新的 ABI 版本基线
# Create a new ABI version baseline.
#
# 1. 只修改 abi/abi-version.txt 的唯一真源；
# 2. 为这个确切版本创建不可变完整契约快照；
# 3. 校验同主版本旧快照只被扩展、Patch 升级契约完全不变；
# 4. 提示随后运行冻结与公开闸门。脚本不代替设计裁决，也不会自动合并/推送。
# =============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
version="${1:-}"
if ! [[ "$version" =~ ^([0-9]{1,5})\.([0-9]{1,5})\.([0-9]{1,5})$ ]]; then
  echo "用法：bash scripts/abi-release.sh <Major.Minor.Patch>" >&2
  exit 2
fi
IFS=. read -r new_major new_minor new_patch <<<"$version"

read -r old_major old_minor old_patch <<<"$(awk -F= '
  $1 ~ /^[[:space:]]*major[[:space:]]*$/ {gsub(/[[:space:]]/, "", $2); major=$2}
  $1 ~ /^[[:space:]]*minor[[:space:]]*$/ {gsub(/[[:space:]]/, "", $2); minor=$2}
  $1 ~ /^[[:space:]]*patch[[:space:]]*$/ {gsub(/[[:space:]]/, "", $2); patch=$2}
  END {print major, minor, patch}
' abi/abi-version.txt)"

if (( new_major < old_major || (new_major == old_major && new_minor < old_minor) \
      || (new_major == old_major && new_minor == old_minor && new_patch <= old_patch) )); then
  echo "✗ ABI 版本只能单调前进：$old_major.$old_minor.$old_patch -> $version" >&2
  exit 1
fi

tmp="$(mktemp "${TMPDIR:-/tmp}/jasper-abi-version.XXXXXX")"
trap 'rm -f -- "$tmp"' EXIT
sed \
  -e "s/^major[[:space:]]*=.*/major = $new_major/" \
  -e "s/^minor[[:space:]]*=.*/minor = $new_minor/" \
  -e "s/^patch[[:space:]]*=.*/patch = $new_patch/" \
  abi/abi-version.txt > "$tmp"
mv -- "$tmp" abi/abi-version.txt
trap - EXIT

bash scripts/abi-contract.sh generate
bash scripts/abi-contract.sh check
echo "ABI $version 基线已建立。下一步：审阅快照差异，运行 bash scripts/abi-freeze.sh，再走公开闸门与完整验收。"
