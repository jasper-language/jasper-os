#!/bin/bash
# =============================================================================
# abi-freeze.sh —— 把登记表中尚未冻结的接口追加进 abi/system-ids.lock（发布前运行）
#
# 只追加、不修改：已在锁文件中的条目原样保留；构建期 build.rs 会检查登记表没有删除或改动它们。
# 用法：bash scripts/abi-freeze.sh        （打印新冻结的条目）
# =============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REG="$ROOT/abi/system-ids.txt"; LOCK="$ROOT/abi/system-ids.lock"
added=0
while IFS= read -r line; do
  case "$line" in ''|\#*) continue;; esac
  id="$(printf '%s' "$line" | awk '{print $1}')"
  if ! grep -v '^#' "$LOCK" | awk '{print $1}' | grep -qx "$id"; then
    printf '%s\n' "$line" >> "$LOCK"; echo "  冻结：$line"; added=$((added+1))
  fi
done < "$REG"
echo "新冻结 $added 条"
