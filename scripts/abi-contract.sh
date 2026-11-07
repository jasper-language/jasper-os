#!/bin/bash
# =============================================================================
# abi-contract.sh —— ABI 完整契约快照的生成、检查与历史不可变性门槛
# ABI contract snapshot generation, checking, and immutable-history gate.
#
# 用法 / Usage:
#   bash scripts/abi-contract.sh check
#   bash scripts/abi-contract.sh generate
#   bash scripts/abi-contract.sh immutable <git-base>
#
# `generate` 只创建当前版本尚不存在的快照；绝不覆盖已提交快照。
# `immutable` 拒绝在 base...HEAD 中修改、删除或重命名任何旧快照；新增快照允许。
# =============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
if [ -r "$HOME/.cargo/env" ]; then source "$HOME/.cargo/env"; fi

case "${1:-}" in
  check)
    cargo run -q -p xtask -- abi-contract check
    ;;
  generate)
    cargo run -q -p xtask -- abi-contract generate
    ;;
  immutable)
    base="${2:-}"
    if [ -z "$base" ]; then
      echo "用法：bash scripts/abi-contract.sh immutable <git-base>" >&2
      exit 2
    fi
    if ! git rev-parse --verify "$base^{commit}" >/dev/null 2>&1; then
      echo "ABI 快照历史门槛：base 不存在或不可解析，跳过（需要完整历史 checkout）"
      exit 0
    fi
    bad=0
    while IFS=$'\t' read -r status path extra; do
      [ -n "${status:-}" ] || continue
      case "$status" in
        A|AM)
          ;;
        *)
          echo "✗ ABI 快照不可变：$status $path${extra:+ -> $extra}" >&2
          bad=1
          ;;
      esac
    done < <(git diff --name-status "$base"...HEAD -- 'abi/snapshots/*.contract')
    if [ "$bad" -ne 0 ]; then
      echo "旧快照只能保持原样；ABI 变化必须提升版本并新增 <Major.Minor.Patch>.contract" >&2
      exit 1
    fi
    echo "ABI snapshot history gate: PASS"
    ;;
  *)
    echo "用法：bash scripts/abi-contract.sh check|generate|immutable <git-base>" >&2
    exit 2
    ;;
esac
