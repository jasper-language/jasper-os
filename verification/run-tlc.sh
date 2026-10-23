#!/usr/bin/env bash
# 在已安装 Java 的环境中运行 TLB 击落模型；TLA_JAR 可指向既有 tla2tools.jar。
set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
jar="${TLA_JAR:-$here/tla2tools.jar}"
if [ ! -f "$jar" ]; then
  jar="${TMPDIR:-/tmp}/tla2tools-1.8.0.jar"
  if [ ! -f "$jar" ]; then
    curl -fsSL --retry 3 \
      https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar \
      -o "$jar"
  fi
fi
meta="$(mktemp -d)"
trap 'find "$meta" -type f -delete; find "$meta" -depth -type d -empty -delete' EXIT
java -XX:+UseParallelGC -cp "$jar" tlc2.TLC \
  -workers 4 -cleanup -metadir "$meta" \
  -config "$here/tlb_shootdown.cfg" "$here/tlb_shootdown.tla"
