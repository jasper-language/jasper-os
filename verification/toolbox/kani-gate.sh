# 各验证套件共用：Kani 只在正式版发版时验证，日常不跑、不判（JASPER_RUN_KANI=1 打开）。
# Kani runs at formal releases only; daily suites skip it and report it as not run.
kani_enabled() { [ "${JASPER_RUN_KANI:-0}" = 1 ]; }
if kani_enabled; then KANI_STATUS="Kani run"; else KANI_STATUS="Kani: verified at release"; fi
