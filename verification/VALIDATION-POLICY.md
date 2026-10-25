# Required verification toolbox

User-approved 2026-10-23: Verus+Z3, Proptest, Miri, cargo-fuzz, Kani, Loom. Apply by property, with concurrency checking during design. Unsupported cases require an explicit reason and substitute evidence; never label them PASS.

- Quota/permission arithmetic: Verus specs tied to production, Proptest reference/shrinking, actual Rust Kani.
- RAM/pin lifetime: production ownership host adapter for Miri; instrumented concurrency for Loom.
- ABI decoding: Proptest malformed inputs and cargo-fuzz corpus/regressions.
- Wake/revoke publication: TLA+ protocol/negatives plus Loom implementation interleavings.
- Hardware TLB/IRQ/CPL3: actual QEMU assertions remain mandatory; host adapters declare abstraction.

Verus/Proptest/Miri/cargo-fuzz/Loom new coverage is pending. Existing TLA+ and 12 Kani harnesses do not imply new coverage. Record source identity, versions, commands, assumptions, bounds and results. Abstract reimplementations alone do not prove production Rust.

每轮主线推进，同时为一小块现有代码补Verus+Z3→Proptest→Miri→cargo-fuzz→Kani→Loom完整覆盖；逐步积累，不以全库覆盖阻塞推进。纯性能保留原指标延期至内核完成后优化；正确性/安全/资源仍硬门。Usage新增Kani单项54113真实通过236检查，整套13项待重生成。
