//! 中断到达计数回绕自检：分发器的每槽位到达计数是 `u32`，长期运行后会从 `u32::MAX` 回绕到 0。
//! Boot-time self-check that interrupt arrival counting stays correct across the `u32` wrap.
//!
//! # 做什么
//! * 用一个局部计数器（初值 `u32::MAX - 3`），经分发器**同一个**递增函数 [`irq::count_arrival`] 记 6 次到达，
//!   再用中断对象**同一个**求差函数 [`arrivals_since`] 计算增量，必须为 6；
//! * 边界：两次读数相同 ⇒ 增量为 0（不得把当前读数整体当成新到达）。
//!
//! # 边界与原因
//! * 不写任何真实槽位的计数：真实计数被中断对象与其他演练按读数差使用，人为改写会破坏它们；
//!   局部计数器走的是与真实路径完全相同的代码，因此足以证明回绕下不丢到达。
//!
//! 输出 `[JSR-KRN0] case=…` 与 `[JSR-KRN0] summary irq_count failed=<n>`；不符时输出 `[JSR-KRN0-FAIL] <原因>` 并计入失败数。

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::interrupt::arrivals_since;

use crate::{irq, kprintln};

/// 回绕用例的起始读数。
/// Starting reading of the wrap case.
const WRAP_START: u32 = u32::MAX - 3;
/// 回绕用例记的到达次数。
/// Arrivals counted in the wrap case.
const WRAP_ARRIVALS: u32 = 6;

static FAILED: AtomicU32 = AtomicU32::new(0);

fn check(ok: bool, what: &str) {
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-KRN0-FAIL] {}", what);
    }
}

/// 运行自检并输出汇总。
/// Run the self-check and emit the summary.
pub fn run() {
    let counter = AtomicU32::new(WRAP_START);
    let seen = counter.load(Ordering::Acquire);
    for _ in 0..WRAP_ARRIVALS {
        irq::count_arrival(&counter);
    }
    let now = counter.load(Ordering::Acquire);
    let delta = arrivals_since(seen, now);
    let wrapped = now < seen;
    let ok = delta == WRAP_ARRIVALS && wrapped;
    check(wrapped, "计数器没有跨越 u32 回绕");
    check(delta == WRAP_ARRIVALS, "回绕后的到达增量不等于实际到达次数");
    kprintln!(
        "[JSR-KRN0] case=irq_count_wrap start={} arrivals={} delta={} ok={}",
        seen,
        WRAP_ARRIVALS,
        delta,
        ok
    );

    let same = counter.load(Ordering::Acquire);
    let delta_same = arrivals_since(same, counter.load(Ordering::Acquire));
    check(delta_same == 0, "读数未变时增量不为 0");
    kprintln!("[JSR-KRN0] case=irq_count_same delta={} ok={}", delta_same, delta_same == 0);

    kprintln!("[JSR-KRN0] summary irq_count failed={}", failed());
}

/// 断言失败次数。
/// Number of failed assertions.
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}
