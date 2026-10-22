//! DRV-2A 演练：每核 MSI 向量分配、绑定、投递与拒绝路径；并打印 virtio 功能的 MSI-X 解析结果。
//! DRV-2A demo: per-CPU MSI vector allocation, binding, delivery and refusal paths, plus MSI-X results.
//!
//! # 断言
//! * 每个在线处理器各分到一个向量并绑定计数处理函数；从引导处理器逐个自测触发后，
//!   只有目标处理器收到、恰好一次，其他处理器的计数不变，处理函数恰好被调用一次。
//! * 释放并解绑后再触发同一向量：旧处理函数不被调用，目标处理器的伪 MSI 计数加一；
//!   重新分配并绑定新处理函数后可以再次正常投递。
//! * 拒绝路径：越界处理器、未在线处理器、某核向量耗尽、重复释放、释放未分配或别核的向量
//!   全部被拒且位图不变；其他处理器的分配不受影响。
//! * 全部释放后每核回到零分配，并可重新分配。
//! * 每个 virtio 功能的 MSI-X 表 / PBA 位置被解析并输出；解析失败计入失败断言。
//!
//! 汇总行 `[JSR-MSI] summary …` 在本文件最后输出，`failed` 进入 kmain 的失败计数。

use alloc::format;
use core::fmt;
use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::interrupt::arrivals_since;
use kernel_core::msi::{MsiError, Vector, VectorPool};
use kernel_core::pci::Bdf;
use kernel_core::smp::{CpuSet, MAX_CPUS};

use crate::{arch, irq, kprintln, pci, sched};

/// 断言失败次数（验收要求为 0）。
static FAILED: AtomicU32 = AtomicU32::new(0);
/// 断言总数。
static CHECKS: AtomicU32 = AtomicU32::new(0);
/// 主处理函数被调用的次数。
static HANDLED: AtomicU32 = AtomicU32::new(0);
/// 改绑后的处理函数被调用的次数。
static REBOUND: AtomicU32 = AtomicU32::new(0);

/// 记录一次断言；失败时打印原因。
fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-MSI-FAIL] {}", what);
    }
}

/// 断言失败次数。
/// Number of failed assertions.
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 主处理函数：只计数，证明绑定生效。
fn primary_handler() {
    HANDLED.fetch_add(1, Ordering::Relaxed);
}

/// 改绑后的处理函数：只计数，证明重新绑定生效。
fn rebound_handler() {
    REBOUND.fetch_add(1, Ordering::Relaxed);
}

/// 有界等待条件成立。
fn wait_until(mut cond: impl FnMut() -> bool) -> bool {
    for _ in 0..20_000_000u64 {
        if cond() {
            return true;
        }
        core::hint::spin_loop();
    }
    cond()
}

/// 投递后短暂等待，用于确认没有第二次投递。
fn settle() {
    for _ in 0..100_000u64 {
        core::hint::spin_loop();
    }
}

/// virtio 设备号范围（传统 0x1000–0x103f 与 modern 0x1040–0x107f）。
fn virtio_id(device: u16) -> bool {
    (0x1000..=0x107f).contains(&device)
}

/// `bb:dd.f` 形式的 BDF（诊断输出用）。
struct BdfFmt(Bdf);

impl fmt::Display for BdfFmt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}:{:02x}.{}", self.0.bus(), self.0.device(), self.0.function())
    }
}

/// 运行演练并输出汇总。
/// Run the demo and emit the summary.
pub fn run() {
    // 投递目标包含引导处理器自身：必须开中断，否则本地 MSI 要等到演练结束才会被取走。
    let was_enabled = arch::irq_save_disable();
    arch::irq_enable();
    irq::reset_msi_stats();
    let online = sched::online_cpus();
    let cpus = online.len();
    let mut vectors_per_cpu = 0usize;
    let mut delivered = 0usize;

    match arch::msi_vector_range() {
        Some(range) => {
            vectors_per_cpu = range.count as usize;
            match VectorPool::new(range.first, range.count, online) {
                Ok(pool) => delivered = exercise(&pool, online),
                Err(e) => check(false, &format!("MSI 向量池构造被拒：{}", e.name())),
            }
        }
        None => check(false, "平台未提供 MSI 向量范围"),
    }

    let msix_functions = report_msix();
    check(cpus > 0, "没有在线处理器");
    check(delivered == cpus, "并非每个在线处理器都恰好收到一次 MSI");
    // 伪 MSI 的精确增量（释放后 +1、改绑后不再增加）已在 `rebind_check` 中逐条断言，
    // 这里不再要求全局为 0：单处理器时改绑的被试就是引导处理器。

    kprintln!(
        "[JSR-MSI] summary cpus={} vectors_per_cpu={} delivered={}/{} msix_functions={} checks={} failed={}",
        cpus,
        vectors_per_cpu,
        delivered,
        cpus,
        msix_functions,
        CHECKS.load(Ordering::Relaxed),
        FAILED.load(Ordering::Relaxed)
    );
    arch::irq_restore(was_enabled);
}

/// 向量分配、投递、改绑、拒绝路径与基线回归；返回成功投递的处理器数。
fn exercise(pool: &VectorPool, online: CpuSet) -> usize {
    let mut vectors = [None; MAX_CPUS];

    // 每个在线处理器各分一个向量并绑定处理函数。
    for cpu in online.iter() {
        match pool.alloc(cpu) {
            Ok(vector) => match irq::msi_bind(cpu, vector.get(), Some(primary_handler)) {
                Ok(()) => vectors[cpu] = Some(vector.get()),
                Err(e) => check(false, &format!("绑定处理器 {} 的 MSI 被拒：{}", cpu, e.name())),
            },
            Err(e) => check(false, &format!("处理器 {} 的 MSI 向量分配失败：{}", cpu, e.name())),
        }
    }
    check(vectors.iter().filter(|v| v.is_some()).count() == online.len(), "不是每个在线处理器都分到向量");

    let mut delivered = 0usize;
    let mut addresses = [0u64; MAX_CPUS];
    for cpu in online.iter() {
        let Some(vector) = vectors[cpu] else { continue };
        let Some(message) = arch::msi_message(cpu, vector) else {
            check(false, "无法组合 MSI 消息");
            continue;
        };
        addresses[cpu] = message.address;
        check(message.data == vector as u32, "MSI 消息数据与向量不一致");

        let mut before = [0u32; MAX_CPUS];
        for other in online.iter() {
            before[other] = irq::msi_count(other, vector);
        }
        let before_handled = HANDLED.load(Ordering::Relaxed);
        let before_spurious = irq::msi_spurious(cpu);
        if let Err(e) = arch::msi_trigger(cpu, vector) {
            check(false, &format!("向处理器 {} 投递 MSI 失败：{}", cpu, e.name()));
            continue;
        }
        let arrived = wait_until(|| arrivals_since(before[cpu], irq::msi_count(cpu, vector)) > 0);
        settle();

        let mut only_target = true;
        for other in online.iter() {
            let delta = irq::msi_count(other, vector).wrapping_sub(before[other]);
            if other == cpu {
                only_target &= delta == 1;
            } else {
                only_target &= delta == 0;
            }
        }
        check(arrived, "目标处理器没有收到 MSI");
        check(only_target, "MSI 没有恰好一次送达目标处理器");
        check(HANDLED.load(Ordering::Relaxed) == before_handled + 1, "处理函数调用次数不为 1");
        check(irq::msi_spurious(cpu) == before_spurious, "已绑定的向量被记为伪 MSI");
        if arrived && only_target {
            delivered += 1;
        }
    }
    check(distinct_addresses(&addresses, online) || !arch::MSI_ADDRESS_ENCODES_TARGET, "不同处理器的 MSI 目标地址相同");

    // 改绑：释放并解绑后同一向量变成伪 MSI；重新分配并绑定新处理函数后恢复投递。
    rebind_check(pool, online, &mut vectors);

    // 拒绝路径：释放别核的向量、未分配、重复释放、越界向量。
    refusal_check(pool, online);

    // 某核耗尽：再分配被拒且位图不变；其他核仍可分配。
    exhaustion_check(pool, online);

    // 全部释放并解绑，回到零分配基线，然后每核都能重新分配一次。
    let mut zero = true;
    for cpu in online.iter() {
        for index in 0..pool.count() as usize {
            let _ = irq::msi_bind(cpu, pool.first() + index as u8, None);
        }
        let _ = pool.free_all(cpu);
        zero &= pool.allocated(cpu) == 0;
    }
    check(zero, "全部释放后没有回到零分配基线");
    for cpu in online.iter() {
        match pool.alloc(cpu) {
            Ok(vector) => {
                check(pool.is_allocated(cpu, vector) == Ok(true), "清空后重新分配不可见");
                check(pool.free(cpu, vector).is_ok(), "清空后重新分配无法释放");
            }
            Err(e) => check(false, &format!("清空后处理器 {} 无法重新分配：{}", cpu, e.name())),
        }
    }

    delivered
}

/// 改绑检查：释放后旧处理函数不再被调用，伪 MSI 计数加一；重新绑定后恢复。
fn rebind_check(pool: &VectorPool, online: CpuSet, vectors: &mut [Option<u8>; MAX_CPUS]) {
    let Some(victim) = online.iter().next() else { return };
    let Some(vector) = vectors[victim] else { return };

    let before_handled = HANDLED.load(Ordering::Relaxed);
    let before_rebound = REBOUND.load(Ordering::Relaxed);
    let before_spurious = irq::msi_spurious(victim);
    let before_count = irq::msi_count(victim, vector);

    check(irq::msi_bind(victim, vector, None).is_ok(), "解绑 MSI 处理函数失败");
    match pool.free(victim, Vector::new(vector)) {
        Ok(()) => check(true, "释放后触发"),
        Err(e) => {
            check(false, &format!("释放向量被拒：{}", e.name()));
            return;
        }
    }
    if let Err(e) = arch::msi_trigger(victim, vector) {
        check(false, &format!("释放后投递 MSI 失败：{}", e.name()));
        return;
    }
    let arrived = wait_until(|| arrivals_since(before_count, irq::msi_count(victim, vector)) > 0);
    settle();
    check(arrived, "释放后的向量没有被接收");
    check(arrivals_since(before_count, irq::msi_count(victim, vector)) == 1, "释放后的向量收到不止一次");
    check(irq::msi_spurious(victim) == before_spurious + 1, "伪 MSI 计数没有加一");
    check(HANDLED.load(Ordering::Relaxed) == before_handled, "旧处理函数仍被调用");

    // 重新分配（应回到最低空闲位）并绑定第二个处理函数。
    match pool.alloc(victim) {
        Ok(again) => {
            check(again == Vector::new(vector), "释放后没有回到最低空闲向量");
            check(irq::msi_bind(victim, again.get(), Some(rebound_handler)).is_ok(), "改绑失败");
            let count = irq::msi_count(victim, again.get());
            if let Err(e) = arch::msi_trigger(victim, again.get()) {
                check(false, &format!("改绑后投递 MSI 失败：{}", e.name()));
                return;
            }
            let arrived = wait_until(|| arrivals_since(count, irq::msi_count(victim, again.get())) > 0);
            settle();
            check(arrived, "改绑后的向量没有被接收");
            check(REBOUND.load(Ordering::Relaxed) == before_rebound + 1, "新处理函数没有被调用");
            check(HANDLED.load(Ordering::Relaxed) == before_handled, "改绑后旧处理函数仍被调用");
            vectors[victim] = Some(again.get());
        }
        Err(e) => check(false, &format!("改绑时重新分配失败：{}", e.name())),
    }
}

/// 释放别核的向量、未分配向量、重复释放与越界向量全部被拒且位图不变。
fn refusal_check(pool: &VectorPool, online: CpuSet) {
    check(pool.alloc(MAX_CPUS).is_err(), "越界处理器未被拒绝");
    check(pool.free(MAX_CPUS, Vector::new(pool.first())).is_err(), "越界处理器释放未被拒绝");

    if let Some(offline) = (0..MAX_CPUS).find(|&cpu| !online.contains(cpu)) {
        check(pool.alloc(offline) == Err(MsiError::NotOnline), "未在线处理器分配未被拒绝");
        check(pool.free(offline, Vector::new(pool.first())) == Err(MsiError::NotOnline), "未在线处理器释放未被拒绝");
    }

    let mut cpus = online.iter();
    let (Some(a), Some(b)) = (cpus.next(), cpus.next()) else { return };
    let before = pool.allocated(a);
    let extra = match pool.alloc(a) {
        Ok(v) => v,
        Err(e) => {
            check(false, &format!("拒绝路径准备分配失败：{}", e.name()));
            return;
        }
    };
    check(pool.free(b, extra) == Err(MsiError::NotAllocated), "释放别核的向量未被拒绝");
    check(pool.allocated(b) > 0, "另一核的位图被误清");
    check(pool.allocated(a) == before + 1, "被拒后本核位图改变");
    check(pool.free(a, extra).is_ok(), "本核释放自己的向量失败");
    check(pool.free(a, extra) == Err(MsiError::NotAllocated), "重复释放未被拒绝");
    check(pool.allocated(a) == before, "重复释放后位图改变");

    let unallocated = Vector::new(pool.first() + 2);
    if pool.is_allocated(a, unallocated) == Ok(false) {
        check(pool.free(a, unallocated) == Err(MsiError::NotAllocated), "释放未分配的向量未被拒绝");
    }
    if let Some(out) = pool.first().checked_add(pool.count()) {
        check(pool.free(a, Vector::new(out)) == Err(MsiError::OutOfRange), "越界向量释放未被拒绝");
        check(pool.is_allocated(a, Vector::new(out)) == Err(MsiError::OutOfRange), "越界向量查询未被拒绝");
    }
}

/// 耗尽某核的向量后再分配被拒、位图不变；其他核仍可分配。
fn exhaustion_check(pool: &VectorPool, online: CpuSet) {
    let Some(exhaust) = online.iter().next() else { return };
    let mut allocated = 0usize;
    loop {
        match pool.alloc(exhaust) {
            Ok(_) => allocated += 1,
            Err(MsiError::Exhausted) => break,
            Err(e) => {
                check(false, &format!("耗尽过程中出现意外错误：{}", e.name()));
                return;
            }
        }
        if allocated > kernel_core::msi::MAX_SLOTS {
            check(false, "向量分配没有上界");
            return;
        }
    }
    check(allocated > 0, "耗尽路径没有分配任何向量");
    check(pool.allocated(exhaust) == pool.count() as usize, "耗尽后分配数不等于每核容量");
    check(pool.alloc(exhaust) == Err(MsiError::Exhausted), "耗尽后再分配未被拒绝");
    check(pool.allocated(exhaust) == pool.count() as usize, "拒绝时位图改变");
    check(MsiError::Exhausted.name() == "system.irq.error.msi_exhausted", "耗尽错误名不稳定");

    if let Some(other) = online.iter().find(|&cpu| cpu != exhaust) {
        match pool.alloc(other) {
            Ok(vector) => {
                check(pool.is_allocated(other, vector) == Ok(true), "其他核分配不可见");
                check(pool.free(other, vector).is_ok(), "其他核分配的向量无法释放");
            }
            Err(e) => check(false, &format!("其他核被耗尽路径影响：{}", e.name())),
        }
    }
}

/// 地址集合在每个在线处理器上互不相同。
fn distinct_addresses(addresses: &[u64; MAX_CPUS], online: CpuSet) -> bool {
    let mut seen = [0u64; MAX_CPUS];
    let mut count = 0usize;
    for cpu in online.iter() {
        for previous in seen.iter().take(count) {
            if *previous == addresses[cpu] {
                return false;
            }
        }
        seen[count] = addresses[cpu];
        count += 1;
    }
    true
}

/// 打印每个 virtio 功能的 MSI-X 解析结果，返回成功解析的功能数。
fn report_msix() -> u32 {
    let mut count = 0u32;
    for device in pci::table().devices() {
        if device.header.vendor != 0x1AF4 || !virtio_id(device.header.device) {
            continue;
        }
        match device.msix {
            Some(capability) => {
                let table = capability.table();
                kprintln!(
                    "[JSR-MSI] dev bdf={} msix table_size={} table_bir={} pba_bir={} ok=true",
                    BdfFmt(device.bdf),
                    table.table_size(),
                    table.table_bir(),
                    table.pba_bir()
                );
                count += 1;
            }
            None => match device.msix_error {
                Some(e) => {
                    check(false, "virtio 功能的 MSI-X 能力解析失败");
                    kprintln!("[JSR-MSI] dev bdf={} msix ok=false reason={}", BdfFmt(device.bdf), e.name());
                }
                None => kprintln!("[JSR-MSI] dev bdf={} msix=none", BdfFmt(device.bdf)),
            },
        }
        if let Some(e) = device.msi_error {
            check(false, "设备 MSI 能力解析失败");
            kprintln!("[JSR-MSI] dev bdf={} msi ok=false reason={}", BdfFmt(device.bdf), e.name());
        }
    }
    count
}
