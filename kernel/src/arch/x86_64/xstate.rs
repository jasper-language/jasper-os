//! Runtime x86 extended CPU-state configuration.
//!
//! The active XCR0 mask and its architectural save-area size are discovered at
//! boot. Task contexts and syscall frames query this configuration instead of
//! assuming a fixed XSAVE size.

use core::sync::atomic::{AtomicU64, Ordering};

pub(crate) const FXSAVE_BYTES: usize = 512;
pub(crate) const XSTATE_ALIGN: usize = 64;

#[no_mangle]
static JSR_XSTATE_MASK: AtomicU64 = AtomicU64::new(0);

#[no_mangle]
static JSR_XSTATE_SIZE: AtomicU64 = AtomicU64::new(FXSAVE_BYTES as u64);

/// Installs the common system XCR0 policy after the caller has written XCR0.
///
/// CPUID.0xD:0.EBX reports the save-area size for the XCR0 value currently
/// installed on this CPU. Every CPU in the initial Jasper configuration is
/// required to agree on the same active state set.
/// 在调用方写入 XCR0 后安装全系统共享策略；CPUID 报告的是当前 XCR0
/// 配置所需的标准 XSAVE 区字节数，BSP/AP 必须得到完全一致的策略。
pub(crate) fn configure(mask: u64) -> bool {
    let size = if mask == 0 {
        FXSAVE_BYTES
    } else {
        let leaf = core::arch::x86_64::__cpuid_count(0xD, 0);
        let Ok(size) = usize::try_from(leaf.ebx) else {
            return false;
        };
        size
    };
    if size < FXSAVE_BYTES {
        return false;
    }
    let previous_mask = JSR_XSTATE_MASK.load(Ordering::Acquire);
    if previous_mask != 0 {
        return previous_mask == mask
            && JSR_XSTATE_SIZE.load(Ordering::Acquire) == size as u64;
    }
    // Publish the size before the mask. A concurrently booting CPU must never
    // observe a nonzero of this CPU's mask paired with the 512-byte boot default.
    // 先发布尺寸再发布掩码；并发上线的 CPU 绝不能把非零掩码与 512 字节
    // 启动默认值配成一对。
    JSR_XSTATE_SIZE.store(size as u64, Ordering::Release);
    if JSR_XSTATE_MASK
        .compare_exchange(0, mask, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return JSR_XSTATE_MASK.load(Ordering::Acquire) == mask
            && JSR_XSTATE_SIZE.load(Ordering::Acquire) == size as u64;
    }
    true
}

pub(crate) fn mask() -> u64 {
    JSR_XSTATE_MASK.load(Ordering::Acquire)
}

/// Size of the active architectural XSAVE/XRSTOR image.
/// 当前架构 XSAVE/XRSTOR 映像的实际字节数。
pub(crate) fn save_size() -> usize {
    JSR_XSTATE_SIZE.load(Ordering::Acquire) as usize
}

/// Standard-format XSAVE area size required by one guest XCR0 subset.
///
/// Jasper currently admits x87, SSE and AVX. The legacy region plus standard
/// header is always present; AVX adds the CPUID-reported offset and size.
pub(crate) fn size_for_xcr0(mask: u64) -> Option<usize> {
    if mask & !0x7 != 0 {
        return None;
    }
    let mut size = FXSAVE_BYTES + kernel_core::xsave::STANDARD_HEADER_BYTES;
    if mask & (1 << 2) != 0 {
        let avx = core::arch::x86_64::__cpuid_count(0xD, 2);
        if avx.eax == 0 {
            return None;
        }
        let end = usize::try_from(avx.ebx).ok()?.checked_add(usize::try_from(avx.eax).ok()?)?;
        size = size.max(end);
    }
    Some(size)
}

/// Size allocated per task. FXSAVE-only configurations keep their compact
/// 512-byte image inside `TaskContext`.
/// 每任务状态区大小；仅 FXSAVE 时继续使用任务上下文内的紧凑回退区。
pub(crate) fn task_area_size() -> usize {
    if mask() == 0 {
        0
    } else {
        save_size()
    }
}

/// Syscall entry always owns an aligned full-size image, including FXSAVE-only
/// configurations, so signal and syscall paths share one size contract.
/// syscall 入口始终拥有对齐的完整尺寸映像，即使仅使用 FXSAVE；信号与系统
/// 调用路径因此共享同一尺寸合同。
pub(crate) fn syscall_area_size() -> usize {
    save_size()
}
