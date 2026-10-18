//! 仿真器测试设备（`sifive,test0`）：让仿真器以给定退出码结束（RISC-V 上没有 x86 那样的调试退出端口）。
//! Emulator test device used to terminate with a chosen exit status.
//!
//! 写入 `(退出码 << 16) | 0x3333` 即让 QEMU 以该退出码结束。设备树里没有该设备时（例如真机），
//! 退回到经 SBI 以「系统故障」关机，再不行就停机——无论哪种都不会继续执行。

use core::sync::atomic::{AtomicU64, Ordering};

use super::{cpu, sbi};

/// 「带退出码的失败」命令字。
const FINISHER_FAIL: u32 = 0x3333;

/// 寄存器的虚拟地址（0 = 设备树里没有该设备）。
static BASE: AtomicU64 = AtomicU64::new(0);

/// 设置寄存器的虚拟地址（引导适配层解析设备树后调用）。
pub fn set_base(va: u64) {
    BASE.store(va, Ordering::Relaxed);
}

/// 以 `code` 结束仿真（不返回）。
pub fn exit(code: u16) -> ! {
    match BASE.load(Ordering::Relaxed) {
        0 => sbi::shutdown_failure(),
        // SAFETY：基地址来自设备树中的测试设备节点；写命令字只会让仿真器退出。
        va => unsafe { (va as *mut u32).write_volatile((u32::from(code) << 16) | FINISHER_FAIL) },
    }
    loop {
        cpu::irq_mask();
        // SAFETY：中断已关闭，wfi 只让处理器停在这里。
        unsafe { core::arch::asm!("wfi", options(nomem, nostack)) };
    }
}
