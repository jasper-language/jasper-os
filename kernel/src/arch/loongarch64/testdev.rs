//! QEMU 的 LoongArch `virt` 没有与 RISC-V `sifive,test0` 等价的通用退出设备。
//! 因此验收通过串口标记与 QEMU 超时终止判定；失败路径关中断停机。

use super::cpu;

/// Stop the machine after reporting the requested status through serial output.
pub fn stop(_code: u32) -> ! {
    loop {
        cpu::irq_mask();
        // SAFETY: interrupts are disabled and idle only waits for an interrupt.
        unsafe { core::arch::asm!("idle 0", options(nostack, preserves_flags)) };
    }
}
