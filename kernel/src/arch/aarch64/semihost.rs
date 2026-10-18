//! 半主机（semihosting）退出：让仿真器以给定退出码结束（AArch64 上没有 x86 那样的调试退出端口）。
//! Semihosting exit so the emulator terminates with a chosen status.
//!
//! 仿真器须开启半主机（QEMU：`-semihosting`）；未开启时 `hlt` 会作为未定义指令陷入内核，
//! 由异常入口按「内核态致命异常」停机——结果同样是停在这里，不会继续执行。

/// 半主机操作：带状态的退出（AArch64 形式，参数块 = [原因, 退出码]）。
const SYS_EXIT: u64 = 0x18;
/// 退出原因：应用程序正常退出（附带退出码）。
const ADP_STOPPED_APPLICATION_EXIT: u64 = 0x2_0026;

/// 以 `code` 结束仿真（不返回）。
pub fn exit(code: u32) -> ! {
    let block: [u64; 2] = [ADP_STOPPED_APPLICATION_EXIT, u64::from(code)];
    // SAFETY：`hlt #0xf000` 是 AArch64 半主机调用约定；参数块在调用期间有效。
    unsafe {
        core::arch::asm!(
            "hlt #0xf000",
            in("x0") SYS_EXIT,
            in("x1") block.as_ptr(),
            options(nostack)
        );
    }
    loop {
        super::cpu::irq_mask();
        // SAFETY：等待中断；中断已屏蔽，只会因调试事件醒来，醒来后继续等。
        unsafe { core::arch::asm!("wfi", options(nomem, nostack)) };
    }
}
