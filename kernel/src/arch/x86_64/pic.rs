//! 8259 PIC：重映射到 0x20..0x2F 并负责 EOI。
//!
//! 重映射原因：PIC 默认把 IRQ0–7 投到向量 8–15，与 CPU 异常冲突。
//! 未来换成 APIC / 其他 ISA 的中断控制器时，只替换本文件，Core 只认逻辑中断线。

use pic8259::ChainedPics;
use spin::Mutex;

/// 主片向量偏移：IRQ0（定时器）→ 向量 32。
pub const PIC_1_OFFSET: u8 = 32;
/// 从片向量偏移。
pub const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;
/// 定时器（IRQ0）对应的向量号。
pub const TIMER_VECTOR: u8 = PIC_1_OFFSET;

/// 级联的两片 PIC。
static PICS: Mutex<ChainedPics> = Mutex::new(unsafe { ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET) });

/// 主片屏蔽字：只放行 IRQ0（定时器）与 IRQ2（级联）。其余设备中断经 I/O APIC 投递，在 8259 上一律屏蔽。
const MASTER_MASK: u8 = !0b0000_0101;
/// 从片全部屏蔽。
const SLAVE_MASK: u8 = 0xFF;

/// 初始化并重映射 PIC，只放行定时器。
pub fn init() {
    // SAFETY：偏移量不与 CPU 异常向量（0–31）重叠；屏蔽字只影响 8259 自身的输入线。
    unsafe {
        let mut pics = PICS.lock();
        pics.initialize();
        pics.write_masks(MASTER_MASK, SLAVE_MASK);
    }
}

/// 向 PIC 发送中断结束（EOI）。
///
/// # Safety
/// `vector` 必须是正在处理的那个中断的向量号。
pub unsafe fn end_of_interrupt(vector: u8) {
    PICS.lock().notify_end_of_interrupt(vector);
}
