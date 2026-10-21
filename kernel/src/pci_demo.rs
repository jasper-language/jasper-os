//! DRV-1B 演练：在 QEMU 上核对启动期 PCI 设备表，并输出 `[JSR-PCI]` 结构化事件。
//! DRV-1B demo: verify the boot-time PCI device table on QEMU and emit `[JSR-PCI]` events.
//!
//! # 断言
//! * 枚举到功能，且没有枚举错误、没有因容量丢弃功能；
//! * 找得到 QEMU 默认机型的宿主桥（类 0x06 / 子类 0x00）与 ISA 桥（类 0x06 / 子类 0x01）；
//! * 每个已发现的 virtio 设备（厂商 0x1af4、设备号在 virtio 范围内）至少有一个 BAR，
//!   且所有已实现 BAR 的尺寸非零、为 2 的幂；virtio 设备个数只如实报告，由启动方核对
//!   （内核不知道启动方挂了几个设备，不挂设备的普通启动也必须通过）；
//! * 非法 BDF（设备号 ≥ 32、功能号 ≥ 8）与非法配置偏移被拒绝；
//! * BAR 探测前后标准头逐双字一致（寄存器恢复原状）。
//!
//! 汇总行 `[JSR-PCI] summary …` 在本文件最后输出，`failed` 直接进入 kmain 的失败计数。

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::pci::{legacy_address, Bar, Bdf, Ecam};

use crate::{kprintln, pci};

/// 断言失败次数（验收要求为 0）。
static FAILED: AtomicU32 = AtomicU32::new(0);
/// 断言总数。
static CHECKS: AtomicU32 = AtomicU32::new(0);

/// 记录一次断言；失败时打印原因。
fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-PCI-FAIL] {}", what);
    }
}

/// 断言失败次数。
/// Number of failed assertions.
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// virtio 设备号范围（传统 0x1000–0x103f 与 modern 0x1040–0x107f）。
fn virtio_id(device: u16) -> bool {
    (0x1000..=0x107f).contains(&device)
}

/// 一个 BAR 的尺寸合法：非零且为 2 的幂。
fn bar_size_ok(bar: &Bar) -> bool {
    match *bar {
        Bar::None => true,
        Bar::Io { size, .. } => size != 0 && size.is_power_of_two(),
        Bar::Memory { size, .. } => size != 0 && size.is_power_of_two(),
    }
}

/// 运行演练并输出汇总。
/// Run the demo and emit the summary.
pub fn run() {
    let table = pci::table();

    check(table.functions() > 0, "没有枚举到任何 PCI 功能");
    check(!table.enumerate_error, "配置空间枚举读取失败");
    check(table.dropped == 0, "设备表容量不足（功能被丢弃）");
    check(table.probe_failed == 0, "有功能的 BAR 探测失败");
    check(table.restored, "BAR 探测后标准头未恢复原状");

    let host_bridge = table.devices().any(|d| d.header.class == 0x06 && d.header.subclass == 0x00);
    let isa_bridge = table.devices().any(|d| d.header.class == 0x06 && d.header.subclass == 0x01);
    check(host_bridge, "找不到宿主桥（class 0x06 / subclass 0x00）");
    check(isa_bridge, "找不到 ISA 桥（class 0x06 / subclass 0x01）");

    let mut virtio = 0u32;
    let mut virtio_ok = true;
    for device in table.devices() {
        if device.header.vendor != 0x1AF4 || !virtio_id(device.header.device) {
            continue;
        }
        virtio += 1;
        virtio_ok &= device.bar_count() > 0;
        virtio_ok &= device.bars.iter().all(bar_size_ok);
    }
    check(virtio_ok, "virtio 设备的 BAR 缺失、尺寸为零或不是 2 的幂");

    let valid = Bdf::new(0, 0, 0);
    let invalid_bdf = Bdf::new(0, 32, 0).is_none()
        && Bdf::new(0, 0, 8).is_none()
        && valid.and_then(|b| legacy_address(b, 1)).is_none()
        && valid.and_then(|b| legacy_address(b, 0x100)).is_none();
    check(invalid_bdf, "非法 BDF / 非法配置偏移未被拒绝");

    let window = Ecam { base: 0xE000_0000, segment: 0, bus_start: 0, bus_end: 0xFF };
    let ecam_rejects = valid.and_then(|b| window.address(b, 0x1000)).is_none()
        && valid.and_then(|b| window.address(b, 2)).is_none();
    check(ecam_rejects, "ECAM 窗口外的偏移未被拒绝");

    kprintln!(
        "[JSR-PCI] demo host_bridge={} isa_bridge={} virtio={} invalid_bdf={} bars_restored={}",
        host_bridge,
        isa_bridge,
        virtio,
        invalid_bdf,
        table.restored
    );
    kprintln!(
        "[JSR-PCI] summary mechanism={} functions={} bars={} checks={} failed={}",
        table.mechanism.as_str(),
        table.functions(),
        table.bars,
        CHECKS.load(Ordering::Relaxed),
        FAILED.load(Ordering::Relaxed)
    );
}
