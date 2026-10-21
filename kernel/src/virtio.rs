//! 现代 virtio 1.x PCI 传输的最小实现：能力区定位、特性协商、队列建立、通知与 ISR。
//! Minimal modern virtio 1.x PCI transport: capability windows, feature negotiation, queue setup and notification.
//!
//! # 职责
//! * 沿已解析的厂商能力定位 common / notify / ISR / device 配置区，经 [`crate::mmio`] 映射为不可缓存窗口。
//! * 实现设备复位、状态位推进、`VIRTIO_F_VERSION_1` 协商与回读校验。
//! * 用从全局页帧分配器取得的四页连续物理内存建立一条队列（描述符表 / 可用环 / 已用环 / 缓冲区）。
//! * 提交单个设备可写描述符、通知设备，并读取已用环与 ISR 状态。
//!
//! # 边界
//! * 只服务本轮的送达演练：一条队列、固定 64 字节缓冲区、单描述符请求；不实现多队列、间接描述符或事件抑制。
//! * 不含任何指令集专有值；队列内存在全物理内存映射中访问，寄存器经 BAR 映射访问。
//! * 不注册中断处理函数、不决定 MSI-X 向量；这些由演练层完成。

use core::sync::atomic::{fence, Ordering};

use kernel_core::device::{CAP_CFG_COMMON, CAP_CFG_DEVICE, CAP_CFG_ISR, CAP_CFG_NOTIFY};
use kernel_core::frame::{PhysFrame, FRAME_SIZE};
use kernel_core::pci::{Bar, Bdf};

use crate::mmio::{Mapping, MmioError};
use crate::{mm, pci, sched};

/// virtio 设备的 PCI 厂商号。
/// PCI vendor ID of virtio devices.
pub const VIRTIO_VENDOR: u16 = 0x1AF4;
/// 传统（transitional）virtio-rng 的设备号。
/// Legacy/transitional virtio-rng device ID.
pub const RNG_DEVICE_LEGACY: u16 = 0x1005;
/// 仅现代（modern-only）virtio-rng 的设备号。
/// Modern-only virtio-rng device ID.
pub const RNG_DEVICE_MODERN: u16 = 0x1044;

/// 设备状态：已确认。
pub const STATUS_ACKNOWLEDGE: u8 = 1;
/// 设备状态：驱动已装载。
pub const STATUS_DRIVER: u8 = 2;
/// 设备状态：驱动就绪。
pub const STATUS_DRIVER_OK: u8 = 4;
/// 设备状态：特性已确认。
pub const STATUS_FEATURES_OK: u8 = 8;
/// 设备状态：驱动出错。
pub const STATUS_FAILED: u8 = 128;

/// `VIRTIO_F_VERSION_1` 位于设备特性第 1 页的第 0 位。
/// `VIRTIO_F_VERSION_1` is bit 0 of feature page 1.
const VIRTIO_F_VERSION_1: u32 = 1 << 0;
/// 描述符标志：设备可写。
/// Descriptor flag: device-writable buffer.
const VIRTQ_DESC_F_WRITE: u16 = 2;

/// 通用配置各寄存器的字节偏移。
const COMMON_DEVICE_FEATURE_SELECT: u64 = 0x00;
const COMMON_DEVICE_FEATURE: u64 = 0x04;
const COMMON_DRIVER_FEATURE_SELECT: u64 = 0x08;
const COMMON_DRIVER_FEATURE: u64 = 0x0C;
const COMMON_DEVICE_STATUS: u64 = 0x14;
const COMMON_QUEUE_SELECT: u64 = 0x16;
const COMMON_QUEUE_SIZE: u64 = 0x18;
const COMMON_QUEUE_MSIX_ENTRY: u64 = 0x1A;
const COMMON_QUEUE_ENABLE: u64 = 0x1C;
const COMMON_QUEUE_NOTIFY_OFF: u64 = 0x1E;
const COMMON_QUEUE_DESC: u64 = 0x20;
const COMMON_QUEUE_DRIVER: u64 = 0x28;
const COMMON_QUEUE_DEVICE: u64 = 0x30;

/// 复位等待上界（调度器 tick）。
const RESET_TICKS: u64 = 100;
/// 每次演练使用的队列项数上限。
const WANTED_QUEUE_SIZE: u16 = 16;
/// 每个描述符指向的缓冲区字节数。
pub const BUFFER_BYTES: usize = 64;
/// 队列占用的连续物理页数：描述符表 / 可用环 / 已用环 / 缓冲区各一页。
const QUEUE_PAGES: usize = 4;

/// virtio 传输错误。
/// virtio transport error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtioError {
    /// 设备缺少现代 virtio 所需的厂商能力。
    /// The device lacks a capability required by modern virtio.
    NoModernCapability,
    /// 通知能力没有可读的偏移倍率。
    /// The notification capability has no readable offset multiplier.
    NoNotifyMultiplier,
    /// 能力指向的 BAR 区间无法映射。
    /// A capability window cannot be mapped.
    MapFailed(MmioError),
    /// 设备报告的队列大小不可用。
    /// The device reports an unusable queue size.
    BadQueueSize,
    /// 设备拒绝队列的 MSI-X 向量（回读 0xFFFF）。
    /// The device rejected the queue MSI-X vector.
    QueueVectorRejected,
    /// 复位在限定 tick 内没有完成。
    /// Reset did not complete within the tick bound.
    ResetTimeout,
    /// 设备不支持 `VIRTIO_F_VERSION_1`。
    /// The device does not offer `VIRTIO_F_VERSION_1`.
    Version1Unavailable,
    /// 写入 `FEATURES_OK` 后设备没有确认。
    /// The device did not acknowledge `FEATURES_OK`.
    FeatureRejected,
    /// 没有取得物理连续的队列页。
    /// No physically contiguous queue pages were available.
    NoContiguousFrames,
    /// 物理内存线性映射不可用。
    /// The linear physical-memory mapping is unavailable.
    NoPhysMap,
    /// 通知地址超出已映射的通知窗口。
    /// The notification address falls outside the mapped window.
    NotifyOutOfWindow,
}

impl VirtioError {
    /// 规范名。
    /// Canonical name.
    pub const fn name(self) -> &'static str {
        match self {
            VirtioError::NoModernCapability => "system.device.error.virtio_no_modern_capability",
            VirtioError::NoNotifyMultiplier => "system.device.error.virtio_no_notify_multiplier",
            VirtioError::MapFailed(reason) => reason.name(),
            VirtioError::BadQueueSize => "system.device.error.virtio_bad_queue_size",
            VirtioError::QueueVectorRejected => "system.device.error.virtio_queue_vector_rejected",
            VirtioError::ResetTimeout => "system.device.error.virtio_reset_timeout",
            VirtioError::Version1Unavailable => "system.device.error.virtio_version1_unavailable",
            VirtioError::FeatureRejected => "system.device.error.virtio_feature_rejected",
            VirtioError::NoContiguousFrames => "system.memory.error.out_of_frames",
            VirtioError::NoPhysMap => "system.device.error.virtio_no_phys_map",
            VirtioError::NotifyOutOfWindow => "system.device.error.virtio_notify_out_of_window",
        }
    }
}

impl From<MmioError> for VirtioError {
    fn from(reason: MmioError) -> VirtioError {
        VirtioError::MapFailed(reason)
    }
}

/// 一个 virtio-rng 设备是否属于本轮支持的设备号。
/// Whether a device ID denotes a virtio-rng device supported here.
pub const fn is_rng_device(device: u16) -> bool {
    device == RNG_DEVICE_LEGACY || device == RNG_DEVICE_MODERN
}

/// 现代 virtio PCI 传输句柄（四个能力窗口各持有一份映射）。
/// Modern virtio PCI transport handle with one mapping per capability window.
pub struct VirtioPci {
    bdf: Bdf,
    common: Mapping,
    notify: Mapping,
    isr: Mapping,
    device_config: Mapping,
    notify_multiplier: u32,
}

impl VirtioPci {
    /// 为已枚举设备建立传输句柄；缺少任一现代能力时返回 [`VirtioError::NoModernCapability`]。
    /// Builds a transport handle for an enumerated device.
    pub fn new(device: &pci::Device) -> Result<VirtioPci, VirtioError> {
        if device.caps_error {
            return Err(VirtioError::NoModernCapability);
        }
        let common = map_capability(device, CAP_CFG_COMMON, 0x40)?;
        let notify = map_capability(device, CAP_CFG_NOTIFY, 4)?;
        let isr = map_capability(device, CAP_CFG_ISR, 1)?;
        let device_config = map_capability(device, CAP_CFG_DEVICE, 4)?;
        let notify_multiplier = pci::notify_multiplier(device).ok_or(VirtioError::NoNotifyMultiplier)?;
        Ok(VirtioPci { bdf: device.bdf, common, notify, isr, device_config, notify_multiplier })
    }

    /// 设备地址。
    /// Device address.
    pub const fn bdf(&self) -> Bdf {
        self.bdf
    }

    /// 当前设备状态。
    /// Current device status.
    pub fn status(&self) -> u8 {
        // SAFETY：通用配置窗口已映射且覆盖状态寄存器。
        unsafe { self.common.read8(COMMON_DEVICE_STATUS) }
    }

    /// 写入设备状态（复位就是写 0）。
    /// Writes the device status.
    fn write_status(&self, value: u8) {
        // SAFETY：同 `status`；写入的是标准状态字节。
        unsafe { self.common.write8(COMMON_DEVICE_STATUS, value) };
    }

    /// 追加状态位。
    /// Adds status bits.
    pub fn add_status(&self, bits: u8) {
        self.write_status(self.status() | bits);
    }

    /// 复位设备并等待状态归零；超时返回 [`VirtioError::ResetTimeout`]。
    /// Resets the device and waits for the status to become zero.
    pub fn reset(&self) -> Result<(), VirtioError> {
        self.write_status(0);
        let start = sched::timer_ticks();
        while self.status() != 0 {
            if sched::timer_ticks().wrapping_sub(start) >= RESET_TICKS {
                return Err(VirtioError::ResetTimeout);
            }
            core::hint::spin_loop();
        }
        Ok(())
    }

    /// 读取设备特性的一页。
    /// Reads one page of device features.
    fn device_features(&self, page: u32) -> u32 {
        // SAFETY：选择寄存器与数据寄存器都在通用配置窗口内。
        unsafe {
            self.common.write32(COMMON_DEVICE_FEATURE_SELECT, page);
            self.common.read32(COMMON_DEVICE_FEATURE)
        }
    }

    /// 写入驱动特性的一页。
    /// Writes one page of driver features.
    fn driver_features(&self, page: u32, value: u32) {
        // SAFETY：同 `device_features`。
        unsafe {
            self.common.write32(COMMON_DRIVER_FEATURE_SELECT, page);
            self.common.write32(COMMON_DRIVER_FEATURE, value);
        }
    }

    /// 按现代传输协商 `VIRTIO_F_VERSION_1` 并确认 `FEATURES_OK`。
    ///
    /// 设备未提供该特性或写入后没有回读确认时返回结构化错误，调用者不得继续使用该设备。
    /// Negotiates `VIRTIO_F_VERSION_1` and confirms `FEATURES_OK`.
    pub fn negotiate_version_1(&self) -> Result<(), VirtioError> {
        self.add_status(STATUS_ACKNOWLEDGE);
        self.add_status(STATUS_DRIVER);
        let offered = self.device_features(1);
        if offered & VIRTIO_F_VERSION_1 == 0 {
            return Err(VirtioError::Version1Unavailable);
        }
        self.driver_features(0, 0);
        self.driver_features(1, VIRTIO_F_VERSION_1);
        self.add_status(STATUS_FEATURES_OK);
        if self.status() & STATUS_FEATURES_OK == 0 {
            return Err(VirtioError::FeatureRejected);
        }
        Ok(())
    }

    /// 建立队列 0 并请求 MSI-X 表项下标 `entry`；返回设备给出的 `queue_notify_off`。
    ///
    /// 这里的 `entry` 是 MSI-X 表项下标（0 起），不是处理器中断向量号：设备只索引自己的表。
    /// 设备报告的队列大小不足 2、回读不一致或拒绝该表项（回读 0xFFFF）时返回结构化错误。
    /// Sets up queue 0, requests an MSI-X table entry index, and returns the device's notify offset.
    pub fn setup_queue(&self, queue: &mut Queue, entry: u16) -> Result<u16, VirtioError> {
        // SAFETY：所有寄存器都在已映射的通用配置窗口内。
        unsafe {
            self.common.write16(COMMON_QUEUE_SELECT, 0);
            let offered = self.common.read16(COMMON_QUEUE_SIZE);
            if offered < 2 {
                return Err(VirtioError::BadQueueSize);
            }
            let size = offered.min(WANTED_QUEUE_SIZE);
            if !size.is_power_of_two() {
                return Err(VirtioError::BadQueueSize);
            }
            self.common.write16(COMMON_QUEUE_SIZE, size);
            if self.common.read16(COMMON_QUEUE_SIZE) != size {
                return Err(VirtioError::BadQueueSize);
            }
            let (desc, driver, device) = queue.addresses();
            self.common.write32(COMMON_QUEUE_DESC, desc as u32);
            self.common.write32(COMMON_QUEUE_DESC + 4, (desc >> 32) as u32);
            self.common.write32(COMMON_QUEUE_DRIVER, driver as u32);
            self.common.write32(COMMON_QUEUE_DRIVER + 4, (driver >> 32) as u32);
            self.common.write32(COMMON_QUEUE_DEVICE, device as u32);
            self.common.write32(COMMON_QUEUE_DEVICE + 4, (device >> 32) as u32);
            self.common.write16(COMMON_QUEUE_MSIX_ENTRY, entry);
            if self.common.read16(COMMON_QUEUE_MSIX_ENTRY) == 0xFFFF {
                return Err(VirtioError::QueueVectorRejected);
            }
            self.common.write16(COMMON_QUEUE_ENABLE, 1);
            queue.set_size(size);
            Ok(self.common.read16(COMMON_QUEUE_NOTIFY_OFF))
        }
    }

    /// 通知队列 0；`notify_off` 来自 [`VirtioPci::setup_queue`]。
    /// Notifies queue 0.
    pub fn notify(&self, notify_off: u16) -> Result<(), VirtioError> {
        let offset = notify_off as u64 * self.notify_multiplier as u64;
        if offset.checked_add(4).is_none_or(|end| end > self.notify.len()) {
            return Err(VirtioError::NotifyOutOfWindow);
        }
        // SAFETY：通知地址已校验在映射内；写入的队列号 0 是唯一的队列。
        unsafe { self.notify.write16(offset, 0) };
        Ok(())
    }

    /// 读取并清除设备 ISR 状态字节。
    /// Reads and clears the device ISR status byte.
    pub fn read_isr(&self) -> u8 {
        // SAFETY：ISR 能力窗口已映射至少 1 字节。
        unsafe { self.isr.read8(0) }
    }

    /// 读取设备专用配置的一个双字（virtio-rng 不使用，但保留通用读取能力）。
    /// Reads a dword of device-specific configuration.
    pub fn read_device_config32(&self, offset: u64) -> u32 {
        // SAFETY：调用者给出的偏移必须落在设备配置窗口内；本演练只用于诊断。
        unsafe { self.device_config.read32(offset) }
    }
}

/// 按能力类型映射一段 BAR 窗口；能力缺失或映射失败时返回结构化错误。
fn map_capability(
    device: &pci::Device,
    cfg_type: u8,
    minimum: u32,
) -> Result<Mapping, VirtioError> {
    let cap = device.caps[..device.cap_count]
        .iter()
        .find(|cap| cap.cfg_type == cfg_type)
        .ok_or(VirtioError::NoModernCapability)?;
    let bar = *device.bars.get(cap.bar as usize).ok_or(VirtioError::NoModernCapability)?;
    let length = cap.length.max(minimum);
    Ok(Mapping::map(&bar, cap.bar_offset, length)?)
}

/// 一条 virtio 队列的全部内存与游标。
///
/// 四页物理连续内存：描述符表、可用环、已用环、每个描述符 64 字节的缓冲区。
/// All memory and cursors of one virtio queue.
pub struct Queue {
    base: PhysFrame,
    desc: *mut u8,
    avail: *mut u8,
    used: *mut u8,
    buffers: *mut u8,
    desc_phys: u64,
    avail_phys: u64,
    used_phys: u64,
    size: u16,
    avail_idx: u16,
    used_idx: u16,
}

impl Queue {
    /// 分配四页物理连续内存并初始化描述符；失败时归还本次已分配的全部页帧。
    /// Allocates four physically contiguous pages and initialises the descriptors.
    pub fn new() -> Result<Queue, VirtioError> {
        let frames = allocate_contiguous()?;
        let base = frames[0];
        let desc_phys = frames[0].start();
        let avail_phys = frames[1].start();
        let used_phys = frames[2].start();
        let buffers_phys = frames[3].start();
        let Some(desc) = mm::phys_to_virt(desc_phys) else {
            release(base);
            return Err(VirtioError::NoPhysMap);
        };
        let Some(avail) = mm::phys_to_virt(avail_phys) else {
            release(base);
            return Err(VirtioError::NoPhysMap);
        };
        let Some(used) = mm::phys_to_virt(used_phys) else {
            release(base);
            return Err(VirtioError::NoPhysMap);
        };
        let Some(buffers) = mm::phys_to_virt(buffers_phys) else {
            release(base);
            return Err(VirtioError::NoPhysMap);
        };
        // SAFETY：四页都是本次独占取得的帧，线性映射覆盖全部物理内存。
        unsafe {
            core::ptr::write_bytes(desc, 0, FRAME_SIZE as usize);
            core::ptr::write_bytes(avail, 0, FRAME_SIZE as usize);
            core::ptr::write_bytes(used, 0, FRAME_SIZE as usize);
            core::ptr::write_bytes(buffers, 0, FRAME_SIZE as usize);
        }
        let mut queue = Queue {
            base,
            desc,
            avail,
            used,
            buffers,
            desc_phys,
            avail_phys,
            used_phys,
            size: WANTED_QUEUE_SIZE,
            avail_idx: 0,
            used_idx: 0,
        };
        queue.init_descriptors(buffers_phys);
        Ok(queue)
    }

    /// 实际使用的队列项数（由 [`VirtioPci::setup_queue`] 回写）。
    /// Number of usable queue entries.
    pub const fn size(&self) -> u16 {
        self.size
    }

    /// 三段队列内存的物理地址（描述符表 / 可用环 / 已用环）。
    /// Physical addresses of the descriptor table, available ring and used ring.
    pub const fn addresses(&self) -> (u64, u64, u64) {
        (self.desc_phys, self.avail_phys, self.used_phys)
    }

    /// 设置实际队列大小；超过本地描述符容量时按本地容量截断。
    /// Sets the usable queue size, clamped to the local descriptor capacity.
    fn set_size(&mut self, size: u16) {
        self.size = size.min(WANTED_QUEUE_SIZE);
    }

    /// 提交第 `descriptor` 号描述符到可用环（不做通知）。
    /// Publishes one descriptor in the available ring.
    pub fn submit(&mut self, descriptor: u16) -> Result<(), VirtioError> {
        if descriptor >= self.size {
            return Err(VirtioError::BadQueueSize);
        }
        let slot = (self.avail_idx % self.size) as usize;
        // SAFETY：可用环位于独占队列页内；环项与 idx 都是标准布局。
        unsafe {
            write_u16(self.avail.add(4 + slot * 2), descriptor);
            fence(Ordering::Release);
            write_u16(self.avail.add(2), self.avail_idx.wrapping_add(1));
        }
        fence(Ordering::SeqCst);
        self.avail_idx = self.avail_idx.wrapping_add(1);
        Ok(())
    }

    /// 已用环是否已推进；推进时返回 `(描述符号, 写入字节数)` 并移动本地游标。
    /// Takes one used-ring entry when the device has advanced the ring.
    pub fn take_used(&mut self) -> Option<(u16, u32)> {
        // SAFETY：已用环位于独占队列页内；先读 idx，再按游标读元素。
        let index = unsafe { read_u16(self.used.add(2)) };
        if index == self.used_idx {
            return None;
        }
        let slot = (self.used_idx % self.size) as usize;
        // SAFETY：`slot < size ≤ WANTED_QUEUE_SIZE`，元素布局为 id/len 各 32 位。
        let (id, len) = unsafe {
            let id = read_u32(self.used.add(4 + slot * 8));
            let len = read_u32(self.used.add(8 + slot * 8));
            (id, len)
        };
        fence(Ordering::Acquire);
        self.used_idx = self.used_idx.wrapping_add(1);
        Some((id as u16, len))
    }

    /// 已用环的当前下标（诊断用）。
    /// Current used-ring index.
    pub fn used_index(&self) -> u16 {
        self.used_idx
    }

    /// 初始化每个描述符：指向各自的 64 字节缓冲区，设备可写，无链。
    fn init_descriptors(&mut self, buffers_phys: u64) {
        for i in 0..WANTED_QUEUE_SIZE as usize {
            let at = i * 16;
            let addr = buffers_phys + (i * BUFFER_BYTES) as u64;
            // SAFETY：描述符表位于独占队列页内，`at + 16` 不越界。
            unsafe {
                write_u64(self.desc.add(at), addr);
                write_u32(self.desc.add(at + 8), BUFFER_BYTES as u32);
                write_u16(self.desc.add(at + 12), VIRTQ_DESC_F_WRITE);
                write_u16(self.desc.add(at + 14), 0);
            }
        }
        let _ = self.buffers;
    }
}

impl Drop for Queue {
    fn drop(&mut self) {
        let _ = mm::frame::deallocate_contiguous(self.base, QUEUE_PAGES);
    }
}

/// 分配四页物理连续的帧；失败时不留下已占用的帧。
fn allocate_contiguous() -> Result<[PhysFrame; QUEUE_PAGES], VirtioError> {
    let base = mm::frame::allocate_contiguous(QUEUE_PAGES).map_err(|_| VirtioError::NoContiguousFrames)?;
    Ok([
        base,
        PhysFrame::from_number(base.number() + 1),
        PhysFrame::from_number(base.number() + 2),
        PhysFrame::from_number(base.number() + 3),
    ])
}

/// 归还一组已取得的帧（初始化中途失败时使用）。
fn release(base: PhysFrame) {
    let _ = mm::frame::deallocate_contiguous(base, QUEUE_PAGES);
}

unsafe fn write_u16(at: *mut u8, value: u16) {
    core::ptr::write_unaligned(at as *mut u16, value);
}

unsafe fn write_u32(at: *mut u8, value: u32) {
    core::ptr::write_unaligned(at as *mut u32, value);
}

unsafe fn write_u64(at: *mut u8, value: u64) {
    core::ptr::write_unaligned(at as *mut u64, value);
}

unsafe fn read_u16(at: *const u8) -> u16 {
    core::ptr::read_unaligned(at as *const u16)
}

unsafe fn read_u32(at: *const u8) -> u32 {
    core::ptr::read_unaligned(at as *const u32)
}

impl VirtioPci {
    /// 用于诊断：设备专用配置区是否可读（返回偏移 0 的双字）。
    /// Diagnostic read of device-specific configuration offset 0.
    pub fn device_config_probe(&self) -> u32 {
        self.read_device_config32(0)
    }
}

/// `Bar` 的内存区间是否足以容纳一段能力窗口（供调用者做启动期诊断）。
/// Whether a BAR can hold a capability window.
pub fn bar_contains(bar: &Bar, offset: u32, length: u32) -> bool {
    match *bar {
        Bar::Memory { size, .. } => offset as u64 + length as u64 <= size,
        _ => false,
    }
}
