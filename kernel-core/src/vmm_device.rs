//! Vendor-neutral guest-facing virtio-MMIO device contract.
//!
//! This module owns only the architectural register and queue state consumed
//! by a guest virtio driver. It performs no DMA and generates no host effect;
//! backends provide those separately so reset, queue publication and interrupt
//! acknowledgement remain one testable state machine.

pub const MMIO_MAGIC: u32 = 0x7472_6976;
pub const MMIO_VERSION: u32 = 2;
pub const QUEUE_COUNT: usize = 4;
pub const CONFIG_OFFSET: u64 = 0x100;

pub const STATUS_ACKNOWLEDGE: u8 = 1 << 0;
pub const STATUS_DRIVER: u8 = 1 << 1;
pub const STATUS_DRIVER_OK: u8 = 1 << 2;
pub const STATUS_FEATURES_OK: u8 = 1 << 3;
pub const STATUS_NEEDS_RESET: u8 = 1 << 6;
pub const STATUS_FAILED: u8 = 1 << 7;
pub const STATUS_KNOWN: u8 =
    STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_DRIVER_OK | STATUS_FEATURES_OK | STATUS_NEEDS_RESET | STATUS_FAILED;

pub const FEATURE_NOTIFY_ON_EMPTY: u32 = 1 << 24;
pub const FEATURE_RING_INDIRECT_DESC: u32 = 1 << 28;
pub const FEATURE_RING_EVENT_IDX: u32 = 1 << 29;
pub const FEATURE_VERSION_1: u32 = 1 << 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtioDeviceType {
    Gpu,
    Net,
    Block,
    Console,
    Rng,
    Fs,
}

impl VirtioDeviceType {
    pub const fn id(self) -> u32 {
        match self {
            VirtioDeviceType::Gpu => 5,
            VirtioDeviceType::Net => 1,
            VirtioDeviceType::Block => 2,
            VirtioDeviceType::Console => 3,
            VirtioDeviceType::Rng => 4,
            VirtioDeviceType::Fs => 26,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            VirtioDeviceType::Gpu => "virtio-gpu",
            VirtioDeviceType::Net => "virtio-net",
            VirtioDeviceType::Block => "virtio-blk",
            VirtioDeviceType::Console => "virtio-console",
            VirtioDeviceType::Rng => "virtio-rng",
            VirtioDeviceType::Fs => "virtio-fs",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MmioError {
    Misaligned,
    UnsupportedWidth,
    UnknownRegister,
    QueueOutOfRange,
    QueueSize,
    QueueNotReady,
}

impl MmioError {
    pub const fn name(self) -> &'static str {
        match self {
            MmioError::Misaligned => "system.device.error.mmio_misaligned",
            MmioError::UnsupportedWidth => "system.device.error.mmio_width",
            MmioError::UnknownRegister => "system.device.error.mmio_unknown_register",
            MmioError::QueueOutOfRange => "system.device.error.virtio_queue_index",
            MmioError::QueueSize => "system.device.error.virtio_bad_queue_size",
            MmioError::QueueNotReady => "system.device.error.virtio_queue_not_ready",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QueueAddress {
    pub descriptor: u64,
    pub driver: u64,
    pub device: u64,
}

impl QueueAddress {
    pub const fn zero() -> Self {
        Self { descriptor: 0, driver: 0, device: 0 }
    }

    pub const fn complete(self) -> bool {
        self.descriptor != 0 && self.driver != 0 && self.device != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueState {
    pub max_size: u16,
    pub size: u16,
    pub ready: bool,
    pub address: QueueAddress,
}

impl QueueState {
    pub const fn new(max_size: u16) -> Self {
        Self { max_size, size: 0, ready: false, address: QueueAddress::zero() }
    }

    fn reset(&mut self) {
        self.size = 0;
        self.ready = false;
        self.address = QueueAddress::zero();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmioWrite {
    pub interrupt: bool,
    pub queue_notified: Option<u16>,
}

impl MmioWrite {
    const NONE: Self = Self { interrupt: false, queue_notified: None };
}

pub struct VirtioMmio {
    device: VirtioDeviceType,
    status: u8,
    device_features: [u32; 2],
    driver_features: [u32; 2],
    feature_select: u32,
    driver_feature_select: u32,
    queue_select: u16,
    queues: [QueueState; QUEUE_COUNT],
    interrupt_status: u32,
    config_generation: u32,
}

impl VirtioMmio {
    pub const fn new(device: VirtioDeviceType, queue_size: u16, device_features: [u32; 2]) -> Self {
        Self {
            device,
            status: 0,
            device_features,
            driver_features: [0; 2],
            feature_select: 0,
            driver_feature_select: 0,
            queue_select: 0,
            queues: [
                QueueState::new(queue_size),
                QueueState::new(queue_size),
                QueueState::new(queue_size),
                QueueState::new(queue_size),
            ],
            interrupt_status: 0,
            config_generation: 0,
        }
    }

    pub const fn device(&self) -> VirtioDeviceType {
        self.device
    }

    pub const fn status(&self) -> u8 {
        self.status
    }

    pub const fn driver_features(&self) -> [u32; 2] {
        self.driver_features
    }

    pub const fn queue(&self, index: u16) -> Option<QueueState> {
        if index as usize >= QUEUE_COUNT {
            return None;
        }
        Some(self.queues[index as usize])
    }

    pub fn interrupt_status(&self) -> u32 {
        self.interrupt_status
    }

    pub fn raise_interrupt(&mut self, bits: u32) {
        self.interrupt_status |= bits;
    }

    pub fn bump_config(&mut self) {
        self.config_generation = self.config_generation.wrapping_add(1);
    }

    pub fn read(&self, offset: u64, width: u8) -> Result<u64, MmioError> {
        check_access(offset, width)?;
        let value = match offset {
            0x000 => u64::from(MMIO_MAGIC),
            0x004 => u64::from(MMIO_VERSION),
            0x008 => u64::from(self.device.id()),
            0x00c => 0,
            0x010 => self.device_features[self.feature_select as usize & 1] as u64,
            0x014 => u64::from(self.feature_select),
            0x020 => self.driver_features[self.driver_feature_select as usize & 1] as u64,
            0x024 => u64::from(self.driver_feature_select),
            0x030 => u64::from(self.queue_select),
            0x034 => u64::from(self.selected_queue()?.max_size),
            0x038 => u64::from(self.selected_queue()?.size),
            0x044 => u64::from(self.selected_queue()?.ready),
            0x060 => u64::from(self.interrupt_status),
            0x070 => u64::from(self.status),
            0x080 => self.selected_queue()?.address.descriptor,
            0x084 => self.selected_queue()?.address.descriptor >> 32,
            0x090 => self.selected_queue()?.address.driver,
            0x094 => self.selected_queue()?.address.driver >> 32,
            0x0a0 => self.selected_queue()?.address.device,
            0x0a4 => self.selected_queue()?.address.device >> 32,
            0x0fc => u64::from(self.config_generation),
            CONFIG_OFFSET.. => 0,
            _ => return Err(MmioError::UnknownRegister),
        };
        Ok(value & width_mask(width))
    }

    pub fn write(&mut self, offset: u64, width: u8, value: u64) -> Result<MmioWrite, MmioError> {
        check_access(offset, width)?;
        let value = value & width_mask(width);
        match offset {
            0x014 => self.feature_select = value as u32,
            0x024 => self.driver_feature_select = value as u32,
            0x020 => self.driver_features[self.driver_feature_select as usize & 1] = value as u32,
            0x030 => {
                if value as usize >= QUEUE_COUNT {
                    return Err(MmioError::QueueOutOfRange);
                }
                self.queue_select = value as u16;
            }
            0x038 => {
                let selected = self.queue_select as usize;
                let max = self.queues[selected].max_size;
                let size = value as u16;
                if size != 0 && (size > max || !size.is_power_of_two()) {
                    return Err(MmioError::QueueSize);
                }
                self.queues[selected].size = size;
            }
            0x044 => {
                let selected = self.queue_select as usize;
                let queue = &mut self.queues[selected];
                if value != 0 {
                    // A queue address of zero is a valid GPA. The spec does not
                    // reserve all-zero addresses, so queue size is the readiness
                    // fact; the backend must still bounds-check every descriptor.
                    if queue.size == 0 {
                        return Err(MmioError::QueueNotReady);
                    }
                }
                queue.ready = value != 0;
            }
            0x050 => {
                let queue = self.queue_select;
                if !self.selected_queue()?.ready {
                    return Err(MmioError::QueueNotReady);
                }
                return Ok(MmioWrite { queue_notified: Some(queue), ..MmioWrite::NONE });
            }
            0x064 => {
                self.interrupt_status &= !(value as u32);
            }
            0x070 => {
                if value == 0 {
                    self.reset();
                } else {
                    self.status = value as u8 & STATUS_KNOWN;
                }
            }
            0x080 => {
                let queue = self.selected_queue_mut()?;
                queue.address.descriptor = (queue.address.descriptor & !0xffff_ffff) | value;
            }
            0x084 => {
                let queue = self.selected_queue_mut()?;
                queue.address.descriptor =
                    (queue.address.descriptor & 0xffff_ffff) | (value << 32);
            }
            0x090 => {
                let queue = self.selected_queue_mut()?;
                queue.address.driver = (queue.address.driver & !0xffff_ffff) | value;
            }
            0x094 => {
                let queue = self.selected_queue_mut()?;
                queue.address.driver = (queue.address.driver & 0xffff_ffff) | (value << 32);
            }
            0x0a0 => {
                let queue = self.selected_queue_mut()?;
                queue.address.device = (queue.address.device & !0xffff_ffff) | value;
            }
            0x0a4 => {
                let queue = self.selected_queue_mut()?;
                queue.address.device = (queue.address.device & 0xffff_ffff) | (value << 32);
            }
            _ => return Err(MmioError::UnknownRegister),
        }
        Ok(MmioWrite::NONE)
    }

    fn reset(&mut self) {
        self.status = 0;
        self.driver_features = [0; 2];
        self.feature_select = 0;
        self.driver_feature_select = 0;
        self.queue_select = 0;
        self.interrupt_status = 0;
        for queue in &mut self.queues {
            queue.reset();
        }
    }

    fn selected_queue(&self) -> Result<&QueueState, MmioError> {
        self.queues.get(self.queue_select as usize).ok_or(MmioError::QueueOutOfRange)
    }

    fn selected_queue_mut(&mut self) -> Result<&mut QueueState, MmioError> {
        self.queues.get_mut(self.queue_select as usize).ok_or(MmioError::QueueOutOfRange)
    }
}

fn check_access(offset: u64, width: u8) -> Result<(), MmioError> {
    if !matches!(width, 1 | 2 | 4 | 8) {
        return Err(MmioError::UnsupportedWidth);
    }
    if offset % u64::from(width) != 0 {
        return Err(MmioError::Misaligned);
    }
    Ok(())
}

const fn width_mask(width: u8) -> u64 {
    if width == 8 { u64::MAX } else { (1u64 << (width as u32 * 8)) - 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device() -> VirtioMmio {
        VirtioMmio::new(
            VirtioDeviceType::Fs,
            8,
            [FEATURE_RING_INDIRECT_DESC, FEATURE_VERSION_1],
        )
    }

    #[test]
    fn identity_features_and_failure_atomic_queue_setup() {
        let mut d = device();
        assert_eq!(d.read(0, 4), Ok(u64::from(MMIO_MAGIC)));
        assert_eq!(d.read(4, 4), Ok(u64::from(MMIO_VERSION)));
        assert_eq!(d.read(8, 4), Ok(26));
        d.write(0x014, 4, 1).unwrap();
        assert_eq!(d.read(0x010, 4), Ok(u64::from(FEATURE_VERSION_1)));
        d.write(0x030, 4, QUEUE_COUNT as u64).unwrap_err();
        d.write(0x030, 4, 0).unwrap();
        d.write(0x038, 4, 3).unwrap_err();
        assert_eq!(d.queue(0).unwrap().size, 0);
        d.write(0x038, 4, 8).unwrap();
        d.write(0x044, 4, 1).unwrap();
        assert!(d.queue(0).unwrap().ready);
    }

    #[test]
    fn queue_publication_notify_and_reset_are_explicit() {
        let mut d = device();
        d.write(0x030, 4, 0).unwrap();
        d.write(0x038, 4, 8).unwrap();
        d.write(0x080, 8, 0x1000).unwrap();
        d.write(0x090, 8, 0x2000).unwrap();
        d.write(0x0a0, 8, 0x3000).unwrap();
        d.write(0x044, 4, 1).unwrap();
        assert_eq!(
            d.queue(0).unwrap().address,
            QueueAddress { descriptor: 0x1000, driver: 0x2000, device: 0x3000 }
        );
        let write = d.write(0x050, 4, 0).unwrap();
        assert_eq!(write.queue_notified, Some(0));
        d.raise_interrupt(3);
        d.write(0x064, 4, 1).unwrap();
        assert_eq!(d.interrupt_status(), 2);
        d.write(0x070, 1, u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER)).unwrap();
        d.write(0x070, 1, 0).unwrap();
        assert_eq!(d.status(), 0);
        assert_eq!(d.queue(0).unwrap(), QueueState::new(8));
        assert_eq!(d.interrupt_status(), 0);
    }

    #[test]
    fn zero_gpa_is_a_valid_queue_address() {
        let mut d = device();
        d.write(0x038, 4, 8).unwrap();
        d.write(0x044, 4, 1).unwrap();
        assert!(d.queue(0).unwrap().ready);
        assert_eq!(d.queue(0).unwrap().address, QueueAddress::zero());
    }

    #[test]
    fn access_validation_is_failure_atomic() {
        let mut d = device();
        assert_eq!(d.write(1, 2, 0), Err(MmioError::Misaligned));
        assert_eq!(d.read(0, 3), Err(MmioError::UnsupportedWidth));
        assert_eq!(d.write(0x018, 4, 1), Err(MmioError::UnknownRegister));
        assert_eq!(d.read(0x018, 4), Err(MmioError::UnknownRegister));
        assert_eq!(d.status(), 0);
    }
}
