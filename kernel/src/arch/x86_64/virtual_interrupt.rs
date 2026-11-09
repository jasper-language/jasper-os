//! x86 virtual PIC, I/O APIC and PIT state for HWV-4.

pub const PIC_IRQ_COUNT: usize = 16;
pub const IOAPIC_GSI_COUNT: usize = 24;
pub const PENDING_LIMIT: usize = 32;
pub const FIRST_EXTERNAL: u8 = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterruptError {
    IrqOutOfRange,
    GsiOutOfRange,
    GsiUnmapped,
    InvalidVector,
    InvalidPeriod,
    PendingQueueFull,
    NotInService,
}

impl InterruptError {
    pub const fn name(self) -> &'static str {
        match self {
            InterruptError::IrqOutOfRange => "system.hwvirt.interrupt.error.irq_out_of_range",
            InterruptError::GsiOutOfRange => "system.hwvirt.interrupt.error.gsi_out_of_range",
            InterruptError::GsiUnmapped => "system.hwvirt.interrupt.error.gsi_unmapped",
            InterruptError::InvalidVector => "system.hwvirt.interrupt.error.invalid_vector",
            InterruptError::InvalidPeriod => "system.hwvirt.interrupt.error.invalid_period",
            InterruptError::PendingQueueFull => "system.hwvirt.interrupt.error.pending_queue_full",
            InterruptError::NotInService => "system.hwvirt.interrupt.error.not_in_service",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RaiseResult {
    Queued(u8),
    Masked,
    AlreadyPending(u8),
}

#[derive(Clone, Copy)]
struct IoRedirection {
    vector: u8,
    destination: u8,
    masked: bool,
}

impl IoRedirection {
    const MASKED: Self = Self {
        vector: 0,
        destination: 0,
        masked: true,
    };
}

#[derive(Clone, Copy)]
struct Pit {
    vector: u8,
    period: u32,
    remaining: u32,
}

/// Finite virtual interrupt-controller state for the first HWV-4 checkpoint.
pub struct VirtualInterruptController {
    pic_mask: u16,
    io: [IoRedirection; IOAPIC_GSI_COUNT],
    pit: Option<Pit>,
    pending: [u8; PENDING_LIMIT],
    pending_head: usize,
    pending_len: usize,
    in_service: [u64; 4],
    raised: u64,
    delivered: u64,
    eois: u64,
}

impl VirtualInterruptController {
    pub const fn new() -> Self {
        Self {
            pic_mask: u16::MAX,
            io: [IoRedirection::MASKED; IOAPIC_GSI_COUNT],
            pit: None,
            pending: [0; PENDING_LIMIT],
            pending_head: 0,
            pending_len: 0,
            in_service: [0; 4],
            raised: 0,
            delivered: 0,
            eois: 0,
        }
    }

    pub const fn pic_irq_vector(irq: u8) -> u8 {
        FIRST_EXTERNAL + irq
    }

    pub fn set_pic_mask(&mut self, irq: u8, masked: bool) -> Result<(), InterruptError> {
        if irq as usize >= PIC_IRQ_COUNT {
            return Err(InterruptError::IrqOutOfRange);
        }
        let bit = 1u16 << irq;
        if masked {
            self.pic_mask |= bit;
        } else {
            self.pic_mask &= !bit;
        }
        Ok(())
    }

    pub fn raise_pic(&mut self, irq: u8) -> Result<RaiseResult, InterruptError> {
        if irq as usize >= PIC_IRQ_COUNT {
            return Err(InterruptError::IrqOutOfRange);
        }
        if self.pic_mask & (1u16 << irq) != 0 {
            return Ok(RaiseResult::Masked);
        }
        self.queue(Self::pic_irq_vector(irq))
    }

    pub fn route_ioapic(
        &mut self,
        gsi: u8,
        vector: u8,
        destination: u8,
    ) -> Result<(), InterruptError> {
        if gsi as usize >= IOAPIC_GSI_COUNT {
            return Err(InterruptError::GsiOutOfRange);
        }
        if !valid_external_vector(vector) {
            return Err(InterruptError::InvalidVector);
        }
        self.io[gsi as usize] = IoRedirection {
            vector,
            destination,
            masked: false,
        };
        Ok(())
    }

    pub fn mask_ioapic(&mut self, gsi: u8) -> Result<(), InterruptError> {
        if gsi as usize >= IOAPIC_GSI_COUNT {
            return Err(InterruptError::GsiOutOfRange);
        }
        self.io[gsi as usize].masked = true;
        Ok(())
    }

    pub fn raise_ioapic(&mut self, gsi: u8) -> Result<RaiseResult, InterruptError> {
        if gsi as usize >= IOAPIC_GSI_COUNT {
            return Err(InterruptError::GsiOutOfRange);
        }
        let route = self.io[gsi as usize];
        if route.masked || !valid_external_vector(route.vector) {
            return Ok(RaiseResult::Masked);
        }
        self.queue(route.vector)
    }

    pub fn ioapic_destination(&self, gsi: u8) -> Result<u8, InterruptError> {
        if gsi as usize >= IOAPIC_GSI_COUNT {
            return Err(InterruptError::GsiOutOfRange);
        }
        let route = self.io[gsi as usize];
        if route.masked || !valid_external_vector(route.vector) {
            Err(InterruptError::GsiUnmapped)
        } else {
            Ok(route.destination)
        }
    }

    pub fn arm_pit(&mut self, vector: u8, period_ticks: u32) -> Result<(), InterruptError> {
        if !valid_external_vector(vector) {
            return Err(InterruptError::InvalidVector);
        }
        if period_ticks == 0 {
            return Err(InterruptError::InvalidPeriod);
        }
        self.pit = Some(Pit {
            vector,
            period: period_ticks,
            remaining: period_ticks,
        });
        Ok(())
    }

    pub fn disarm_pit(&mut self) {
        self.pit = None;
    }

    pub fn tick(&mut self) -> Result<Option<RaiseResult>, InterruptError> {
        let Some(pit) = self.pit.as_mut() else {
            return Ok(None);
        };
        pit.remaining -= 1;
        if pit.remaining != 0 {
            return Ok(None);
        }
        let vector = pit.vector;
        pit.remaining = pit.period;
        self.queue(vector).map(Some)
    }

    pub fn take_pending(&mut self) -> Option<u8> {
        if self.pending_len == 0 {
            return None;
        }
        let vector = self.pending[self.pending_head];
        self.pending_head = (self.pending_head + 1) % PENDING_LIMIT;
        self.pending_len -= 1;
        if self.in_service_bit(vector) {
            return self.take_pending();
        }
        let word = vector as usize / 64;
        let bit = vector as usize % 64;
        self.in_service[word] |= 1u64 << bit;
        self.delivered = self.delivered.saturating_add(1);
        Some(vector)
    }

    pub fn eoi(&mut self, vector: u8) -> Result<(), InterruptError> {
        if !valid_external_vector(vector) {
            return Err(InterruptError::InvalidVector);
        }
        if !self.in_service_bit(vector) {
            return Err(InterruptError::NotInService);
        }
        let word = vector as usize / 64;
        let bit = vector as usize % 64;
        self.in_service[word] &= !(1u64 << bit);
        self.eois = self.eois.saturating_add(1);
        Ok(())
    }

    pub fn pending_count(&self) -> usize {
        self.pending_len
    }

    pub fn in_service(&self, vector: u8) -> bool {
        valid_external_vector(vector) && self.in_service_bit(vector)
    }

    pub fn raised(&self) -> u64 {
        self.raised
    }

    pub fn delivered(&self) -> u64 {
        self.delivered
    }

    pub fn eois(&self) -> u64 {
        self.eois
    }

    fn queue(&mut self, vector: u8) -> Result<RaiseResult, InterruptError> {
        if !valid_external_vector(vector) {
            return Err(InterruptError::InvalidVector);
        }
        if self.pending_contains(vector) || self.in_service_bit(vector) {
            return Ok(RaiseResult::AlreadyPending(vector));
        }
        if self.pending_len == PENDING_LIMIT {
            return Err(InterruptError::PendingQueueFull);
        }
        let tail = (self.pending_head + self.pending_len) % PENDING_LIMIT;
        self.pending[tail] = vector;
        self.pending_len += 1;
        self.raised = self.raised.saturating_add(1);
        Ok(RaiseResult::Queued(vector))
    }

    fn pending_contains(&self, vector: u8) -> bool {
        (0..self.pending_len)
            .any(|i| self.pending[(self.pending_head + i) % PENDING_LIMIT] == vector)
    }

    fn in_service_bit(&self, vector: u8) -> bool {
        let word = vector as usize / 64;
        let bit = vector as usize % 64;
        self.in_service[word] & (1u64 << bit) != 0
    }
}

impl Default for VirtualInterruptController {
    fn default() -> Self {
        Self::new()
    }
}

pub const fn valid_external_vector(vector: u8) -> bool {
    vector >= FIRST_EXTERNAL
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_pending_and_eoi_keep_single_delivery() {
        let mut c = VirtualInterruptController::new();
        assert_eq!(c.raise_pic(0), Ok(RaiseResult::Masked));
        c.set_pic_mask(0, false).unwrap();
        assert_eq!(c.raise_pic(0), Ok(RaiseResult::Queued(32)));
        assert_eq!(c.raise_pic(0), Ok(RaiseResult::AlreadyPending(32)));
        assert_eq!(c.take_pending(), Some(32));
        assert!(c.in_service(32));
        assert_eq!(c.take_pending(), None);
        c.eoi(32).unwrap();
        assert_eq!(c.raise_pic(0), Ok(RaiseResult::Queued(32)));
        assert_eq!(c.delivered(), 1);
    }

    #[test]
    fn routes_and_timer_are_bounded() {
        let mut c = VirtualInterruptController::new();
        c.route_ioapic(4, 0x30, 3).unwrap();
        assert_eq!(c.ioapic_destination(4), Ok(3));
        assert_eq!(c.raise_ioapic(4), Ok(RaiseResult::Queued(0x30)));
        c.arm_pit(0x21, 2).unwrap();
        assert_eq!(c.tick(), Ok(None));
        assert_eq!(c.tick(), Ok(Some(RaiseResult::Queued(0x21))));
        assert_eq!(
            c.route_ioapic(24, 0x31, 0),
            Err(InterruptError::GsiOutOfRange)
        );
        assert_eq!(c.arm_pit(0x21, 0), Err(InterruptError::InvalidPeriod));
    }
}
