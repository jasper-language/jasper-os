//! Port-I/O decoding, claims and a small self-describing PIO device.
//!
//! PIO is deliberately separate from MMIO. The VMX backend decodes a single
//! non-string `IN`/`OUT` instruction into [`PioAccess`], routes its port through
//! a fixed [`PortMap`], and only then calls the claiming device. Unsupported
//! widths, string/repeated operations and unmapped ports fail without executing
//! a partial device action.

pub const PIO_PROBE_MAGIC: u32 = 0x4f49_504a; // "JPIO" little-endian
pub const PIO_PROBE_VERSION: u16 = 1;
pub const PIO_PROBE_DEVICE_ID: u16 = 0x5049;
pub const PIO_PROBE_BASE: u16 = 0x0500;
pub const PIO_PROBE_CONTROL: u64 = 0x00;
pub const PIO_PROBE_STATUS: u64 = 0x04;
pub const PIO_PROBE_GENERATION: u64 = 0x06;
pub const PIO_PROBE_COMMAND: u64 = 0x08;
pub const PIO_PROBE_WRITES: u64 = 0x0c;
pub const PIO_PROBE_LAST_COMMAND: u64 = 0x0e;
pub const PIO_PROBE_REQUESTS: u64 = 0x10;
pub const PIO_PROBE_CANCELS: u64 = 0x14;

pub const PIO_STATUS_READY: u8 = 1;
pub const PIO_STATUS_PENDING: u8 = 2;
pub const PIO_STATUS_CANCELLED: u8 = 4;
pub const PIO_COMMAND_RESET: u8 = 1;
pub const PIO_COMMAND_PING: u8 = 2;
pub const PIO_COMMAND_PEND: u8 = 3;
pub const PIO_COMMAND_CANCEL: u8 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PioDirection {
    In,
    Out,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PioWidth {
    Byte,
    Word,
    Dword,
}

impl PioWidth {
    pub const fn from_vmx_bits(bits: u64) -> Option<Self> {
        match bits & 0x7 {
            0 => Some(Self::Byte),
            1 => Some(Self::Word),
            3 => Some(Self::Dword),
            _ => None,
        }
    }

    pub const fn bytes(self) -> u8 {
        match self {
            Self::Byte => 1,
            Self::Word => 2,
            Self::Dword => 4,
        }
    }

    pub const fn mask(self) -> u64 {
        match self {
            Self::Byte => u8::MAX as u64,
            Self::Word => u16::MAX as u64,
            Self::Dword => u32::MAX as u64,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PioError {
    UnsupportedWidth,
    StringOperation,
    RepeatedOperation,
    InstructionLength,
    EmptyRange,
    RangeOverflow,
    PortConflict,
    UnmappedPort,
    Misaligned,
    UnknownRegister,
    NotReady,
}

impl PioError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::UnsupportedWidth => "system.device.error.pio_width",
            Self::StringOperation => "system.device.error.pio_string_unsupported",
            Self::RepeatedOperation => "system.device.error.pio_repeat_unsupported",
            Self::InstructionLength => "system.device.error.pio_instruction_length",
            Self::EmptyRange => "system.device.error.pio_empty_range",
            Self::RangeOverflow => "system.device.error.pio_range_overflow",
            Self::PortConflict => "system.device.error.pio_port_conflict",
            Self::UnmappedPort => "system.device.error.pio_unmapped_port",
            Self::Misaligned => "system.device.error.pio_misaligned",
            Self::UnknownRegister => "system.device.error.pio_unknown_register",
            Self::NotReady => "system.device.error.pio_not_ready",
        }
    }
}

/// One decoded, non-string x86 port access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PioAccess {
    pub direction: PioDirection,
    pub port: u16,
    pub width: PioWidth,
    pub register: u8,
    pub value: u64,
}

impl PioAccess {
    /// Decode VMX `EXIT_QUALIFICATION` plus the source/destination GPR value.
    ///
    /// String and REP forms are rejected because they transfer an unbounded
    /// number of elements and need a separate completion/cancellation model.
    pub fn decode_vmx(qualification: u64, instruction_length: u64, register_value: u64) -> Result<Self, PioError> {
        if qualification & (1 << 4) != 0 {
            return Err(PioError::StringOperation);
        }
        if qualification & (1 << 5) != 0 {
            return Err(PioError::RepeatedOperation);
        }
        if instruction_length == 0 {
            return Err(PioError::InstructionLength);
        }
        let width = PioWidth::from_vmx_bits(qualification).ok_or(PioError::UnsupportedWidth)?;
        let direction = if qualification & (1 << 3) != 0 {
            PioDirection::In
        } else {
            PioDirection::Out
        };
        let register = ((qualification >> 8) & 0xf) as u8;
        let port = ((qualification >> 16) & 0xffff) as u16;
        Ok(Self {
            direction,
            port,
            width,
            register,
            value: register_value & width.mask(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortRange {
    pub base: u16,
    pub len: u16,
}

impl PortRange {
    pub const fn new(base: u16, len: u16) -> Self {
        Self { base, len }
    }

    pub const fn contains(self, port: u16) -> bool {
        let offset = port as u32;
        let base = self.base as u32;
        offset >= base && offset < base + self.len as u32
    }

    pub const fn end_exclusive(self) -> u32 {
        self.base as u32 + self.len as u32
    }

    pub const fn valid(self) -> bool {
        self.len != 0 && self.end_exclusive() <= 0x1_0000
    }

    pub const fn overlaps(self, other: Self) -> bool {
        (self.base as u32) < other.end_exclusive() && (other.base as u32) < self.end_exclusive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortClaim {
    pub range: PortRange,
    pub token: u16,
}

/// Fixed-size port map. Allocation is rejected on overflow or overlap before
/// any existing claim is modified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortMap<const N: usize> {
    claims: [Option<PortClaim>; N],
}

impl<const N: usize> PortMap<N> {
    pub const fn new() -> Self {
        Self { claims: [None; N] }
    }

    /// Construction-time registration for static device layouts.
    ///
    /// Invalid or overlapping static claims are programming errors and panic
    /// at compile time when used in a const initializer.
    pub const fn with_claim(self, base: u16, len: u16, token: u16) -> Self {
        let mut this = self;
        let claim = PortClaim { range: PortRange::new(base, len), token };
        assert!(claim.range.valid(), "invalid PIO claim");
        let mut index = 0;
        while index < N {
            if let Some(existing) = this.claims[index] {
                assert!(!existing.range.overlaps(claim.range), "overlapping PIO claim");
            }
            index += 1;
        }
        index = 0;
        while index < N {
            if this.claims[index].is_none() {
                this.claims[index] = Some(claim);
                return this;
            }
            index += 1;
        }
        panic!("PIO port map full");
    }

    pub fn register(&mut self, range: PortRange, token: u16) -> Result<(), PioError> {
        if !range.valid() {
            return Err(if range.len == 0 {
                PioError::EmptyRange
            } else {
                PioError::RangeOverflow
            });
        }
        let slot = self
            .claims
            .iter()
            .position(Option::is_none)
            .ok_or(PioError::PortConflict)?;
        if self.claims.iter().flatten().any(|claim| claim.range.overlaps(range)) {
            return Err(PioError::PortConflict);
        }
        self.claims[slot] = Some(PortClaim { range, token });
        Ok(())
    }

    pub fn route(&self, port: u16) -> Option<u16> {
        self.claims
            .iter()
            .flatten()
            .find(|claim| claim.range.contains(port))
            .map(|claim| claim.token)
    }

    pub fn claims(&self) -> impl Iterator<Item = PortClaim> + '_ {
        self.claims.iter().flatten().copied()
    }
}

impl<const N: usize> Default for PortMap<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Small self-describing PIO device used to prove discovery, reset and
/// failure-atomic register handling on the real guest bus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PioProbe {
    generation: u16,
    writes: u32,
    requests: u32,
    cancels: u32,
    last_command: u8,
    ready: bool,
    pending: bool,
    cancelled: bool,
}

impl PioProbe {
    pub const fn new() -> Self {
        Self {
            generation: 1,
            writes: 0,
            requests: 0,
            cancels: 0,
            last_command: 0,
            ready: true,
            pending: false,
            cancelled: false,
        }
    }

    pub const fn generation(self) -> u16 {
        self.generation
    }

    pub const fn writes(self) -> u32 {
        self.writes
    }

    pub const fn last_command(self) -> u8 {
        self.last_command
    }

    pub const fn requests(self) -> u32 {
        self.requests
    }

    pub const fn cancels(self) -> u32 {
        self.cancels
    }

    fn check_access(offset: u64, width: PioWidth) -> Result<(), PioError> {
        let bytes = u64::from(width.bytes());
        if offset % bytes != 0 {
            return Err(PioError::Misaligned);
        }
        if !matches!(
            (offset, width),
            (PIO_PROBE_CONTROL, PioWidth::Dword)
                | (PIO_PROBE_STATUS, PioWidth::Word)
                | (PIO_PROBE_GENERATION, PioWidth::Word)
                | (PIO_PROBE_COMMAND, PioWidth::Byte)
                | (PIO_PROBE_WRITES, PioWidth::Dword)
                | (PIO_PROBE_LAST_COMMAND, PioWidth::Byte)
                | (PIO_PROBE_REQUESTS, PioWidth::Dword)
                | (PIO_PROBE_CANCELS, PioWidth::Dword)
        ) {
            return Err(PioError::UnknownRegister);
        }
        Ok(())
    }

    pub fn read(&self, offset: u64, width: PioWidth) -> Result<u64, PioError> {
        Self::check_access(offset, width)?;
        Ok(match offset {
            PIO_PROBE_CONTROL => {
                u64::from(PIO_PROBE_MAGIC)
                    | (u64::from(PIO_PROBE_VERSION) << 32)
                    | (u64::from(PIO_PROBE_DEVICE_ID) << 48)
            }
            PIO_PROBE_STATUS => u64::from(self.status()),
            PIO_PROBE_GENERATION => u64::from(self.generation),
            PIO_PROBE_COMMAND => 0,
            PIO_PROBE_WRITES => u64::from(self.writes),
            PIO_PROBE_LAST_COMMAND => u64::from(self.last_command),
            PIO_PROBE_REQUESTS => u64::from(self.requests),
            PIO_PROBE_CANCELS => u64::from(self.cancels),
            _ => return Err(PioError::UnknownRegister),
        })
    }

    pub fn write(&mut self, offset: u64, width: PioWidth, value: u64) -> Result<(), PioError> {
        Self::check_access(offset, width)?;
        match offset {
            PIO_PROBE_COMMAND => {
                let command = value as u8;
                match command {
                    PIO_COMMAND_RESET => {
                        self.generation =
                            self.generation.checked_add(1).ok_or(PioError::RangeOverflow)?;
                        self.writes = 0;
                        self.pending = false;
                        self.cancelled = false;
                    }
                    PIO_COMMAND_PING => {
                        self.writes = self.writes.checked_add(1).ok_or(PioError::RangeOverflow)?;
                    }
                    PIO_COMMAND_PEND => {
                        if self.pending {
                            return Err(PioError::NotReady);
                        }
                        self.requests =
                            self.requests.checked_add(1).ok_or(PioError::RangeOverflow)?;
                        self.pending = true;
                        self.cancelled = false;
                    }
                    PIO_COMMAND_CANCEL => {
                        if !self.pending {
                            return Err(PioError::NotReady);
                        }
                        self.cancels =
                            self.cancels.checked_add(1).ok_or(PioError::RangeOverflow)?;
                        self.pending = false;
                        self.cancelled = true;
                    }
                    _ => return Err(PioError::UnknownRegister),
                }
                self.last_command = command;
                self.ready = true;
                Ok(())
            }
            PIO_PROBE_STATUS | PIO_PROBE_CONTROL | PIO_PROBE_GENERATION | PIO_PROBE_WRITES => {
                Err(PioError::NotReady)
            }
            PIO_PROBE_LAST_COMMAND | PIO_PROBE_REQUESTS | PIO_PROBE_CANCELS => {
                Err(PioError::NotReady)
            }
            _ => Err(PioError::UnknownRegister),
        }
    }

    const fn status(self) -> u8 {
        let mut status = if self.ready { PIO_STATUS_READY } else { 0 };
        if self.pending {
            status |= PIO_STATUS_PENDING;
        }
        if self.cancelled {
            status |= PIO_STATUS_CANCELLED;
        }
        status
    }
}

impl Default for PioProbe {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vmx_access_decodes_width_direction_port_and_register() {
        let out = PioAccess::decode_vmx((0x3f8 << 16) | (2 << 8) | 1, 2, 0x1234_5678).unwrap();
        assert_eq!(out.direction, PioDirection::Out);
        assert_eq!(out.port, 0x3f8);
        assert_eq!(out.width, PioWidth::Word);
        assert_eq!(out.register, 2);
        assert_eq!(out.value, 0x5678);

        let input = PioAccess::decode_vmx((1 << 3) | (0x500 << 16) | (7 << 8) | 3, 2, 0).unwrap();
        assert_eq!(input.direction, PioDirection::In);
        assert_eq!(input.port, 0x500);
        assert_eq!(input.width, PioWidth::Dword);
        assert_eq!(input.register, 7);
    }

    #[test]
    fn malformed_io_forms_fail_closed_before_routing() {
        assert_eq!(
            PioAccess::decode_vmx(1 << 4, 1, 0),
            Err(PioError::StringOperation)
        );
        assert_eq!(
            PioAccess::decode_vmx(1 << 5, 1, 0),
            Err(PioError::RepeatedOperation)
        );
        assert_eq!(
            PioAccess::decode_vmx(2, 1, 0),
            Err(PioError::UnsupportedWidth)
        );
        assert_eq!(
            PioAccess::decode_vmx(0, 0, 0),
            Err(PioError::InstructionLength)
        );
    }

    #[test]
    fn port_ranges_reject_overflow_and_route_exact_boundaries() {
        let range = PortRange::new(0x3f8, 8);
        assert!(range.contains(0x3f8));
        assert!(range.contains(0x3ff));
        assert!(!range.contains(0x400));
        assert!(!PortRange::new(0xffff, 2).valid());
        assert!(!PortRange::new(0x3f8, 0).valid());

        let mut map = PortMap::<3>::new();
        map.register(range, 7).unwrap();
        assert_eq!(map.route(0x3f8), Some(7));
        assert_eq!(map.route(0x3ff), Some(7));
        assert_eq!(map.route(0x400), None);
    }

    #[test]
    fn overlapping_and_full_registration_leave_the_map_unchanged() {
        let mut map = PortMap::<2>::new().with_claim(0x20, 2, 1).with_claim(0x40, 1, 2);
        let before = map;
        assert_eq!(map.register(PortRange::new(0x21, 2), 3), Err(PioError::PortConflict));
        assert_eq!(map, before);
        assert_eq!(map.register(PortRange::new(0x80, 1), 4), Err(PioError::PortConflict));
        assert_eq!(map, before);
        assert_eq!(map.route(0x21), Some(1));
        assert_eq!(map.route(0x40), Some(2));
    }

    #[test]
    fn static_claims_accept_adjacent_ranges() {
        let map = PortMap::<3>::new()
            .with_claim(0x3f8, 8, 1)
            .with_claim(0x400, 1, 2)
            .with_claim(0x500, 16, 3);
        assert_eq!(map.route(0x3ff), Some(1));
        assert_eq!(map.route(0x400), Some(2));
        assert_eq!(map.route(0x50f), Some(3));
        assert_eq!(map.route(0x510), None);
    }

    #[test]
    fn probe_is_discoverable_and_reset_is_atomic() {
        let mut probe = PioProbe::new();
        let control = probe.read(PIO_PROBE_CONTROL, PioWidth::Dword).unwrap();
        assert_eq!(control as u32, PIO_PROBE_MAGIC);
        assert_eq!((control >> 32) as u16, PIO_PROBE_VERSION);
        assert_eq!((control >> 48) as u16, PIO_PROBE_DEVICE_ID);
        assert_eq!(probe.read(PIO_PROBE_STATUS, PioWidth::Word), Ok(1));
        assert_eq!(probe.generation(), 1);
        assert_eq!(
            probe.write(PIO_PROBE_COMMAND, PioWidth::Byte, 0xff),
            Err(PioError::UnknownRegister)
        );
        assert_eq!(probe.generation(), 1);
        assert_eq!(
            probe.write(PIO_PROBE_COMMAND, PioWidth::Byte, u64::from(PIO_COMMAND_PING)),
            Ok(())
        );
        assert_eq!(probe.writes(), 1);
        assert_eq!(probe.write(PIO_PROBE_COMMAND, PioWidth::Byte, 1), Ok(()));
        assert_eq!(probe.generation(), 2);
        assert_eq!(probe.last_command(), 1);
        assert_eq!(probe.writes(), 0);
        assert_eq!(
            probe.write(PIO_PROBE_COMMAND, PioWidth::Byte, u64::from(PIO_COMMAND_PEND)),
            Ok(())
        );
        assert_eq!(
            probe.read(PIO_PROBE_STATUS, PioWidth::Word),
            Ok(u64::from(PIO_STATUS_READY | PIO_STATUS_PENDING))
        );
        assert_eq!(
            probe.write(PIO_PROBE_COMMAND, PioWidth::Byte, u64::from(PIO_COMMAND_CANCEL)),
            Ok(())
        );
        assert_eq!(probe.requests(), 1);
        assert_eq!(probe.cancels(), 1);
        assert_eq!(
            probe.read(PIO_PROBE_STATUS, PioWidth::Word),
            Ok(u64::from(PIO_STATUS_READY | PIO_STATUS_CANCELLED))
        );
        assert_eq!(
            probe.write(PIO_PROBE_COMMAND, PioWidth::Byte, u64::from(PIO_COMMAND_CANCEL)),
            Err(PioError::NotReady)
        );
        assert_eq!(probe.cancels(), 1);
    }

    #[test]
    fn probe_rejects_bad_width_alignment_and_read_only_writes() {
        let mut probe = PioProbe::new();
        assert_eq!(
            probe.read(PIO_PROBE_CONTROL, PioWidth::Word),
            Err(PioError::UnknownRegister)
        );
        assert_eq!(
            probe.read(1, PioWidth::Word),
            Err(PioError::Misaligned)
        );
        assert_eq!(
            probe.write(PIO_PROBE_CONTROL, PioWidth::Dword, 0),
            Err(PioError::NotReady)
        );
        assert_eq!(probe.generation(), 1);
    }
}
