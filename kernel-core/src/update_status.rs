//! Structured, path-free update status returned by the versioned service.
//!
//! This record contains only stable scalar identities and bounded slot facts.
//! Internal control, staging and archive roots never cross this boundary.

pub const MAGIC: u32 = 0x5343_554a; // "JUCS" little-endian.
pub const VERSION: u16 = 1;
pub const BYTES: usize = 160;
pub const FLAG_CANDIDATE: u8 = 1 << 0;
pub const FLAG_REDACTED: u8 = 1 << 1;
pub const FLAG_TERMINAL: u8 = 1 << 2;
pub const NO_SLOT: u8 = u8::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpdateStatus {
    pub service_generation: u64,
    pub transaction_id: u64,
    pub rollback_floor: u64,
    pub security_epoch: u64,
    pub active_slot: u8,
    pub candidate_slot: u8,
    pub active_state: u8,
    pub candidate_state: u8,
    pub active_attempts: u8,
    pub candidate_attempts: u8,
    pub terminal_stage: u8,
    pub active_release: u64,
    pub candidate_release: u64,
    pub data_schema_min: u32,
    pub data_schema_max: u32,
    pub caller_subject: u64,
    pub caller_domain: u32,
    pub active_digest: [u8; 32],
    pub candidate_digest: [u8; 32],
}

impl UpdateStatus {
    pub fn candidate_present(self) -> bool {
        self.candidate_slot != NO_SLOT
    }

    pub fn encode(self) -> [u8; BYTES] {
        let mut out = [0u8; BYTES];
        put_u32(&mut out, 0, MAGIC);
        put_u16(&mut out, 4, VERSION);
        put_u16(&mut out, 6, 1);
        out[8] = FLAG_REDACTED
            | if self.candidate_present() {
                FLAG_CANDIDATE
            } else {
                0
            }
            | if self.terminal_stage != 0 {
                FLAG_TERMINAL
            } else {
                0
            };
        out[9] = self.terminal_stage;
        put_u32(&mut out, 12, BYTES as u32);
        put_u64(&mut out, 16, self.service_generation);
        put_u64(&mut out, 24, self.transaction_id);
        put_u64(&mut out, 32, self.rollback_floor);
        put_u64(&mut out, 40, self.security_epoch);
        put_u64(&mut out, 48, self.active_release);
        put_u64(&mut out, 56, self.candidate_release);
        put_u32(&mut out, 64, self.data_schema_min);
        put_u32(&mut out, 68, self.data_schema_max);
        out[72] = self.active_slot;
        out[73] = self.candidate_slot;
        out[74] = self.active_state;
        out[75] = self.candidate_state;
        out[76] = self.active_attempts;
        out[77] = self.candidate_attempts;
        put_u64(&mut out, 80, self.caller_subject);
        put_u32(&mut out, 88, self.caller_domain);
        out[96..128].copy_from_slice(&self.active_digest);
        out[128..160].copy_from_slice(&self.candidate_digest);
        out
    }

    pub fn decode(bytes: &[u8; BYTES]) -> Option<Self> {
        if get_u32(bytes, 0) != MAGIC
            || get_u16(bytes, 4) != VERSION
            || get_u16(bytes, 6) != 1
            || get_u32(bytes, 12) != BYTES as u32
            || bytes[72] > 1
            || (bytes[73] > 1 && bytes[73] != NO_SLOT)
            || bytes[74] > 3
            || (bytes[73] != NO_SLOT && bytes[75] > 3)
            || bytes[10..12] != [0, 0]
        {
            return None;
        }
        let flags = bytes[8];
        let terminal_stage = bytes[9];
        if flags & !(FLAG_CANDIDATE | FLAG_REDACTED | FLAG_TERMINAL) != 0
            || (flags & FLAG_CANDIDATE != 0) != (bytes[73] != NO_SLOT)
            || (flags & FLAG_TERMINAL != 0) != matches!(terminal_stage, 7 | 10)
            || !matches!(terminal_stage, 0 | 7 | 10)
            || (terminal_stage != 0 && bytes[73] != NO_SLOT)
        {
            return None;
        }
        let mut active_digest = [0u8; 32];
        let mut candidate_digest = [0u8; 32];
        active_digest.copy_from_slice(&bytes[96..128]);
        candidate_digest.copy_from_slice(&bytes[128..160]);
        let candidate_release = get_u64(bytes, 56);
        if bytes[73] == NO_SLOT
            && (candidate_release != 0
                || bytes[75] != 0
                || bytes[77] != 0
                || (terminal_stage == 0 && candidate_digest.iter().any(|byte| *byte != 0))
                || (terminal_stage != 0 && candidate_digest.iter().all(|byte| *byte == 0)))
        {
            return None;
        }
        if bytes[73] != NO_SLOT
            && (candidate_release == 0 || candidate_digest.iter().all(|byte| *byte == 0))
        {
            return None;
        }
        Some(Self {
            service_generation: get_u64(bytes, 16),
            transaction_id: get_u64(bytes, 24),
            rollback_floor: get_u64(bytes, 32),
            security_epoch: get_u64(bytes, 40),
            active_slot: bytes[72],
            candidate_slot: bytes[73],
            active_state: bytes[74],
            candidate_state: bytes[75],
            active_attempts: bytes[76],
            candidate_attempts: bytes[77],
            terminal_stage,
            active_release: get_u64(bytes, 48),
            candidate_release,
            data_schema_min: get_u32(bytes, 64),
            data_schema_max: get_u32(bytes, 68),
            caller_subject: get_u64(bytes, 80),
            caller_domain: get_u32(bytes, 88),
            active_digest,
            candidate_digest,
        })
    }
}

fn put_u16(out: &mut [u8], at: usize, value: u16) {
    out[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut [u8], at: usize, value: u32) {
    out[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut [u8], at: usize, value: u64) {
    out[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}

fn get_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn get_u64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(candidate: bool) -> UpdateStatus {
        UpdateStatus {
            service_generation: 9,
            transaction_id: 7,
            rollback_floor: 3,
            security_epoch: 4,
            active_slot: 0,
            candidate_slot: if candidate { 1 } else { NO_SLOT },
            active_state: 2,
            candidate_state: u8::from(candidate),
            active_attempts: 0,
            candidate_attempts: u8::from(candidate),
            terminal_stage: 0,
            active_release: 3,
            candidate_release: u64::from(candidate) * 4,
            data_schema_min: 1,
            data_schema_max: 2,
            caller_subject: 0x55,
            caller_domain: 1,
            active_digest: [0x31; 32],
            candidate_digest: if candidate { [0x32; 32] } else { [0; 32] },
        }
    }

    #[test]
    fn fixed_record_round_trips_with_or_without_candidate() {
        for candidate in [false, true] {
            let record = sample(candidate);
            assert_eq!(UpdateStatus::decode(&record.encode()), Some(record));
        }
    }

    #[test]
    fn malformed_header_or_candidate_flag_is_rejected() {
        let record = sample(true);
        let mut bytes = record.encode();
        bytes[8] &= !FLAG_CANDIDATE;
        assert_eq!(UpdateStatus::decode(&bytes), None);
        let mut bytes = record.encode();
        bytes[12] = 0;
        assert_eq!(UpdateStatus::decode(&bytes), None);
    }

    #[test]
    fn absent_candidate_cannot_retain_candidate_facts() {
        let record = sample(false);
        let mut bytes = record.encode();
        bytes[56..64].copy_from_slice(&4u64.to_le_bytes());
        assert_eq!(UpdateStatus::decode(&bytes), None);

        let mut bytes = record.encode();
        bytes[96 + 0] = 0;
        bytes[128 + 0] = 1;
        assert_eq!(UpdateStatus::decode(&bytes), None);
    }

    #[test]
    fn terminal_digest_requires_an_explicit_terminal_flag() {
        let mut record = sample(false);
        record.terminal_stage = 7;
        record.candidate_digest = [0x44; 32];
        assert_eq!(UpdateStatus::decode(&record.encode()), Some(record));

        let mut bytes = record.encode();
        bytes[8] &= !FLAG_TERMINAL;
        assert_eq!(UpdateStatus::decode(&bytes), None);

        let mut bytes = record.encode();
        bytes[9] = 8;
        assert_eq!(UpdateStatus::decode(&bytes), None);
    }
}
