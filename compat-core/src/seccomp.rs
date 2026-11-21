//! Bounded classic-BPF evaluation for Linux seccomp filters.

pub const SECCOMP_DATA_BYTES: usize = 64;
pub const MAX_FILTER_INSNS: usize = 4096; // JASPER-HARDCODE-REVIEW: issue=35 source=linux-classic-bpf-v1 reason=Linux-BPF-MAXINSNS-wire-bound
pub const MAX_FILTER_DEPTH: usize = 8; // JASPER-HARDCODE-REVIEW: issue=35 source=linux-classic-bpf-v1 reason=Linux-classic-BPF-nesting-bound

const BPF_CLASS_MASK: u16 = 0x07;
const BPF_LD: u16 = 0x00;
const BPF_LDX: u16 = 0x01;
const BPF_ST: u16 = 0x02;
const BPF_STX: u16 = 0x03;
const BPF_ALU: u16 = 0x04;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_MISC: u16 = 0x07;
const BPF_W: u16 = 0x00;
const BPF_H: u16 = 0x08;
const BPF_B: u16 = 0x10;
const BPF_IMM: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_MEM: u16 = 0x60;
const BPF_LEN: u16 = 0x80;
const BPF_SRC_X: u16 = 0x08;
const BPF_OP_MASK: u16 = 0xf0;
const BPF_ADD: u16 = 0x00;
const BPF_SUB: u16 = 0x10;
const BPF_MUL: u16 = 0x20;
const BPF_DIV: u16 = 0x30;
const BPF_OR: u16 = 0x40;
const BPF_AND: u16 = 0x50;
const BPF_LSH: u16 = 0x60;
const BPF_RSH: u16 = 0x70;
const BPF_NEG: u16 = 0x80;
const BPF_MOD: u16 = 0x90;
const BPF_XOR: u16 = 0xa0;
const BPF_JA: u16 = 0x00;
const BPF_JEQ: u16 = 0x10;
const BPF_JGT: u16 = 0x20;
const BPF_JGE: u16 = 0x30;
const BPF_JSET: u16 = 0x40;
const BPF_TAX: u16 = 0x00;
const BPF_TXA: u16 = 0x80;

pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_KILL_THREAD: u32 = 0x0000_0000;
pub const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
pub const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
pub const SECCOMP_RET_LOG: u32 = 0x7ffc_0000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ACTION_FULL: u32 = 0xffff_0000;
const SECCOMP_RET_DATA: u32 = 0x0000_ffff;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeccompInsn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeccompAction {
    KillProcess,
    KillThread,
    Trap,
    Errno(u16),
    UserNotify,
    Trace(u16),
    Log,
    Allow,
}

impl SeccompAction {
    pub fn from_raw(value: u32) -> Option<Self> {
        match value & SECCOMP_RET_ACTION_FULL {
            SECCOMP_RET_KILL_PROCESS => Some(Self::KillProcess),
            SECCOMP_RET_KILL_THREAD => Some(Self::KillThread),
            SECCOMP_RET_TRAP => Some(Self::Trap),
            SECCOMP_RET_ERRNO => Some(Self::Errno((value & SECCOMP_RET_DATA) as u16)),
            SECCOMP_RET_USER_NOTIF => Some(Self::UserNotify),
            SECCOMP_RET_TRACE => Some(Self::Trace((value & SECCOMP_RET_DATA) as u16)),
            SECCOMP_RET_LOG => Some(Self::Log),
            SECCOMP_RET_ALLOW => Some(Self::Allow),
            _ => None,
        }
    }

    pub fn action_available(value: u32) -> bool {
        matches!(
            value & SECCOMP_RET_ACTION_FULL,
            SECCOMP_RET_KILL_PROCESS
                | SECCOMP_RET_KILL_THREAD
                | SECCOMP_RET_TRAP
                | SECCOMP_RET_ERRNO
                | SECCOMP_RET_USER_NOTIF
                | SECCOMP_RET_TRACE
                | SECCOMP_RET_LOG
                | SECCOMP_RET_ALLOW
        )
    }

    fn precedence(self) -> u8 {
        match self {
            Self::KillProcess => 0,
            Self::KillThread => 1,
            Self::Trap => 2,
            Self::Errno(_) => 3,
            Self::UserNotify => 4,
            Self::Trace(_) => 5,
            Self::Log => 6,
            Self::Allow => 7,
        }
    }

    pub fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::Errno(first), Self::Errno(second)) => Self::Errno(first.min(second)),
            (Self::Trace(first), Self::Trace(second)) => Self::Trace(first.min(second)),
            _ if self.precedence() <= other.precedence() => self,
            _ => other,
        }
    }
}

fn load_size(code: u16) -> Option<usize> {
    match code & 0x18 {
        BPF_W => Some(4),
        BPF_H => Some(2),
        BPF_B => Some(1),
        _ => None,
    }
}

fn read_abs(data: &[u8; SECCOMP_DATA_BYTES], offset: u32, size: usize) -> Option<u32> {
    let offset = usize::try_from(offset).ok()?;
    let bytes = data.get(offset..offset.checked_add(size)?)?;
    let mut value = 0u32;
    for (index, byte) in bytes.iter().enumerate() {
        value |= u32::from(*byte) << (index * 8);
    }
    Some(value)
}

fn jump_target(pc: usize, offset: u8) -> Option<usize> {
    pc.checked_add(1)?.checked_add(usize::from(offset))
}

pub fn validate(filter: &[SeccompInsn]) -> Result<(), ()> {
    if filter.is_empty() || filter.len() > MAX_FILTER_INSNS {
        return Err(());
    }
    for (pc, insn) in filter.iter().copied().enumerate() {
        match insn.code & BPF_CLASS_MASK {
            BPF_LD => {
                let mode = insn.code & 0xe0;
                if load_size(insn.code).is_none()
                    || mode == BPF_ABS
                        && read_abs(&[0; SECCOMP_DATA_BYTES], insn.k, load_size(insn.code).unwrap())
                            .is_none()
                    || mode != BPF_ABS && mode != BPF_IMM && mode != BPF_LEN
                {
                    return Err(());
                }
            }
            BPF_LDX => {
                let mode = insn.code & 0xe0;
                if load_size(insn.code).is_none()
                    || mode != BPF_IMM && mode != BPF_MEM
                    || mode == BPF_MEM && insn.k >= 16
                {
                    return Err(());
                }
            }
            BPF_ST | BPF_STX => {
                let mode = insn.code & 0xe0;
                if load_size(insn.code).is_none() || mode != BPF_MEM || insn.k >= 16 {
                    return Err(());
                }
            }
            BPF_ALU => {
                let operation = insn.code & BPF_OP_MASK;
                if !matches!(
                    operation,
                    BPF_ADD
                        | BPF_SUB
                        | BPF_MUL
                        | BPF_DIV
                        | BPF_OR
                        | BPF_AND
                        | BPF_LSH
                        | BPF_RSH
                        | BPF_NEG
                        | BPF_MOD
                        | BPF_XOR
                ) {
                    return Err(());
                }
            }
            BPF_JMP => {
                let operation = insn.code & BPF_OP_MASK;
                if operation == BPF_JA {
                    let target = pc.checked_add(1).and_then(|next| {
                        next.checked_add(usize::try_from(insn.k).ok()?)
                    });
                    if target.is_none_or(|target| target >= filter.len()) {
                        return Err(());
                    }
                } else if matches!(operation, BPF_JEQ | BPF_JGT | BPF_JGE | BPF_JSET) {
                    let true_target = jump_target(pc, insn.jt);
                    let false_target = jump_target(pc, insn.jf);
                    if true_target.is_none_or(|target| target >= filter.len())
                        || false_target.is_none_or(|target| target >= filter.len())
                    {
                        return Err(());
                    }
                } else {
                    return Err(());
                }
            }
            BPF_RET => {
                if insn.code != (BPF_RET | BPF_W)
                    || SeccompAction::from_raw(insn.k).is_none()
                {
                    return Err(());
                }
            }
            BPF_MISC => {
                let operation = insn.code & 0xf8;
                if operation != BPF_TAX && operation != BPF_TXA {
                    return Err(());
                }
            }
            _ => return Err(()),
        }
    }
    Ok(())
}

pub fn evaluate(
    filter: &[SeccompInsn],
    data: &[u8; SECCOMP_DATA_BYTES],
) -> Result<SeccompAction, ()> {
    let mut accumulator = 0u32;
    let mut index = 0u32;
    let mut scratch = [0u32; 16];
    let mut pc = 0usize;
    for _ in 0..=MAX_FILTER_INSNS {
        let insn = *filter.get(pc).ok_or(())?;
        let next = pc.checked_add(1).ok_or(())?;
        match insn.code & BPF_CLASS_MASK {
            BPF_LD => match insn.code & 0xe0 {
                BPF_ABS => {
                    accumulator =
                        read_abs(data, insn.k, load_size(insn.code).ok_or(())?).ok_or(())?;
                }
                BPF_IMM => accumulator = insn.k,
                BPF_LEN => accumulator = SECCOMP_DATA_BYTES as u32,
                _ => return Err(()),
            },
            BPF_LDX => match insn.code & 0xe0 {
                BPF_IMM => index = insn.k,
                BPF_MEM => index = *scratch.get(insn.k as usize).ok_or(())?,
                _ => return Err(()),
            },
            BPF_ST => {
                *scratch.get_mut(insn.k as usize).ok_or(())? = accumulator;
            }
            BPF_STX => {
                *scratch.get_mut(insn.k as usize).ok_or(())? = index;
            }
            BPF_ALU => {
                let source = if insn.code & BPF_SRC_X != 0 {
                    index
                } else {
                    insn.k
                };
                match insn.code & BPF_OP_MASK {
                    BPF_ADD => accumulator = accumulator.wrapping_add(source),
                    BPF_SUB => accumulator = accumulator.wrapping_sub(source),
                    BPF_MUL => accumulator = accumulator.wrapping_mul(source),
                    BPF_DIV if source != 0 => accumulator /= source,
                    BPF_OR => accumulator |= source,
                    BPF_AND => accumulator &= source,
                    BPF_LSH => accumulator = accumulator.wrapping_shl(source & 31),
                    BPF_RSH => accumulator = accumulator.wrapping_shr(source & 31),
                    BPF_NEG => accumulator = accumulator.wrapping_neg(),
                    BPF_MOD if source != 0 => accumulator %= source,
                    BPF_XOR => accumulator ^= source,
                    _ => return Err(()),
                }
            }
            BPF_JMP => {
                let source = if insn.code & BPF_SRC_X != 0 {
                    index
                } else {
                    insn.k
                };
                match insn.code & BPF_OP_MASK {
                    BPF_JA => {
                        pc = next
                            .checked_add(usize::try_from(insn.k).map_err(|_| ())?)
                            .ok_or(())?;
                        continue;
                    }
                    BPF_JEQ => {
                        pc = if accumulator == source {
                            jump_target(pc, insn.jt)
                        } else {
                            jump_target(pc, insn.jf)
                        }
                        .ok_or(())?;
                        continue;
                    }
                    BPF_JGT => {
                        pc = if accumulator > source {
                            jump_target(pc, insn.jt)
                        } else {
                            jump_target(pc, insn.jf)
                        }
                        .ok_or(())?;
                        continue;
                    }
                    BPF_JGE => {
                        pc = if accumulator >= source {
                            jump_target(pc, insn.jt)
                        } else {
                            jump_target(pc, insn.jf)
                        }
                        .ok_or(())?;
                        continue;
                    }
                    BPF_JSET => {
                        pc = if accumulator & source != 0 {
                            jump_target(pc, insn.jt)
                        } else {
                            jump_target(pc, insn.jf)
                        }
                        .ok_or(())?;
                        continue;
                    }
                    _ => return Err(()),
                }
            }
            BPF_RET => return SeccompAction::from_raw(insn.k).ok_or(()),
            BPF_MISC if insn.code & 0xf8 == BPF_TAX => index = accumulator,
            BPF_MISC if insn.code & 0xf8 == BPF_TXA => accumulator = index,
            _ => return Err(()),
        }
        pc = next;
    }
    Err(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instruction(code: u16, jt: u8, jf: u8, k: u32) -> SeccompInsn {
        SeccompInsn { code, jt, jf, k }
    }

    #[test]
    fn syscall_number_filter_returns_requested_action() {
        let filter = [
            instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, 0),
            instruction(BPF_JMP | BPF_JEQ, 0, 1, 39),
            instruction(BPF_RET | BPF_W, 0, 0, SECCOMP_RET_ERRNO | 1),
            instruction(BPF_RET | BPF_W, 0, 0, SECCOMP_RET_ALLOW),
        ];
        validate(&filter).unwrap();
        let mut data = [0u8; SECCOMP_DATA_BYTES];
        data[..4].copy_from_slice(&39i32.to_le_bytes());
        assert_eq!(evaluate(&filter, &data), Ok(SeccompAction::Errno(1)));
        data[..4].copy_from_slice(&60i32.to_le_bytes());
        assert_eq!(evaluate(&filter, &data), Ok(SeccompAction::Allow));
    }

    #[test]
    fn invalid_jump_and_absolute_load_fail_validation() {
        assert!(validate(&[instruction(BPF_RET | BPF_W, 0, 0, SECCOMP_RET_ALLOW)]).is_ok());
        assert!(validate(&[instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, 61)]).is_err());
        assert!(validate(&[
            instruction(BPF_JMP | BPF_JA, 0, 0, 9),
            instruction(BPF_RET | BPF_W, 0, 0, SECCOMP_RET_ALLOW),
        ])
        .is_err());

        let exact = vec![instruction(BPF_RET | BPF_W, 0, 0, SECCOMP_RET_ALLOW); MAX_FILTER_INSNS];
        assert!(validate(&exact).is_ok());
        let oversized = vec![instruction(BPF_RET | BPF_W, 0, 0, SECCOMP_RET_ALLOW); MAX_FILTER_INSNS + 1];
        assert!(validate(&oversized).is_err());
    }

    #[test]
    fn action_precedence_and_errno_payload_are_stable() {
        assert_eq!(
            SeccompAction::Allow.combine(SeccompAction::KillThread),
            SeccompAction::KillThread
        );
        assert_eq!(
            SeccompAction::Errno(13).combine(SeccompAction::Errno(1)),
            SeccompAction::Errno(1)
        );
    }
}
