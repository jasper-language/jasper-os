//! ACPI WDAT hardware-watchdog backend.
//!
//! This consumes only firmware-declared actions and supports SystemMemory and
//! SystemIO register spaces. Unsupported or absent firmware declarations fail
//! closed and are reported; the kernel never guesses a chipset watchdog layout.

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::acpi::{self, Wdat, WdatInstruction, WdatRegister};
use kernel_core::paging::VirtPage;

use crate::boot::BootSpec;
use crate::sync::IrqSpinLock;

use super::{port, smp};

const ACTION_RESET: u8 = 1;
const ACTION_SET_COUNTDOWN: u8 = 6;
const ACTION_SET_RUNNING: u8 = 9;
const ACTION_SET_REBOOT: u8 = 17;
const ACTION_SET_STATUS: u8 = 33;
const INSTRUCTION_PRESERVE: u8 = 0x80;
const TIMEOUT_SECONDS: u32 = 60;
const PET_INTERVAL_TICKS: u32 = 100;

struct Device {
    table: Wdat,
    phys_offset: u64,
    countdown: u32,
}

static DEVICE: IrqSpinLock<Option<Device>> =
    IrqSpinLock::ranked(crate::lockorder::WATCHDOG, None);
static PET_TICKS: AtomicU32 = AtomicU32::new(0);

/// Initialize the firmware-declared hardware watchdog after kernel mappings
/// are available. Returns true only after the device is armed and petted.
#[cfg(feature = "boot-autorecovery")]
pub fn init(boot: &BootSpec) -> bool {
    let Some(rsdp) = boot.acpi_rsdp else {
        crate::early::mark("WDOG NO ACPI");
        return false;
    };
    let Some(phys_offset) = boot.phys_offset else {
        crate::early::mark("WDOG NO PHYSMAP");
        return false;
    };
    let table = match acpi::parse_wdat(&smp::PhysWindow(phys_offset), rsdp) {
        Ok(table) => table,
        Err(error) => {
            crate::console::write_str("[JSR-WATCHDOG] backend=acpi-wdat available=false reason=");
            crate::console::write_str(error.name());
            crate::console::write_str("\n");
            return false;
        }
    };
    let timeout_ms = u64::from(TIMEOUT_SECONDS) * 1000;
    let countdown = timeout_ms / u64::from(table.timer_period_ms);
    if countdown < u64::from(table.min_count)
        || countdown > u64::from(table.max_count)
        || countdown > u64::from(u32::MAX)
    {
        crate::console::write_str("[JSR-WATCHDOG] backend=acpi-wdat available=false reason=timeout_out_of_range\n");
        return false;
    }
    let device = Device {
        table,
        phys_offset,
        countdown: countdown as u32,
    };
    let _ = run_action(&device, ACTION_SET_STATUS, 0, None);
    let _ = run_action(&device, ACTION_SET_REBOOT, 0, None);
    if !run_action(&device, ACTION_SET_COUNTDOWN, device.countdown, None)
        || !run_action(&device, ACTION_SET_RUNNING, 0, None)
        || !run_action(&device, ACTION_RESET, device.countdown, None)
    {
        crate::console::write_str("[JSR-WATCHDOG] backend=acpi-wdat available=false reason=action_failed\n");
        return false;
    }
    // Read-only access check when firmware exposes it. Failure is reported by
    // the failed action above and never converted into a software-only success.
    let _ = run_action(&device, 4, 0, None);
    *DEVICE.lock() = Some(device);
    crate::console::write_str(
        "[JSR-WATCHDOG] backend=acpi-wdat available=true timeout_s=60 reset=true\n",
    );
    true
}

#[cfg(not(feature = "boot-autorecovery"))]
pub fn init(_boot: &BootSpec) -> bool {
    false
}

/// Pet an armed hardware watchdog. Timer ticks throttle register traffic.
pub fn pet() {
    let table = DEVICE.lock();
    let Some(device) = table.as_ref() else {
        return;
    };
    if PET_TICKS.fetch_add(1, Ordering::Relaxed) % PET_INTERVAL_TICKS != 0 {
        return;
    }
    let _ = run_action(device, ACTION_RESET, device.countdown, None);
}

/// Pet immediately without timer throttling. Callers place this outside a
/// measured interval.
pub fn pet_force() {
    let table = DEVICE.lock();
    let Some(device) = table.as_ref() else {
        return;
    };
    let _ = run_action(device, ACTION_RESET, device.countdown, None);
}

fn run_action(device: &Device, action: u8, parameter: u32, result: Option<&mut u32>) -> bool {
    let mut found = false;
    let mut action_result = 0u32;
    for instruction in device.table.instructions().filter(|entry| entry.action == action) {
        found = true;
        if !run_instruction(device, instruction, parameter, &mut action_result) {
            return false;
        }
    }
    if let Some(result) = result {
        *result = action_result;
    }
    found
}

fn run_instruction(
    device: &Device,
    instruction: &WdatInstruction,
    parameter: u32,
    result: &mut u32,
) -> bool {
    let preserve = instruction.instruction & INSTRUCTION_PRESERVE != 0;
    let operation = instruction.instruction & !INSTRUCTION_PRESERVE;
    let shift = instruction.register.bit_offset;
    let mask = instruction.mask;
    let Some(shifted_mask) = mask.checked_shl(u32::from(shift)) else {
        return false;
    };
    match operation {
        0 => {
            let Some(value) = read_register(device, &instruction.register) else {
                return false;
            };
            *result = u32::from((value >> shift) & mask == instruction.value & mask);
        }
        1 => {
            let Some(value) = read_register(device, &instruction.register) else {
                return false;
            };
            *result = (value >> shift) & mask;
        }
        2 | 3 => {
            let value = if operation == 3 {
                parameter
            } else {
                instruction.value
            };
            let mut output = (value & mask) << shift;
            if preserve {
                let Some(current) = read_register(device, &instruction.register) else {
                    return false;
                };
                output |= current & !shifted_mask;
            }
            if !write_register(device, &instruction.register, output) {
                return false;
            }
        }
        _ => return false,
    }
    true
}

fn read_register(device: &Device, register: &WdatRegister) -> Option<u32> {
    match register.address_space {
        0 => {
            let address = device.phys_offset.checked_add(register.address)?;
            let page = VirtPage::from_start(address)?;
            crate::mm::map::translate(page)?;
            let pointer = address as *const u8;
            unsafe {
                Some(match register.access_width {
                    1 => u32::from(core::ptr::read_volatile(pointer)),
                    2 => u32::from(core::ptr::read_volatile(pointer.cast::<u16>())),
                    3 => core::ptr::read_volatile(pointer.cast::<u32>()),
                    _ => return None,
                })
            }
        }
        1 => {
            let address = u16::try_from(register.address).ok()?;
            unsafe {
                Some(match register.access_width {
                    1 => u32::from(port::inb(address)),
                    2 => u32::from(port::inw(address)),
                    3 => port::inl(address),
                    _ => return None,
                })
            }
        }
        _ => None,
    }
}

fn write_register(device: &Device, register: &WdatRegister, value: u32) -> bool {
    match register.address_space {
        0 => {
            let Some(address) = device.phys_offset.checked_add(register.address) else {
                return false;
            };
            let Some(page) = VirtPage::from_start(address) else {
                return false;
            };
            if crate::mm::map::translate(page).is_none() {
                return false;
            }
            let pointer = address as *mut u8;
            unsafe {
                match register.access_width {
                    1 => core::ptr::write_volatile(pointer, value as u8),
                    2 => core::ptr::write_volatile(pointer.cast::<u16>(), value as u16),
                    3 => core::ptr::write_volatile(pointer.cast::<u32>(), value),
                    _ => return false,
                }
            }
            true
        }
        1 => {
            let Some(address) = u16::try_from(register.address).ok() else {
                return false;
            };
            unsafe {
                match register.access_width {
                    1 => port::outb(address, value as u8),
                    2 => port::outw(address, value as u16),
                    3 => port::outl(address, value),
                    _ => return false,
                }
            }
            true
        }
        _ => false,
    }
}
