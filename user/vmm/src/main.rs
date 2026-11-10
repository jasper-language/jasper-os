//! User-space VMM acceptance service for HWV-5-VMM.
//!
//! Role 0 publishes a live service and sleeps so the kernel can prove crash
//! revocation. Role 1 publishes a restarted generation, waits for six real
//! VM-exit notifications on its Ring, then validates the fixed exit records.
#![no_std]
#![no_main]

use core::arch::asm;

use kernel_core::hwvirt_vmm::{
    VmExitRecord, VmmAbi, VMM_ABI_BYTES, VMM_ABI_VERSION, VMM_CONTROL_MAGIC,
    VM_EXIT_RECORD_BYTES,
};
use kernel_core::ring_abi::{Cqe, EnterArgs};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

mod ids {
    include!(concat!(env!("OUT_DIR"), "/ids.rs"));
}

const CONTROL_OFFSET: u64 = 256 << 20;
const ABI_HIGH_WORD: u64 = 2;
const ABI_LOW_WORD: u64 = 3;
const RING_HANDLE_WORD: u64 = 4;
const GENERATION_WORD: u64 = 5;
const STATUS_WORD: u64 = 6;
const EXIT_COUNT_WORD: u64 = 7;
const RECORDS_OFFSET: u64 = 64;
const START_OFFSET: u64 = 320;
const START_MAGIC: u64 = 0x5354_4152_5400_0000;
const STATUS_OK: u64 = 0x4857_5635_4f4b;
const STATUS_FAIL: u64 = 0x4857_5635_4641;

unsafe fn syscall3(id: u64, a: u64, b: u64, c: u64) -> i64 {
    let ret: i64;
    asm!(
        "syscall",
        inlateout("rax") id as i64 => ret,
        in("rdi") a,
        in("rsi") b,
        in("rdx") c,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack)
    );
    ret
}

fn write(va: u64, value: u64) {
    // SAFETY: the kernel maps the control page before starting this thread.
    unsafe { core::ptr::write_volatile(va as *mut u64, value) }
}

fn read(va: u64) -> u64 {
    // SAFETY: the kernel maps the control page before starting this thread.
    unsafe { core::ptr::read_volatile(va as *const u64) }
}

fn exit(code: u64) -> ! {
    // SAFETY: integer-only exit syscall.
    unsafe {
        syscall3(ids::SYSTEM_TASK_EXIT, code, 0, 0);
    }
    loop {
        core::hint::spin_loop();
    }
}

fn main(role: u64, generation: u64) -> i32 {
    let base = kernel_core::user_layout::WINDOW_BASE_X86_64;
    let control = base + CONTROL_OFFSET;

    let abi = match VmmAbi::new(
        kernel_core::hwvirt::Backend::Vmx,
        u32::try_from(generation).unwrap_or(0),
        1,
        1,
        16 * 1024,
    ) {
        Some(abi) => abi,
        None => exit(50),
    };
    let encoded = abi.encode();
    let decoded = match VmmAbi::decode(&encoded) {
        Some(decoded) if decoded == abi => decoded,
        _ => exit(51),
    };
    write(control + ABI_HIGH_WORD * 8, u64::from_be_bytes(encoded[0..8].try_into().unwrap()));
    write(control + ABI_LOW_WORD * 8, u64::from_be_bytes(encoded[8..16].try_into().unwrap()));
    write(control + VMM_ABI_BYTES as u64, decoded.features);

    // SAFETY: integer-only Ring creation.
    let ring = unsafe { syscall3(ids::SYSTEM_ASYNC_RING_CREATE, 8, 0, 0) };
    if ring <= 0 {
        exit(52);
    }
    write(control, VMM_CONTROL_MAGIC);
    write(control + 8, u64::from(VMM_ABI_VERSION));
    write(control + RING_HANDLE_WORD * 8, ring as u64);
    write(control + GENERATION_WORD * 8, generation);

    if role == 0 {
        // SAFETY: integer-only blocking wait. The kernel kills this process.
        unsafe {
            syscall3(ids::SYSTEM_TIME_WAIT, 1 << 40, 0, 0);
        }
        exit(53);
    }
    if role != 1 {
        exit(54);
    }

    let start_token = START_MAGIC | u64::from(decoded.generation);
    while read(control + START_OFFSET) != start_token {
        // SAFETY: sleep lets the kernel supervisor publish the start handshake.
        unsafe {
            syscall3(ids::SYSTEM_TIME_WAIT, 1, 0, 0);
        }
    }

    let mut cq = [Cqe::default(); 8];
    let mut args = EnterArgs {
        cq_ptr: cq.as_mut_ptr() as u64,
        cq_max: 6,
        wait_min: 6,
        ..EnterArgs::default()
    };
    // SAFETY: all buffers are local and live until the synchronous enter returns.
    let entered = unsafe {
        syscall3(
            ids::SYSTEM_ASYNC_RING_ENTER,
            ring as u64,
            &mut args as *mut EnterArgs as u64,
            0,
        )
    };
    if entered < 0 || args.reaped != 6 || args.first_error != 0 {
        write(control + STATUS_WORD * 8, STATUS_FAIL);
        exit(55);
    }

    let expected = [10u32, 16, 31, 30, 48, 0];
    for (index, reason) in expected.into_iter().enumerate() {
        let completion = cq[index];
        if completion.result != i64::from(reason) {
            write(control + STATUS_WORD * 8, STATUS_FAIL);
            exit(60 + index as u64);
        }
        let record_va = control + RECORDS_OFFSET + (index * VM_EXIT_RECORD_BYTES) as u64;
        let mut raw = [0u8; VM_EXIT_RECORD_BYTES];
        for (offset, byte) in raw.iter_mut().enumerate() {
            // SAFETY: each index is inside the mapped control page.
            *byte = unsafe { core::ptr::read_volatile((record_va as *const u8).add(offset)) };
        }
        let Some(record) = VmExitRecord::decode(&raw) else {
            write(control + STATUS_WORD * 8, STATUS_FAIL);
            exit(70 + index as u64);
        };
        if record.reason != reason
            || record.generation != 2
            || record.backend != 0
            || (reason == 0 && record.vector != 6)
        {
            write(control + STATUS_WORD * 8, STATUS_FAIL);
            exit(80 + index as u64);
        }
    }
    write(control + GENERATION_WORD * 8, 2);
    write(control + EXIT_COUNT_WORD * 8, 6);
    write(control + STATUS_WORD * 8, STATUS_OK);
    0
}

#[no_mangle]
extern "C" fn _start(role: u64, generation: u64) -> ! {
    let code = main(role, generation);
    exit(if code == 0 { 0 } else { code as u64 })
}
