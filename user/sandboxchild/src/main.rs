#![no_std]
#![no_main]

use core::arch::asm;

mod ids {
    include!(concat!(env!("OUT_DIR"), "/ids.rs"));
}

unsafe fn syscall2(id: u64, a: u64, b: u64) -> i64 {
    let ret: i64;
    #[cfg(target_arch = "x86_64")]
    asm!(
        "syscall",
        inlateout("rax") id as i64 => ret,
        in("rdi") a,
        in("rsi") b,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack)
    );
    #[cfg(target_arch = "aarch64")]
    asm!(
        "svc #0",
        in("x8") id,
        inlateout("x0") a as i64 => ret,
        in("x1") b,
        options(nostack)
    );
    #[cfg(any(target_arch = "riscv64", target_arch = "riscv32"))]
    asm!(
        "ecall",
        in("a7") id,
        inlateout("a0") a as i64 => ret,
        in("a1") b,
        options(nostack)
    );
    ret
}

fn write(text: &str) -> i64 {
    unsafe {
        syscall2(
            ids::SYSTEM_CONSOLE_WRITE,
            text.as_ptr() as u64,
            text.len() as u64,
        )
    }
}

#[no_mangle]
#[link_section = ".text._start"]
pub extern "C" fn _start() -> ! {
    let _ = write("sandbox-child: running native bound workload\n");
    unsafe {
        syscall2(ids::SYSTEM_TASK_EXIT, 0, 0);
    }
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe {
        syscall2(ids::SYSTEM_TASK_EXIT, 101, 0);
    }
    loop {
        core::hint::spin_loop();
    }
}
