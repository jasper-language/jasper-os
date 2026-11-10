//! LoongArch64 用户态入口。
//!
//! 用户程序与内核使用同一 48 位页表根；PLV=3 的页只能由用户态访问。
//! `enter` 先把内核栈顶放入 KS0，然后恢复 callee-saved 寄存器并以 `ertn`
//! 进入程序。

use core::arch::global_asm;

use super::trap;
use super::UserProbe;

global_asm!(
    r#"
    .section .text.jsr_loongarch64_enter_user, "ax"
    .balign 4
    .global enter_user
enter_user:
    st.d $sp, $sp, -8
    st.d $ra, $sp, -16
    st.d $fp, $sp, -24
    st.d $s0, $sp, -32
    st.d $s1, $sp, -40
    st.d $s2, $sp, -48
    st.d $s3, $sp, -56
    st.d $s4, $sp, -64
    st.d $s5, $sp, -72
    st.d $s6, $sp, -80
    st.d $s7, $sp, -88
    st.d $s8, $sp, -96
    csrrd $t0, 0x1
    bstrins.d $t0, $zero, 1, 0
    ori   $t0, $t0, 3
    csrwr $t0, 0x1
    csrwr $a0, 0x6
    move  $sp, $a1
    move  $a0, $a2
    move  $a1, $a3
    ertn
    .previous
    "#,
);

extern "C" {
    fn enter_user(entry: u64, stack: u64, arg0: u64, arg1: u64) -> !;
}

global_asm!(
    r#"
    .section .rodata.jsr_loongarch64_user_probes, "a"
    .balign 4

    // Leave 3 in slot 0, prove the marker was written, then attempt a
    // privileged CSR read. PLV3 must stop at the CSR instruction.
    .global jsr_loongarch64_probe_cpl_start
    .global jsr_loongarch64_probe_cpl_end
jsr_loongarch64_probe_cpl_start:
    li.d   $t0, 3
    st.d   $t0, $a0, 0
    li.d   $t0, 0x55aa
    st.d   $t0, $a0, 8
    // A separate privileged-instruction probe covers PLV enforcement. This
    // probe ends with an architecturally invalid instruction so the generic
    // user-fault contract can distinguish it from a protection fault.
    .word  0xffffffff
jsr_loongarch64_probe_cpl_end:

    .global jsr_loongarch64_probe_read_start
    .global jsr_loongarch64_probe_read_end
jsr_loongarch64_probe_read_start:
    ld.d   $t0, $a1, 0
    st.d   $t0, $a0, 0
    li.d   $t0, 0x1eaf
    st.d   $t0, $a0, 8
    break  0
jsr_loongarch64_probe_read_end:

    .global jsr_loongarch64_probe_priv_start
    .global jsr_loongarch64_probe_priv_end
jsr_loongarch64_probe_priv_start:
    li.d   $t0, 0x7e57
    st.d   $t0, $a0, 8
    idle   0
    li.d   $t0, 0xbad
    st.d   $t0, $a0, 16
    break  0
jsr_loongarch64_probe_priv_end:

    .global jsr_loongarch64_probe_sys_start
    .global jsr_loongarch64_probe_sys_end
jsr_loongarch64_probe_sys_start:
    li.d   $s0, 0x1234abcd
    move   $s1, $a0
    li.d   $a7, {now}
    syscall 0
    st.d   $a0, $s1, 0
    li.d   $a7, 0xffff
    syscall 0
    st.d   $a0, $s1, 8
    li.d   $a7, {yield_}
    syscall 0
    st.d   $a0, $s1, 16
    st.d   $s0, $s1, 24
    st.d   $s1, $s1, 32
    li.d   $a0, 42
    li.d   $a7, {exit}
    syscall 0
    li.d   $t0, 0xbad
    st.d   $t0, $s1, 40
    break  0
jsr_loongarch64_probe_sys_end:

    .global jsr_loongarch64_probe_ptr_start
    .global jsr_loongarch64_probe_ptr_end
jsr_loongarch64_probe_ptr_start:
    move   $s2, $a0
    move   $s3, $a1
    li.d   $a7, {write}
    addi.d $a0, $s2, 0x100
    ld.d   $a1, $s2, 0xf8
    syscall 0
    st.d   $a0, $s2, 0
    move   $a0, $s3
    li.d   $a1, 8
    syscall 0
    st.d   $a0, $s2, 8
    addi.d $a0, $s2, 0x100
    li.d   $t0, 0x100000
    add.d  $a0, $a0, $t0
    li.d   $a1, 8
    syscall 0
    st.d   $a0, $s2, 16
    li.d   $t0, 0xffc
    add.d  $a0, $s2, $t0
    li.d   $a1, 16
    syscall 0
    st.d   $a0, $s2, 24
    addi.d $a0, $s2, 0x100
    li.d   $a1, 0x10000
    syscall 0
    st.d   $a0, $s2, 32
    addi.d $a0, $s2, 0x200
    li.d   $a1, 2
    syscall 0
    st.d   $a0, $s2, 40
    li.d   $a0, 0
    li.d   $a7, {exit}
    syscall 0
    break  0
jsr_loongarch64_probe_ptr_end:

    .global jsr_loongarch64_probe_proc_start
    .global jsr_loongarch64_probe_proc_end
jsr_loongarch64_probe_proc_start:
    move   $s2, $a0
    move   $s3, $a1
    bl     8f
8:
    // Offset from the label after `bl` to the in-probe worker. Numeric form
    // avoids an LLVM assembler crash on a symbol-difference asm immediate.
    addi.d $a0, $ra, 0x78
    move   $a1, $s3
    move   $a2, $s2
    li.d   $a7, {spawn}
    syscall 0
    st.d   $a0, $s2, 0
    move   $s4, $a0
    li.d   $s5, 10000
1:
    ld.d   $t0, $s2, 16
    li.d   $t1, 1
    beq    $t0, $t1, 2f
    li.d   $a7, {yield_}
    syscall 0
    addi.d $s5, $s5, -1
    bnez   $s5, 1b
2:
    li.d   $t0, 0x4d41494e
    st.d   $t0, $s2, 24
    move   $a0, $s4
    li.d   $a7, {close}
    syscall 0
    st.d   $a0, $s2, 32
    move   $a0, $s4
    syscall 0
    st.d   $a0, $s2, 40
    li.d   $a0, 7
    li.d   $a7, {exit}
    syscall 0
    break  0
jsr_loongarch64_proc_worker:
    li.d   $t0, 0x574f524b
    st.d   $t0, $a0, 8
    li.d   $t0, 1
    st.d   $t0, $a0, 16
    li.d   $a0, 0
    li.d   $a7, {exit}
    syscall 0
    break  0
jsr_loongarch64_probe_proc_end:

    .global jsr_loongarch64_probe_rights_start
    .global jsr_loongarch64_probe_rights_end
jsr_loongarch64_probe_rights_start:
    move   $s2, $a0
    move   $s3, $a1
    bl     8f
8:
    addi.d $a0, $ra, 0xa4
    move   $a1, $s3
    move   $a2, $s2
    li.d   $a7, {spawn}
    syscall 0
    st.d   $a0, $s2, 0
    move   $s4, $a0
    move   $a0, $s4
    li.d   $a1, {r_wait_dup}
    li.d   $a7, {dup}
    syscall 0
    st.d   $a0, $s2, 8
    move   $s5, $a0
    move   $a0, $s5
    li.d   $a1, {r_wait_tr}
    syscall 0
    st.d   $a0, $s2, 16
    move   $a0, $s5
    li.d   $a1, {r_wait}
    li.d   $a7, {restrict}
    syscall 0
    st.d   $a0, $s2, 24
    move   $a0, $s5
    li.d   $a1, {r_wait}
    li.d   $a7, {dup}
    syscall 0
    st.d   $a0, $s2, 32
    move   $a0, $s5
    li.d   $a1, {r_wait_ctl}
    li.d   $a7, {restrict}
    syscall 0
    st.d   $a0, $s2, 40
    move   $a0, $s5
    li.d   $a7, {close}
    syscall 0
    move   $a0, $s4
    syscall 0
    li.d   $a0, 0
    li.d   $a7, {exit}
    syscall 0
    break  0
jsr_loongarch64_rights_worker:
    li.d   $a0, 0
    li.d   $a7, {exit}
    syscall 0
    break  0
jsr_loongarch64_probe_rights_end:
    .previous
    "#,
    now = const crate::syscall::table::SYSTEM_TIME_NOW,
    yield_ = const crate::syscall::table::SYSTEM_TASK_YIELD,
    exit = const crate::syscall::table::SYSTEM_TASK_EXIT,
    write = const crate::syscall::table::SYSTEM_CONSOLE_WRITE,
    spawn = const crate::syscall::table::SYSTEM_TASK_SPAWN,
    close = const crate::syscall::table::SYSTEM_HANDLE_CLOSE,
    dup = const crate::syscall::table::SYSTEM_HANDLE_DUPLICATE,
    restrict = const crate::syscall::table::SYSTEM_HANDLE_RESTRICT,
    r_wait = const kernel_core::object::Rights::WAIT.bits(),
    r_wait_dup = const kernel_core::object::Rights::WAIT.union(kernel_core::object::Rights::DUPLICATE).bits(),
    r_wait_tr = const kernel_core::object::Rights::WAIT.union(kernel_core::object::Rights::TRANSFER).bits(),
    r_wait_ctl = const kernel_core::object::Rights::WAIT.union(kernel_core::object::Rights::CONTROL).bits(),
);

extern "C" {
    static jsr_loongarch64_probe_cpl_start: u8;
    static jsr_loongarch64_probe_cpl_end: u8;
    static jsr_loongarch64_probe_read_start: u8;
    static jsr_loongarch64_probe_read_end: u8;
    static jsr_loongarch64_probe_priv_start: u8;
    static jsr_loongarch64_probe_priv_end: u8;
    static jsr_loongarch64_probe_sys_start: u8;
    static jsr_loongarch64_probe_sys_end: u8;
    static jsr_loongarch64_probe_ptr_start: u8;
    static jsr_loongarch64_probe_ptr_end: u8;
    static jsr_loongarch64_probe_proc_start: u8;
    static jsr_loongarch64_probe_proc_end: u8;
    static jsr_loongarch64_probe_rights_start: u8;
    static jsr_loongarch64_probe_rights_end: u8;
}

/// # Safety
/// Entry and stack must be mapped with user permissions in the active address space.
pub unsafe fn enter(entry: u64, stack: u64, arg0: u64, arg1: u64) -> ! {
    enter_user(entry, stack, arg0, arg1)
}

pub fn set_kernel_stack(top: u64) {
    trap::set_kernel_stack(top);
}

pub fn kernel_stack() -> u64 {
    trap::kernel_stack()
}

/// Return the requested position-independent user probe machine code.
pub fn probe(probe: UserProbe) -> &'static [u8] {
    // SAFETY: every pair names symbols in the same read-only assembly block,
    // with start before end.
    unsafe {
        let (start, end) = match probe {
            UserProbe::ReportPrivilege => (
                &jsr_loongarch64_probe_cpl_start as *const u8,
                &jsr_loongarch64_probe_cpl_end as *const u8,
            ),
            UserProbe::ReadAddress => (
                &jsr_loongarch64_probe_read_start as *const u8,
                &jsr_loongarch64_probe_read_end as *const u8,
            ),
            UserProbe::Privileged => (
                &jsr_loongarch64_probe_priv_start as *const u8,
                &jsr_loongarch64_probe_priv_end as *const u8,
            ),
            UserProbe::SyscallSmoke => (
                &jsr_loongarch64_probe_sys_start as *const u8,
                &jsr_loongarch64_probe_sys_end as *const u8,
            ),
            UserProbe::UserPointers => (
                &jsr_loongarch64_probe_ptr_start as *const u8,
                &jsr_loongarch64_probe_ptr_end as *const u8,
            ),
            UserProbe::ProcessThreads => (
                &jsr_loongarch64_probe_proc_start as *const u8,
                &jsr_loongarch64_probe_proc_end as *const u8,
            ),
            UserProbe::HandleRights => (
                &jsr_loongarch64_probe_rights_start as *const u8,
                &jsr_loongarch64_probe_rights_end as *const u8,
            ),
        };
        core::slice::from_raw_parts(start, end as usize - start as usize)
    }
}
