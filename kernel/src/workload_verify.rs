//! Feature-gated native Workload runtime verification.
//!
//! 原生 Workload 运行时验收：真实 Process/Task、私有页、CPU group 和 Ring。

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use kernel_core::paging::MapFlags;
use kernel_core::security_domain::DomainKey;
use kernel_core::smp::CpuSet;
use kernel_core::workload::{ResourceLimits, ResourceUsage, WorkloadState};

use crate::proc::{self, ProcState};
use crate::syscall::{table as abi, SyscallSet};
use crate::task::TaskId;
use crate::{kprintln, sched};

const CODE_OFF: u64 = 0x40_0000;
const EXTRA_OFF: u64 = 0x80_0000;
const ANON_OFF: u64 = 0x100_0000;
const API_CODE_OFF: u64 = 0x140_0000;
const API_DESC_OFF: u64 = 0x180_0000;
const API_INFO_OFF: u64 = 0x1c0_0000;
const MEMBER_CODE_OFF: u64 = 0x200_0000;
const MEMBER_CREATE_OFF: u64 = 0x240_0000;
const MEMBER_SPAWN_OFF: u64 = 0x280_0000;
const MEMBER_ELF_OFF: u64 = 0x2c0_0000;
const MEMBER_KEY_OFF: u64 = 0x300_0000;
const SANDBOX_CODE_OFF: u64 = 0x340_0000;
const SANDBOX_DESC_OFF: u64 = 0x380_0000;
const SANDBOX_INFO_OFF: u64 = 0x3c0_0000;
const SANDBOX_IMAGE_DESC_OFF: u64 = 0x400_0000;
const SANDBOX_VOLUME_DESC_OFF: u64 = 0x440_0000;
const SANDBOX_CLONE_DESC_OFF: u64 = 0x480_0000;
const SANDBOX_IMAGE_INFO_OFF: u64 = 0x4c0_0000;
const SANDBOX_LAYER_INFO_OFF: u64 = 0x500_0000;
const SANDBOX_VOLUME_INFO_OFF: u64 = 0x540_0000;
const STACK_OFF: u64 = 0xC0_0000;

static FAILED: AtomicU32 = AtomicU32::new(0);
static HIERARCHY_STOP: AtomicBool = AtomicBool::new(false);
static HIERARCHY_DONE: AtomicBool = AtomicBool::new(false);

const HIERARCHY_TASK: u64 = 0x574f_0001;

fn hierarchy_worker() {
    while !HIERARCHY_STOP.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }
    HIERARCHY_DONE.store(true, Ordering::Release);
}

fn api_code(base: u64, foreign_key: u64) -> Vec<u8> {
    fn imm32(code: &mut Vec<u8>, opcode: u8, value: u32) {
        code.push(opcode);
        code.extend_from_slice(&value.to_le_bytes());
    }
    fn imm64(code: &mut Vec<u8>, opcode: u8, value: u64) {
        code.extend_from_slice(&[0x48, opcode]);
        code.extend_from_slice(&value.to_le_bytes());
    }
    fn syscall(code: &mut Vec<u8>) {
        code.extend_from_slice(&[0x0f, 0x05]);
    }
    fn test_rax(code: &mut Vec<u8>) {
        code.extend_from_slice(&[0x48, 0x85, 0xc0]);
    }
    fn jle_error(code: &mut Vec<u8>, patches: &mut Vec<usize>) {
        code.extend_from_slice(&[0x0f, 0x8e, 0, 0, 0, 0]);
        patches.push(code.len() - 4);
    }
    fn js_error(code: &mut Vec<u8>, patches: &mut Vec<usize>) {
        code.extend_from_slice(&[0x0f, 0x88, 0, 0, 0, 0]);
        patches.push(code.len() - 4);
    }
    fn jne_error(code: &mut Vec<u8>, patches: &mut Vec<usize>) {
        code.extend_from_slice(&[0x0f, 0x85, 0, 0, 0, 0]);
        patches.push(code.len() - 4);
    }
    fn exit(code: &mut Vec<u8>, status: u32) {
        imm32(code, 0xb8, abi::SYSTEM_PROCESS_EXIT);
        imm32(code, 0xbf, status);
        syscall(code);
        code.extend_from_slice(&[0x0f, 0x0b]);
    }

    let mut code = Vec::new();
    let mut patches = Vec::new();
    imm32(&mut code, 0xb8, abi::SYSTEM_WORKLOAD_CREATE);
    imm64(&mut code, 0xbf, base + API_DESC_OFF);
    syscall(&mut code);
    test_rax(&mut code);
    jle_error(&mut code, &mut patches);
    code.extend_from_slice(&[0x48, 0x89, 0xc3]); // mov rbx, rax

    imm32(&mut code, 0xb8, abi::SYSTEM_WORKLOAD_QUERY);
    code.extend_from_slice(&[0x48, 0x89, 0xdf]); // mov rdi, rbx
    imm64(&mut code, 0xbe, base + API_INFO_OFF);
    imm64(
        &mut code,
        0xba,
        kernel_core::workload_abi::INFO_BYTES as u64,
    );
    syscall(&mut code);
    test_rax(&mut code);
    jle_error(&mut code, &mut patches);

    // A foreign-domain key must be indistinguishable from a missing object.
    imm32(&mut code, 0xb8, abi::SYSTEM_WORKLOAD_QUERY);
    imm64(&mut code, 0xbf, foreign_key);
    imm64(&mut code, 0xbe, base + API_INFO_OFF);
    imm64(
        &mut code,
        0xba,
        kernel_core::workload_abi::INFO_BYTES as u64,
    );
    syscall(&mut code);
    code.extend_from_slice(&[0x48, 0x3d]); // cmp rax, sign-extended imm32
    code.extend_from_slice(&(-(abi::SYSTEM_WORKLOAD_ERROR_NOT_FOUND as i32)).to_le_bytes());
    jne_error(&mut code, &mut patches);

    imm32(&mut code, 0xb8, abi::SYSTEM_WORKLOAD_STOP);
    code.extend_from_slice(&[0x48, 0x89, 0xdf]); // mov rdi, rbx
    syscall(&mut code);
    test_rax(&mut code);
    js_error(&mut code, &mut patches);

    // A second stop completes Stopped only because this Workload has no
    // resources or children. Destroy then removes the terminal registry entry.
    imm32(&mut code, 0xb8, abi::SYSTEM_WORKLOAD_STOP);
    code.extend_from_slice(&[0x48, 0x89, 0xdf]);
    syscall(&mut code);
    test_rax(&mut code);
    js_error(&mut code, &mut patches);
    imm32(&mut code, 0xb8, abi::SYSTEM_WORKLOAD_DESTROY);
    code.extend_from_slice(&[0x48, 0x89, 0xdf]);
    syscall(&mut code);
    test_rax(&mut code);
    js_error(&mut code, &mut patches);

    imm32(&mut code, 0xb8, abi::SYSTEM_WORKLOAD_QUERY);
    code.extend_from_slice(&[0x48, 0x89, 0xdf]);
    imm64(&mut code, 0xbe, base + API_INFO_OFF);
    imm64(
        &mut code,
        0xba,
        kernel_core::workload_abi::INFO_BYTES as u64,
    );
    syscall(&mut code);
    code.extend_from_slice(&[0x48, 0x3d]);
    code.extend_from_slice(&(-(abi::SYSTEM_WORKLOAD_ERROR_NOT_FOUND as i32)).to_le_bytes());
    jne_error(&mut code, &mut patches);
    exit(&mut code, 0);

    let error = code.len();
    for patch in patches {
        let end = patch + 4;
        let displacement = (error as i64 - end as i64) as i32;
        code[patch..end].copy_from_slice(&displacement.to_le_bytes());
    }
    exit(&mut code, 1);
    code
}

fn verify_user_workload_abi(base: u64) {
    let page = kernel_core::frame::FRAME_SIZE as u64;
    let foreign_domain = DomainKey {
        id: 0x574f_9001,
        generation: 1,
    };
    let foreign = match crate::workload::create(
        foreign_domain,
        ResourceLimits {
            cpu_permille: 100,
            memory_bytes: page,
            threads: 1,
            ring_entries: 1,
            io_bytes: 64 * 1024,
            io_ops: 16,
        },
    ) {
        Ok(foreign) => foreign,
        Err(error) => {
            check(false, error.name());
            return;
        }
    };
    check(
        crate::workload::transition(foreign, WorkloadState::Ready).is_ok()
            && crate::workload::transition(foreign, WorkloadState::Running).is_ok(),
        "foreign workload starts",
    );
    let calls = SyscallSet::of(&[
        abi::SYSTEM_PROCESS_EXIT,
        abi::SYSTEM_WORKLOAD_CREATE,
        abi::SYSTEM_WORKLOAD_QUERY,
        abi::SYSTEM_WORKLOAD_STOP,
        abi::SYSTEM_WORKLOAD_DESTROY,
    ]);
    let pid = match proc::create("workload-user-abi", calls) {
        Ok(pid) => pid,
        Err(error) => {
            kprintln!("[JSR-WORKLOAD] user ABI process create failed: {:?}", error);
            check(false, "user ABI process create");
            return;
        }
    };
    let args = kernel_core::workload_abi::CreateArgs {
        parent: None,
        limits: ResourceLimits {
            cpu_permille: 100,
            memory_bytes: 2 * page,
            threads: 1,
            ring_entries: 1,
            io_bytes: 64 * 1024,
            io_ops: 16,
        },
    }
    .encode();
    check(
        proc::map_new(pid, base + API_CODE_OFF, MapFlags::USER | MapFlags::EXECUTE).is_ok()
            && proc::map_new(pid, base + API_DESC_OFF, MapFlags::USER | MapFlags::WRITE).is_ok()
            && proc::map_new(pid, base + API_INFO_OFF, MapFlags::USER | MapFlags::WRITE).is_ok()
            && proc::map_new(
                pid,
                base + STACK_OFF - page,
                MapFlags::USER | MapFlags::WRITE,
            )
            .is_ok(),
        "user ABI pages map",
    );
    let code = api_code(base, foreign.to_raw());
    check(
        proc::write(pid, base + API_CODE_OFF, &code).is_ok()
            && proc::write(pid, base + API_DESC_OFF, &args).is_ok(),
        "user ABI code and descriptor install",
    );
    let task = proc::spawn_thread(
        pid,
        "workload-user-abi",
        base + API_CODE_OFF,
        base + STACK_OFF,
        0,
        0,
    );
    check(task.is_ok(), "user ABI task starts");
    if task.is_err() || !sched::run_until(sched::timer_ticks().saturating_add(1000)) {
        check(false, "user ABI task settles");
        return;
    }
    check(
        matches!(proc::state(pid), Some(ProcState::Exited { code: 0 })),
        "user ABI task exits zero",
    );
    let mut info = [0u8; kernel_core::workload_abi::INFO_BYTES];
    if proc::read(pid, base + API_INFO_OFF, &mut info).is_err() {
        check(false, "user ABI query output readable");
        return;
    }
    let key = kernel_core::workload::WorkloadKey::from_raw(u64::from_le_bytes(
        info[8..16].try_into().expect("fixed key field"),
    ));
    check(key.is_some(), "user ABI returns a workload key");
    check(info[6] == 3, "user ABI query reports Running");
    check(
        u64::from_le_bytes(info[48..56].try_into().expect("fixed usage field")) == 0,
        "user ABI workload starts with zero usage",
    );
    let _ = proc::reap(pid);
    crate::kobj::run_cleanup(usize::MAX);
    check(
        crate::workload::transition(foreign, WorkloadState::Stopping).is_ok()
            && crate::workload::transition(foreign, WorkloadState::Stopped).is_ok()
            && crate::workload::destroy(foreign).is_ok(),
        "foreign workload cleanup",
    );
    let _ = key;
}

fn sandbox_abi_code(base: u64, foreign_key: u64) -> Vec<u8> {
    fn imm32(code: &mut Vec<u8>, opcode: u8, value: u32) {
        code.push(opcode);
        code.extend_from_slice(&value.to_le_bytes());
    }
    fn imm64(code: &mut Vec<u8>, opcode: u8, value: u64) {
        code.extend_from_slice(&[0x48, opcode]);
        code.extend_from_slice(&value.to_le_bytes());
    }
    fn imm64_r10(code: &mut Vec<u8>, value: u64) {
        code.extend_from_slice(&[0x49, 0xba]);
        code.extend_from_slice(&value.to_le_bytes());
    }
    fn imm64_r8(code: &mut Vec<u8>, value: u64) {
        code.extend_from_slice(&[0x49, 0xb8]);
        code.extend_from_slice(&value.to_le_bytes());
    }
    fn syscall(code: &mut Vec<u8>) {
        code.extend_from_slice(&[0x0f, 0x05]);
    }
    fn test_rax(code: &mut Vec<u8>) {
        code.extend_from_slice(&[0x48, 0x85, 0xc0]);
    }
    fn jle_error(code: &mut Vec<u8>, patches: &mut Vec<usize>) {
        code.extend_from_slice(&[0x0f, 0x8e, 0, 0, 0, 0]);
        patches.push(code.len() - 4);
    }
    fn js_error(code: &mut Vec<u8>, patches: &mut Vec<usize>) {
        code.extend_from_slice(&[0x0f, 0x88, 0, 0, 0, 0]);
        patches.push(code.len() - 4);
    }
    fn cmp_rax(code: &mut Vec<u8>, value: i32) {
        code.extend_from_slice(&[0x48, 0x3d]);
        code.extend_from_slice(&value.to_le_bytes());
    }
    fn jne_error(code: &mut Vec<u8>, patches: &mut Vec<usize>) {
        code.extend_from_slice(&[0x0f, 0x85, 0, 0, 0, 0]);
        patches.push(code.len() - 4);
    }
    fn exit(code: &mut Vec<u8>, status: u32) {
        imm32(code, 0xb8, abi::SYSTEM_PROCESS_EXIT);
        imm32(code, 0xbf, status);
        syscall(code);
        code.extend_from_slice(&[0x0f, 0x0b]);
    }

    let mut code = Vec::new();
    let mut patches = Vec::new();
    imm32(&mut code, 0xb8, abi::SYSTEM_SANDBOX_CREATE);
    imm64(&mut code, 0xbf, base + SANDBOX_DESC_OFF);
    syscall(&mut code);
    test_rax(&mut code);
    jle_error(&mut code, &mut patches);
    code.extend_from_slice(&[0x48, 0x89, 0xc3]); // mov rbx, rax

    imm32(&mut code, 0xb8, abi::SYSTEM_SANDBOX_QUERY);
    code.extend_from_slice(&[0x48, 0x89, 0xdf]); // mov rdi, rbx
    imm64(&mut code, 0xbe, base + SANDBOX_INFO_OFF);
    imm64(&mut code, 0xba, kernel_core::sandbox_abi::INFO_BYTES as u64);
    syscall(&mut code);
    test_rax(&mut code);
    jle_error(&mut code, &mut patches);

    // A foreign-domain key is indistinguishable from a missing object.
    imm32(&mut code, 0xb8, abi::SYSTEM_SANDBOX_QUERY);
    imm64(&mut code, 0xbf, foreign_key);
    imm64(&mut code, 0xbe, base + SANDBOX_INFO_OFF);
    imm64(&mut code, 0xba, kernel_core::sandbox_abi::INFO_BYTES as u64);
    syscall(&mut code);
    cmp_rax(&mut code, -(abi::SYSTEM_SANDBOX_ERROR_NOT_FOUND as i32));
    jne_error(&mut code, &mut patches);

    imm32(&mut code, 0xb8, abi::SYSTEM_SANDBOX_QUERY);
    code.extend_from_slice(&[0x48, 0x89, 0xdf]);
    imm64(&mut code, 0xbe, base + SANDBOX_INFO_OFF);
    imm32(&mut code, 0xba, 0);
    syscall(&mut code);
    cmp_rax(
        &mut code,
        -(abi::SYSTEM_SANDBOX_ERROR_BUFFER_TOO_SMALL as i32),
    );
    jne_error(&mut code, &mut patches);

    // Bind the kernel-issued sandbox key into all storage descriptors.
    imm64(&mut code, 0xbf, base + SANDBOX_IMAGE_DESC_OFF + 8);
    code.extend_from_slice(&[0x48, 0x89, 0x1f]); // mov [rdi], rbx
    imm64(&mut code, 0xbf, base + SANDBOX_VOLUME_DESC_OFF + 8);
    code.extend_from_slice(&[0x48, 0x89, 0x1f]);
    imm64(&mut code, 0xbf, base + SANDBOX_CLONE_DESC_OFF + 8);
    code.extend_from_slice(&[0x48, 0x89, 0x1f]);

    imm32(&mut code, 0xb8, abi::SYSTEM_SANDBOX_IMAGE_LOAD);
    imm64(&mut code, 0xbf, base + SANDBOX_IMAGE_DESC_OFF);
    syscall(&mut code);
    test_rax(&mut code);
    jle_error(&mut code, &mut patches);
    code.extend_from_slice(&[0x49, 0x89, 0xc5]); // mov r13, rax
    imm64(&mut code, 0xbf, base + SANDBOX_VOLUME_DESC_OFF + 16);
    code.extend_from_slice(&[0x4c, 0x89, 0x2f]); // mov [rdi], r13

    imm32(&mut code, 0xb8, abi::SYSTEM_SANDBOX_IMAGE_QUERY);
    code.extend_from_slice(&[0x48, 0x89, 0xdf]); // mov rdi, rbx
    code.extend_from_slice(&[0x4c, 0x89, 0xee]); // mov rsi, r13
    imm64(&mut code, 0xba, base + SANDBOX_IMAGE_INFO_OFF);
    imm64_r10(
        &mut code,
        kernel_core::sandbox_storage_abi::IMAGE_INFO_BYTES as u64,
    );
    syscall(&mut code);
    test_rax(&mut code);
    jle_error(&mut code, &mut patches);

    imm32(&mut code, 0xb8, abi::SYSTEM_SANDBOX_IMAGE_LAYER_QUERY);
    code.extend_from_slice(&[0x48, 0x89, 0xdf]);
    code.extend_from_slice(&[0x4c, 0x89, 0xee]);
    code.extend_from_slice(&[0x31, 0xd2]); // xor edx, edx
    imm64_r10(&mut code, base + SANDBOX_LAYER_INFO_OFF);
    imm64_r8(
        &mut code,
        kernel_core::sandbox_storage_abi::LAYER_INFO_BYTES as u64,
    );
    syscall(&mut code);
    test_rax(&mut code);
    jle_error(&mut code, &mut patches);

    imm32(&mut code, 0xb8, abi::SYSTEM_SANDBOX_VOLUME_CREATE);
    imm64(&mut code, 0xbf, base + SANDBOX_VOLUME_DESC_OFF);
    syscall(&mut code);
    test_rax(&mut code);
    jle_error(&mut code, &mut patches);
    code.extend_from_slice(&[0x49, 0x89, 0xc6]); // mov r14, rax
    imm64(&mut code, 0xbf, base + SANDBOX_CLONE_DESC_OFF + 16);
    code.extend_from_slice(&[0x4c, 0x89, 0x37]); // mov [rdi], r14

    imm32(&mut code, 0xb8, abi::SYSTEM_SANDBOX_VOLUME_DUPLICATE);
    imm64(&mut code, 0xbf, base + SANDBOX_CLONE_DESC_OFF);
    syscall(&mut code);
    test_rax(&mut code);
    jle_error(&mut code, &mut patches);
    code.extend_from_slice(&[0x49, 0x89, 0xc7]); // mov r15, rax

    imm32(&mut code, 0xb8, abi::SYSTEM_SANDBOX_IMAGE_QUERY);
    code.extend_from_slice(&[0x48, 0x89, 0xdf]);
    code.extend_from_slice(&[0x4c, 0x89, 0xee]);
    imm64(&mut code, 0xba, base + SANDBOX_IMAGE_INFO_OFF);
    imm64_r10(
        &mut code,
        kernel_core::sandbox_storage_abi::IMAGE_INFO_BYTES as u64,
    );
    syscall(&mut code);
    test_rax(&mut code);
    jle_error(&mut code, &mut patches);

    imm32(&mut code, 0xb8, abi::SYSTEM_SANDBOX_VOLUME_WRITE);
    code.extend_from_slice(&[0x48, 0x89, 0xdf]);
    code.extend_from_slice(&[0x4c, 0x89, 0xf6]);
    imm32(&mut code, 0xba, 7);
    syscall(&mut code);
    test_rax(&mut code);
    js_error(&mut code, &mut patches);

    imm32(&mut code, 0xb8, abi::SYSTEM_SANDBOX_VOLUME_WRITE);
    code.extend_from_slice(&[0x48, 0x89, 0xdf]);
    code.extend_from_slice(&[0x4c, 0x89, 0xfe]);
    imm32(&mut code, 0xba, 3);
    syscall(&mut code);
    test_rax(&mut code);
    js_error(&mut code, &mut patches);

    imm32(&mut code, 0xb8, abi::SYSTEM_SANDBOX_VOLUME_QUERY);
    code.extend_from_slice(&[0x48, 0x89, 0xdf]);
    code.extend_from_slice(&[0x4c, 0x89, 0xf6]);
    imm64(&mut code, 0xba, base + SANDBOX_VOLUME_INFO_OFF);
    imm64_r10(
        &mut code,
        kernel_core::sandbox_storage_abi::VOLUME_INFO_BYTES as u64,
    );
    syscall(&mut code);
    test_rax(&mut code);
    jle_error(&mut code, &mut patches);

    imm32(&mut code, 0xb8, abi::SYSTEM_SANDBOX_IMAGE_DESTROY);
    code.extend_from_slice(&[0x48, 0x89, 0xdf]);
    code.extend_from_slice(&[0x4c, 0x89, 0xee]);
    syscall(&mut code);
    cmp_rax(
        &mut code,
        -(abi::SYSTEM_SANDBOX_STORAGE_ERROR_IN_USE as i32),
    );
    jne_error(&mut code, &mut patches);

    imm32(&mut code, 0xb8, abi::SYSTEM_SANDBOX_VOLUME_DESTROY);
    code.extend_from_slice(&[0x48, 0x89, 0xdf]);
    code.extend_from_slice(&[0x4c, 0x89, 0xf6]);
    syscall(&mut code);
    cmp_rax(
        &mut code,
        -(abi::SYSTEM_SANDBOX_STORAGE_ERROR_IN_USE as i32),
    );
    jne_error(&mut code, &mut patches);

    imm32(&mut code, 0xb8, abi::SYSTEM_SANDBOX_VOLUME_DESTROY);
    code.extend_from_slice(&[0x48, 0x89, 0xdf]);
    code.extend_from_slice(&[0x4c, 0x89, 0xfe]);
    syscall(&mut code);
    test_rax(&mut code);
    js_error(&mut code, &mut patches);

    imm32(&mut code, 0xb8, abi::SYSTEM_SANDBOX_VOLUME_RELEASE);
    code.extend_from_slice(&[0x48, 0x89, 0xdf]);
    code.extend_from_slice(&[0x4c, 0x89, 0xf6]);
    imm32(&mut code, 0xba, 7);
    syscall(&mut code);
    test_rax(&mut code);
    js_error(&mut code, &mut patches);

    imm32(&mut code, 0xb8, abi::SYSTEM_SANDBOX_VOLUME_DESTROY);
    code.extend_from_slice(&[0x48, 0x89, 0xdf]);
    code.extend_from_slice(&[0x4c, 0x89, 0xf6]);
    syscall(&mut code);
    test_rax(&mut code);
    js_error(&mut code, &mut patches);

    imm32(&mut code, 0xb8, abi::SYSTEM_SANDBOX_IMAGE_DESTROY);
    code.extend_from_slice(&[0x48, 0x89, 0xdf]);
    code.extend_from_slice(&[0x4c, 0x89, 0xee]);
    syscall(&mut code);
    test_rax(&mut code);
    js_error(&mut code, &mut patches);

    imm32(&mut code, 0xb8, abi::SYSTEM_SANDBOX_IMAGE_QUERY);
    code.extend_from_slice(&[0x48, 0x89, 0xdf]);
    code.extend_from_slice(&[0x4c, 0x89, 0xee]);
    imm64(&mut code, 0xba, base + SANDBOX_IMAGE_INFO_OFF);
    imm64_r10(
        &mut code,
        kernel_core::sandbox_storage_abi::IMAGE_INFO_BYTES as u64,
    );
    syscall(&mut code);
    cmp_rax(
        &mut code,
        -(abi::SYSTEM_SANDBOX_IMAGE_ERROR_NOT_FOUND as i32),
    );
    jne_error(&mut code, &mut patches);

    imm32(&mut code, 0xb8, abi::SYSTEM_SANDBOX_STOP);
    code.extend_from_slice(&[0x48, 0x89, 0xdf]);
    syscall(&mut code);
    test_rax(&mut code);
    js_error(&mut code, &mut patches);
    imm32(&mut code, 0xb8, abi::SYSTEM_SANDBOX_STOP);
    code.extend_from_slice(&[0x48, 0x89, 0xdf]);
    syscall(&mut code);
    test_rax(&mut code);
    js_error(&mut code, &mut patches);
    imm32(&mut code, 0xb8, abi::SYSTEM_SANDBOX_DESTROY);
    code.extend_from_slice(&[0x48, 0x89, 0xdf]);
    syscall(&mut code);
    test_rax(&mut code);
    js_error(&mut code, &mut patches);

    imm32(&mut code, 0xb8, abi::SYSTEM_SANDBOX_QUERY);
    code.extend_from_slice(&[0x48, 0x89, 0xdf]);
    imm64(&mut code, 0xbe, base + SANDBOX_INFO_OFF);
    imm64(&mut code, 0xba, kernel_core::sandbox_abi::INFO_BYTES as u64);
    syscall(&mut code);
    cmp_rax(&mut code, -(abi::SYSTEM_SANDBOX_ERROR_NOT_FOUND as i32));
    jne_error(&mut code, &mut patches);
    exit(&mut code, 0);

    let error = code.len();
    for patch in patches {
        let end = patch + 4;
        let displacement = (error as i64 - end as i64) as i32;
        code[patch..end].copy_from_slice(&displacement.to_le_bytes());
    }
    exit(&mut code, 1);
    code
}

fn verify_sandbox_abi(base: u64) {
    let page = kernel_core::frame::FRAME_SIZE as u64;
    let foreign_domain = DomainKey {
        id: 0x574f_9002,
        generation: 1,
    };
    let limits = ResourceLimits {
        cpu_permille: 100,
        memory_bytes: 2 * page,
        threads: 1,
        ring_entries: 1,
        io_bytes: 64 * 1024,
        io_ops: 16,
    };
    let foreign = match crate::sandbox::create_sandbox(foreign_domain, limits) {
        Ok(key) => key,
        Err(error) => {
            check(false, error.name());
            return;
        }
    };
    check(
        crate::sandbox::mark_ready(foreign_domain, foreign).is_ok()
            && crate::sandbox::start(foreign_domain, foreign).is_ok(),
        "foreign sandbox starts",
    );
    let calls = SyscallSet::of(&[
        abi::SYSTEM_PROCESS_EXIT,
        abi::SYSTEM_SANDBOX_CREATE,
        abi::SYSTEM_SANDBOX_QUERY,
        abi::SYSTEM_SANDBOX_STOP,
        abi::SYSTEM_SANDBOX_DESTROY,
        abi::SYSTEM_SANDBOX_IMAGE_LOAD,
        abi::SYSTEM_SANDBOX_IMAGE_QUERY,
        abi::SYSTEM_SANDBOX_IMAGE_LAYER_QUERY,
        abi::SYSTEM_SANDBOX_IMAGE_DESTROY,
        abi::SYSTEM_SANDBOX_VOLUME_CREATE,
        abi::SYSTEM_SANDBOX_VOLUME_DUPLICATE,
        abi::SYSTEM_SANDBOX_VOLUME_QUERY,
        abi::SYSTEM_SANDBOX_VOLUME_WRITE,
        abi::SYSTEM_SANDBOX_VOLUME_RELEASE,
        abi::SYSTEM_SANDBOX_VOLUME_DESTROY,
    ]);
    let pid = match proc::create("sandbox-user-abi", calls) {
        Ok(pid) => pid,
        Err(error) => {
            kprintln!("[JSR-SANDBOX] user ABI process create failed: {:?}", error);
            check(false, "sandbox user ABI process create");
            return;
        }
    };
    let args = kernel_core::workload_abi::CreateArgs {
        parent: None,
        limits,
    }
    .encode();
    let dummy_sandbox =
        kernel_core::sandbox::SandboxKey::from_raw((1 << 16) | 1).expect("valid key");
    let content = kernel_core::sandbox_image::ContentDigest::new([0x11; 32]).unwrap();
    let signature = kernel_core::sandbox_image::ContentDigest::new([0x22; 32]).unwrap();
    let mut layers = [kernel_core::sandbox_image::ImageLayerSpec::default();
        kernel_core::sandbox_image::MAX_IMAGE_LAYERS];
    layers[0] = kernel_core::sandbox_image::ImageLayerSpec { content, bytes: 5 };
    layers[1] = kernel_core::sandbox_image::ImageLayerSpec {
        content: signature,
        bytes: 7,
    };
    let image_add = kernel_core::sandbox_storage_abi::ImageAddArgs {
        sandbox: dummy_sandbox,
        spec: kernel_core::sandbox_image::ImageSpec {
            image: kernel_core::sandbox_image::SignedImage {
                content,
                signer: 7,
                signature,
                version: kernel_core::sandbox_image::ImageVersion {
                    major: 1,
                    minor: 0,
                    patch: 0,
                },
            },
            rootfs_bytes: 12,
            writable_bytes: 64,
            max_volumes: 2,
        },
        layer_count: 2,
        layers,
    }
    .encode()
    .expect("bounded image descriptor");
    let volume_create = kernel_core::sandbox_storage_abi::VolumeCreateArgs {
        sandbox: dummy_sandbox,
        image: kernel_core::sandbox_image::ImageKey::from_raw((1 << 16) | 1)
            .expect("valid image key"),
        capacity_bytes: 32,
    }
    .encode();
    let volume_clone = kernel_core::sandbox_storage_abi::VolumeCloneArgs {
        sandbox: dummy_sandbox,
        parent: kernel_core::sandbox_image::VolumeKey::from_raw((1 << 16) | 1)
            .expect("valid volume key"),
        capacity_bytes: 16,
    }
    .encode();
    let code = sandbox_abi_code(base, foreign.to_raw());
    check(
        proc::map_new(
            pid,
            base + SANDBOX_CODE_OFF,
            MapFlags::USER | MapFlags::EXECUTE,
        )
        .is_ok()
            && proc::map_new(
                pid,
                base + SANDBOX_DESC_OFF,
                MapFlags::USER | MapFlags::WRITE,
            )
            .is_ok()
            && proc::map_new(
                pid,
                base + SANDBOX_INFO_OFF,
                MapFlags::USER | MapFlags::WRITE,
            )
            .is_ok()
            && [
                SANDBOX_IMAGE_DESC_OFF,
                SANDBOX_VOLUME_DESC_OFF,
                SANDBOX_CLONE_DESC_OFF,
                SANDBOX_IMAGE_INFO_OFF,
                SANDBOX_LAYER_INFO_OFF,
                SANDBOX_VOLUME_INFO_OFF,
            ]
            .iter()
            .all(|offset| {
                proc::map_new(pid, base + offset, MapFlags::USER | MapFlags::WRITE).is_ok()
            })
            && proc::map_new(
                pid,
                base + STACK_OFF - page,
                MapFlags::USER | MapFlags::WRITE,
            )
            .is_ok(),
        "sandbox user ABI pages map",
    );
    check(
        proc::write(pid, base + SANDBOX_CODE_OFF, &code).is_ok()
            && proc::write(pid, base + SANDBOX_DESC_OFF, &args).is_ok()
            && proc::write(pid, base + SANDBOX_IMAGE_DESC_OFF, &image_add).is_ok()
            && proc::write(pid, base + SANDBOX_VOLUME_DESC_OFF, &volume_create).is_ok()
            && proc::write(pid, base + SANDBOX_CLONE_DESC_OFF, &volume_clone).is_ok(),
        "sandbox user ABI inputs install",
    );
    let task = proc::spawn_thread(
        pid,
        "sandbox-user-abi",
        base + SANDBOX_CODE_OFF,
        base + STACK_OFF,
        0,
        0,
    );
    check(task.is_ok(), "sandbox user ABI task starts");
    if task.is_err() || !sched::run_until(sched::timer_ticks().saturating_add(1000)) {
        check(false, "sandbox user ABI task settles");
        return;
    }
    check(
        matches!(proc::state(pid), Some(ProcState::Exited { code: 0 })),
        "sandbox user ABI exits zero",
    );
    let mut info = [0u8; kernel_core::sandbox_abi::INFO_BYTES];
    check(
        proc::read(pid, base + SANDBOX_INFO_OFF, &mut info).is_ok(),
        "sandbox query output readable",
    );
    check(&info[0..4] == b"JSB1", "sandbox query magic");
    check(
        u16::from_le_bytes([info[4], info[5]]) == kernel_core::sandbox_abi::VERSION,
        "sandbox query version",
    );
    check(info[6] == 3, "sandbox query reports Running");
    let mut image_info = [0u8; kernel_core::sandbox_storage_abi::IMAGE_INFO_BYTES];
    let mut layer_info = [0u8; kernel_core::sandbox_storage_abi::LAYER_INFO_BYTES];
    let mut volume_info = [0u8; kernel_core::sandbox_storage_abi::VOLUME_INFO_BYTES];
    check(
        proc::read(pid, base + SANDBOX_IMAGE_INFO_OFF, &mut image_info).is_ok()
            && proc::read(pid, base + SANDBOX_LAYER_INFO_OFF, &mut layer_info).is_ok()
            && proc::read(pid, base + SANDBOX_VOLUME_INFO_OFF, &mut volume_info).is_ok(),
        "sandbox storage query outputs readable",
    );
    check(&image_info[0..4] == b"JSI1", "sandbox image info magic");
    check(
        u16::from_le_bytes([image_info[114], image_info[115]]) == 2,
        "sandbox image reports two volumes",
    );
    check(&layer_info[0..4] == b"JSI1", "sandbox layer info magic");
    check(
        u64::from_le_bytes(layer_info[40..48].try_into().expect("layer bytes")) == 5,
        "sandbox layer bytes",
    );
    check(&volume_info[0..4] == b"JSV1", "sandbox volume info magic");
    check(
        u64::from_le_bytes(volume_info[40..48].try_into().expect("used bytes")) == 7,
        "sandbox parent volume usage",
    );
    let _ = proc::reap(pid);
    crate::kobj::run_cleanup(usize::MAX);
    check(
        crate::sandbox::stop(foreign_domain, foreign).is_ok()
            && crate::sandbox::stop(foreign_domain, foreign).is_ok()
            && crate::sandbox::destroy(foreign_domain, foreign).is_ok(),
        "foreign sandbox cleanup",
    );
}

fn member_elf(base: u64, wait_ticks: u32) -> Vec<u8> {
    fn section(
        image: &mut [u8],
        shoff: usize,
        index: usize,
        name: u32,
        kind: u32,
        offset: usize,
        size: usize,
        align: u64,
    ) {
        let at = shoff + index * 64;
        image[at..at + 4].copy_from_slice(&name.to_le_bytes());
        image[at + 4..at + 8].copy_from_slice(&kind.to_le_bytes());
        image[at + 24..at + 32].copy_from_slice(&(offset as u64).to_le_bytes());
        image[at + 32..at + 40].copy_from_slice(&(size as u64).to_le_bytes());
        image[at + 48..at + 56].copy_from_slice(&align.to_le_bytes());
    }

    let note_offset = 4096 + 26;
    let names = b"\0.shstrtab\0.note.jasper.abi\0";
    let names_offset = note_offset + kernel_core::abi_version::NOTE_BYTES;
    let shoff = names_offset + names.len();
    let mut image = Vec::new();
    image.resize(shoff + 3 * 64, 0);
    image[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    image[16..18].copy_from_slice(&2u16.to_le_bytes());
    image[18..20].copy_from_slice(&62u16.to_le_bytes());
    image[20..24].copy_from_slice(&1u32.to_le_bytes());
    image[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
    image[58..60].copy_from_slice(&64u16.to_le_bytes());
    image[60..62].copy_from_slice(&3u16.to_le_bytes());
    image[62..64].copy_from_slice(&1u16.to_le_bytes());
    let entry = base + 0x20_0000;
    image[24..32].copy_from_slice(&entry.to_le_bytes());
    image[32..40].copy_from_slice(&64u64.to_le_bytes());
    image[52..54].copy_from_slice(&64u16.to_le_bytes());
    image[54..56].copy_from_slice(&56u16.to_le_bytes());
    image[56..58].copy_from_slice(&1u16.to_le_bytes());
    image[64..68].copy_from_slice(&1u32.to_le_bytes());
    image[68..72].copy_from_slice(&5u32.to_le_bytes());
    image[72..80].copy_from_slice(&4096u64.to_le_bytes());
    image[80..88].copy_from_slice(&entry.to_le_bytes());
    image[96..104].copy_from_slice(&26u64.to_le_bytes());
    image[104..112].copy_from_slice(&26u64.to_le_bytes());
    image[112..120].copy_from_slice(&4096u64.to_le_bytes());
    let code = &mut image[4096..];
    if wait_ticks == 0 {
        code[..5].copy_from_slice(&[0xb8, 0, 0, 0, 0]);
        code[1..5].copy_from_slice(&abi::SYSTEM_PROCESS_EXIT.to_le_bytes());
        code[5..10].copy_from_slice(&[0xbf, 51, 0, 0, 0]);
        code[10..14].copy_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
    } else {
        code[..5].copy_from_slice(&[0xb8, 0, 0, 0, 0]);
        code[1..5].copy_from_slice(&abi::SYSTEM_TIME_WAIT.to_le_bytes());
        code[5..10].copy_from_slice(&[0xbf, 0, 0, 0, 0]);
        code[6..10].copy_from_slice(&wait_ticks.to_le_bytes());
        code[10..12].copy_from_slice(&[0x0f, 0x05]);
        code[12..17].copy_from_slice(&[0xb8, 0, 0, 0, 0]);
        code[13..17].copy_from_slice(&abi::SYSTEM_PROCESS_EXIT.to_le_bytes());
        code[17..22].copy_from_slice(&[0xbf, 51, 0, 0, 0]);
        code[22..26].copy_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
    }
    let note = kernel_core::abi_version::encode_note(
        kernel_core::abi_version::ProgramAbi::native_requirement(),
    );
    image[note_offset..note_offset + note.len()].copy_from_slice(&note);
    image[names_offset..shoff].copy_from_slice(names);
    section(&mut image, shoff, 1, 1, 3, names_offset, names.len(), 1);
    section(&mut image, shoff, 2, 11, 7, note_offset, note.len(), 4);
    image
}

fn member_spawn_code(base: u64, terminate: bool) -> Vec<u8> {
    fn imm32(code: &mut Vec<u8>, opcode: u8, value: u32) {
        code.push(opcode);
        code.extend_from_slice(&value.to_le_bytes());
    }
    fn imm64(code: &mut Vec<u8>, opcode: u8, value: u64) {
        code.extend_from_slice(&[0x48, opcode]);
        code.extend_from_slice(&value.to_le_bytes());
    }
    fn syscall(code: &mut Vec<u8>) {
        code.extend_from_slice(&[0x0f, 0x05]);
    }
    fn test_rax(code: &mut Vec<u8>) {
        code.extend_from_slice(&[0x48, 0x85, 0xc0]);
    }
    fn js_error(code: &mut Vec<u8>, patches: &mut Vec<usize>) {
        code.extend_from_slice(&[0x0f, 0x88, 0, 0, 0, 0]);
        patches.push(code.len() - 4);
    }
    fn jle_error(code: &mut Vec<u8>, patches: &mut Vec<usize>) {
        code.extend_from_slice(&[0x0f, 0x8e, 0, 0, 0, 0]);
        patches.push(code.len() - 4);
    }
    fn cmp_rax(code: &mut Vec<u8>, value: i32) {
        code.extend_from_slice(&[0x48, 0x3d]);
        code.extend_from_slice(&value.to_le_bytes());
    }
    fn cmp_rax_u64(code: &mut Vec<u8>, value: u64) {
        code.extend_from_slice(&[0x48, 0xb9]);
        code.extend_from_slice(&value.to_le_bytes());
        code.extend_from_slice(&[0x48, 0x39, 0xc8]);
    }
    fn jne_error(code: &mut Vec<u8>, patches: &mut Vec<usize>) {
        code.extend_from_slice(&[0x0f, 0x85, 0, 0, 0, 0]);
        patches.push(code.len() - 4);
    }
    fn exit(code: &mut Vec<u8>, status: u32) {
        imm32(code, 0xb8, abi::SYSTEM_PROCESS_EXIT);
        imm32(code, 0xbf, status);
        syscall(code);
        code.extend_from_slice(&[0x0f, 0x0b]);
    }

    let mut code = Vec::new();
    let mut patches = Vec::new();
    imm32(&mut code, 0xb8, abi::SYSTEM_WORKLOAD_CREATE);
    imm64(&mut code, 0xbf, base + MEMBER_CREATE_OFF);
    syscall(&mut code);
    test_rax(&mut code);
    jle_error(&mut code, &mut patches);
    code.extend_from_slice(&[0x48, 0x89, 0xc3]); // mov rbx, rax
    imm64(&mut code, 0xbf, base + MEMBER_KEY_OFF);
    code.extend_from_slice(&[0x48, 0x89, 0x1f]); // mov [rdi], rbx

    imm32(&mut code, 0xb8, abi::SYSTEM_WORKLOAD_SPAWN);
    code.extend_from_slice(&[0x48, 0x89, 0xdf]); // mov rdi, rbx
    imm64(&mut code, 0xbe, base + MEMBER_SPAWN_OFF);
    syscall(&mut code);
    test_rax(&mut code);
    js_error(&mut code, &mut patches);

    imm32(&mut code, 0xb8, abi::SYSTEM_WORKLOAD_MEMBER_QUERY);
    code.extend_from_slice(&[0x48, 0x89, 0xdf]);
    syscall(&mut code);
    cmp_rax(&mut code, 1);
    jne_error(&mut code, &mut patches);

    if terminate {
        imm32(&mut code, 0xb8, abi::SYSTEM_WORKLOAD_KILL);
        code.extend_from_slice(&[0x48, 0x89, 0xdf]);
        syscall(&mut code);
        test_rax(&mut code);
        js_error(&mut code, &mut patches);
    }

    imm64(&mut code, 0xbf, base + MEMBER_SPAWN_OFF + 72);
    code.extend_from_slice(&[0x48, 0x8b, 0x3f]); // mov rdi, [rdi]
    imm32(&mut code, 0xb8, abi::SYSTEM_PROCESS_WAIT);
    syscall(&mut code);
    if terminate {
        cmp_rax_u64(
            &mut code,
            (crate::workload::WORKLOAD_TERMINATED_CODE as u32) as u64,
        );
    } else {
        cmp_rax(&mut code, 51);
    }
    jne_error(&mut code, &mut patches);

    imm64(&mut code, 0xbf, base + MEMBER_SPAWN_OFF + 72);
    code.extend_from_slice(&[0x48, 0x8b, 0x3f]);
    imm32(&mut code, 0xb8, abi::SYSTEM_HANDLE_CLOSE);
    syscall(&mut code);
    test_rax(&mut code);
    js_error(&mut code, &mut patches);
    imm64(&mut code, 0xbf, base + MEMBER_SPAWN_OFF + 80);
    code.extend_from_slice(&[0x48, 0x8b, 0x3f]);
    imm32(&mut code, 0xb8, abi::SYSTEM_HANDLE_CLOSE);
    syscall(&mut code);
    test_rax(&mut code);
    js_error(&mut code, &mut patches);
    imm32(&mut code, 0xb8, abi::SYSTEM_WORKLOAD_MEMBER_QUERY);
    code.extend_from_slice(&[0x48, 0x89, 0xdf]);
    syscall(&mut code);
    cmp_rax(&mut code, 0);
    jne_error(&mut code, &mut patches);
    exit(&mut code, 0);

    let error = code.len();
    for patch in patches {
        let end = patch + 4;
        let displacement = (error as i64 - end as i64) as i32;
        code[patch..end].copy_from_slice(&displacement.to_le_bytes());
    }
    exit(&mut code, 1);
    code
}

fn verify_workload_spawn(base: u64, terminate: bool) {
    let page = kernel_core::frame::FRAME_SIZE as u64;
    let calls = if terminate {
        SyscallSet::of(&[
            abi::SYSTEM_PROCESS_EXIT,
            abi::SYSTEM_PROCESS_WAIT,
            abi::SYSTEM_HANDLE_CLOSE,
            abi::SYSTEM_TIME_WAIT,
            abi::SYSTEM_WORKLOAD_CREATE,
            abi::SYSTEM_WORKLOAD_SPAWN,
            abi::SYSTEM_WORKLOAD_KILL,
            abi::SYSTEM_WORKLOAD_MEMBER_QUERY,
        ])
    } else {
        SyscallSet::of(&[
            abi::SYSTEM_PROCESS_EXIT,
            abi::SYSTEM_PROCESS_WAIT,
            abi::SYSTEM_HANDLE_CLOSE,
            abi::SYSTEM_WORKLOAD_CREATE,
            abi::SYSTEM_WORKLOAD_SPAWN,
            abi::SYSTEM_WORKLOAD_MEMBER_QUERY,
        ])
    };
    let pid = match proc::create("workload-member-spawn", calls) {
        Ok(pid) => pid,
        Err(error) => {
            kprintln!("[JSR-WORKLOAD] member spawn process failed: {:?}", error);
            check(false, "member spawn process");
            return;
        }
    };
    let create = kernel_core::workload_abi::CreateArgs {
        parent: None,
        limits: ResourceLimits {
            cpu_permille: 100,
            memory_bytes: 8 * page,
            threads: 1,
            ring_entries: 1,
            io_bytes: 64 * 1024,
            io_ops: 16,
        },
    }
    .encode();
    let elf = member_elf(base, if terminate { 20 } else { 0 });
    let spawn = kernel_core::spawn_abi::SpawnDesc {
        image_ptr: base + MEMBER_ELF_OFF,
        image_len: elf.len() as u64,
        calls: if terminate {
            SyscallSet::of(&[abi::SYSTEM_PROCESS_EXIT, abi::SYSTEM_TIME_WAIT])
        } else {
            SyscallSet::of(&[abi::SYSTEM_PROCESS_EXIT])
        },
        arg: 0,
        cpu_limit_permille: kernel_core::spawn_abi::CPU_UNLIMITED,
        ..Default::default()
    }
    .encode();
    let code = member_spawn_code(base, terminate);
    check(
        proc::map_new(
            pid,
            base + MEMBER_CODE_OFF,
            MapFlags::USER | MapFlags::EXECUTE,
        )
        .is_ok()
            && proc::map_new(
                pid,
                base + MEMBER_CREATE_OFF,
                MapFlags::USER | MapFlags::WRITE,
            )
            .is_ok()
            && proc::map_new(
                pid,
                base + MEMBER_SPAWN_OFF,
                MapFlags::USER | MapFlags::WRITE,
            )
            .is_ok()
            && proc::map_new(pid, base + MEMBER_ELF_OFF, MapFlags::USER | MapFlags::WRITE).is_ok()
            && proc::map_new(pid, base + MEMBER_ELF_OFF + page, MapFlags::USER).is_ok()
            && proc::map_new(pid, base + MEMBER_KEY_OFF, MapFlags::USER | MapFlags::WRITE).is_ok()
            && proc::map_new(
                pid,
                base + STACK_OFF - page,
                MapFlags::USER | MapFlags::WRITE,
            )
            .is_ok(),
        "member spawn pages map",
    );
    check(
        proc::write(pid, base + MEMBER_CODE_OFF, &code).is_ok()
            && proc::write(pid, base + MEMBER_CREATE_OFF, &create).is_ok()
            && proc::write(pid, base + MEMBER_SPAWN_OFF, &spawn).is_ok()
            && proc::write(pid, base + MEMBER_ELF_OFF, &elf).is_ok(),
        "member spawn inputs install",
    );
    let task = proc::spawn_thread(
        pid,
        "workload-member-spawn",
        base + MEMBER_CODE_OFF,
        base + STACK_OFF,
        0,
        0,
    );
    check(task.is_ok(), "member spawn task starts");
    if task.is_err() || !sched::run_until(sched::timer_ticks().saturating_add(1000)) {
        check(false, "member spawn task settles");
        return;
    }
    check(
        matches!(proc::state(pid), Some(ProcState::Exited { code: 0 })),
        "member spawn task exits zero",
    );
    let mut raw = [0u8; 8];
    if proc::read(pid, base + MEMBER_KEY_OFF, &mut raw).is_err() {
        check(false, "member workload key readable");
        return;
    }
    let key = kernel_core::workload::WorkloadKey::from_raw(u64::from_le_bytes(raw));
    check(key.is_some(), "member workload key valid");
    let _ = proc::reap(pid);
    crate::kobj::run_cleanup(usize::MAX);
    if let Some(key) = key {
        check(
            crate::workload::usage(key) == Some(ResourceUsage::default()),
            "member process releases workload resources",
        );
        let stopping = crate::workload::snapshot(key)
            .is_ok_and(|snapshot| snapshot.state == WorkloadState::Stopping)
            || crate::workload::transition(key, WorkloadState::Stopping).is_ok();
        check(
            stopping
                && crate::workload::transition(key, WorkloadState::Stopped).is_ok()
                && crate::workload::destroy(key).is_ok(),
            "member workload cleanup",
        );
    }
}

fn check(ok: bool, message: &str) {
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-WORKLOAD] CHECK FAILED: {}", message);
    }
}

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed) + {
        #[cfg(feature = "workload-io-verify")]
        {
            crate::workload_io_verify::failed()
        }
        #[cfg(not(feature = "workload-io-verify"))]
        {
            0
        }
    }
}

fn exit_code() -> [u8; 11] {
    let id = abi::SYSTEM_PROCESS_EXIT as u32;
    let mut code = [0x90; 11];
    code[0] = 0xb8;
    code[1..5].copy_from_slice(&id.to_le_bytes());
    code[5..7].copy_from_slice(&[0x31, 0xff]);
    code[7..9].copy_from_slice(&[0x0f, 0x05]);
    code[9..11].copy_from_slice(&[0x0f, 0x0b]);
    code
}

fn verify_hierarchical_cpu(domain: DomainKey) {
    let page = kernel_core::frame::FRAME_SIZE as u64;
    let parent_limits = ResourceLimits {
        cpu_permille: 500,
        memory_bytes: page,
        threads: 1,
        ring_entries: 1,
        io_bytes: 64 * 1024,
        io_ops: 16,
    };
    let child_limits = ResourceLimits {
        cpu_permille: 100,
        ..parent_limits
    };
    let parent = match crate::workload::create(domain, parent_limits) {
        Ok(parent) => parent,
        Err(error) => {
            check(false, error.name());
            return;
        }
    };
    check(
        crate::workload::transition(parent, WorkloadState::Ready).is_ok(),
        "cpu parent ready",
    );
    check(
        crate::workload::transition(parent, WorkloadState::Running).is_ok(),
        "cpu parent running",
    );
    let child = match crate::workload::create_child(parent, child_limits) {
        Ok(child) => child,
        Err(error) => {
            check(false, error.name());
            return;
        }
    };
    check(
        crate::workload::transition(child, WorkloadState::Ready).is_ok(),
        "cpu child ready",
    );
    check(
        crate::workload::transition(child, WorkloadState::Running).is_ok(),
        "cpu child running",
    );
    let parent_group = match crate::workload::cpu_group(parent) {
        Ok(group) => group,
        Err(error) => {
            check(false, error.name());
            return;
        }
    };
    let child_group = match crate::workload::cpu_group(child) {
        Ok(group) => group,
        Err(error) => {
            check(false, error.name());
            return;
        }
    };

    HIERARCHY_STOP.store(false, Ordering::Release);
    HIERARCHY_DONE.store(false, Ordering::Release);
    let spawned = sched::spawn_on(
        TaskId(HIERARCHY_TASK),
        "workload-cpu-child",
        hierarchy_worker,
        Some(child_group),
        CpuSet::first(1),
    );
    check(spawned.is_ok(), "hierarchical CPU worker starts");
    let _ = sched::run_until(sched::timer_ticks().saturating_add(250));
    let parent_stats = sched::cpu_group_stats(parent_group).unwrap_or_default();
    let child_stats = sched::cpu_group_stats(child_group).unwrap_or_default();
    check(
        child_stats.used_ticks > 0 && parent_stats.used_ticks == child_stats.used_ticks,
        "child execution charges the whole ancestor chain",
    );
    check(
        child_stats.throttle_events > 0,
        "child CPU quota throttles real execution",
    );

    HIERARCHY_STOP.store(true, Ordering::Release);
    check(
        sched::run_until(sched::timer_ticks().saturating_add(100)),
        "hierarchical CPU worker settles",
    );
    check(
        HIERARCHY_DONE.load(Ordering::Acquire),
        "hierarchical CPU worker observes stop",
    );
    check(
        crate::workload::transition(child, WorkloadState::Stopping).is_ok(),
        "cpu child stopping",
    );
    check(
        crate::workload::transition(child, WorkloadState::Stopped).is_ok(),
        "cpu child stopped",
    );
    check(
        crate::workload::destroy(child).is_ok(),
        "cpu child destroyed",
    );
    check(
        crate::workload::transition(parent, WorkloadState::Stopping).is_ok(),
        "cpu parent stopping",
    );
    check(
        crate::workload::transition(parent, WorkloadState::Stopped).is_ok(),
        "cpu parent stopped",
    );
    check(
        crate::workload::destroy(parent).is_ok(),
        "cpu parent destroyed",
    );
}

pub fn run() {
    let base = crate::arch::USER_WINDOW.0;
    let page = kernel_core::frame::FRAME_SIZE as u64;
    let groups_before = sched::live_cpu_groups();
    let frames_before = crate::mm::frame::free_frames();
    let release_failures_before = crate::workload::memory_release_failures();
    let domain = DomainKey {
        id: 0x574f,
        generation: 1,
    };
    let limits = ResourceLimits {
        cpu_permille: 500,
        memory_bytes: 6 * page,
        threads: 1,
        ring_entries: 4,
        io_bytes: 1,
        io_ops: 1,
    };
    let workload = match crate::workload::create(domain, limits) {
        Ok(key) => key,
        Err(error) => {
            check(false, error.name());
            return;
        }
    };
    check(
        crate::workload::transition(workload, WorkloadState::Ready).is_ok(),
        "workload ready",
    );
    check(
        crate::workload::transition(workload, WorkloadState::Running).is_ok(),
        "workload running",
    );
    let calls = SyscallSet::of(&[
        abi::SYSTEM_PROCESS_EXIT as u32,
        abi::SYSTEM_ASYNC_RING_CREATE as u32,
    ]);
    let pid = match proc::create("workload-verify", calls) {
        Ok(pid) => pid,
        Err(error) => {
            kprintln!("[JSR-WORKLOAD] process create failed: {:?}", error);
            check(false, "process create");
            return;
        }
    };
    check(proc::bind_workload(pid, workload), "bind workload");
    let io = crate::workload::begin_process_io(pid, 1, 1);
    check(io.is_ok(), "process I/O admission");
    if let Ok(io) = io {
        io.commit();
    }
    check(
        crate::workload::begin_process_io(pid, 1, 1).is_err(),
        "second I/O request exceeds lifetime quota",
    );
    check(
        proc::map_new(pid, base + CODE_OFF, MapFlags::USER | MapFlags::EXECUTE).is_ok(),
        "map code",
    );
    check(
        proc::map_new(
            pid,
            base + STACK_OFF - page,
            MapFlags::USER | MapFlags::WRITE,
        )
        .is_ok(),
        "map stack",
    );
    check(
        proc::map_new(pid, base + EXTRA_OFF, MapFlags::USER | MapFlags::WRITE).is_ok(),
        "map third page",
    );
    check(
        proc::map_anon(pid, base + ANON_OFF, 1, true).is_ok(),
        "map anonymous page",
    );
    let _memory_object = proc::create_memory(pid, 2);
    check(_memory_object.is_ok(), "direct memory object fits");
    check(
        crate::workload::usage(workload).is_some_and(|usage| usage.memory_bytes == 6 * page),
        "direct memory object memory usage",
    );
    let _guest_memory = proc::create_guest_memory(pid, 1);
    check(
        _guest_memory.is_ok(),
        "guest memory object fits its separate budget",
    );
    check(
        proc::vm_guest_memory_quota(pid).is_some_and(|usage| usage.mapped == 1),
        "guest memory uses its separate account",
    );
    check(
        crate::workload::usage(workload).is_some_and(|usage| usage.memory_bytes == 6 * page),
        "guest memory must not consume ordinary workload bytes",
    );
    let before_reject = crate::workload::usage(workload).unwrap_or_default();
    let fourth = proc::map_new(
        pid,
        base + EXTRA_OFF + page,
        MapFlags::USER | MapFlags::WRITE,
    );
    check(fourth.is_err(), "fourth page must exceed memory quota");
    let second_memory_object = proc::create_memory(pid, 2);
    check(
        second_memory_object.is_err(),
        "second memory object must exceed memory quota",
    );
    check(
        proc::map_anon(pid, base + ANON_OFF + page, 1, true).is_err(),
        "anonymous page must exceed memory quota",
    );
    check(
        crate::workload::usage(workload) == Some(before_reject),
        "memory rejection must be atomic",
    );
    check(
        proc::write(pid, base + CODE_OFF, &exit_code()).is_ok(),
        "write exit code",
    );

    let ring = crate::ring::create_for(pid, 4);
    check(ring.is_ok(), "first ring fits");
    check(
        crate::ring::create_for(pid, 1).is_err(),
        "second ring exceeds quota",
    );
    check(
        crate::workload::usage(workload).is_some_and(|usage| usage.ring_entries == 4),
        "ring usage",
    );
    let first = proc::spawn_thread(
        pid,
        "workload-main",
        base + CODE_OFF,
        base + STACK_OFF,
        0,
        0,
    );
    check(first.is_ok(), "first task");
    check(
        proc::spawn_thread(
            pid,
            "workload-over-limit",
            base + CODE_OFF,
            base + STACK_OFF,
            0,
            0,
        )
        .is_err(),
        "second task exceeds quota",
    );
    if first.is_ok() && ring.is_ok() {
        let settled = sched::run_until(sched::timer_ticks().saturating_add(1000));
        check(settled, "workload process settles");
    }
    check(
        matches!(proc::state(pid), Some(ProcState::Exited { code: 0 })),
        "workload process exits zero",
    );
    let _ = proc::reap(pid);
    crate::kobj::run_cleanup(usize::MAX);
    check(
        crate::workload::usage(workload) == Some(ResourceUsage::default()),
        "all workload usage returns to zero",
    );
    check(
        crate::workload::memory_release_failures() == release_failures_before,
        "workload memory releases never underflow",
    );
    check(
        crate::workload::transition(workload, WorkloadState::Stopping).is_ok(),
        "workload stopping",
    );
    check(
        crate::workload::transition(workload, WorkloadState::Stopped).is_ok(),
        "workload stopped",
    );
    check(
        crate::workload::destroy(workload).is_ok(),
        "workload destroy with member unbound",
    );
    verify_hierarchical_cpu(domain);
    verify_user_workload_abi(base);
    verify_sandbox_abi(base);
    verify_workload_spawn(base, false);
    verify_workload_spawn(base, true);
    check(
        crate::mm::frame::free_frames() == frames_before,
        "frame baseline",
    );
    check(
        sched::live_cpu_groups() == groups_before,
        "CPU group baseline",
    );
    #[cfg(feature = "workload-io-verify")]
    crate::workload_io_verify::run();
    kprintln!(
        "[JSR-WORKLOAD] runtime=true checks_failed={} ring={} task={}",
        failed(),
        ring.map(|handle| handle.raw()).unwrap_or(0),
        first.map(|(task, _)| task.0).unwrap_or(0)
    );
}
