//! Real Jasper page-table and Ring 3 proof for the compatibility ELF loader.
//!
//! 职责：在真实 QEMU 中把嵌入的静态 `user-hello` ELF 交给 `compat-loader`
//! 生成布局，再经 Jasper 页表后端装载和执行。
//! 边界：这是真实 ELF 后端证据，不是未修改 Linux libc/ld-linux 的执行声明。
//! Responsibility: prove the real page-table and entry backend with an embedded static ELF.

use core::sync::atomic::{AtomicU32, Ordering};

use alloc::vec::Vec;
use jasper_compat_loader::{
    build_initial_stack, map_image, prepare_relocations, protect_relro, read_lifecycle_callbacks,
    run_process_entry, ExecutionPlan, ImageLayout, InitialStackInput, LoaderMemory, MappingRequest,
    MemoryPermissions, RelocationContext, RuntimeModule, SymbolTable,
};
use kernel_core::objtable::ObjId;

use crate::compat_elf::{JasperExecutionBackend, JasperLoaderMemory};
use crate::mm::frame::free_frames;
use crate::proc::{self, ProcState};
use crate::syscall::{table as abi, SyscallSet};
use crate::{arch, kobj, kprintln, sched};

static FAILED: AtomicU32 = AtomicU32::new(0);
static USER_HELLO: &[u8] = include_bytes!(env!("JSR_USER_HELLO"));

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

fn check(ok: bool, stage: &'static str) {
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-COMPAT-ELF-FAIL] stage={}", stage);
    }
}

fn cleanup(pid: ObjId) {
    let _ = proc::reap(pid);
    kobj::run_cleanup(usize::MAX);
}

fn verify_transaction(pid: ObjId) {
    let address = arch::USER_WINDOW.0 + 0x20_0000;
    let mut memory = JasperLoaderMemory::new(pid);
    memory.begin_transaction().unwrap();
    let permissions = MemoryPermissions {
        readable: true,
        writable: true,
        executable: false,
    };
    memory
        .map(
            &[],
            MappingRequest {
                address,
                file_ranges: &[],
                memory_bytes: kernel_core::frame::FRAME_SIZE,
                permissions,
            },
        )
        .unwrap();
    memory.write(address, b"rollback").unwrap();
    memory.rollback_transaction().unwrap();
    check(proc::page_flags(pid, address).is_none(), "rollback_map");
    check(proc::frame_count(pid) == Some(0), "rollback_frames");

    let no_transaction_address = arch::USER_WINDOW.0 + 0x20_2000;
    let mut no_transaction = JasperLoaderMemory::new(pid);
    check(
        no_transaction.map(
            &[],
            MappingRequest {
                address: no_transaction_address,
                file_ranges: &[],
                memory_bytes: kernel_core::frame::FRAME_SIZE,
                permissions,
            },
        ) == Err(jasper_compat_loader::LoaderError::BadTransaction),
        "map_requires_transaction",
    );
    check(
        proc::page_flags(pid, no_transaction_address).is_none()
            && proc::frame_count(pid) == Some(0),
        "map_no_transaction_residue",
    );

    let committed_address = arch::USER_WINDOW.0 + 0x20_3000;
    let mut committed = JasperLoaderMemory::new(pid);
    committed.begin_transaction().unwrap();
    committed
        .map(
            &[],
            MappingRequest {
                address: committed_address,
                file_ranges: &[],
                memory_bytes: kernel_core::frame::FRAME_SIZE,
                permissions,
            },
        )
        .unwrap();
    committed.commit_transaction().unwrap();
    let flags_before = proc::page_flags(pid, committed_address);
    let mut no_transaction_protect = JasperLoaderMemory::new(pid);
    check(
        no_transaction_protect.protect(
            committed_address,
            kernel_core::frame::FRAME_SIZE,
            MemoryPermissions {
                readable: true,
                writable: false,
                executable: false,
            },
        ) == Err(jasper_compat_loader::LoaderError::BadTransaction),
        "protect_requires_transaction",
    );
    check(
        proc::page_flags(pid, committed_address) == flags_before,
        "protect_no_transaction_residue",
    );
    proc::unmap_page(pid, committed_address).unwrap();
    check(proc::frame_count(pid) == Some(0), "transaction_cleanup");
}

fn check_native_abi() -> bool {
    let native = match kernel_core::elf::parse(USER_HELLO, arch::ELF_MACHINE, arch::ELF_CLASS) {
        Ok(image) => image,
        Err(_) => return false,
    };
    if kernel_core::abi_version::check_image(
        native.abi(),
        kernel_core::abi_version::NATIVE,
    )
    .is_err()
    {
        return false;
    }
    native
        .required_capabilities()
        .first_unavailable(crate::profile::has_capability)
        .is_none()
}

pub fn run() {
    let free_before = free_frames();
    let syscalls_before = crate::syscall::call_count();
    let allowed = SyscallSet::of(&[
        abi::SYSTEM_CONSOLE_WRITE,
        abi::SYSTEM_ABI_GET,
        abi::SYSTEM_TASK_EXIT,
    ]);
    let Ok(pid) = proc::create("compat-elf", allowed) else {
        check(false, "create");
        return;
    };
    check(check_native_abi(), "native_abi");
    verify_transaction(pid);

    let plan = match jasper_compat_loader::parse(USER_HELLO) {
        Ok(plan) => plan,
        Err(_) => {
            check(false, "parse");
            cleanup(pid);
            return;
        }
    };
    check(plan.interpreter.is_none(), "static_image");
    let image = match ImageLayout::new(&plan, 0, kernel_core::frame::FRAME_SIZE) {
        Ok(image) => image,
        Err(_) => {
            check(false, "layout");
            cleanup(pid);
            return;
        }
    };
    let mut memory = JasperLoaderMemory::new(pid);
    check(map_image(&mut memory, USER_HELLO, &image).is_ok(), "map");

    let mut symbols = SymbolTable::new();
    let relocated = symbols.append_image(USER_HELLO, &image, 1).is_ok()
        && prepare_relocations(
            &mut memory,
            &plan,
            &image,
            RelocationContext {
                module_id: 1,
                static_tls_offset: None,
            },
            &symbols,
        )
        .and_then(|patches| {
            jasper_compat_loader::apply_relocation_patches(&mut memory, &image, &patches)
        })
        .is_ok();
    check(relocated, "relocate");
    let callbacks = match read_lifecycle_callbacks(&mut memory, &image) {
        Ok(callbacks) => callbacks,
        Err(_) => {
            check(false, "lifecycle");
            cleanup(pid);
            return;
        }
    };
    check(
        protect_relro(&mut memory, &image, kernel_core::frame::FRAME_SIZE).is_ok(),
        "relro",
    );

    let modules = [RuntimeModule {
        module_id: 1,
        image: image.clone(),
        callbacks,
        requires: Vec::new(),
        interpreter_required: false,
    }];
    let Ok(execution) = ExecutionPlan::new(&modules, 0, None) else {
        check(false, "execution_plan");
        cleanup(pid);
        return;
    };
    let arg0 = b"compat-elf".as_slice();
    let argv = [arg0];
    let random = [0x5au8; 16];
    let stack = build_initial_stack(InitialStackInput {
        stack_top: arch::USER_WINDOW.0 + 0xc0_0000,
        argv: &argv,
        envp: &[],
        page_size: kernel_core::frame::FRAME_SIZE,
        program_headers: None,
        program_header_entry_size: 0,
        program_header_count: 0,
        program_entry: image.entry,
        interpreter_base: 0,
        auxv: &[],
        random: Some(&random),
    });
    check(stack.is_ok(), "initial_stack");
    let mut backend = JasperExecutionBackend::new(pid, "compat-elf");
    if let Ok(stack) = stack {
        check(run_process_entry(&mut backend, &execution, stack).is_ok(), "transfer");
        check(backend.task().is_some(), "thread");
        sched::run();
    }

    let state = proc::state(pid);
    let exited = state == Some(ProcState::Exited { code: 0 });
    let syscall_delta = crate::syscall::call_count().saturating_sub(syscalls_before);
    let ring3 = backend.task().is_some() && syscall_delta > 0;
    check(ring3, "ring3");
    check(exited, "exit");
    check(syscall_delta > 0, "ring3_syscall");
    cleanup(pid);
    let resources = free_frames() == free_before;
    check(resources, "resources");
    kprintln!(
        "[JSR-COMPAT-ELF] backend=true map=true relocate=true stack=true ring3={} exit={} resources={} failed={}",
        ring3,
        exited,
        resources,
        failed()
    );
}
