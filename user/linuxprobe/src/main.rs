//! Minimal unmodified-toolchain Linux x86_64 syscall-ABI probe.
//!
//! 这是没有 Jasper ABI 章的静态 Linux ET_EXEC fixture，用来证明兼容入口、
//! 参数复制、返回约定、权限拒绝和进程退出路径；不代表 libc/Wine 已完成。
//! This is a static Linux ET_EXEC fixture without Jasper ABI metadata.

#![no_std]
#![no_main]

use core::arch::asm;

const SYS_WRITE: u64 = 1;
const SYS_READ: u64 = 0;
const SYS_CLOSE: u64 = 3;
const SYS_MMAP: u64 = 9;
const SYS_MPROTECT: u64 = 10;
const SYS_MUNMAP: u64 = 11;
const SYS_SCHED_YIELD: u64 = 24;
const SYS_CLONE: u64 = 56;
const SYS_WAIT4: u64 = 61;
const SYS_GETPID: u64 = 39;
const SYS_GETPPID: u64 = 110;
const SYS_GETTID: u64 = 186;
const SYS_FUTEX: u64 = 202;
const SYS_EPOLL_WAIT: u64 = 232;
const SYS_EPOLL_CTL: u64 = 233;
const SYS_EPOLL_CREATE1: u64 = 291;
const SYS_EVENTFD2: u64 = 290;
const SYS_TIMERFD_CREATE: u64 = 283;
const SYS_SIGNALFD4: u64 = 289;
const SYS_PIPE2: u64 = 293;
const SYS_IO_URING_SETUP: u64 = 425;
const SYS_IO_URING_ENTER: u64 = 426;
const SYS_IO_URING_REGISTER: u64 = 427;
const SYS_EXIT_GROUP: u64 = 231;
const SYS_FCNTL: u64 = 72;
const F_SETPIPE_SZ: u64 = 1031;
const F_GETPIPE_SZ: u64 = 1032;

const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_PRIVATE: u64 = 2;
const MAP_SHARED: u64 = 1;
const MAP_ANONYMOUS: u64 = 0x20;
const EPOLLIN: u32 = 1;
const EPOLLONESHOT: u32 = 0x4000_0000;
const EPOLL_CTL_ADD: u64 = 1;
const EPOLL_CTL_DEL: u64 = 2;
const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;
const SIGCHLD: u64 = 17;
const IORING_REGISTER_FILES: u64 = 2;
const IORING_UNREGISTER_FILES: u64 = 3;
const IORING_OFF_SQES: u64 = 0x1000_0000;
const PAGE_BYTES: u64 = 4096;

static mut FUTEX_SHARED_ADDRESS: u64 = 0;
static FUTEX_TIMEOUT: [i64; 2] = [2, 0];

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn syscall1(number: u64, arg0: u64) -> i64 {
    let result: i64;
    asm!(
        "syscall",
        inlateout("rax") number as i64 => result,
        in("rdi") arg0,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack)
    );
    result
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn syscall3(number: u64, arg0: u64, arg1: u64, arg2: u64) -> i64 {
    let result: i64;
    asm!(
        "syscall",
        inlateout("rax") number as i64 => result,
        in("rdi") arg0,
        in("rsi") arg1,
        in("rdx") arg2,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack)
    );
    result
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn syscall6(
    number: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> i64 {
    let result: i64;
    asm!(
        "syscall",
        inlateout("rax") number as i64 => result,
        in("rdi") arg0,
        in("rsi") arg1,
        in("rdx") arg2,
        in("r10") arg3,
        in("r8") arg4,
        in("r9") arg5,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack)
    );
    result
}

#[cfg(target_arch = "x86_64")]
unsafe fn exit(code: u64) -> ! {
    syscall1(SYS_EXIT_GROUP, code);
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn futex_child() -> ! {
    let state = FUTEX_SHARED_ADDRESS as *mut u32;
    state.add(1).write_volatile(1);
    let result = syscall6(
        SYS_FUTEX,
        state.cast::<u8>() as u64,
        FUTEX_WAIT,
        0,
        FUTEX_TIMEOUT.as_ptr() as u64,
        0,
        0,
    );
    state.add(2).write_volatile(if result == 0 { 1 } else { 2 });
    exit(0)
}

#[cfg(target_arch = "x86_64")]
unsafe fn write_bytes(fd: u64, bytes: &[u8]) -> bool {
    syscall3(SYS_WRITE, fd, bytes.as_ptr() as u64, bytes.len() as u64) == bytes.len() as i64
}

#[cfg(target_arch = "x86_64")]
unsafe fn write_syscall_number(fd: u64, value: i64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buffer = [0u8; 19];
    buffer[..3].copy_from_slice(b"0x=");
    let negative = value < 0;
    let mut number = value.unsigned_abs();
    let mut cursor = buffer.len();
    loop {
        cursor -= 1;
        buffer[cursor] = HEX[(number & 0xf) as usize];
        number >>= 4;
        if number == 0 {
            break;
        }
    }
    if negative {
        cursor -= 1;
        buffer[cursor] = b'-';
    }
    let _ = write_bytes(fd, &buffer[cursor..]);
    let _ = write_bytes(fd, b"\n");
}

#[cfg(target_arch = "x86_64")]
unsafe fn test_epoll() -> bool {
    let mut pipe = [0i32; 2];
    if syscall6(SYS_PIPE2, pipe.as_mut_ptr() as u64, 0, 0, 0, 0, 0) != 0 {
        return false;
    }
    let epoll = syscall1(SYS_EPOLL_CREATE1, 0);
    if epoll < 0 {
        return false;
    }
    let mut interest = [0u8; 12];
    interest[..4].copy_from_slice(&(EPOLLIN | EPOLLONESHOT).to_le_bytes());
    interest[4..].copy_from_slice(&0xfeed_u64.to_le_bytes());
    if syscall6(
        SYS_EPOLL_CTL,
        epoll as u64,
        EPOLL_CTL_ADD,
        pipe[0] as u64,
        interest.as_ptr() as u64,
        0,
        0,
    ) != 0
    {
        return false;
    }
    let byte = [0xa5u8];
    if syscall3(
        SYS_WRITE,
        pipe[1] as u64,
        byte.as_ptr() as u64,
        byte.len() as u64,
    ) != 1
    {
        return false;
    }
    let mut event = [0u8; 12];
    let ready = syscall6(
        SYS_EPOLL_WAIT,
        epoll as u64,
        event.as_mut_ptr() as u64,
        1,
        200,
        0,
        0,
    );
    let events = u32::from_le_bytes(event[..4].try_into().unwrap());
    let data = u64::from_le_bytes(event[4..].try_into().unwrap());
    let oneshot_drained = syscall6(
        SYS_EPOLL_WAIT,
        epoll as u64,
        event.as_mut_ptr() as u64,
        1,
        0,
        0,
        0,
    ) == 0;
    let delete = syscall6(
        SYS_EPOLL_CTL,
        epoll as u64,
        EPOLL_CTL_DEL,
        pipe[0] as u64,
        0,
        0,
        0,
    );
    let _ = syscall1(SYS_CLOSE, epoll as u64);
    let _ = syscall1(SYS_CLOSE, pipe[0] as u64);
    let _ = syscall1(SYS_CLOSE, pipe[1] as u64);
    ready == 1 && events & EPOLLIN != 0 && data == 0xfeed && oneshot_drained && delete == 0
}

#[cfg(target_arch = "x86_64")]
unsafe fn test_many_epolls() -> bool {
    const COUNT: usize = 12;
    let mut fds = [-1i64; COUNT];
    for index in 0..COUNT {
        fds[index] = syscall1(SYS_EPOLL_CREATE1, 0);
        if fds[index] < 0 {
            for opened in &fds[..index] {
                let _ = syscall1(SYS_CLOSE, *opened as u64);
            }
            return false;
        }
    }
    let mut closed = true;
    for fd in fds {
        closed &= syscall1(SYS_CLOSE, fd as u64) == 0;
    }
    closed
}

#[cfg(target_arch = "x86_64")]
unsafe fn test_many_eventfds() -> bool {
    const COUNT: usize = 40;
    let mut fds = [-1i64; COUNT];
    for index in 0..COUNT {
        fds[index] = syscall3(SYS_EVENTFD2, 0, 0, 0);
        if fds[index] < 0 {
            let mut digits = [b'0'; 20];
            let mut value = index;
            let mut at = digits.len();
            loop {
                at -= 1;
                digits[at] = b'0' + (value % 10) as u8;
                value /= 10;
                if value == 0 {
                    break;
                }
            }
            let _ = write_bytes(2, b"eventfd-debug: create index=");
            let _ = write_bytes(2, &digits[at..]);
            let _ = write_bytes(2, b"\n");
            for opened in &fds[..index] {
                let _ = syscall1(SYS_CLOSE, *opened as u64);
            }
            return false;
        }
    }
    let value = 7u64.to_le_bytes();
    let mut read_value = [0u8; 8];
    let wrote = syscall3(
        SYS_WRITE,
        fds[0] as u64,
        value.as_ptr() as u64,
        value.len() as u64,
    ) == 8;
    let read = wrote
        && syscall3(
            SYS_READ,
            fds[0] as u64,
            read_value.as_mut_ptr() as u64,
            read_value.len() as u64,
        ) == 8
        && u64::from_le_bytes(read_value) == 7;
    let mut closed = true;
    for fd in fds {
        closed &= syscall1(SYS_CLOSE, fd as u64) == 0;
    }
    read && closed
}

#[cfg(target_arch = "x86_64")]
unsafe fn test_many_timerfds() -> bool {
    const COUNT: usize = 40;
    let mut fds = [-1i64; COUNT];
    for index in 0..COUNT {
        fds[index] = syscall3(SYS_TIMERFD_CREATE, 1, 0, 0);
        if fds[index] < 0 {
            for opened in &fds[..index] {
                let _ = syscall1(SYS_CLOSE, *opened as u64);
            }
            return false;
        }
    }
    let mut closed = true;
    for fd in fds {
        closed &= syscall1(SYS_CLOSE, fd as u64) == 0;
    }
    closed
}

#[cfg(target_arch = "x86_64")]
unsafe fn test_many_signalfds() -> bool {
    const COUNT: usize = 40;
    let mask = 1u64 << 10;
    let mut fds = [-1i64; COUNT];
    for index in 0..COUNT {
        fds[index] = syscall6(
            SYS_SIGNALFD4,
            u64::MAX,
            (&mask) as *const u64 as u64,
            8,
            0,
            0,
            0,
        );
        if fds[index] < 0 {
            for opened in &fds[..index] {
                let _ = syscall1(SYS_CLOSE, *opened as u64);
            }
            return false;
        }
    }
    let mut closed = true;
    for fd in fds {
        closed &= syscall1(SYS_CLOSE, fd as u64) == 0;
    }
    closed
}

#[cfg(target_arch = "x86_64")]
unsafe fn test_many_pipes() -> bool {
    const COUNT: usize = 40;
    const F_SETPIPE_BYTES: u64 = 128 * 1024;
    let mut pairs = [[-1i32; 2]; COUNT];
    for index in 0..COUNT {
        if syscall6(SYS_PIPE2, pairs[index].as_mut_ptr() as u64, 0, 0, 0, 0, 0) != 0 {
            for pair in &pairs[..index] {
                let _ = syscall1(SYS_CLOSE, pair[0] as u64);
                let _ = syscall1(SYS_CLOSE, pair[1] as u64);
            }
            return false;
        }
        let byte = [index as u8];
        let mut read_back = [0u8; 1];
        if syscall3(SYS_WRITE, pairs[index][1] as u64, byte.as_ptr() as u64, 1) != 1
            || syscall3(
                SYS_READ,
                pairs[index][0] as u64,
                read_back.as_mut_ptr() as u64,
                1,
            ) != 1
            || read_back[0] != index as u8
        {
            for pair in &pairs[..=index] {
                let _ = syscall1(SYS_CLOSE, pair[0] as u64);
                let _ = syscall1(SYS_CLOSE, pair[1] as u64);
            }
            return false;
        }
    }
    let pipe = pairs[0];
    let resized = syscall3(SYS_FCNTL, pipe[1] as u64, F_SETPIPE_SZ, F_SETPIPE_BYTES);
    let observed = syscall3(SYS_FCNTL, pipe[0] as u64, F_GETPIPE_SZ, 0);
    if resized != F_SETPIPE_BYTES as i64 || observed != F_SETPIPE_BYTES as i64 {
        let _ = write_bytes(
            2,
            if resized != F_SETPIPE_BYTES as i64 {
                b"linux-native: large-pipe resize failed "
            } else {
                b"linux-native: large-pipe readback failed "
            },
        );
        write_syscall_number(
            2,
            if resized != F_SETPIPE_BYTES as i64 {
                resized
            } else {
                observed
            },
        );
        for pair in &pairs {
            let _ = syscall1(SYS_CLOSE, pair[0] as u64);
            let _ = syscall1(SYS_CLOSE, pair[1] as u64);
        }
        return false;
    }
    let mut closed = true;
    for pair in pairs {
        closed &= syscall1(SYS_CLOSE, pair[0] as u64) == 0;
        closed &= syscall1(SYS_CLOSE, pair[1] as u64) == 0;
    }
    closed
}

#[cfg(target_arch = "x86_64")]
unsafe fn test_mmap() -> bool {
    let address = syscall6(
        SYS_MMAP,
        0,
        2 * PAGE_BYTES,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if address < 0 {
        return false;
    }
    let bytes = address as *mut u8;
    bytes.write_volatile(0x5a);
    bytes.add(PAGE_BYTES as usize).write_volatile(0xa5);
    let protected = syscall3(SYS_MPROTECT, address as u64, 2 * PAGE_BYTES, PROT_READ) == 0;
    let values =
        bytes.read_volatile() == 0x5a && bytes.add(PAGE_BYTES as usize).read_volatile() == 0xa5;
    let released = syscall1(SYS_MUNMAP, address as u64) == 0;
    protected && values && released
}

#[cfg(target_arch = "x86_64")]
unsafe fn test_futex() -> bool {
    let shared = syscall6(
        SYS_MMAP,
        0,
        PAGE_BYTES,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if shared < 0 {
        let _ = write_bytes(2, b"futex-debug: mmap\n");
        return false;
    }
    let state = shared as *mut u32;
    state.add(1).write_volatile(0);
    state.add(2).write_volatile(0);
    FUTEX_SHARED_ADDRESS = shared as u64;
    let child = syscall6(SYS_CLONE, SIGCHLD, 0, 0, 0, 0, 0);
    if child == 0 {
        futex_child();
    }
    if child <= 0 {
        let _ = syscall1(SYS_MUNMAP, shared as u64);
        let _ = write_bytes(2, b"futex-debug: clone\n");
        return false;
    }
    let mut spins = 0u32;
    while state.add(1).read_volatile() == 0 && spins < 100_000 {
        let _ = syscall1(SYS_SCHED_YIELD, 0);
        spins += 1;
    }
    let waiting = state.add(1).read_volatile() == 1;
    for _ in 0..10 {
        let _ = syscall1(SYS_SCHED_YIELD, 0);
    }
    let woke = syscall6(SYS_FUTEX, state.cast::<u8>() as u64, FUTEX_WAKE, 1, 0, 0, 0) == 1;
    let mut status = 0i32;
    let reaped = syscall6(
        SYS_WAIT4,
        child as u64,
        (&mut status) as *mut i32 as u64,
        0,
        0,
        0,
        0,
    ) == child;
    let child_result = state.add(2).read_volatile();
    if !waiting || !woke || !reaped || child_result != 1 {
        let detail = if !waiting {
            b"futex-debug: waiting\n".as_slice()
        } else if !woke {
            b"futex-debug: wake\n".as_slice()
        } else if !reaped {
            b"futex-debug: reap\n".as_slice()
        } else {
            b"futex-debug: child\n".as_slice()
        };
        let _ = write_bytes(2, detail);
    }
    let result = waiting && woke && reaped && child_result == 1;
    let _ = syscall1(SYS_MUNMAP, shared as u64);
    result
}

#[cfg(target_arch = "x86_64")]
unsafe fn ring_read_u32(base: *mut u8, offset: usize) -> u32 {
    let bytes = core::slice::from_raw_parts(base.add(offset), 4);
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[cfg(target_arch = "x86_64")]
unsafe fn ring_write_u32(base: *mut u8, offset: usize, value: u32) {
    core::slice::from_raw_parts_mut(base.add(offset), 4).copy_from_slice(&value.to_le_bytes());
}

#[cfg(target_arch = "x86_64")]
unsafe fn test_io_uring() -> bool {
    let mut params = [0u8; 120];
    let ring_fd = syscall6(
        SYS_IO_URING_SETUP,
        4,
        params.as_mut_ptr() as u64,
        0,
        0,
        0,
        0,
    );
    if ring_fd < 0 {
        let _ = write_bytes(2, b"uring-debug: setup\n");
        return false;
    }
    let ring = syscall6(
        SYS_MMAP,
        0,
        2 * PAGE_BYTES,
        PROT_READ | PROT_WRITE,
        MAP_SHARED,
        ring_fd as u64,
        0,
    );
    let sqes = syscall6(
        SYS_MMAP,
        0,
        PAGE_BYTES,
        PROT_READ | PROT_WRITE,
        MAP_SHARED,
        ring_fd as u64,
        IORING_OFF_SQES,
    );
    if ring < 0 || sqes < 0 {
        let _ = write_bytes(2, b"uring-debug: mmap\n");
        return false;
    }
    let ring = ring as *mut u8;
    let sqes = sqes as *mut u8;
    core::ptr::write_bytes(sqes, 0, 64);
    core::slice::from_raw_parts_mut(sqes.add(32), 8).copy_from_slice(&0x55aa_u64.to_le_bytes());
    ring_write_u32(ring, 0x80, 0);
    ring_write_u32(ring, 0x04, 1);
    let submitted = syscall6(SYS_IO_URING_ENTER, ring_fd as u64, 1, 0, 0, 0, 0);
    let completed = ring_read_u32(ring, 0x100) == 0
        && ring_read_u32(ring, 0x104) == 1
        && u64::from_le_bytes(
            core::slice::from_raw_parts(ring.add(0x1000), 8)
                .try_into()
                .unwrap(),
        ) == 0x55aa
        && i32::from_le_bytes(
            core::slice::from_raw_parts(ring.add(0x1008), 4)
                .try_into()
                .unwrap(),
        ) == 0;
    if submitted != 1 {
        let _ = write_bytes(2, b"uring-debug: submit\n");
    } else if !completed {
        let _ = write_bytes(2, b"uring-debug: completion\n");
    }

    let mut pipe = [0i32; 2];
    let pipe_created = syscall6(SYS_PIPE2, pipe.as_mut_ptr() as u64, 0, 0, 0, 0, 0) == 0;
    if !pipe_created {
        let _ = write_bytes(2, b"uring-debug: pipe\n");
    }
    let files_registered = pipe_created
        && syscall6(
            SYS_IO_URING_REGISTER,
            ring_fd as u64,
            IORING_REGISTER_FILES,
            pipe.as_ptr() as u64,
            2,
            0,
            0,
        ) == 0;
    if !files_registered {
        let _ = write_bytes(2, b"uring-debug: register-files\n");
    }
    let files_unregistered = files_registered
        && syscall6(
            SYS_IO_URING_REGISTER,
            ring_fd as u64,
            IORING_UNREGISTER_FILES,
            0,
            0,
            0,
            0,
        ) == 0;
    if files_registered && !files_unregistered {
        let _ = write_bytes(2, b"uring-debug: unregister\n");
    }
    let registered = files_unregistered;
    if pipe[0] > 0 {
        let _ = syscall1(SYS_CLOSE, pipe[0] as u64);
        let _ = syscall1(SYS_CLOSE, pipe[1] as u64);
    }
    let _ = syscall1(SYS_MUNMAP, sqes as u64);
    let _ = syscall1(SYS_MUNMAP, ring as u64);
    let _ = syscall1(SYS_CLOSE, ring_fd as u64);
    submitted == 1 && completed && registered
}

#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    const MESSAGE: &[u8] = b"linux-abi: fd1 raw x86_64 ET_EXEC entered\n";
    const STDERR_MESSAGE: &[u8] = b"linux-abi: fd2 raw bytes accepted\n";
    // SAFETY: static immutable bytes and fd 1/2 map to the compatibility console.
    let written = unsafe { syscall3(SYS_WRITE, 1, MESSAGE.as_ptr() as u64, MESSAGE.len() as u64) };
    if written != MESSAGE.len() as i64 {
        unsafe { exit(90) }
    }
    let written_err = unsafe {
        syscall3(
            SYS_WRITE,
            2,
            STDERR_MESSAGE.as_ptr() as u64,
            STDERR_MESSAGE.len() as u64,
        )
    };
    if written_err != STDERR_MESSAGE.len() as i64 {
        unsafe { exit(94) }
    }
    // Linux write(fd, invalid_ptr, 0) succeeds without dereferencing the pointer.
    let zero = unsafe { syscall3(SYS_WRITE, 1, 0, 0) };
    if zero != 0 {
        unsafe { exit(95) }
    }
    // Non-empty writes still require a readable user range and return -EFAULT.
    let fault = unsafe { syscall3(SYS_WRITE, 1, 0, 1) };
    if fault != -14 {
        unsafe { exit(96) }
    }
    // SAFETY: identity syscalls take no pointers.
    let pid = unsafe { syscall1(SYS_GETPID, 0) };
    let tid = unsafe { syscall1(SYS_GETTID, 0) };
    if pid <= 0 || tid <= 0 {
        unsafe { exit(91) }
    }
    // getppid is intentionally not granted in this first compatibility profile.
    let denied = unsafe { syscall1(SYS_GETPPID, 0) };
    if denied != -1 {
        unsafe { exit(92) }
    }
    if !unsafe { test_epoll() } {
        unsafe { exit(97) }
    }
    if !unsafe { test_many_epolls() } {
        unsafe { exit(102) }
    }
    if !unsafe { test_many_eventfds() } {
        unsafe { exit(103) }
    }
    if !unsafe { test_many_timerfds() } {
        unsafe { exit(104) }
    }
    if !unsafe { test_many_signalfds() } {
        unsafe { exit(105) }
    }
    if !unsafe { test_many_pipes() } {
        unsafe { exit(106) }
    }
    if !unsafe { test_mmap() } {
        unsafe { exit(98) }
    }
    if !unsafe { test_futex() } {
        unsafe { exit(99) }
    }
    if !unsafe { test_io_uring() } {
        unsafe { exit(100) }
    }
    let summary = b"linux-native: epoll=true many_epolls=true many_eventfds=true many_timerfds=true many_signalfds=true many_pipes=true futex=true mmap=true io_uring=true\n";
    if !unsafe { write_bytes(1, summary) } {
        unsafe { exit(101) }
    }
    unsafe { exit(0) }
}

#[cfg(not(target_arch = "x86_64"))]
#[panic_handler]
fn unsupported(_: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(target_arch = "x86_64")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { exit(93) }
}
