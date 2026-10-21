//! user-devprobe：DRV-1C 的用户态演练程序。
//! DRV-1C user-space probe for `system.device.list` / `open` / `get`.
//!
//! # 角色（内核经入口参数 `role` 选择）
//! * `0`：完整演练——列举设备（含缓冲区不足返回所需长度）、按类别 / vendor 过滤、打开 virtio-net、
//!   读取完整描述；并验证非法 BDF、权限越级复制、已关闭句柄等拒绝路径。所有句柄最终关闭。
//! * `1`：进程没有被授予任何设备系统调用——`list` / `open` 都必须返回 `rights_denied`。
//!
//! # 输出与退出码
//! 每个断言输出一行 `[JSR-DEV] case=… ok=true|false`，最后输出 `[JSR-DEV] summary checks=N failed=M handles_live=K`。
//! 全部通过时以退出码 0 结束，否则以 1 结束；内核演练据此判定，并核对对象数回到基线。
#![no_std]
#![no_main]

use core::arch::asm;
use core::fmt::{self, Write as _};

use kernel_core::device::{
    Desc, Filter, Record, BAR_KIND_NONE, DESC_SIZE, FILTER_ALL_CLASS, FILTER_ALL_VENDOR, RECORD_SIZE,
};
use kernel_core::object::Rights;

/// 系统调用号（构建期从登记表生成）。
#[allow(dead_code)]
mod ids {
    include!(concat!(env!("OUT_DIR"), "/ids.rs"));
}

/// 列表缓冲区（足以容纳启动期设备表的全部记录）。
static mut LIST: [u8; 2048] = [0; 2048];
/// 完整描述缓冲区。
static mut DESC: [u8; DESC_SIZE] = [0; DESC_SIZE];

/// 断言总数与失败数。
static mut CHECKS: u32 = 0;
static mut FAILED: u32 = 0;

/// 发起一个三参数系统调用（x86_64：rax=ID，rdi/rsi/rdx=参数，rcx/r11 被占用）。
/// The probe is validated on x86_64 only (the other ISAs are frozen).
///
/// # Safety
/// 参数必须符合该调用的约定；作为指针传入的值须指向本进程内、在调用期间有效的内存。
#[cfg(target_arch = "x86_64")]
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

#[cfg(not(target_arch = "x86_64"))]
compile_error!("user-devprobe 只支持 x86_64（DRV-1C 的验收范围；其它指令集冻结）");

/// 一行输出缓冲区。
struct Line {
    buf: [u8; 224],
    len: usize,
}

impl Line {
    fn new() -> Line {
        Line { buf: [0; 224], len: 0 }
    }

    fn as_str(&self) -> &str {
        // SAFETY：只写入 ASCII 与 UTF-8 字面量，长度不越过缓冲区。
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

impl fmt::Write for Line {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        if self.len + bytes.len() > self.buf.len() {
            return Err(fmt::Error);
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }
}

/// `system.console.write`；返回内核写入的字节数或负数错误码。
fn write_text(text: &str) -> i64 {
    // SAFETY：text 位于本进程的只读数据或栈上。
    unsafe { syscall3(ids::SYSTEM_CONSOLE_WRITE, text.as_ptr() as u64, text.len() as u64, 0) }
}

/// 输出一行（越界时静默截断，不影响断言本身）。
fn log(args: fmt::Arguments<'_>) {
    let mut line = Line::new();
    let _ = line.write_fmt(args);
    let _ = write_text(line.as_str());
}

/// 记录一个断言并输出一行；失败时额外输出 `[JSR-DEV-FAIL]`。
macro_rules! emit {
    ($ok:expr, $($t:tt)*) => {{
        let ok = $ok;
        // SAFETY：单线程程序，计数器只在这里修改。
        unsafe {
            CHECKS += 1;
            if !ok {
                FAILED += 1;
            }
        }
        log(format_args!("[JSR-DEV] {} ok={}", format_args!($($t)*), ok));
        if !ok {
            log(format_args!("[JSR-DEV-FAIL] {}", format_args!($($t)*)));
        }
    }};
}

/// 以退出码结束本线程。
fn exit(code: u64) -> ! {
    // SAFETY：task.exit 不访问用户内存。
    unsafe {
        syscall3(ids::SYSTEM_TASK_EXIT, code, 0, 0);
    }
    loop {
        core::hint::spin_loop();
    }
}

fn list_raw(filter: u32, ptr: u64, cap: u64) -> i64 {
    // SAFETY：ptr 指向本进程的静态缓冲区（或 0，容量为 0 时内核不写）。
    unsafe { syscall3(ids::SYSTEM_DEVICE_LIST, filter as u64, ptr, cap) }
}

fn open(bdf: u32, rights: Rights) -> i64 {
    // SAFETY：参数全是整数，内核自行校验。
    unsafe { syscall3(ids::SYSTEM_DEVICE_OPEN, bdf as u64, rights.bits() as u64, 0) }
}

fn get(handle: i64, buf: &mut [u8]) -> i64 {
    // SAFETY：buf 指向本进程内可写的栈 / 静态内存。
    unsafe { syscall3(ids::SYSTEM_DEVICE_GET, handle as u64, buf.as_mut_ptr() as u64, buf.len() as u64) }
}

fn close(handle: i64) -> i64 {
    // SAFETY：参数是句柄值。
    unsafe { syscall3(ids::SYSTEM_HANDLE_CLOSE, handle as u64, 0, 0) }
}

fn duplicate(handle: i64, rights: Rights) -> i64 {
    // SAFETY：参数是句柄值与权限位。
    unsafe { syscall3(ids::SYSTEM_HANDLE_DUPLICATE, handle as u64, rights.bits() as u64, 0) }
}

/// 角色 0：完整设备演练。返回时全部句柄已关闭。
fn probe_devices() -> ! {
    let all = Filter::ALL.to_word();
    let mut live: i32 = 0;

    // —— 列表长度协商：容量 0 时返回所需字节数；容量不足时一个字节也不写。——
    let need = list_raw(all, 0, 0);
    let need_ok = need > 0 && (need as usize) % RECORD_SIZE == 0 && (need as usize) <= 2048;
    emit!(need_ok, "case=list_need need={}", need);
    if !need_ok {
        log(format_args!("[JSR-DEV] summary checks={} failed={} handles_live={}", checks(), failed(), live));
        exit(1);
    }

    let ptr = core::ptr::addr_of_mut!(LIST) as *mut u8;
    // SAFETY：静态缓冲区只由本线程访问；整块填图案，用于验证失败路径一个字节都不写。
    unsafe {
        for i in 0..2048 {
            *ptr.add(i) = 0xAA;
        }
        let short = list_raw(all, ptr as u64, (need - 1) as u64);
        let mut untouched = short == need;
        for i in 0..2048 {
            if *ptr.add(i) != 0xAA {
                untouched = false;
                break;
            }
        }
        emit!(untouched, "case=list_short need={} got={} unchanged={}", need, short, untouched);
    }

    // SAFETY：单线程，独占 LIST。
    let list: &mut [u8] = unsafe { &mut *core::ptr::addr_of_mut!(LIST) };
    let listed = list_raw(all, list.as_mut_ptr() as u64, list.len() as u64);
    let count = if listed > 0 { listed as usize / RECORD_SIZE } else { 0 };
    emit!(
        listed == need && count > 0,
        "case=list_all records={} bytes={}",
        count,
        listed
    );

    // —— 类别过滤：QEMU 的 virtio-net 属于类 0x02；厂商过滤：0x1af4。——
    let class_filter = Filter { vendor: FILTER_ALL_VENDOR, class: 0x02 }.to_word();
    let by_class = list_raw(class_filter, list.as_mut_ptr() as u64, list.len() as u64);
    emit!(
        by_class > 0 && (by_class as usize) % RECORD_SIZE == 0,
        "case=filter_class class=2 bytes={}",
        by_class
    );
    let vendor_filter = Filter { vendor: 0x1AF4, class: FILTER_ALL_CLASS }.to_word();
    let by_vendor = list_raw(vendor_filter, list.as_mut_ptr() as u64, list.len() as u64);
    emit!(
        by_vendor > 0 && (by_vendor as usize) % RECORD_SIZE == 0,
        "case=filter_vendor vendor=0x1af4 bytes={}",
        by_vendor
    );

    // 在完整列表里找 virtio-net（厂商 0x1af4、类 0x02）。
    let mut net_bdf = 0u32;
    let mut net_record = None;
    for i in 0..count {
        let mut raw = [0u8; RECORD_SIZE];
        raw.copy_from_slice(&list[i * RECORD_SIZE..(i + 1) * RECORD_SIZE]);
        let record = Record::decode(&raw);
        if record.vendor == 0x1AF4 && record.class == 0x02 {
            net_bdf = record.bdf;
            net_record = Some(record);
            break;
        }
    }
    let net_ok = net_record.is_some() && net_record.map(|r| r.bar_count > 0) == Some(true);
    emit!(
        net_ok,
        "case=find_net bdf=0x{:06x} bars={}",
        net_bdf,
        net_record.map(|r| r.bar_count).unwrap_or(0)
    );
    if !net_ok {
        log(format_args!("[JSR-DEV] summary checks={} failed={} handles_live={}", checks(), failed(), live));
        exit(1);
    }

    // —— 打开 virtio-net（申请全部设备权限），读取完整描述。——
    let max = Rights::READ.union(Rights::MAP).union(Rights::DUPLICATE).union(Rights::TRANSFER);
    let handle = open(net_bdf, max);
    if handle > 0 {
        live += 1;
    }
    emit!(handle > 0, "case=open bdf=0x{:06x} rights=0x{:x} handle={}", net_bdf, max.bits(), handle);

    let mut small = [0xAAu8; DESC_SIZE - 1];
    let small_ret = get(handle, &mut small);
    let small_unchanged = small.iter().all(|&b| b == 0xAA);
    emit!(
        small_ret == -(ids::SYSTEM_DEVICE_ERROR_BUFFER_TOO_SMALL as i64) && small_unchanged,
        "case=get_short ret={} want={} unchanged={}",
        small_ret,
        -(ids::SYSTEM_DEVICE_ERROR_BUFFER_TOO_SMALL as i64),
        small_unchanged
    );

    // SAFETY：单线程，独占 DESC。
    let desc_buf: &mut [u8] = unsafe { &mut *core::ptr::addr_of_mut!(DESC) };
    let got = get(handle, desc_buf);
    let mut desc_raw = [0u8; DESC_SIZE];
    desc_raw.copy_from_slice(desc_buf);
    let desc = Desc::decode(&desc_raw);
    let record = net_record.unwrap_or(Record {
        bdf: 0,
        vendor: 0,
        device: 0,
        class: 0,
        subclass: 0,
        prog_if: 0,
        bar_count: 0,
        first_bar_kind: BAR_KIND_NONE,
        first_bar_base: 0,
        first_bar_size: 0,
    });
    let desc_ok = got == DESC_SIZE as i64
        && desc.bdf == net_bdf
        && desc.bdf == record.bdf
        && desc.vendor == 0x1AF4
        && desc.class == 0x02
        && desc.bar_count > 0
        && desc.bar_count == record.bar_count;
    emit!(
        desc_ok,
        "case=get_desc bdf=0x{:06x} vendor=0x{:04x} class=0x{:02x} bars={} bytes={}",
        desc.bdf,
        desc.vendor,
        desc.class,
        desc.bar_count,
        got
    );

    // —— 拒绝路径 1：非法 BDF（设备号 32）与保留位非零的过滤字。——
    let bad_bdf = open(0x0000_2000, Rights::READ);
    emit!(
        bad_bdf == -(ids::SYSTEM_ERROR_INVALID_ARGUMENT as i64),
        "case=reject_bad_bdf ret={}",
        bad_bdf
    );
    let bad_filter = list_raw(0x0100_0000, 0, 0);
    emit!(
        bad_filter == -(ids::SYSTEM_ERROR_INVALID_ARGUMENT as i64),
        "case=reject_bad_filter ret={}",
        bad_filter
    );

    // —— 拒绝路径 2：权限越级复制（原句柄没有 WRITE，复制时申请 WRITE）。——
    let escalated = Rights::READ.union(Rights::MAP).union(Rights::WRITE);
    let esc = duplicate(handle, escalated);
    emit!(
        esc == -(ids::SYSTEM_HANDLE_ERROR_RIGHTS_DENIED as i64),
        "case=reject_escalate ret={}",
        esc
    );

    // —— 正常降权复制 + 没有 DUPLICATE 的句柄不能复制。——
    let dup = duplicate(handle, Rights::READ.union(Rights::MAP));
    if dup > 0 {
        live += 1;
    }
    emit!(dup > 0 && dup != handle, "case=duplicate handle={} duplicate={}", handle, dup);

    let read_only = open(net_bdf, Rights::READ);
    if read_only > 0 {
        live += 1;
    }
    let no_dup = duplicate(read_only, Rights::READ);
    emit!(
        read_only > 0 && no_dup == -(ids::SYSTEM_HANDLE_ERROR_RIGHTS_DENIED as i64),
        "case=reject_no_duplicate ret={}",
        no_dup
    );
    if read_only > 0 && close(read_only) == 0 {
        live -= 1;
    }

    // —— 拒绝路径 3：关闭句柄后读取必须被拒，重复关闭也必须被拒。——
    let closed = close(handle);
    if closed == 0 {
        live -= 1;
    }
    let after_close = get(handle, desc_buf);
    emit!(
        closed == 0 && after_close == -(ids::SYSTEM_HANDLE_ERROR_INVALID as i64),
        "case=reject_closed close={} get={}",
        closed,
        after_close
    );
    let double_close = close(handle);
    emit!(
        double_close == -(ids::SYSTEM_HANDLE_ERROR_INVALID as i64),
        "case=reject_double_close ret={}",
        double_close
    );

    if dup > 0 && close(dup) == 0 {
        live -= 1;
    }
    emit!(live == 0, "case=handles_closed live={}", live);
    log(format_args!("[JSR-DEV] summary checks={} failed={} handles_live={}", checks(), failed(), live));
    exit(if failed() == 0 && live == 0 { 0 } else { 1 });
}

/// 角色 1：进程没有设备访问能力；设备调用必须在分发层被拒。
fn probe_no_capability() -> ! {
    let list_ret = list_raw(Filter::ALL.to_word(), 0, 0);
    emit!(
        list_ret == -(ids::SYSTEM_ERROR_RIGHTS_DENIED as i64),
        "case=reject_no_capability_list ret={}",
        list_ret
    );
    let open_ret = open(0, Rights::READ);
    emit!(
        open_ret == -(ids::SYSTEM_ERROR_RIGHTS_DENIED as i64),
        "case=reject_no_capability_open ret={}",
        open_ret
    );
    log(format_args!("[JSR-DEV] summary checks={} failed={} handles_live=0", checks(), failed()));
    exit(if failed() == 0 { 0 } else { 1 });
}

fn checks() -> u32 {
    // SAFETY：只读取单线程写入的计数器。
    unsafe { CHECKS }
}

fn failed() -> u32 {
    // SAFETY：只读取单线程写入的计数器。
    unsafe { FAILED }
}

/// 程序入口（链接脚本把它放在代码段最前面）；`role` 由内核的入口参数给出。
/// Program entry (placed first in the text segment by the linker); `role` comes from the kernel.
#[no_mangle]
#[link_section = ".text._start"]
pub extern "C" fn _start(role: usize, _arg: usize) -> ! {
    match role {
        0 => probe_devices(),
        _ => probe_no_capability(),
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(101)
}
