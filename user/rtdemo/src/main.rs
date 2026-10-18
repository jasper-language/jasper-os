//! user-rtdemo：用户态运行时（jasper-rt）的验收程序。
//! Acceptance program for the user-space runtime.
//!
//! 入口参数 `(role, _)`：
//!
//! | role | 用例组 | 期望退出码 |
//! |---|---|---|
//! | 0 | 全部功能用例（堆、匿名内存、线程、Channel、异步环、错误名），逐步检查 | 0（失败时为步骤编号） |
//! | 1 | `panic!`：运行时输出信息后终止进程 | 101 |
//! | 2 | 线程栈溢出：触到栈下方的未映射保护区 ⇒ 页故障终止整个进程 | 故障终止 |
//!
//! 每一步都检查成功路径**和**对应的失败路径（错误必须是登记表中的那个错误，而且失败不留下任何改动）。
#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::{format, vec};

use jasper_rt::channel;
use jasper_rt::ring::{Completion, Op, Ring, Sqe};
use jasper_rt::{entry, heap, mem, println, sys, task, time, Error, Handle, Rights};

entry!(main);

fn main(role: u64, _arg: u64) -> i32 {
    match role {
        0 => match all() {
            Ok(n) => {
                println!("rtdemo: ok checks={}", n);
                0
            }
            Err(step) => {
                println!("rtdemo: FAIL step={}", step);
                step as i32
            }
        },
        1 => panic!("演示 panic：运行时应输出本信息并以 101 结束进程"),
        2 => stack_overflow(),
        _ => 99,
    }
}

/// 检查计数器：每个检查点一个编号，失败时以该编号退出，便于定位。
struct Steps(u32);

impl Steps {
    fn check(&mut self, ok: bool) -> Result<(), u32> {
        self.0 += 1;
        if ok {
            Ok(())
        } else {
            Err(self.0)
        }
    }
}

fn all() -> Result<u32, u32> {
    let mut s = Steps(0);
    heap_cases(&mut s)?;
    memory_cases(&mut s)?;
    thread_cases(&mut s)?;
    channel_cases(&mut s)?;
    ring_cases(&mut s)?;
    error_cases(&mut s)?;
    Ok(s.0)
}

/// 堆：集合、格式化（含中文）、闭包、触发增长、全部释放后空闲字节回到总量、超量请求得到错误而不是 panic。
fn heap_cases(s: &mut Steps) -> Result<(), u32> {
    let before = heap::stats().0;
    {
        let v: Vec<u64> = (0..100_000u64).collect();
        s.check(v.iter().sum::<u64>() == 100_000 * 99_999 / 2)?;
        let mut m = BTreeMap::new();
        for i in 0..1000u32 {
            m.insert(i.wrapping_mul(2_654_435_761), i);
        }
        s.check(m.len() == 1000 && m.values().map(|&v| v as u64).sum::<u64>() == 999 * 1000 / 2)?;
        let text: String = format!("你好，{}！第 {} 号", "jasper-os", 42);
        s.check(text == "你好，jasper-os！第 42 号")?;
        let add: Box<dyn Fn(u64) -> u64> = Box::new(move |x| x + v.len() as u64);
        s.check(add(1) == 100_001)?;
        let (total, _, _) = heap::stats();
        s.check(total > before && total >= 800_000)?;
        println!("rtdemo: heap grown_to={} map_calls_ok=true", total);
    }
    // 全部释放：空闲链表合并回一块或少数几块，空闲字节等于总量
    let (total, free, blocks) = heap::stats();
    s.check(total == free)?;
    println!("rtdemo: heap after_free total={} free={} blocks={}", total, free, blocks);
    // 超过堆区间上限：得到错误
    let mut big: Vec<u8> = Vec::new();
    s.check(big.try_reserve(512 << 20).is_err())?;
    // 堆区间内、但超过进程帧配额（多次映射中途被拒并回滚）：同样得到错误，且之后堆照常可用
    s.check(big.try_reserve(64 << 20).is_err())?;
    let small = vec![7u8; 4096];
    s.check(small.iter().all(|&b| b == 7))?;
    Ok(())
}

/// 匿名内存：映射 / 读写 / 各类拒绝（全有或全无）/ 取消映射 / 帧配额。
fn memory_cases(s: &mut Steps) -> Result<(), u32> {
    let base = sys::WINDOW_BASE + 0x3_0000_0000;
    let page = sys::PAGE;
    s.check(mem::map(base, 4, mem::WRITE).is_ok())?;
    // SAFETY：[base, base + 4 页) 刚映射为可写的清零页，只在本函数内使用。
    let words = unsafe { core::slice::from_raw_parts_mut(base as *mut u64, 4 * 512) };
    s.check(words.iter().all(|&w| w == 0))?;
    words[0] = 0x6a73_7072;
    words[4 * 512 - 1] = 0x726f_7366;
    s.check(words[0] == 0x6a73_7072 && words[4 * 512 - 1] == 0x726f_7366)?;

    // 拒绝：重叠、部分重叠（前一页空闲）、未对齐、页数为 0、标志含未定义位、超出私有窗口、单次页数超限
    s.check(mem::map(base, 1, mem::WRITE) == Err(Error::MEMORY_ALREADY_MAPPED))?;
    s.check(mem::map(base - page, 2, mem::WRITE) == Err(Error::MEMORY_ALREADY_MAPPED))?;
    s.check(mem::unmap(base - page, 1) == Err(Error::MEMORY_INVALID_ADDRESS))?; // 部分重叠失败后前一页仍未映射
    s.check(mem::map(base + 8 * page + 1, 1, mem::WRITE) == Err(Error::MEMORY_INVALID_ADDRESS))?;
    s.check(mem::map(base + 8 * page, 0, mem::WRITE) == Err(Error::MEMORY_INVALID_ADDRESS))?;
    s.check(mem::map(base + 8 * page, 1, 1 << 1) == Err(Error::INVALID_ARGUMENT))?;
    s.check(mem::map(0x1000, 1, mem::WRITE) == Err(Error::MEMORY_INVALID_ADDRESS))?;
    s.check(mem::map(0x2000_0000_0000 - page, 2, mem::WRITE) == Err(Error::MEMORY_INVALID_ADDRESS))?;
    s.check(mem::map(base + 8 * page, 1025, mem::WRITE) == Err(Error::MEMORY_INVALID_ADDRESS))?;
    s.check(mem::map(base + 8 * page, u64::MAX / page, mem::WRITE) == Err(Error::MEMORY_INVALID_ADDRESS))?;

    // 取消映射：区间含未映射页 ⇒ 什么也不改（原数据仍在）
    s.check(mem::unmap(base, 5) == Err(Error::MEMORY_INVALID_ADDRESS))?;
    s.check(words[0] == 0x6a73_7072)?;
    s.check(mem::unmap(base, 4).is_ok())?;
    s.check(mem::unmap(base, 1) == Err(Error::MEMORY_INVALID_ADDRESS))?; // 重复取消映射

    // 帧配额：每次 1024 页（4 MiB）直到被拒；被拒的那次不留下任何映射；随后全部取消映射
    let quota_base = sys::WINDOW_BASE + 0x4_0000_0000;
    let chunk = 1024u64;
    let mut mapped = 0u64;
    let refused = loop {
        match mem::map(quota_base + mapped * chunk * page, chunk, mem::WRITE) {
            Ok(()) => mapped += 1,
            Err(e) => break e,
        }
        if mapped > 64 {
            break Error(0);
        }
    };
    s.check(refused == Error::QUOTA_EXCEEDED && mapped >= 1)?;
    s.check(mem::unmap(quota_base + mapped * chunk * page, 1) == Err(Error::MEMORY_INVALID_ADDRESS))?;
    for i in 0..mapped {
        s.check(mem::unmap(quota_base + i * chunk * page, chunk).is_ok())?;
    }
    println!("rtdemo: memory quota_chunks={} refused={}", mapped, refused);
    // 配额释放后可以再次映射
    s.check(mem::map(quota_base, chunk, mem::WRITE).is_ok() && mem::unmap(quota_base, chunk).is_ok())?;
    Ok(())
}

/// 线程：spawn / join、退出码、共享堆、栈槽位归还后可复用。
fn thread_cases(s: &mut Steps) -> Result<(), u32> {
    let a = task::spawn(|| (1..=1000u64).sum::<u64>() % 1000 + 1).map_err(|_| 1000 + s.0)?;
    let b = task::spawn(|| {
        let v: Vec<u32> = (0..5000).map(|i| i * 3).collect();
        (v.iter().filter(|&&x| x % 2 == 0).count()) as u64
    })
    .map_err(|_| 1000 + s.0)?;
    let ra = a.join();
    let rb = b.join();
    s.check(ra == Ok(500 + 1))?;
    s.check(rb == Ok(2500))?;
    // 再来一轮：栈槽位已归还，同一槽位可复用
    for i in 0..4u64 {
        let t = task::spawn(move || i * 10 + 3).map_err(|_| 1000 + s.0)?;
        s.check(t.join() == Ok(i * 10 + 3))?;
    }
    println!("rtdemo: threads joined a={:?} b={:?}", ra, rb);
    Ok(())
}

/// Channel：跨线程往返（字节 + 句柄）、按需扩大接收缓冲区、缓冲区不足时消息留在队列、对端关闭。
fn channel_cases(s: &mut Steps) -> Result<(), u32> {
    let (here, there) = channel::pair().map_err(|_| 2000 + s.0)?;
    // 回声线程：把收到的字节反转后发回，并把收到的句柄原样随回复送回
    let echo = task::spawn(move || {
        let mut rounds = 0u64;
        while let Ok((mut data, handles)) = there.recv_vec() {
            data.reverse();
            if there.send_with(&data, handles).is_err() {
                return 900;
            }
            rounds += 1;
        }
        rounds
    })
    .map_err(|_| 2000 + s.0)?;

    // 1. 只含字节
    s.check(here.send("你好 jasper".as_bytes()).is_ok())?;
    let (data, hs) = here.recv_vec().map_err(|_| 2000 + s.0)?;
    let mut expect = "你好 jasper".as_bytes().to_vec();
    expect.reverse();
    s.check(data == expect && hs.is_empty())?;

    // 2. 带句柄：传一个只有 WAIT | TRANSFER 的线程句柄出去，再收回来，收回的句柄仍可用于等待
    let sleeper = task::spawn(|| {
        let _ = time::sleep(2);
        77
    })
    .map_err(|_| 2000 + s.0)?;
    let dup = sleeper.handle().duplicate(Rights::WAIT.union(Rights::TRANSFER)).map_err(|_| 2000 + s.0)?;
    s.check(here.send_with(b"with-handle", vec![dup]).is_ok())?;
    let (_, mut back) = here.recv_vec().map_err(|_| 2000 + s.0)?;
    s.check(back.len() == 1)?;
    let returned: Handle = back.pop().ok_or(2000 + s.0)?;
    s.check(task::wait_task(&returned) == Ok(77))?;
    s.check(returned.duplicate(Rights::WAIT.union(Rights::CONTROL)) == Err(Error::HANDLE_RIGHTS_DENIED))?; // 只能降权
    drop(returned);
    s.check(sleeper.join() == Ok(77))?;

    // 3. 大消息：40 KiB，接收方从 256 字节缓冲起按需扩大
    let big: Vec<u8> = (0..40 * 1024).map(|i| (i % 251) as u8).collect();
    s.check(here.send(&big).is_ok())?;
    let (got, _) = here.recv_vec().map_err(|_| 2000 + s.0)?;
    s.check(got.len() == big.len() && got.iter().rev().zip(big.iter()).all(|(a, b)| a == b))?;

    // 4. 单次 recv 缓冲区不足：报错，消息留在队列，随后用足够的缓冲区收到同一条
    s.check(here.send(b"0123456789").is_ok())?;
    let mut tiny = [0u8; 4];
    // recv 阻塞到回复到达；缓冲区不足的报错说明回复已在队列中、只是没有交付
    s.check(here.recv(&mut tiny).map(|r| r.len).err() == Some(Error::CHANNEL_BUFFER_TOO_SMALL))?;
    let mut enough = [0u8; 16];
    let r = here.recv(&mut enough).map_err(|_| 2000 + s.0)?;
    s.check(&enough[..r.len] == b"9876543210")?;

    // 5. 超过单条消息上限的发送在本地就被拒
    let huge = vec![0u8; channel::MAX_BYTES + 1];
    s.check(here.send(&huge) == Err(Error::INVALID_ARGUMENT))?;

    // 6. 关闭本端 ⇒ 回声线程的 recv 得到对端关闭，线程以往返次数退出
    drop(here);
    s.check(echo.join() == Ok(4))?;
    println!("rtdemo: channel roundtrips=4 handle_returned=true");
    Ok(())
}

/// 异步环：提交 → 完成、标签原样带回、取消、等待线程、被拒的提交。
fn ring_cases(s: &mut Steps) -> Result<(), u32> {
    let ring = Ring::create(8).map_err(|_| 3000 + s.0)?;
    let long = ring.submit(1, Op::Sleep(100_000)).map_err(|_| 3000 + s.0)?;
    let now = ring.submit(2, Op::Now).map_err(|_| 3000 + s.0)?;
    s.check(now > long)?; // 请求 ID 单调递增
    let mut out = [Completion { request_id: 0, user_tag: 0, op: 0, result: 0 }; 4];
    let n = ring.reap(&mut out, 1).map_err(|_| 3000 + s.0)?;
    s.check(n == 1 && out[0].request_id == now && out[0].user_tag == 2 && out[0].outcome().is_ok())?;

    // 取消长等待：同步取消成功，完成记录以 cancelled 到达；重复取消得到 already_completed / not_found
    s.check(ring.cancel(long).is_ok())?;
    let n = ring.reap(&mut out, 1).map_err(|_| 3000 + s.0)?;
    s.check(n == 1 && out[0].request_id == long && out[0].outcome() == Err(Error::ASYNC_CANCELLED))?;
    let again = ring.cancel(long);
    s.check(again == Err(Error::ASYNC_ALREADY_COMPLETED) || again == Err(Error::ASYNC_NOT_FOUND))?;

    // 经 ring 等待线程退出
    let t = task::spawn(|| 55).map_err(|_| 3000 + s.0)?;
    let w = ring.submit(3, Op::WaitTask(t.handle())).map_err(|_| 3000 + s.0)?;
    let n = ring.reap(&mut out, 1).map_err(|_| 3000 + s.0)?;
    s.check(n == 1 && out[0].request_id == w && out[0].outcome() == Ok(55))?;
    // 句柄参数超出 32 位：一律视为无效句柄，不截断成低 32 位所指的那个线程（同步与经 ring 两条路径）
    let alias = t.handle().raw() as u64 | 1 << 32;
    s.check(jasper_rt::error::check(sys::call(jasper_rt::ids::SYSTEM_TASK_WAIT, alias, 0, 0)) == Err(Error::HANDLE_INVALID))?;
    let sqe = Sqe { op: jasper_rt::ids::SYSTEM_TASK_WAIT as u32, flags: 0, user_tag: 5, arg0: alias, arg1: 0 };
    // SAFETY：该操作不引用用户内存。
    s.check(unsafe { ring.submit_raw(sqe) } == Err(Error::HANDLE_INVALID))?;
    s.check(t.join() == Ok(55))?;

    // 被拒的提交：句柄不指向线程 ⇒ 不产生请求，错误随提交返回
    let not_a_task = ring.handle().duplicate(Rights::WAIT).map_err(|_| 3000 + s.0)?;
    let r = ring.submit(4, Op::WaitTask(&not_a_task));
    s.check(r == Err(Error::HANDLE_INVALID) || r == Err(Error::HANDLE_RIGHTS_DENIED))?;
    println!("rtdemo: ring cancelled_ok=true wait_task=55");
    Ok(())
}

/// 错误：名字来自登记表；关闭无效句柄得到 handle.error.invalid。
fn error_cases(s: &mut Steps) -> Result<(), u32> {
    s.check(Error::HANDLE_INVALID.name() == "system.handle.error.invalid")?;
    s.check(Error(1).name() == "unregistered")?;
    // SAFETY：60000 不是本进程中任何句柄（句柄表容量 64），关闭它只会得到错误。
    let bogus = unsafe { Handle::from_raw(60000) };
    s.check(bogus.close() == Err(Error::HANDLE_INVALID))?;
    println!("rtdemo: error name={}", Error::QUOTA_EXCEEDED);
    Ok(())
}

/// 在新线程里无限递归：栈下方是未映射的保护区，越界即页故障，整个进程被终止。
fn stack_overflow() -> i32 {
    #[inline(never)]
    #[allow(unconditional_recursion)] // 有意无限递归：直到触到保护区
    fn deep(n: u64, pad: &mut [u8; 512]) -> u64 {
        pad[0] = n as u8;
        let mut next = [0u8; 512];
        deep(n + 1, core::hint::black_box(&mut next)) + pad[0] as u64
    }
    let t = task::spawn(|| deep(0, &mut [0u8; 512]));
    match t {
        Ok(t) => {
            let _ = t.join();
            98 // 不应到达：故障终止整个进程
        }
        Err(_) => 97,
    }
}
