//! 健壮性测试：对处理不可信输入的解析器与状态机做**确定性随机测试**（固定种子，可复现；不引入外部依赖）。
//! Deterministic randomized robustness tests for parsers and state machines that handle untrusted input.
//!
//! 每项测试检查两类性质：
//! * **不崩溃**：任意输入都不得 panic（包括调试构建中的算术溢出检查）
//! * **不变量**：接受的结果必须满足语义约束（例如 ELF 段都落在文件内、Ring 的信用守恒、对象表与模型一致）
//!
//! 失败时打印种子与迭代号，可据此单独复现。

use std::collections::{HashMap, HashSet};
use std::vec::Vec;

use crate::argcase::Prng as Rng;
use crate::async_ring::{AsyncRing, Cancelled, Exec, Submission, Terminal};
use crate::elf::{self, PAGE};
use crate::object::{HandleError, HandleTable, Rights};
use crate::objtable::{ObjError, ObjectTable};
use crate::ring_abi::{Cqe, EnterArgs, MsgDesc, Sqe};

// ———————————————————————— ELF ————————————————————————

const X86_64: u16 = 62;

/// 一个合法的两段静态可执行文件。
fn valid_elf() -> Vec<u8> {
    let mut b = vec![0u8; 0x3000];
    b[0..4].copy_from_slice(b"\x7fELF");
    b[4] = 2;
    b[5] = 1;
    b[6] = 1;
    b[16..18].copy_from_slice(&2u16.to_le_bytes());
    b[18..20].copy_from_slice(&X86_64.to_le_bytes());
    let code = 0x1000_0040_0000u64;
    b[24..32].copy_from_slice(&code.to_le_bytes());
    b[32..40].copy_from_slice(&64u64.to_le_bytes());
    b[54..56].copy_from_slice(&56u16.to_le_bytes());
    b[56..58].copy_from_slice(&2u16.to_le_bytes());
    let segs = [(1u32, 5u32, 0x1000u64, code, 0x100u64, 0x100u64), (1, 6, 0x2000, code + 0x1000, 0x10, 0x3000)];
    for (i, (ty, fl, off, va, fsz, msz)) in segs.iter().enumerate() {
        let p = 64 + i * 56;
        b[p..p + 4].copy_from_slice(&ty.to_le_bytes());
        b[p + 4..p + 8].copy_from_slice(&fl.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&off.to_le_bytes());
        b[p + 16..p + 24].copy_from_slice(&va.to_le_bytes());
        b[p + 32..p + 40].copy_from_slice(&fsz.to_le_bytes());
        b[p + 40..p + 48].copy_from_slice(&msz.to_le_bytes());
    }
    b
}

/// 一个合法的两段 ELF32 静态可执行文件（RISC-V32，装载在 32 位用户窗口内）。
fn valid_elf32() -> Vec<u8> {
    let mut b = vec![0u8; 0x3000];
    b[0..4].copy_from_slice(b"\x7fELF");
    (b[4], b[5], b[6]) = (1, 1, 1);
    b[16..18].copy_from_slice(&2u16.to_le_bytes());
    b[18..20].copy_from_slice(&RISCV.to_le_bytes());
    b[24..28].copy_from_slice(&0x0080_0010u32.to_le_bytes());
    b[28..32].copy_from_slice(&52u32.to_le_bytes());
    b[42..44].copy_from_slice(&32u16.to_le_bytes());
    b[44..46].copy_from_slice(&2u16.to_le_bytes());
    for (i, (off, va, fsz, msz, fl)) in [(0x1000u32, 0x0080_0000u32, 0x100u32, 0x100u32, 5u32), (0x2000, 0x0080_1000, 0x10, 0x3000, 6)].into_iter().enumerate() {
        let p = 52 + i * 32;
        for (at, v) in [(0, 1u32), (4, off), (8, va), (16, fsz), (20, msz), (24, fl)] {
            b[p + at..p + at + 4].copy_from_slice(&v.to_le_bytes());
        }
    }
    b
}

const RISCV: u16 = 243;

/// 对合法镜像 `base` 做 `iters` 轮随机变异（覆盖 `fields` 中的结构字段 = (偏移, 宽度)，或改写前 256 字节中的任意字节，
/// 偶尔截断），每个被接受的结果都检查不变量；`limit` 为该类别的地址空间上限（ELF32 为 4 GiB）。
fn fuzz_elf(base: &[u8], machine: u16, class: elf::ElfClass, fields: &[(usize, usize)], seed: u64, iters: u32, limit: Option<u64>) {
    assert!(elf::parse(base, machine, class).is_ok(), "基准镜像应合法");
    let mut rng = Rng::new(seed);
    let mut accepted = 0;
    for iter in 0..iters {
        let mut img = base.to_vec();
        let edits = 1 + rng.below(4);
        for _ in 0..edits {
            if rng.chance(60) {
                // 覆盖一个结构字段为（偏向边界的）随机值
                let (f, width) = fields[rng.below(fields.len() as u64) as usize];
                let v = rng.boundary_biased().to_le_bytes();
                img[f..f + width].copy_from_slice(&v[..width]);
            } else {
                let i = rng.below(0x100) as usize;
                img[i] = rng.next_u64() as u8;
            }
        }
        if rng.chance(10) {
            let n = rng.below(img.len() as u64) as usize;
            img.truncate(n);
        }
        let Ok(e) = elf::parse(&img, machine, class) else { continue };
        accepted += 1;
        let segs: Vec<_> = e.segments().copied().collect();
        assert!(!segs.is_empty(), "iter {iter}: 接受的镜像至少有一个装载段");
        for s in &segs {
            let end = s.offset.checked_add(s.filesz).expect("文件区间不溢出");
            assert!(end <= img.len() as u64 && s.filesz <= s.memsz, "iter {iter}: 段的文件数据必须在镜像内");
            assert_eq!(s.vaddr % PAGE, s.offset % PAGE, "iter {iter}: vaddr/offset 模页一致");
            let (lo, hi) = s.page_range().expect("接受的段页区间可表示");
            assert!(lo < hi, "iter {iter}");
            assert!(limit.is_none_or(|top| hi <= top), "iter {iter}: 段落在该类别的地址空间内");
            let _ = s.file_bytes(&img); // 不得越界
        }
        for (i, a) in segs.iter().enumerate() {
            for b in &segs[i + 1..] {
                let (al, ah) = a.page_range().unwrap();
                let (bl, bh) = b.page_range().unwrap();
                assert!(ah <= bl || bh <= al, "iter {iter}: 段按页不重叠");
            }
        }
        assert!(
            segs.iter().any(|s| s.flags.execute && e.entry >= s.vaddr && e.entry < s.vaddr + s.memsz),
            "iter {iter}: 入口在可执行段内"
        );
    }
    assert!(accepted > 100, "变异中应仍有一部分合法镜像（验证测试本身有效）：{accepted}");
}

#[test]
fn elf_parser_survives_mutations_and_keeps_invariants() {
    let fields = [24, 32, 64 + 8, 64 + 16, 64 + 32, 64 + 40, 120 + 8, 120 + 16, 120 + 32, 120 + 40, 56, 54].map(|f| (f, if f == 56 || f == 54 { 2 } else { 8 }));
    fuzz_elf(&valid_elf(), X86_64, elf::ElfClass::Elf64, &fields, 0x5EED_E1F0, 60_000, None);
}

#[test]
fn elf32_parser_survives_mutations_and_keeps_invariants() {
    // ELF32 的入口、程序头偏移、两个程序头的 offset/vaddr/filesz/memsz（4 字节）与表项大小/个数（2 字节）
    let fields = [24, 28, 52 + 4, 52 + 8, 52 + 16, 52 + 20, 84 + 4, 84 + 8, 84 + 16, 84 + 20, 42, 44].map(|f| (f, if f == 42 || f == 44 { 2 } else { 4 }));
    fuzz_elf(&valid_elf32(), RISCV, elf::ElfClass::Elf32, &fields, 0x5EED_E132, 40_000, Some(1 << 32));
}

// ———————————————————————— 系统接口登记表 ————————————————————————

#[test]
fn abi_registry_parser_never_panics() {
    let alphabet: Vec<char> = "abcxyz_.09 \t#\nsystem.error.op 一二".chars().collect();
    let mut rng = Rng::new(0xAB1);
    for _ in 0..30_000 {
        let len = rng.below(80) as usize;
        let s: String = (0..len).map(|_| alphabet[rng.below(alphabet.len() as u64) as usize]).collect();
        let _ = crate::abi::validate(&s, |_| {});
        let _ = crate::abi::lint_name(&s, if rng.chance(50) { "op" } else { "error" });
        let _ = crate::abi::check_frozen(&s, &s);
    }
}

// ———————————————————————— 用户态记录布局 ————————————————————————

#[test]
fn ring_records_roundtrip_any_bytes() {
    let mut rng = Rng::new(0xC0DE);
    for _ in 0..20_000 {
        let mut b = [0u8; 56];
        for x in b.iter_mut() {
            *x = rng.next_u64() as u8;
        }
        let s: [u8; 32] = b[..32].try_into().unwrap();
        assert_eq!(Sqe::decode(&s).encode(), s);
        assert_eq!(Cqe::decode(&s).encode(), s);
        // MsgDesc 现在是 40 字节（多出内核盖章的发送方字段）。
        let md: [u8; 40] = b[..40].try_into().unwrap();
        assert_eq!(MsgDesc::decode(&md).encode(), md);
        assert_eq!(EnterArgs::decode(&b).encode(), b);
    }
}

// ———————————————————————— 异步环状态机 ————————————————————————

/// 对照模型：每个请求的可观察状态。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Model {
    Queued,
    Running(Exec),
    /// 已裁决为取消，等后端静止。
    CancelledRunning,
    /// 控制块可能已销毁（终态已裁决）。
    Decided,
}

#[test]
fn async_ring_random_operations_keep_invariants() {
    const C: usize = 8;
    for seed in 1..=40u64 {
        let mut rng = Rng::new(seed * 0x9E37_79B9);
        let cap = 1 + rng.below(C as u64) as usize;
        let mut r: AsyncRing<C, 16> = AsyncRing::new(cap).unwrap();
        let mut model: HashMap<u64, Model> = HashMap::new();
        let mut published: HashSet<u64> = HashSet::new();
        let mut last_id = 0u64;
        let mut closing = false;
        for step in 0..3_000 {
            let ids: Vec<u64> = model.iter().filter(|(_, m)| **m != Model::Decided).map(|(id, _)| *id).collect();
            let pick = |rng: &mut Rng| if ids.is_empty() { rng.next_u64() % 50 } else { ids[rng.below(ids.len() as u64) as usize] };
            match rng.below(9) {
                0 | 1 => {
                    let buf = rng.chance(30);
                    match r.submit(Submission { op: 1, user_tag: rng.below(3), context: 0, uses_buffer: buf }) {
                        Ok(id) => {
                            assert!(!closing, "seed {seed} step {step}: closing 后不得接受提交");
                            assert!(id > last_id, "seed {seed}: 请求 ID 单调");
                            last_id = id;
                            model.insert(id, Model::Queued);
                        }
                        Err(_) => {}
                    }
                }
                2 => {
                    let id = pick(&mut rng);
                    let exec = if rng.chance(50) { Exec::Abortable } else { Exec::NonAbortable };
                    if r.start(id, exec).is_ok() {
                        assert_eq!(model.get(&id), Some(&Model::Queued), "seed {seed}: 只有排队中的请求能开始");
                        model.insert(id, Model::Running(exec));
                    }
                }
                3 => {
                    let id = pick(&mut rng);
                    if let Ok(t) = r.finish(id, rng.below(100) as i64) {
                        let m = model[&id];
                        assert!(matches!(m, Model::Running(_) | Model::CancelledRunning), "seed {seed}: finish 只对执行中的请求");
                        if m == Model::CancelledRunning {
                            assert_eq!(t, Terminal::Cancelled, "seed {seed}: 先取消者为准（D 只一次）");
                        }
                        model.insert(id, Model::Decided);
                    }
                }
                4 => {
                    let id = pick(&mut rng);
                    if r.quiesce(id).is_ok() {
                        assert_eq!(model[&id], Model::CancelledRunning, "seed {seed}: 只有被取消的执行中请求才报告静止");
                        model.insert(id, Model::Decided);
                    }
                }
                5 => {
                    let id = pick(&mut rng);
                    match r.cancel(id) {
                        Ok(Cancelled::NotStarted) => {
                            assert_eq!(model.get(&id), Some(&Model::Queued));
                            model.insert(id, Model::Decided);
                        }
                        Ok(Cancelled::AbortBackend { .. }) => {
                            assert_eq!(model.get(&id), Some(&Model::Running(Exec::Abortable)));
                            model.insert(id, Model::CancelledRunning);
                        }
                        Err(_) => {}
                    }
                }
                6 => {
                    let n = rng.below(4) as usize;
                    for i in 0..n.min(r.ready()) {
                        let c = r.peek(i).unwrap();
                        assert!(published.insert(c.request_id), "seed {seed}: 每个请求最多发布一条完成");
                    }
                    r.consume(n.min(r.ready()));
                }
                7 if rng.chance(5) => {
                    closing = true;
                    r.close(|_, id| {
                        model.insert(id, Model::CancelledRunning);
                    });
                    for m in model.values_mut() {
                        if *m == Model::Queued {
                            *m = Model::Decided;
                        }
                    }
                }
                _ => {
                    while r.take_reclaimed().is_some() {}
                }
            }
            // 守恒：可用信用 + 已预留 + 已发布未消费 = 容量
            assert_eq!(r.credits() + r.reserved() + r.ready(), cap, "seed {seed} step {step}: 信用守恒");
            assert!(r.ready() <= cap && r.in_flight() <= 16, "seed {seed}");
        }
        // 收尾：让所有执行中的请求结束，控制块应全部销毁
        let ids: Vec<(u64, Model)> = model.iter().map(|(k, v)| (*k, *v)).collect();
        for (id, m) in ids {
            match m {
                Model::Running(_) => {
                    let _ = r.finish(id, 0);
                }
                Model::CancelledRunning => {
                    let _ = r.quiesce(id);
                }
                Model::Queued => {
                    let _ = r.cancel(id);
                }
                Model::Decided => {}
            }
        }
        r.consume(r.ready());
        assert_eq!(r.in_flight(), 0, "seed {seed}: 全部结束后控制块应全部销毁");
        assert_eq!(r.credits(), cap, "seed {seed}: 全部消费后信用全部归还");
    }
}

// ———————————————————————— 对象表与句柄表 ————————————————————————

#[test]
fn object_table_matches_reference_model() {
    let mut rng = Rng::new(0x0B7E);
    let mut t: ObjectTable<u32, 16> = ObjectTable::new();
    // 模型：id → (owners, internal, closing)；closing 只在外部所有权从有降到零时置位（新建对象即使没有所有者也是 Live）；
    // dead 记录已死亡的标识（之后必须永远无效）
    let mut model: HashMap<u64, (u32, u32, bool)> = HashMap::new();
    let mut ids: Vec<crate::objtable::ObjId> = Vec::new();
    let mut dead: Vec<crate::objtable::ObjId> = Vec::new();
    for step in 0..50_000 {
        match rng.below(6) {
            0 => {
                let (o, i) = (rng.below(3) as u32, rng.below(3) as u32);
                match t.insert(step, o, i) {
                    Ok(id) => {
                        assert!(o + i > 0);
                        model.insert(id.raw(), (o, i, false));
                        ids.push(id);
                    }
                    Err(ObjError::Underflow) => assert_eq!(o + i, 0),
                    Err(ObjError::Full) => assert_eq!(t.live(), 16, "表满只能因为槽位全被占用（含待清理的死亡对象）"),
                    Err(e) => panic!("意外错误 {e:?}"),
                }
            }
            1 | 2 if !ids.is_empty() => {
                let id = ids[rng.below(ids.len() as u64) as usize];
                let owner = rng.chance(50);
                let res = if owner { t.release_owner(id) } else { t.release_internal(id) };
                let Some(&(o, i, closing)) = model.get(&id.raw()) else {
                    assert!(res.is_err(), "已死亡的标识必须无效");
                    continue;
                };
                let (o2, i2) = if owner { (o.wrapping_sub(1), i) } else { (o, i.wrapping_sub(1)) };
                if (owner && o == 0) || (!owner && i == 0) {
                    assert_eq!(res, Err(ObjError::Underflow), "step {step}: 计数为 0 时释放应报下溢");
                    continue;
                }
                let r = res.unwrap();
                assert_eq!(r.dead, o2 == 0 && i2 == 0, "step {step}: 两种计数都为 0 才死亡");
                if r.dead {
                    model.remove(&id.raw());
                    dead.push(id);
                } else {
                    model.insert(id.raw(), (o2, i2, closing || (owner && o2 == 0)));
                }
            }
            3 if !ids.is_empty() => {
                let id = ids[rng.below(ids.len() as u64) as usize];
                let owner = rng.chance(50);
                let res = if owner { t.acquire_owner(id) } else { t.acquire_internal(id) };
                match model.get_mut(&id.raw()) {
                    Some((o, i, closing)) => {
                        if owner && *closing {
                            assert!(res.is_err(), "closing 对象不能再获得所有者");
                        } else {
                            res.unwrap();
                            if owner {
                                *o += 1
                            } else {
                                *i += 1
                            }
                        }
                    }
                    None => assert!(res.is_err(), "已死亡的标识必须无效"),
                }
            }
            4 => {
                let _ = t.take_dead();
            }
            _ => {
                for d in &dead {
                    assert!(t.counts(*d).is_err() && t.get(*d).is_err(), "step {step}: 死亡对象的旧标识永远无效");
                }
            }
        }
        for (raw, (o, i, _)) in &model {
            let id = ids.iter().find(|x| x.raw() == *raw).unwrap();
            let c = t.counts(*id).unwrap();
            assert_eq!((c.0, c.1), (*o, *i), "step {step}: 计数与模型一致");
        }
        if ids.len() > 64 {
            ids.retain(|x| model.contains_key(&x.raw()));
        }
    }
}

#[test]
fn handle_table_never_resolves_stale_handles() {
    let mut rng = Rng::new(0x4A11);
    let mut t: HandleTable<u64, 4> = HandleTable::new();
    let mut live: HashMap<u64, u64> = HashMap::new();
    let mut stale: HashSet<u64> = HashSet::new();
    let mut next = 0u64;
    // 足够多的轮次覆盖反复分配释放；断言重点是「旧句柄永不复活」，与代次是否耗尽无关
    for step in 0..400_000u64 {
        if rng.chance(55) {
            next += 1;
            match t.put(next, Rights::ALL) {
                Ok(h) => {
                    assert!(!stale.contains(&h.raw()), "step {step}: 新句柄值不得与已关闭的句柄值重复（不回绕）");
                    live.insert(h.raw(), next);
                }
                Err(HandleError::TableFull) => assert!(live.len() == 4 || t.free_slots() == 0),
                Err(e) => panic!("意外错误 {e:?}"),
            }
        } else if let Some(&raw) = live.keys().next() {
            let h = crate::object::HandleId::from_raw(raw);
            assert_eq!(t.remove(h), Ok(live.remove(&raw).unwrap()));
            stale.insert(raw);
        }
        if step % 997 == 0 {
            for raw in stale.iter().take(64) {
                assert!(t.get(crate::object::HandleId::from_raw(*raw)).is_err(), "step {step}: 旧句柄永远无效");
            }
        }
    }
    assert!(t.free_slots() < 4, "长时间运行后应有槽位因世代耗尽而退役");
}
