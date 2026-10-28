// issue #7 第一片：启动阶段跟踪器（kernel_core::boot_stage::Tracker）的 Verus 伴随模型。
// Verus companion model of kernel_core::boot_stage::Tracker (issue #7, slice 1).
//
// 模型与 Rust 源一一对应：started / done 为位掩码，running / failed 用 NONE(=10) 表示「无」。
// 证明：begin 成功 ⇒ 未失败、无运行中阶段、此前未开始、直接依赖全部完成；begin/complete/fail 保持不变量
// （done ⊆ started ⊆ 全集；运行中阶段已开始未完成且依赖已完成；每个已完成阶段的直接依赖都已完成；
// 失败后 begin 一律被拒）；依赖表只指向更靠前的阶段。
// 另含 capacity 记录 encode/parse 的字段往返引理（补链）。
// 伴随模型不直接验证 Rust 源；一致性由 Proptest / fuzz 差分与 Kani 在真实源上补足。
use vstd::prelude::*;

verus! {

pub const COUNT: u32 = 10;
pub const NONE: u32 = 10;
pub const ALL: u32 = 0x3ff;

/// 直接依赖表（与 GRAPH 一致）。Direct prerequisites, mirroring GRAPH.
pub open spec fn req(i: u32) -> u32 {
    if i == 0 { 0 }
    else if i == 1 { 0x1 }
    else if i == 2 { 0x2 }
    else if i == 3 { 0x2 }
    else if i == 4 { 0x8 }
    else if i == 5 { 0x18 }
    else if i == 6 { 0x20 }
    else if i == 7 { 0x30 }
    else if i == 8 { 0x20 }
    else { 0x144 }
}

fn req_exec(i: u32) -> (r: u32)
    requires i < COUNT,
    ensures r == req(i),
{
    if i == 0 { 0 }
    else if i == 1 { 0x1 }
    else if i == 2 { 0x2 }
    else if i == 3 { 0x2 }
    else if i == 4 { 0x8 }
    else if i == 5 { 0x18 }
    else if i == 6 { 0x20 }
    else if i == 7 { 0x30 }
    else if i == 8 { 0x20 }
    else { 0x144 }
}

/// 依赖只指向更靠前的阶段（图无环的充分条件）。Prerequisites point strictly backwards.
proof fn graph_points_backwards(i: u32)
    requires i < COUNT,
    ensures req(i) & !(((1u32 << i) - 1) as u32) == 0,
{
    if i == 0 { assert(0u32 & !(((1u32 << 0u32) - 1) as u32) == 0) by (bit_vector); }
    else if i == 1 { assert(1u32 & !(((1u32 << 1u32) - 1) as u32) == 0) by (bit_vector); }
    else if i == 2 { assert(2u32 & !(((1u32 << 2u32) - 1) as u32) == 0) by (bit_vector); }
    else if i == 3 { assert(2u32 & !(((1u32 << 3u32) - 1) as u32) == 0) by (bit_vector); }
    else if i == 4 { assert(8u32 & !(((1u32 << 4u32) - 1) as u32) == 0) by (bit_vector); }
    else if i == 5 { assert(0x18u32 & !(((1u32 << 5u32) - 1) as u32) == 0) by (bit_vector); }
    else if i == 6 { assert(0x20u32 & !(((1u32 << 6u32) - 1) as u32) == 0) by (bit_vector); }
    else if i == 7 { assert(0x30u32 & !(((1u32 << 7u32) - 1) as u32) == 0) by (bit_vector); }
    else if i == 8 { assert(0x20u32 & !(((1u32 << 8u32) - 1) as u32) == 0) by (bit_vector); }
    else { assert(0x144u32 & !(((1u32 << 9u32) - 1) as u32) == 0) by (bit_vector); }
}

pub struct Tracker {
    pub started: u32,
    pub done: u32,
    pub running: u32,
    pub failed: u32,
}

pub open spec fn bit_in(m: u32, i: u32) -> bool {
    m & (1u32 << i) != 0
}

/// 每个已完成阶段的直接依赖都已完成。Every done stage has all its prerequisites done.
pub open spec fn closed(d: u32) -> bool {
    forall|k: u32| #![trigger bit_in(d, k)] k < COUNT && bit_in(d, k) ==> req(k) & !d == 0
}

pub open spec fn inv(t: Tracker) -> bool {
    &&& t.done & !t.started == 0
    &&& t.started & !ALL == 0
    &&& t.running <= NONE
    &&& t.failed <= NONE
    &&& (t.running < NONE ==> bit_in(t.started, t.running) && !bit_in(t.done, t.running)
            && req(t.running) & !t.done == 0)
    &&& (t.running < NONE ==> t.failed == NONE)
    &&& closed(t.done)
}

fn new_tracker() -> (t: Tracker)
    ensures inv(t),
{
    let t = Tracker { started: 0, done: 0, running: NONE, failed: NONE };
    assert(0u32 & !0u32 == 0) by (bit_vector);
    assert(0u32 & !ALL == 0) by (bit_vector);
    assert forall|k: u32| k < COUNT && #[trigger] bit_in(0u32, k) implies req(k) & !0u32 == 0 by {
        assert(k < 32 ==> 0u32 & (1u32 << k) == 0) by (bit_vector);
    }
    t
}

/// 0 = Ok；1 = Halted；2 = Busy；3 = Duplicate；4 = MissingDependency。
fn begin(t: &mut Tracker, s: u32) -> (r: u8)
    requires inv(*old(t)), s < COUNT,
    ensures
        inv(*final(t)),
        r == 0 ==> old(t).failed == NONE && old(t).running == NONE && !bit_in(old(t).started, s)
            && req(s) & !old(t).done == 0 && final(t).running == s,
        r != 0 ==> *final(t) == *old(t),
        old(t).failed < NONE ==> r != 0,
{
    if t.failed < NONE {
        return 1;
    }
    if t.running < NONE {
        return 2;
    }
    let bit = 1u32 << s;
    if t.started & bit != 0 {
        return 3;
    }
    if req_exec(s) & !t.done != 0 {
        return 4;
    }
    let ghost old_t = *t;
    t.started = t.started | bit;
    t.running = s;
    let ghost st = old_t.started;
    let ghost d = old_t.done;
    assert(d & !st == 0 ==> d & !(st | bit) == 0) by (bit_vector);
    assert(s < 10 && st & !0x3ffu32 == 0 ==> (st | (1u32 << s)) & !0x3ffu32 == 0) by (bit_vector);
    assert(s < 32 ==> (st | (1u32 << s)) & (1u32 << s) != 0) by (bit_vector);
    assert(s < 32 && st & (1u32 << s) == 0 && d & !st == 0 ==> d & (1u32 << s) == 0) by (bit_vector);
    0
}

fn complete(t: &mut Tracker, s: u32) -> (r: bool)
    requires inv(*old(t)), s < COUNT,
    ensures inv(*final(t)), r == (old(t).running == s), !r ==> *final(t) == *old(t),
        r ==> final(t).done == (old(t).done | (1u32 << s)),
{
    if t.running != s {
        return false;
    }
    let ghost old_t = *t;
    let bit = 1u32 << s;
    t.done = t.done | bit;
    t.running = NONE;
    let ghost st = old_t.started;
    let ghost d = old_t.done;
    assert(d & !st == 0 && st & (1u32 << s) != 0 ==> (d | (1u32 << s)) & !st == 0) by (bit_vector);
    assert forall|k: u32| k < COUNT && #[trigger] bit_in(d | (1u32 << s), k)
        implies req(k) & !(d | (1u32 << s)) == 0 by {
        let x = req(k);
        assert(k < 32 && s < 32 && k != s && (d | (1u32 << s)) & (1u32 << k) != 0
            ==> d & (1u32 << k) != 0) by (bit_vector);
        assert(x & !d == 0 ==> x & !(d | (1u32 << s)) == 0) by (bit_vector);
        if k != s {
            assert(bit_in(d, k));
        }
    }
    true
}

fn fail(t: &mut Tracker, s: u32) -> (r: bool)
    requires inv(*old(t)), s < COUNT,
    ensures inv(*final(t)), r == (old(t).running == s), r ==> final(t).failed == s, !r ==> *final(t) == *old(t),
{
    if t.running != s {
        return false;
    }
    t.running = NONE;
    t.failed = s;
    true
}

/// 失败之后的任意 begin 都被拒且不改状态。After a failure every begin is refused.
fn halted_refuses(t: &mut Tracker, s: u32)
    requires inv(*old(t)), s < COUNT, old(t).failed < NONE,
    ensures *final(t) == *old(t),
{
    let r = begin(t, s);
    assert(r != 0);
}

// ---- 补链：capacity 记录字段往返（u32 小端拆分与重组）。Capacity record field round trip. ----

/// 小端四字节重组（每个字节取 0..=255）。Little-endian join of four byte values.
pub open spec fn le_join(b0: u32, b1: u32, b2: u32, b3: u32) -> u32 {
    b0 | (b1 << 8u32) | (b2 << 16u32) | (b3 << 24u32)
}

/// put 拆出的四个字节经 get 重组后等于原值。Bytes split by put rejoin to the value under get.
proof fn field_round_trip(v: u32)
    ensures le_join(v & 0xff, (v >> 8u32) & 0xff, (v >> 16u32) & 0xff, (v >> 24u32) & 0xff) == v,
{
    assert(((v & 0xff) | (((v >> 8u32) & 0xff) << 8u32) | (((v >> 16u32) & 0xff) << 16u32)
        | (((v >> 24u32) & 0xff) << 24u32)) == v) by (bit_vector);
}

/// 「0 = 不覆盖」编码：解码 nonzero(encode(o)) 与 o 一致（Some(0) 与 None 同义，内核侧不产生 Some(0)）。
pub open spec fn enc(o: Option<u32>) -> u32 {
    match o { Some(x) => x, None => 0 }
}
pub open spec fn dec(v: u32) -> Option<u32> {
    if v == 0 { None } else { Some(v) }
}
proof fn override_round_trip(o: Option<u32>)
    requires o != Some(0u32),
    ensures dec(enc(o)) == o,
{
}

fn main() {}

} // verus!
