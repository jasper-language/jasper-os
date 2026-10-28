// 伴随模型（issue #6 第一片）：kernel_core::assembly::Assembly 的就绪集合闭包性，
// 以及既有 kernel_core::module::ModuleManager（补链）装载/卸载的同一闭包性。
// 模块集合以 u16 位图建模（MAX_MODULES = 16），deps[j] = 模块 j 依赖的提供者位图。
// 「闭包」= 每个就绪（已装载）模块的依赖都在就绪集合内——这正是「未启动却报告可用」不可能发生的条件：
// 发布掩码只取就绪模块的能力，闭包保证这些能力所依赖的服务也都可用。
// 本文件不直接验证 Rust 源码；生产实现与模型的一致性由 Proptest / fuzz 差分与 Kani 保证。
// Companion model only; production/model agreement is covered by the differential tests.
use vstd::prelude::*;

verus! {

pub open spec fn has(m: u16, i: u16) -> bool {
    m & (1u16 << i) != 0
}

pub open spec fn closed(ready: u16, deps: Seq<u16>) -> bool {
    deps.len() == 16 && forall|j: u16| j < 16 && #[trigger] has(ready, j) ==> deps[j as int] & !ready == 0
}

proof fn lemma_grow_keeps_subset(d: u16, r: u16, i: u16)
    requires i < 16, d & !r == 0,
    ensures d & !(r | (1u16 << i)) == 0,
{
    assert(d & !(r | (1u16 << i)) == 0) by (bit_vector)
        requires i < 16, d & !r == 0;
}

proof fn lemma_has_grow(r: u16, i: u16, j: u16)
    requires i < 16, j < 16,
    ensures has(r | (1u16 << i), j) == (has(r, j) || j == i),
{
    assert(((r | (1u16 << i)) & (1u16 << j) != 0) == ((r & (1u16 << j) != 0) || j == i)) by (bit_vector)
        requires i < 16, j < 16;
}

proof fn lemma_has_shrink(r: u16, i: u16, j: u16)
    requires i < 16, j < 16,
    ensures has(r & !(1u16 << i), j) == (has(r, j) && j != i),
{
    assert(((r & !(1u16 << i)) & (1u16 << j) != 0) == ((r & (1u16 << j) != 0) && j != i)) by (bit_vector)
        requires i < 16, j < 16;
}

proof fn lemma_shrink_keeps_subset(d: u16, r: u16, i: u16)
    requires i < 16, d & !r == 0, d & (1u16 << i) == 0,
    ensures d & !(r & !(1u16 << i)) == 0,
{
    assert(d & !(r & !(1u16 << i)) == 0) by (bit_vector)
        requires i < 16, d & !r == 0, d & (1u16 << i) == 0;
}

/// Assembly::start 的一步 / ModuleManager::load：依赖全部就绪且激活成功才加入就绪集合。
fn activate_step(ready: u16, Ghost(deps): Ghost<Seq<u16>>, di: u16, i: u16, ok: bool) -> (r: u16)
    requires i < 16, closed(ready, deps), deps[i as int] == di,
    ensures
        closed(r, deps),
        has(r, i) ==> di & !ready == 0,
        forall|j: u16| j < 16 && j != i ==> (#[trigger] has(r, j) == has(ready, j)),
{
    if di & !ready == 0 && ok {
        let r = ready | (1u16 << i);
        proof {
            assert forall|j: u16| j < 16 && #[trigger] has(r, j) implies deps[j as int] & !r == 0 by {
                lemma_has_grow(ready, i, j);
                lemma_grow_keeps_subset(deps[j as int], ready, i);
            }
            assert forall|j: u16| j < 16 && j != i implies (#[trigger] has(r, j) == has(ready, j)) by {
                lemma_has_grow(ready, i, j);
            }
        }
        r
    } else {
        proof {
            // i 已就绪时其依赖本就在 ready 中（闭包）。
            assert(has(ready, i) ==> deps[i as int] & !ready == 0);
        }
        ready
    }
}

/// Assembly::stop / ModuleManager::unload：只有没有就绪模块依赖 i 时才移除 i。
fn stop_step(ready: u16, Ghost(deps): Ghost<Seq<u16>>, i: u16) -> (r: u16)
    requires
        i < 16,
        closed(ready, deps),
        forall|j: u16| j < 16 && #[trigger] has(ready, j) ==> deps[j as int] & (1u16 << i) == 0,
    ensures closed(r, deps), has(r, i) == false,
{
    let r = ready & !(1u16 << i);
    proof {
        assert forall|j: u16| j < 16 && #[trigger] has(r, j) implies deps[j as int] & !r == 0 by {
            lemma_has_shrink(ready, i, j);
            lemma_shrink_keeps_subset(deps[j as int], ready, i);
        }
        lemma_has_shrink(ready, i, i);
    }
    r
}

/// 全有全无回滚 / ModuleManager::unload_all：清空后平凡闭包、什么都不发布。
fn rollback(Ghost(deps): Ghost<Seq<u16>>) -> (r: u16)
    requires deps.len() == 16,
    ensures closed(r, deps), forall|j: u16| j < 16 ==> #[trigger] has(r, j) == false,
{
    proof {
        assert forall|j: u16| j < 16 implies #[trigger] has(0u16, j) == false by {
            assert(0u16 & (1u16 << j) == 0) by (bit_vector);
        }
    }
    0
}

fn main() {}

} // verus!
