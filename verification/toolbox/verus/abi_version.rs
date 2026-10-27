//! Verus/Z3 规格：原生 ABI 世代的兼容性判定（issue #8）。
//! Verus/Z3 specification of the native ABI generation compatibility rule.
//!
//! 规格与 `kernel_core::abi_version::compatible` 一一对应：
//! 程序加载被接受，当且仅当「主版本相同」且「程序要求的最低次版本 ≤ 内核次版本」。
//! Patch 只记录、不参与功能门槛；跨主版本没有兼容义务。
//!
//! 注意：这是规格级模型，不证明 Rust 编译产物；代码级有界证明由本目录的 Kani
//! harness（`abi-fv` 特性）承担，畸形输入由 Proptest 与 cargo-fuzz 覆盖。

use vstd::prelude::*;

verus! {

/// 与生产实现相同的兼容性谓词（参数为 16 位无符号值的自然数抽象）。
spec fn compatible(
    program_major: nat,
    program_min_minor: nat,
    kernel_major: nat,
    kernel_minor: nat,
) -> bool {
    program_major == kernel_major && program_min_minor <= kernel_minor
}

/// 被接受 ⇒ 主版本相同。
proof fn accepted_implies_same_major(
    program_major: nat,
    program_min_minor: nat,
    kernel_major: nat,
    kernel_minor: nat,
)
    ensures
        compatible(program_major, program_min_minor, kernel_major, kernel_minor)
            ==> program_major == kernel_major,
{
}

/// 被接受 ⇒ 程序要求的最低次版本不高于内核次版本。
proof fn accepted_implies_minor_bound(
    program_major: nat,
    program_min_minor: nat,
    kernel_major: nat,
    kernel_minor: nat,
)
    ensures
        compatible(program_major, program_min_minor, kernel_major, kernel_minor)
            ==> program_min_minor <= kernel_minor,
{
}

/// 同主版本且次版本不高于内核 ⇒ 必须接受（不存在额外的隐藏门槛）。
proof fn same_major_within_minor_is_accepted(
    program_major: nat,
    program_min_minor: nat,
    kernel_major: nat,
    kernel_minor: nat,
)
    requires
        program_major == kernel_major,
        program_min_minor <= kernel_minor,
    ensures
        compatible(program_major, program_min_minor, kernel_major, kernel_minor),
{
}

/// 跨主版本 ⇒ 必须拒绝，且不按旧编号猜测语义。
proof fn major_mismatch_is_rejected(
    program_major: nat,
    program_min_minor: nat,
    kernel_major: nat,
    kernel_minor: nat,
)
    requires
        program_major != kernel_major,
    ensures
        !compatible(program_major, program_min_minor, kernel_major, kernel_minor),
{
}

/// 同主版本但程序要求更高的次版本 ⇒ 必须拒绝。
proof fn newer_minor_is_rejected(
    program_major: nat,
    program_min_minor: nat,
    kernel_major: nat,
    kernel_minor: nat,
)
    requires
        program_major == kernel_major,
        program_min_minor > kernel_minor,
    ensures
        !compatible(program_major, program_min_minor, kernel_major, kernel_minor),
{
}

/// 带 Patch 的完整谓词：Patch 被刻意排除在门槛之外。
spec fn compatible_with_patch(
    program_major: nat,
    program_min_minor: nat,
    program_patch: nat,
    kernel_major: nat,
    kernel_minor: nat,
    kernel_patch: nat,
) -> bool {
    program_major == kernel_major && program_min_minor <= kernel_minor
}

/// Patch 不参与门槛：任取两个 Patch，接受/拒绝结果与不带 Patch 的谓词相同。
proof fn patch_is_not_a_gate(
    program_major: nat,
    program_min_minor: nat,
    program_patch: nat,
    kernel_major: nat,
    kernel_minor: nat,
    kernel_patch: nat,
)
    ensures
        compatible_with_patch(
            program_major,
            program_min_minor,
            program_patch,
            kernel_major,
            kernel_minor,
            kernel_patch,
        ) == compatible(program_major, program_min_minor, kernel_major, kernel_minor),
{
}

fn main() {}
}
