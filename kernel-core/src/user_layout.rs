//! 各指令集的用户私有窗口起点与用户程序的固定装载地址：内核、用户态运行时与用户程序的构建脚本共用这一份。
//! Per-ISA start of the private user window and the fixed load address of user programs, shared by
//! the kernel, the user runtime and the user programs' build scripts.
//!
//! # 为什么放在这里
//! 私有窗口的位置由各指令集的页表形状决定（内核的 arch 层各自定义并在编译期断言与这里一致），
//! 而用户程序是固定地址的静态可执行文件：链接地址必须落在该指令集的窗口内。把数值集中在一处，
//! 避免链接脚本、运行时布局与内核三处各写一遍而悄悄失配。
//!
//! # 用法
//! 用户程序的构建脚本以 `CARGO_CFG_TARGET_ARCH` 调用 [`image_base`]，经链接器参数
//! `--defsym=JSR_IMAGE_BASE=<地址>` 交给链接脚本（`. = JSR_IMAGE_BASE;`）。
//!
//! # 边界
//! 只有数值与按指令集名查找；不涉及页表、映射或任何装载逻辑。

/// x86_64 私有窗口起点（4 级页表顶级表项 32 起）。
/// Start of the x86_64 private window.
pub const WINDOW_BASE_X86_64: u64 = 32 << 39;
/// AArch64 私有窗口起点（TTBR0 顶级表项 32 起，与 x86_64 相同）。
/// Start of the AArch64 private window.
pub const WINDOW_BASE_AARCH64: u64 = 32 << 39;
/// RISC-V64（Sv39）私有窗口起点（顶级表项 32 起，每项 1 GiB）。
/// Start of the RISC-V64 (Sv39) private window.
pub const WINDOW_BASE_RISCV64: u64 = 32 << 30;
/// RISC-V32（Sv32）私有窗口起点（顶级表项 1 起，每项 4 MiB；窗口止于 `0x4000_0000`）。
/// Start of the RISC-V32 (Sv32) private window.
pub const WINDOW_BASE_RISCV32: u64 = 1 << 22;
/// RISC-V32（Sv32）私有窗口终点（不含）：顶级表项 256，其上为内核的线性映射。
/// End (exclusive) of the RISC-V32 private window.
pub const WINDOW_END_RISCV32: u64 = 256 << 22;
/// 各指令集中最小的私有窗口长度（Sv32：255 个 4 MiB 顶级表项 = 1020 MiB）；用户态运行时的布局必须整体落在其中。
/// The smallest private-window size over all ISAs; the runtime layout must fit inside it.
pub const MIN_WINDOW_SIZE: u64 = WINDOW_END_RISCV32 - WINDOW_BASE_RISCV32;
/// 用户程序的装载地址相对窗口起点的偏移（4 MiB：窗口最低处留空，空指针附近的访问一律缺页）。
/// Offset of the user-program load address from the window start.
pub const IMAGE_OFFSET: u64 = 0x40_0000;

/// 按 cargo 的指令集名（`CARGO_CFG_TARGET_ARCH` 的取值）查私有窗口起点；不支持的指令集返回 `None`。
/// Looks up the private-window start by cargo target-arch name.
pub fn window_base(target_arch: &str) -> Option<u64> {
    match target_arch {
        "x86_64" => Some(WINDOW_BASE_X86_64),
        "aarch64" => Some(WINDOW_BASE_AARCH64),
        "riscv64" => Some(WINDOW_BASE_RISCV64),
        "riscv32" => Some(WINDOW_BASE_RISCV32),
        _ => None,
    }
}

/// 按指令集名查用户程序的固定装载地址（窗口起点 + [`IMAGE_OFFSET`]）；不支持的指令集返回 `None`。
/// Looks up the fixed user-program load address by cargo target-arch name.
pub fn image_base(target_arch: &str) -> Option<u64> {
    window_base(target_arch).map(|w| w + IMAGE_OFFSET)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_base_per_arch_and_rejects_unknown() {
        assert_eq!(image_base("x86_64"), Some(0x1000_0040_0000));
        assert_eq!(image_base("aarch64"), Some(0x1000_0040_0000));
        assert_eq!(image_base("riscv64"), Some(0x8_0040_0000));
        assert_eq!(image_base("riscv32"), Some(0x0080_0000));
        assert_eq!(image_base("mips"), None);
        assert_eq!(window_base(""), None);
        assert_eq!(window_base("RISCV32"), None);
    }

    #[test]
    fn every_window_holds_at_least_the_minimum_size() {
        // 64 位指令集：窗口终点 = 顶级表项 64；Sv32：顶级表项 256。最小窗口（Sv32）恰为 MIN_WINDOW_SIZE
        let windows = [
            (WINDOW_BASE_X86_64, 64u64 << 39),
            (WINDOW_BASE_AARCH64, 64 << 39),
            (WINDOW_BASE_RISCV64, 64 << 30),
            (WINDOW_BASE_RISCV32, WINDOW_END_RISCV32),
        ];
        for (base, end) in windows {
            let size = end - base;
            assert!(size >= MIN_WINDOW_SIZE);
            assert!(IMAGE_OFFSET < size);
        }
        assert_eq!(windows.iter().map(|(b, e)| e - b).min(), Some(MIN_WINDOW_SIZE));
    }
}
