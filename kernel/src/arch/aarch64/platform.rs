//! AArch64 boot-platform adaptation for explicit verification platforms.
//!
//! 通用 AArch64 入口只使用启动协议传入的 DTB。只有显式编译的 Pixel 验收
//! Profile 才选择其固件表窗口；该选择集中在本适配模块，不散落在通用 MMU 路径。

/// Platform selected by the explicit verification build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootPlatform {
    GenericFdt,
    PixelVerification,
}

pub const fn active() -> BootPlatform {
    if cfg!(jasper_verification_platform) {
        BootPlatform::PixelVerification
    } else {
        BootPlatform::GenericFdt
    }
}

/// Normal-RAM base used while the first FDT windows are built.
pub const fn direct_boot_normal(dtb_hint: u64) -> Option<u64> {
    match active() {
        BootPlatform::GenericFdt => {
            if dtb_hint == 0 {
                None
            } else {
                Some(dtb_hint)
            }
        }
        BootPlatform::PixelVerification => {
            // JASPER-HARDCODE-REVIEW: issue=35 source=pixel-verification-platform reason=explicit-platform-adapter
            Some(0x4000_0000) // JASPER-HARDCODE-REVIEW: issue=35 source=pixel-verification-platform reason=explicit-pixel-uefi-table-window
        }
    }
}

/// Minimum linear-map span needed before the full FDT graph is parsed.
pub const fn minimum_linear_gib() -> u64 {
    match active() {
        BootPlatform::GenericFdt => 2,
        BootPlatform::PixelVerification => 4, // JASPER-HARDCODE-REVIEW: issue=35 source=pixel-verification-platform reason=explicit-platform-minimum-map
    }
}
