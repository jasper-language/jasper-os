//! 模块放置：进程内（可信）还是隔离进程（不可信）。
//! Module placement: in-process (trusted) or in an isolated process (untrusted).
//!
//! # 两类模块
//! * **进程内模块**：映射进宿主进程，与宿主共享全部权限（地址空间、句柄、系统调用）。只适合可信模块。
//! * **隔离模块**：在独立的子进程中运行，只持有宿主明确授予的系统调用与句柄；与宿主之间只经通道交换字节。
//!   模块崩溃只终止那个子进程。
//!
//! # 判定
//! 放置由 [`PlacementPolicy`]（策略，可替换）根据**来源**（[`Origin`]，由取得字节的一方声明）与
//! **验签结果**（[`Provenance`]）给出。无论用哪个策略，[`decide`] 都强制一条不可覆盖的规则：
//! **自动获取的模块（[`Origin::Acquired`]）只能隔离运行**。
//!
//! 为什么来源由调用方声明：字节从哪里来只有取得它的组件知道（模块自己的清单不可信）；
//! 自动获取模块的组件把它标为 `Acquired`，此后任何装载路径都不可能把它放进宿主进程。

use crate::trust::Provenance;

/// 模块字节的来源。
/// Where the module bytes came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// 本地提供：随系统或应用一起发布、由宿主自己的构建或安装流程放置。
    Local,
    /// 自动获取：由自动化组件（例如智能体）在运行时取得，未经人工安装。
    Acquired,
}

/// 放置结果。
/// Placement decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    /// 可以装入宿主进程。
    InProcess,
    /// 只能在隔离进程中运行。
    Isolated,
}

/// 放置策略（Strategy）：给出来源与验签结果下的放置。不可覆盖的规则由 [`decide`] 另行强制。
/// Placement strategy.
pub trait PlacementPolicy {
    /// 判定放置。
    /// Decides the placement.
    fn place(&self, origin: Origin, provenance: &Provenance<'_>) -> Placement;
}

/// 标准策略：本地来源且已通过信任策略（受信签名，或开发模式下经审计放行的未签名模块）⇒ 进程内；其余隔离。
/// The standard policy: local modules that passed the trust policy may run in-process.
#[derive(Debug, Clone, Copy, Default)]
pub struct Standard;

impl PlacementPolicy for Standard {
    fn place(&self, origin: Origin, _provenance: &Provenance<'_>) -> Placement {
        match origin {
            Origin::Local => Placement::InProcess,
            Origin::Acquired => Placement::Isolated,
        }
    }
}

/// 按发布者限定的策略：只有列出的发布者签名的本地模块可以进程内运行；未签名模块与其它发布者一律隔离。
/// Only modules signed by the listed publishers may run in-process.
#[derive(Debug, Clone, Copy)]
pub struct InProcessPublishers<'a> {
    /// 允许进程内运行的发布者名。
    pub publishers: &'a [&'a str],
}

impl PlacementPolicy for InProcessPublishers<'_> {
    fn place(&self, origin: Origin, provenance: &Provenance<'_>) -> Placement {
        match (origin, provenance) {
            (Origin::Local, Provenance::Signed { publisher }) if self.publishers.contains(publisher) => Placement::InProcess,
            _ => Placement::Isolated,
        }
    }
}

/// 所有策略都只能隔离运行（例如宿主自己完全不接受进程内扩展）。
/// Everything is isolated.
#[derive(Debug, Clone, Copy, Default)]
pub struct AlwaysIsolated;

impl PlacementPolicy for AlwaysIsolated {
    fn place(&self, _origin: Origin, _provenance: &Provenance<'_>) -> Placement {
        Placement::Isolated
    }
}

/// 最终判定：先强制「自动获取 ⇒ 隔离」，再交给策略。
/// Final decision: `Acquired` is always isolated, regardless of the policy.
pub fn decide(policy: &dyn PlacementPolicy, origin: Origin, provenance: &Provenance<'_>) -> Placement {
    if origin == Origin::Acquired {
        return Placement::Isolated;
    }
    policy.place(origin, provenance)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 一个（错误地）总是放进进程内的策略：用来证明不可覆盖的规则确实不可覆盖。
    struct Permissive;
    impl PlacementPolicy for Permissive {
        fn place(&self, _: Origin, _: &Provenance<'_>) -> Placement {
            Placement::InProcess
        }
    }

    const SIGNED: Provenance<'static> = Provenance::Signed { publisher: "jasper.dev" };
    const OTHER: Provenance<'static> = Provenance::Signed { publisher: "someone.else" };
    const UNSIGNED: Provenance<'static> = Provenance::UnsignedDevelopment;

    #[test]
    fn acquired_is_always_isolated() {
        let only_dev = InProcessPublishers { publishers: &["jasper.dev"] };
        let policies: [&dyn PlacementPolicy; 4] = [&Standard, &only_dev, &AlwaysIsolated, &Permissive];
        for p in policies {
            for prov in [SIGNED, OTHER, UNSIGNED] {
                assert_eq!(decide(p, Origin::Acquired, &prov), Placement::Isolated);
            }
        }
    }

    #[test]
    fn standard_policy_places_local_in_process() {
        for prov in [SIGNED, OTHER, UNSIGNED] {
            assert_eq!(decide(&Standard, Origin::Local, &prov), Placement::InProcess);
        }
    }

    #[test]
    fn publisher_policy_isolates_unlisted_and_unsigned() {
        let only_dev = InProcessPublishers { publishers: &["jasper.dev"] };
        assert_eq!(decide(&only_dev, Origin::Local, &SIGNED), Placement::InProcess);
        assert_eq!(decide(&only_dev, Origin::Local, &OTHER), Placement::Isolated);
        assert_eq!(decide(&only_dev, Origin::Local, &UNSIGNED), Placement::Isolated);
        let none = InProcessPublishers { publishers: &[] };
        assert_eq!(decide(&none, Origin::Local, &SIGNED), Placement::Isolated);
        assert_eq!(decide(&AlwaysIsolated, Origin::Local, &SIGNED), Placement::Isolated);
    }
}
