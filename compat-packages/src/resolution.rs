//! Deterministic dependency planning for compatibility components.
//! 兼容组件的确定性依赖规划。
//!
//! This module plans a complete selection before the caller stages any bytes.
//! It does not grant launch authority and does not replace signature, digest,
//! archive, transaction, or lifecycle checks.
//! 本模块只规划选择，不授予运行权限，也不替代签名、摘要、归档、事务或生命周期检查。

use std::collections::{BTreeMap, BTreeSet};

use semver::{Version, VersionReq};

use crate::{ComponentManifest, DependencyRequirement};

/// Runtime facts against which candidates are resolved.
/// 候选组件解析所依据的运行环境事实。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolutionPlatform {
    /// Target architecture, for example `x86_64`.
    /// 目标架构，例如 `x86_64`。
    pub architecture: String,
    /// Runtime identity, for example `jasper-linux`.
    /// 运行时身份，例如 `jasper-linux`。
    pub runtime: String,
    /// Runtime ABI version.
    /// 运行时 ABI 版本。
    pub abi: Version,
    /// Features and named capabilities exposed by the admitted runtime.
    /// 已准入运行时公开的特性与具名能力。
    pub capabilities: BTreeSet<String>,
}

/// One selected component version.
/// 一个已选择的组件版本。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectedComponent {
    /// Stable component name.
    /// 稳定组件名。
    pub name: String,
    /// Selected semantic or lexical version.
    /// 选定的语义或词法版本。
    pub version: String,
}

/// A complete dependency-first installation plan.
/// 依赖优先的完整安装计划。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolutionPlan {
    /// Dependencies in deterministic installation order, root last.
    /// 确定性安装顺序；依赖在前，根组件在最后。
    pub order: Vec<SelectedComponent>,
}

/// Why a catalog cannot satisfy a requested component.
/// 目录无法满足请求组件的原因。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolutionError {
    /// No candidate has the requested package name.
    /// 没有请求名称的候选。
    Missing {
        /// Required component name.
        /// 所需组件名。
        package: String,
    },
    /// Candidates exist, but none satisfy all active constraints.
    /// 有候选，但没有版本满足全部活动约束。
    Unsatisfied {
        /// Required component name.
        /// 所需组件名。
        package: String,
        /// Constraints that must hold simultaneously.
        /// 必须同时成立的约束。
        requirements: Vec<String>,
    },
    /// A candidate targets a different architecture, runtime, ABI, or capability set.
    /// 候选目标架构、运行时、ABI 或能力集不匹配。
    Platform {
        /// Candidate component name.
        /// 候选组件名。
        package: String,
        /// Candidate version.
        /// 候选版本。
        version: String,
        /// Human-readable mismatch reason.
        /// 可读的不匹配原因。
        reason: String,
    },
    /// Two selected candidates declare incompatible versions.
    /// 两个已选候选声明了不兼容版本。
    Conflict {
        /// First component.
        /// 第一个组件。
        package: String,
        /// Conflicting component.
        /// 冲突组件。
        conflicting: String,
        /// Declared conflict constraint.
        /// 声明的冲突约束。
        requirement: String,
    },
    /// The selected graph contains a cycle.
    /// 已选依赖图包含环。
    Cycle {
        /// Cycle order with the first component repeated at the end.
        /// 环顺序，末尾重复首组件。
        chain: Vec<String>,
    },
}

impl std::fmt::Display for ResolutionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing { package } => write!(formatter, "missing component {package}"),
            Self::Unsatisfied {
                package,
                requirements,
            } => write!(
                formatter,
                "no version of {package} satisfies {}",
                requirements.join(", ")
            ),
            Self::Platform {
                package,
                version,
                reason,
            } => write!(
                formatter,
                "component {package} {version} is incompatible: {reason}"
            ),
            Self::Conflict {
                package,
                conflicting,
                requirement,
            } => write!(
                formatter,
                "component {package} conflicts with {conflicting} {requirement}"
            ),
            Self::Cycle { chain } => write!(formatter, "dependency cycle: {}", chain.join(" -> ")),
        }
    }
}

impl std::error::Error for ResolutionError {}

/// Resolve a root component and its complete dependency closure.
/// 解析根组件及其完整依赖闭包。
pub fn resolve(
    root: &ComponentManifest,
    catalog: &[ComponentManifest],
    platform: &ResolutionPlatform,
) -> Result<ResolutionPlan, ResolutionError> {
    check_platform(root, platform)?;
    let mut by_name = BTreeMap::<String, Vec<ComponentManifest>>::new();
    for candidate in catalog.iter().cloned() {
        by_name
            .entry(candidate.name.clone())
            .or_default()
            .push(candidate);
    }
    for candidates in by_name.values_mut() {
        candidates.sort_by(|left, right| {
            version_key(&right.version)
                .cmp(&version_key(&left.version))
                .then_with(|| right.archive_sha256.cmp(&left.archive_sha256))
                .then_with(|| right.name.cmp(&left.name))
        });
    }

    let mut selected = BTreeMap::<String, ComponentManifest>::new();
    selected.insert(root.name.clone(), root.clone());
    let mut requirements = root
        .requires
        .iter()
        .cloned()
        .map(|requirement| (root.name.clone(), requirement))
        .collect::<Vec<_>>();

    search(&mut by_name, platform, &mut selected, &mut requirements)?;
    let order = dependency_order(&selected)?;
    Ok(ResolutionPlan {
        order: order
            .into_iter()
            .map(|name| {
                let candidate = &selected[&name];
                SelectedComponent {
                    name,
                    version: candidate.version.clone(),
                }
            })
            .collect(),
    })
}

fn search(
    by_name: &mut BTreeMap<String, Vec<ComponentManifest>>,
    platform: &ResolutionPlatform,
    selected: &mut BTreeMap<String, ComponentManifest>,
    requirements: &mut Vec<(String, DependencyRequirement)>,
) -> Result<(), ResolutionError> {
    let Some(index) = requirements
        .iter()
        .position(|(_, requirement)| !selected.contains_key(&requirement.name))
    else {
        for (_, requirement) in requirements.iter() {
            let candidate = selected
                .get(&requirement.name)
                .expect("all requirements are selected");
            if !requirement.matches(&candidate.version) {
                return Err(ResolutionError::Unsatisfied {
                    package: requirement.name.clone(),
                    requirements: vec![format!(
                        "{} does not satisfy {}",
                        candidate.version, requirement.version
                    )],
                });
            }
        }
        return dependency_order(selected).map(|_| ());
    };
    let (source, requirement) = requirements[index].clone();
    let active_constraints = requirements
        .iter()
        .filter(|(_, active)| active.name == requirement.name)
        .map(|(_, active)| active.clone())
        .collect::<Vec<_>>();
    let Some(candidates) = by_name.get(&requirement.name) else {
        return Err(ResolutionError::Missing {
            package: requirement.name,
        });
    };
    let candidate_versions = candidates.clone();
    let mut last_failure = None;
    for candidate in candidate_versions {
        if !active_constraints
            .iter()
            .all(|required| required.matches(&candidate.version))
        {
            continue;
        }
        if let Err(error) = check_platform(&candidate, platform) {
            last_failure = Some(error);
            continue;
        }
        if let Some(conflict) = conflicts_with_selected(&candidate, selected) {
            last_failure = Some(conflict);
            continue;
        }

        selected.insert(candidate.name.clone(), candidate.clone());
        let old_len = requirements.len();
        requirements.extend(
            candidate
                .requires
                .iter()
                .cloned()
                .map(|required| (candidate.name.clone(), required)),
        );
        match search(by_name, platform, selected, requirements) {
            Ok(()) => return Ok(()),
            Err(error) => {
                last_failure = Some(error);
                requirements.truncate(old_len);
                selected.remove(&candidate.name);
            }
        }
    }
    if let Some(error) = last_failure {
        return Err(error);
    }
    let mut rendered = active_constraints
        .into_iter()
        .map(|required| format!("{}@{}", source, required.version))
        .collect::<Vec<_>>();
    rendered.sort();
    Err(ResolutionError::Unsatisfied {
        package: requirement.name,
        requirements: rendered,
    })
}

fn check_platform(
    candidate: &ComponentManifest,
    platform: &ResolutionPlatform,
) -> Result<(), ResolutionError> {
    let incompatible = |reason: String| ResolutionError::Platform {
        package: candidate.name.clone(),
        version: candidate.version.clone(),
        reason,
    };
    if candidate.arch != platform.architecture {
        return Err(incompatible(format!(
            "architecture {} does not match {}",
            candidate.arch, platform.architecture
        )));
    }
    if candidate
        .runtime
        .as_deref()
        .is_some_and(|runtime| runtime != platform.runtime)
    {
        return Err(incompatible(format!(
            "runtime {} does not match {}",
            candidate.runtime.as_deref().unwrap_or_default(),
            platform.runtime
        )));
    }
    if let Some(abi) = candidate.abi.as_deref() {
        let requirement = VersionReq::parse(abi)
            .map_err(|error| incompatible(format!("invalid ABI requirement {abi}: {error}")))?;
        if !requirement.matches(&platform.abi) {
            return Err(incompatible(format!(
                "ABI requirement {abi} does not match {}",
                platform.abi
            )));
        }
    }
    if let Some(missing) = candidate
        .capabilities
        .iter()
        .find(|capability| !platform.capabilities.contains(capability.as_str()))
    {
        return Err(incompatible(format!("missing capability {missing}")));
    }
    Ok(())
}

fn conflicts_with_selected(
    candidate: &ComponentManifest,
    selected: &BTreeMap<String, ComponentManifest>,
) -> Option<ResolutionError> {
    for conflict in &candidate.conflicts {
        if selected
            .get(&conflict.name)
            .is_some_and(|other| conflict.matches(&other.version))
        {
            return Some(ResolutionError::Conflict {
                package: candidate.name.clone(),
                conflicting: conflict.name.clone(),
                requirement: conflict.version.clone(),
            });
        }
    }
    for other in selected.values() {
        if let Some(conflict) = other.conflicts.iter().find(|conflict| {
            conflict.name == candidate.name && conflict.matches(&candidate.version)
        }) {
            return Some(ResolutionError::Conflict {
                package: other.name.clone(),
                conflicting: candidate.name.clone(),
                requirement: conflict.version.clone(),
            });
        }
    }
    None
}

fn dependency_order(
    selected: &BTreeMap<String, ComponentManifest>,
) -> Result<Vec<String>, ResolutionError> {
    fn visit(
        name: &str,
        selected: &BTreeMap<String, ComponentManifest>,
        active: &mut Vec<String>,
        done: &mut BTreeSet<String>,
        order: &mut Vec<String>,
    ) -> Result<(), ResolutionError> {
        if done.contains(name) {
            return Ok(());
        }
        if let Some(index) = active.iter().position(|active_name| active_name == name) {
            let mut chain = active[index..].to_vec();
            chain.push(name.to_string());
            return Err(ResolutionError::Cycle { chain });
        }
        let Some(candidate) = selected.get(name) else {
            return Ok(());
        };
        active.push(name.to_string());
        let mut dependencies = candidate
            .requires
            .iter()
            .filter(|required| selected.contains_key(&required.name))
            .map(|required| required.name.clone())
            .collect::<Vec<_>>();
        dependencies.sort();
        for dependency in dependencies {
            visit(&dependency, selected, active, done, order)?;
        }
        active.pop();
        done.insert(name.to_string());
        order.push(name.to_string());
        Ok(())
    }

    let mut active = Vec::new();
    let mut done = BTreeSet::new();
    let mut order = Vec::new();
    for name in selected.keys() {
        visit(name, selected, &mut active, &mut done, &mut order)?;
    }
    Ok(order)
}

fn version_key(version: &str) -> (bool, Version, String) {
    match Version::parse(version) {
        Ok(parsed) => (true, parsed, String::new()),
        Err(_) => (false, Version::new(0, 0, 0), version.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(
        name: &str,
        version: &str,
        requires: &[(&str, &str)],
        conflicts: &[(&str, &str)],
    ) -> ComponentManifest {
        ComponentManifest {
            name: name.into(),
            version: version.into(),
            arch: "x86_64".into(),
            archive_sha256: "a".repeat(64),
            license: "MIT".into(),
            entrypoint: "bin/app".into(),
            requires: requires
                .iter()
                .map(|(name, version)| DependencyRequirement {
                    name: (*name).into(),
                    version: (*version).into(),
                })
                .collect(),
            runtime: Some("jasper-linux".into()),
            abi: Some(">=3.18,<4".into()),
            capabilities: vec!["gpu.vulkan".into()],
            conflicts: conflicts
                .iter()
                .map(|(name, version)| DependencyRequirement {
                    name: (*name).into(),
                    version: (*version).into(),
                })
                .collect(),
        }
    }

    fn platform() -> ResolutionPlatform {
        ResolutionPlatform {
            architecture: "x86_64".into(),
            runtime: "jasper-linux".into(),
            abi: Version::new(3, 21, 0),
            capabilities: ["gpu.vulkan".to_string()].into_iter().collect(),
        }
    }

    #[test]
    fn selects_highest_compatible_versions_with_dependencies_first() {
        let root = manifest("app", "1.0.0", &[("runtime", ">=2.0.0,<3.0.0")], &[]);
        let catalog = vec![
            manifest("runtime", "2.0.0", &[("base", ">=1.0.0,<2.0.0")], &[]),
            manifest("runtime", "2.5.0", &[("base", ">=1.5.0,<2.0.0")], &[]),
            manifest("base", "1.0.0", &[], &[]),
            manifest("base", "1.5.0", &[], &[]),
            manifest("base", "2.0.0", &[], &[]),
        ];
        let plan = resolve(&root, &catalog, &platform()).unwrap();
        assert_eq!(
            plan.order,
            vec![
                SelectedComponent {
                    name: "base".into(),
                    version: "1.5.0".into()
                },
                SelectedComponent {
                    name: "runtime".into(),
                    version: "2.5.0".into()
                },
                SelectedComponent {
                    name: "app".into(),
                    version: "1.0.0".into()
                }
            ]
        );
    }

    #[test]
    fn backtracks_when_newer_choice_conflicts() {
        let root = manifest(
            "app",
            "1.0.0",
            &[("runtime", ">=1.0.0,<3.0.0"), ("ui", ">=1.0.0,<2.0.0")],
            &[],
        );
        let catalog = vec![
            manifest("runtime", "1.0.0", &[], &[]),
            manifest("runtime", "2.0.0", &[], &[("ui", ">=1.0.0,<2.0.0")]),
            manifest("ui", "1.0.0", &[], &[]),
        ];
        let plan = resolve(&root, &catalog, &platform()).unwrap();
        assert_eq!(
            plan.order
                .iter()
                .map(|selected| (selected.name.as_str(), selected.version.as_str()))
                .collect::<Vec<_>>(),
            vec![("runtime", "1.0.0"), ("ui", "1.0.0"), ("app", "1.0.0")]
        );
    }

    #[test]
    fn backtracks_when_a_later_dependency_constrains_an_earlier_choice() {
        let root = manifest(
            "app",
            "1.0.0",
            &[("shared", ">=1.0.0,<3.0.0"), ("consumer", ">=1.0.0")],
            &[],
        );
        let catalog = vec![
            manifest("shared", "1.0.0", &[], &[]),
            manifest("shared", "2.0.0", &[], &[]),
            manifest("consumer", "1.0.0", &[("shared", ">=2.0.0")], &[]),
        ];
        let plan = resolve(&root, &catalog, &platform()).unwrap();
        assert_eq!(
            plan.order
                .iter()
                .map(|selected| (selected.name.as_str(), selected.version.as_str()))
                .collect::<Vec<_>>(),
            vec![("shared", "2.0.0"), ("consumer", "1.0.0"), ("app", "1.0.0")]
        );
    }

    #[test]
    fn rejects_platform_abi_capability_and_architecture_mismatches() {
        let mut candidate = manifest("app", "1.0.0", &[], &[]);
        candidate.arch = "aarch64".into();
        assert!(matches!(
            resolve(&candidate, &[], &platform()),
            Err(ResolutionError::Platform { .. })
        ));
        candidate.arch = "x86_64".into();
        candidate.runtime = Some("other-runtime".into());
        assert!(matches!(
            resolve(&candidate, &[], &platform()),
            Err(ResolutionError::Platform { .. })
        ));
        candidate.runtime = Some("jasper-linux".into());
        candidate.abi = Some(">=4.0".into());
        assert!(matches!(
            resolve(&candidate, &[], &platform()),
            Err(ResolutionError::Platform { .. })
        ));
        candidate.abi = Some(">=3.18,<4".into());
        candidate.capabilities.push("audio.output".into());
        assert!(matches!(
            resolve(&candidate, &[], &platform()),
            Err(ResolutionError::Platform { .. })
        ));
    }

    #[test]
    fn detects_cycles_instead_of_claiming_a_plan() {
        let root = manifest("a", "1.0.0", &[("b", ">=1.0.0")], &[]);
        let catalog = vec![manifest("b", "1.0.0", &[("a", ">=1.0.0")], &[])];
        assert_eq!(
            resolve(&root, &catalog, &platform()),
            Err(ResolutionError::Cycle {
                chain: vec!["a".into(), "b".into(), "a".into()]
            })
        );
    }

    #[test]
    fn missing_and_unsatisfied_requirements_are_distinct() {
        let root = manifest("app", "1.0.0", &[("missing", "")], &[]);
        assert_eq!(
            resolve(&root, &[], &platform()),
            Err(ResolutionError::Missing {
                package: "missing".into()
            })
        );
        let root = manifest("app", "1.0.0", &[("base", ">=2.0.0")], &[]);
        assert!(matches!(
            resolve(
                &root,
                &[manifest("base", "1.0.0", &[], &[])],
                &platform()
            ),
            Err(ResolutionError::Unsatisfied { package, .. }) if package == "base"
        ));
    }
}
