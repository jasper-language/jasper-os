//! 清单（manifest，SPEC §11）：模块的身份、版本、调用约定、装载阶段、生命周期、依赖、所需能力与宿主接口。
//! The module manifest.
//!
//! # 文本格式
//! UTF-8，每行一项 `键 = 值`（键与值去掉两端空白）；空行与以 `#` 开头的行忽略。
//!
//! | 键 | 必需 | 单值 | 取值 |
//! |---|---|---|---|
//! | `core.name` | 是 | 是 | 模块名：小写字母、数字、`.`、`_`、`-`，1–64 字节 |
//! | `core.version` | 是 | 是 | `主.次.修订`，各为 1–9 位十进制数 |
//! | `core.abi` | 是 | 是 | 调用约定，`[a-z0-9._]` 1–16 字节，如 `c.v1`；须与平台记录的 `abi` 一致 |
//! | `core.stage` | 是 | 是 | `build` / `boot` / `runtime`，须与头部 `stage` 一致 |
//! | `core.lifecycle` | 否 | 是 | `plugin`（缺省）或 `system` |
//! | `core.runtime` | 否 | 是 | 宿主运行时版本须满足的区间，如 `>=0.1,<0.2` |
//! | `core.depends` | 否 | 否 | 依赖：`名字` 或 `名字@区间`，逗号分隔；以 `<` `>` `=` 开头的片段续接前一项的区间 |
//! | `core.host` | 否 | 是 | 需要的宿主接口表，`[a-z0-9._]` 1–32 字节，如 `jaso.host.v1` |
//! | `core.requires` | 否 | 否 | 所需能力（逗号分隔）；能力名 `[a-z0-9._]` 1–64 字节，合计 ≤ 32 |
//! | `core.exports` | 否 | 否 | 导出名（逗号分隔）；合计 ≤ 256；导出表必须与它一一对应 |
//! | `core.description` | 否 | 是 | 说明文字 |
//! | `core.publisher` | 否 | 是 | 发布者名（`[a-z0-9._-]` 1–64 字节）；签名模块必须声明 |
//!
//! **核心段通用、扩展各占命名空间**：`core.` 之外的键必须形如 `<命名空间>.<键>`（如 `web.route`），
//! 本解析器保留它们供各自的框架读取，自己不解释；`core.` 下出现未知键则拒绝（核心字段只随格式版本增加）。
//! 清单里的能力是**请求**，不是授权：装载器把它与调用者实际授予的能力比对，缺一项就拒绝装载。
//!
//! 错误按行的先后报告第一处；各行都合法后，按 `core.name`、`core.version`、`core.abi`、`core.stage` 的顺序检查缺失。

use crate::code::ErrorCode;
use crate::Stage;

/// 清单错误（行号从 1 起）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestError {
    /// 不是 UTF-8。
    NotUtf8,
    /// 某行不是 `键 = 值`。
    BadLine(u32),
    /// 键不合法（不在 `core.` 已知键中，或扩展键缺命名空间）。
    BadKey(u32),
    /// 必需键缺失。
    Missing(&'static str),
    /// 同一个单值键出现多次，或依赖名重复。
    Duplicate(u32),
    /// 取值不合法。
    BadValue(u32),
    /// 个数超限（能力、导出名或依赖）。
    Limit(u32),
}

impl ManifestError {
    /// 稳定错误码。
    pub const fn code(self) -> ErrorCode {
        match self {
            ManifestError::NotUtf8 => ErrorCode::ManifestUtf8,
            ManifestError::BadLine(_) => ErrorCode::ManifestLine,
            ManifestError::BadKey(_) => ErrorCode::ManifestKey,
            ManifestError::Missing(_) => ErrorCode::ManifestMissing,
            ManifestError::Duplicate(_) => ErrorCode::ManifestDuplicate,
            ManifestError::BadValue(_) => ErrorCode::ManifestValue,
            ManifestError::Limit(_) => ErrorCode::ManifestLimit,
        }
    }
}

/// 单个清单的能力数上限。
pub const MAX_REQUIRES: usize = 32;
/// 单个清单的导出名数上限。
pub const MAX_EXPORT_NAMES: usize = 256;
/// 单个清单的依赖数上限。
pub const MAX_DEPENDS: usize = 32;
/// 一个版本区间的比较式个数上限。
pub const MAX_COMPARATORS: usize = 4;

/// 导出名：字母、数字、`_`、`.`、`$`，1–128 字节（与导出表的要求一致）。
pub(crate) fn symbol_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'.' || c == b'$')
}

/// 模块的生命周期类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifecycle {
    /// 插件：可停止；beta 中卸载请求返回「推迟」。
    Plugin,
    /// 系统模块：拒绝卸载。
    System,
}

/// 版本区间中的比较运算符。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// `>=`
    Ge,
    /// `>`
    Gt,
    /// `<=`
    Le,
    /// `<`
    Lt,
    /// `=`
    Eq,
}

/// 版本区间：1–[`MAX_COMPARATORS`] 个比较式，全部满足才算满足。
/// A version range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionRange {
    items: [(Op, (u32, u32, u32)); MAX_COMPARATORS],
    len: u8,
}

fn number(p: &str) -> Option<u32> {
    if p.is_empty() || p.len() > 9 || !p.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    p.parse().ok()
}

fn version_of(s: &str) -> Option<(u32, u32, u32)> {
    let mut it = s.split('.');
    let v = (number(it.next()?)?, number(it.next()?)?, number(it.next()?)?);
    if it.next().is_some() {
        return None;
    }
    Some(v)
}

/// 区间里的版本：`主.次[.修订]`（缺修订按 0）。
fn short_version_of(s: &str) -> Option<(u32, u32, u32)> {
    let mut it = s.split('.');
    let (a, b) = (number(it.next()?)?, number(it.next()?)?);
    let c = match it.next() {
        Some(p) => number(p)?,
        None => 0,
    };
    if it.next().is_some() {
        return None;
    }
    Some((a, b, c))
}

impl VersionRange {
    /// 解析 `>=0.1,<0.2` 之类的区间；不合法返回 `None`。
    pub fn parse(s: &str) -> Option<VersionRange> {
        let mut r = VersionRange { items: [(Op::Eq, (0, 0, 0)); MAX_COMPARATORS], len: 0 };
        for c in s.split(',').map(str::trim) {
            let (op, rest) = if let Some(v) = c.strip_prefix(">=") {
                (Op::Ge, v)
            } else if let Some(v) = c.strip_prefix("<=") {
                (Op::Le, v)
            } else if let Some(v) = c.strip_prefix('>') {
                (Op::Gt, v)
            } else if let Some(v) = c.strip_prefix('<') {
                (Op::Lt, v)
            } else if let Some(v) = c.strip_prefix('=') {
                (Op::Eq, v)
            } else {
                return None;
            };
            if r.len as usize == MAX_COMPARATORS {
                return None;
            }
            r.items[r.len as usize] = (op, short_version_of(rest)?);
            r.len += 1;
        }
        Some(r)
    }

    /// 比较式。
    pub fn comparators(&self) -> &[(Op, (u32, u32, u32))] {
        &self.items[..self.len as usize]
    }

    /// 版本 `v` 是否满足全部比较式。
    pub fn contains(&self, v: (u32, u32, u32)) -> bool {
        self.comparators().iter().all(|&(op, w)| match op {
            Op::Ge => v >= w,
            Op::Gt => v > w,
            Op::Le => v <= w,
            Op::Lt => v < w,
            Op::Eq => v == w,
        })
    }
}

/// 一项依赖。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dependency<'a> {
    /// 依赖的模块名。
    pub name: &'a str,
    /// 版本区间（不写表示任意版本）。
    pub range: Option<VersionRange>,
}

/// 从一行 `core.depends` 的值中取出第一项的原文：以 `<` `>` `=` 开头的片段续接前一项的区间。
/// 返回 `(本项原文, 逗号之后的余下部分)`；已到末尾时余下部分为 `None`。
fn split_dependency(s: &str) -> (&str, Option<&str>) {
    let mut end = s.find(',').unwrap_or(s.len());
    while end < s.len() && s[end + 1..].trim_start().starts_with(['<', '>', '=']) {
        end += 1 + s[end + 1..].find(',').unwrap_or(s.len() - end - 1);
    }
    if end < s.len() {
        (&s[..end], Some(&s[end + 1..]))
    } else {
        (s, None)
    }
}

fn dependency_of(raw: &str) -> Option<Dependency<'_>> {
    let raw = raw.trim();
    let (name, range) = match raw.split_once('@') {
        Some((n, r)) => (n.trim(), Some(VersionRange::parse(r)?)),
        None => (raw, None),
    };
    if !name_ok(name, b"._-", 64) {
        return None;
    }
    Some(Dependency { name, range })
}

/// 一行 `core.depends` 值中的全部依赖项（不合法的项为 `None`，含末尾逗号留下的空项）。
fn dependencies(v: &str) -> impl Iterator<Item = Option<Dependency<'_>>> {
    let mut rest = Some(v);
    core::iter::from_fn(move || {
        let (item, tail) = split_dependency(rest?);
        rest = tail;
        Some(dependency_of(item))
    })
}

/// 校验通过的清单（借用清单文本）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Manifest<'a> {
    text: &'a str,
    /// 模块名。
    pub name: &'a str,
    /// 版本（主、次、修订）。
    pub version: (u32, u32, u32),
    /// 调用约定。
    pub abi: &'a str,
    /// 装载阶段。
    pub stage: Stage,
    /// 生命周期类别。
    pub lifecycle: Lifecycle,
    /// 宿主运行时版本区间。
    pub runtime: Option<VersionRange>,
    /// 需要的宿主接口表。
    pub host: Option<&'a str>,
    /// 说明。
    pub description: Option<&'a str>,
    /// 发布者名（签名模块必须声明）。
    /// Declared publisher name.
    pub publisher: Option<&'a str>,
}

fn name_ok(s: &str, extra: &[u8], max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || extra.contains(&c))
}

/// 逐行拆出 (行号, 键, 值)；空行与注释跳过。
fn entries(text: &str) -> impl Iterator<Item = (u32, Option<(&str, &str)>)> {
    text.lines().enumerate().filter_map(|(i, l)| {
        let l = l.trim();
        if l.is_empty() || l.starts_with('#') {
            return None;
        }
        let n = i as u32 + 1;
        Some((n, l.split_once('=').map(|(k, v)| (k.trim(), v.trim()))))
    })
}

fn values<'a>(text: &'a str, key: &'a str) -> impl Iterator<Item = &'a str> {
    entries(text).filter_map(|(_, kv)| kv).filter(move |(k, _)| *k == key).map(|(_, v)| v)
}

impl<'a> Manifest<'a> {
    /// 空清单（只作解析前的占位，不是合法清单）。
    pub const fn empty() -> Manifest<'static> {
        Manifest {
            text: "",
            name: "",
            version: (0, 0, 0),
            abi: "",
            stage: Stage::Runtime,
            lifecycle: Lifecycle::Plugin,
            runtime: None,
            host: None,
            description: None,
            publisher: None,
        }
    }

    /// 解析并校验。
    pub fn parse(text: &'a str) -> Result<Manifest<'a>, ManifestError> {
        let (mut name, mut abi, mut host, mut description, mut publisher) = (None, None, None, None, None);
        let (mut version, mut stage, mut lifecycle, mut runtime) = (None, None, None, None);
        let (mut requires, mut exports, mut depends) = (0usize, 0usize, 0usize);
        for (n, kv) in entries(text) {
            let (k, v) = kv.ok_or(ManifestError::BadLine(n))?;
            let once = |seen: bool| if seen { Err(ManifestError::Duplicate(n)) } else { Ok(()) };
            let bad = ManifestError::BadValue(n);
            match k {
                "core.name" => {
                    once(name.is_some())?;
                    name = Some(v).filter(|v| name_ok(v, b"._-", 64));
                    name.ok_or(bad)?;
                }
                "core.version" => {
                    once(version.is_some())?;
                    version = Some(version_of(v).ok_or(bad)?);
                }
                "core.abi" => {
                    once(abi.is_some())?;
                    abi = Some(v).filter(|v| crate::platform::abi_ok(v));
                    abi.ok_or(bad)?;
                }
                "core.stage" => {
                    once(stage.is_some())?;
                    stage = Some(Stage::from_name(v).ok_or(bad)?);
                }
                "core.lifecycle" => {
                    once(lifecycle.is_some())?;
                    lifecycle = Some(match v {
                        "plugin" => Lifecycle::Plugin,
                        "system" => Lifecycle::System,
                        _ => return Err(bad),
                    });
                }
                "core.runtime" => {
                    once(runtime.is_some())?;
                    runtime = Some(VersionRange::parse(v).ok_or(bad)?);
                }
                "core.host" => {
                    once(host.is_some())?;
                    host = Some(v).filter(|v| name_ok(v, b"._", 32));
                    host.ok_or(bad)?;
                }
                "core.description" => {
                    once(description.is_some())?;
                    description = Some(v);
                }
                "core.publisher" => {
                    once(publisher.is_some())?;
                    publisher = Some(v).filter(|v| name_ok(v, b"._-", 64));
                    publisher.ok_or(bad)?;
                }
                "core.depends" => {
                    for (i, d) in dependencies(v).enumerate() {
                        let d = d.ok_or(bad)?;
                        // 与此前各行及本行此前各项都不得重名。只查前 MAX_DEPENDS 项（SPEC §12.1）：超出上限的项已注定
                        // 报 manifest.limit，再查会让验签前的未验证清单按项数平方耗时；这些项仍要校验取值。
                        if depends < MAX_DEPENDS {
                            let earlier = entries(text)
                                .take_while(|(m, _)| *m < n)
                                .filter_map(|(_, kv)| kv)
                                .filter(|(k, _)| *k == "core.depends")
                                .flat_map(|(_, v)| dependencies(v))
                                .chain(dependencies(v).take(i));
                            if earlier.flatten().any(|e| e.name == d.name) {
                                return Err(ManifestError::Duplicate(n));
                            }
                        }
                        depends += 1;
                    }
                    if depends > MAX_DEPENDS {
                        return Err(ManifestError::Limit(n));
                    }
                }
                "core.requires" => {
                    for cap in v.split(',').map(str::trim) {
                        if !name_ok(cap, b"._", 64) {
                            return Err(bad);
                        }
                        requires += 1;
                    }
                    if requires > MAX_REQUIRES {
                        return Err(ManifestError::Limit(n));
                    }
                }
                "core.exports" => {
                    for sym in v.split(',').map(str::trim) {
                        if !symbol_ok(sym) {
                            return Err(bad);
                        }
                        exports += 1;
                    }
                    if exports > MAX_EXPORT_NAMES {
                        return Err(ManifestError::Limit(n));
                    }
                }
                k if k.starts_with("core.") => return Err(ManifestError::BadKey(n)),
                k => {
                    // 扩展键：<命名空间>.<键>，各段非空
                    let ok = k.split_once('.').is_some_and(|(ns, rest)| name_ok(ns, b"_-", 32) && name_ok(rest, b"._-", 64));
                    if !ok {
                        return Err(ManifestError::BadKey(n));
                    }
                }
            }
        }
        Ok(Manifest {
            text,
            name: name.ok_or(ManifestError::Missing("core.name"))?,
            version: version.ok_or(ManifestError::Missing("core.version"))?,
            abi: abi.ok_or(ManifestError::Missing("core.abi"))?,
            stage: stage.ok_or(ManifestError::Missing("core.stage"))?,
            lifecycle: lifecycle.unwrap_or(Lifecycle::Plugin),
            runtime,
            host,
            description,
            publisher,
        })
    }

    /// 所需能力（按出现顺序）。
    pub fn requires(&self) -> impl Iterator<Item = &'a str> {
        values(self.text, "core.requires").flat_map(|v| v.split(',').map(str::trim))
    }

    /// 声明的导出名（按出现顺序）。
    pub fn exports(&self) -> impl Iterator<Item = &'a str> {
        values(self.text, "core.exports").flat_map(|v| v.split(',').map(str::trim))
    }

    /// 依赖（按出现顺序；解析时已校验，这里不会遇到不合法的项）。
    pub fn depends(&self) -> impl Iterator<Item = Dependency<'a>> {
        values(self.text, "core.depends").flat_map(dependencies).flatten()
    }

    /// 扩展键的取值（`key` 须带命名空间，如 `web.route`）；`core.` 键请用对应字段。
    pub fn extension(&self, key: &str) -> Option<&'a str> {
        if key.starts_with("core.") {
            return None;
        }
        entries(self.text).filter_map(|(_, kv)| kv).find(|(k, _)| *k == key).map(|(_, v)| v)
    }

    /// 清单原文。
    pub fn text(&self) -> &'a str {
        self.text
    }
}
