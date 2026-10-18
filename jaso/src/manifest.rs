//! 清单（manifest）：模块的身份、版本、调用约定、所需能力与宿主接口。
//! The module manifest.
//!
//! # 文本格式
//! UTF-8，每行一项 `键 = 值`；空行与以 `#` 开头的行忽略。
//!
//! | 键 | 必需 | 取值 |
//! |---|---|---|
//! | `core.name` | 是 | 模块名：小写字母、数字、`.`、`_`、`-`，1–64 字节 |
//! | `core.version` | 是 | `主.次.修订`，各为十进制数 |
//! | `core.abi` | 是 | 导出函数的调用约定与版本，如 `c.v0` |
//! | `core.host` | 否 | 需要的宿主接口表，如 `jaso.host.v0` |
//! | `core.requires` | 否 | 所需能力（逗号分隔，可出现多行）；能力名：小写字母、数字、`.`、`_` |
//! | `core.description` | 否 | 说明文字 |
//!
//! **核心段通用、扩展各占命名空间**：`core.` 之外的键必须形如 `<命名空间>.<键>`（如 `web.route`），
//! 本解析器保留它们供各自的框架读取，自己不解释；`core.` 下出现未知键则拒绝（核心字段只随格式版本增加）。
//! 清单里的能力是**请求**，不是授权：装载器把它与调用者实际授予的能力比对，缺一项就拒绝装载。

/// 清单错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestError {
    /// 不是 UTF-8。
    NotUtf8,
    /// 某行不是 `键 = 值`（行号从 1 起）。
    BadLine(u32),
    /// 键不合法（不在 `core.` 已知键中，或扩展键缺命名空间）。
    BadKey(u32),
    /// 必需键缺失。
    Missing(&'static str),
    /// 同一个单值键出现多次。
    Duplicate(u32),
    /// 取值不合法。
    BadValue(u32),
    /// 能力数超限。
    TooManyRequires,
}

/// 单个清单的能力数上限。
pub const MAX_REQUIRES: usize = 32;

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
    /// 需要的宿主接口表。
    pub host: Option<&'a str>,
    /// 说明。
    pub description: Option<&'a str>,
}

fn name_ok(s: &str, extra: &[u8], max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || extra.contains(&c))
}

fn version_of(s: &str) -> Option<(u32, u32, u32)> {
    let mut it = s.split('.');
    let mut n = || -> Option<u32> {
        let p = it.next()?;
        if p.is_empty() || p.len() > 9 || !p.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        p.parse().ok()
    };
    let v = (n()?, n()?, n()?);
    if it.next().is_some() {
        return None;
    }
    Some(v)
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

impl<'a> Manifest<'a> {
    /// 空清单（只作解析前的占位，不是合法清单）。
    pub const fn empty() -> Manifest<'static> {
        Manifest { text: "", name: "", version: (0, 0, 0), abi: "", host: None, description: None }
    }

    /// 解析并校验。
    pub fn parse(text: &'a str) -> Result<Manifest<'a>, ManifestError> {
        let (mut name, mut version, mut abi, mut host, mut description) = (None, None, None, None, None);
        let mut requires = 0usize;
        for (n, kv) in entries(text) {
            let (k, v) = kv.ok_or(ManifestError::BadLine(n))?;
            let set = |slot: &mut Option<&'a str>| {
                if slot.is_some() {
                    return Err(ManifestError::Duplicate(n));
                }
                *slot = Some(v);
                Ok(())
            };
            match k {
                "core.name" => {
                    set(&mut name)?;
                    if !name_ok(v, b"._-", 64) {
                        return Err(ManifestError::BadValue(n));
                    }
                }
                "core.version" => {
                    if version.is_some() {
                        return Err(ManifestError::Duplicate(n));
                    }
                    version = Some(version_of(v).ok_or(ManifestError::BadValue(n))?);
                }
                "core.abi" => {
                    set(&mut abi)?;
                    if !name_ok(v, b"._", 32) {
                        return Err(ManifestError::BadValue(n));
                    }
                }
                "core.host" => {
                    set(&mut host)?;
                    if !name_ok(v, b"._", 32) {
                        return Err(ManifestError::BadValue(n));
                    }
                }
                "core.description" => set(&mut description)?,
                "core.requires" => {
                    for cap in v.split(',').map(str::trim) {
                        if !name_ok(cap, b"._", 64) {
                            return Err(ManifestError::BadValue(n));
                        }
                        requires += 1;
                    }
                    if requires > MAX_REQUIRES {
                        return Err(ManifestError::TooManyRequires);
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
            host,
            description,
        })
    }

    /// 所需能力（按出现顺序）。
    pub fn requires(&self) -> impl Iterator<Item = &'a str> {
        entries(self.text)
            .filter_map(|(_, kv)| kv)
            .filter(|(k, _)| *k == "core.requires")
            .flat_map(|(_, v)| v.split(',').map(str::trim))
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
