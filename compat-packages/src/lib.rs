//! Atomic installer for unmodified Linux compatibility components.
//!
//! 负责上游制品校验、安全解包、版本切换、回滚和卸载；不执行组件，也不实现
//! Linux ABI、Wine、DXVK 或 VKD3D-Proton。
//! Verifies and installs upstream components atomically; it never runs them.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component as PathComponent, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use tar::Archive;

const MANIFEST_NAME: &str = "component.manifest";
const STATE_DIR: &str = ".state";
const COMPONENT_DIR: &str = "components";
const MAX_ARCHIVE_ENTRIES: usize = 1_000_000;
const MAX_UNPACKED_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const SUPPORTED_LICENSES: &[&str] = &[
    "0BSD",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSL-1.0",
    "ISC",
    "LGPL-2.0-only",
    "LGPL-2.0-or-later",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "MIT",
    "MPL-2.0",
    "Unlicense",
    "Zlib",
];

/// 一个可独立安装的 Linux 兼容组件清单。
///
/// Describes one independently installable Linux compatibility component.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentManifest {
    /// 组件名，用作安装存储中的稳定目录名。
    pub name: String,
    /// 上游组件版本，不允许包含路径分隔符。
    pub version: String,
    /// 目标 Linux 用户态架构；当前只接受 `x86_64`。
    pub arch: String,
    /// 上游归档的完整 SHA-256 十六进制摘要。
    pub archive_sha256: String,
    /// 上游许可证表达式；其中每个许可证标识必须在允许列表内。
    pub license: String,
    /// 相对于组件根目录的可执行入口。
    pub entrypoint: String,
    /// 组件运行所需的 Jasper 能力或兼容组件。
    pub requires: Vec<String>,
}

impl ComponentManifest {
    /// 解析并校验组件清单。
    ///
    /// Parses and validates a component manifest.
    pub fn parse(text: &str) -> Result<Self, PackageError> {
        let mut name = None;
        let mut version = None;
        let mut arch = None;
        let mut digest = None;
        let mut license = None;
        let mut entrypoint = None;
        let mut requires = Vec::new();
        for (line_no, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| PackageError::Manifest(line_no + 1, "缺失 =".into()))?;
            let key = key.trim();
            let value = value.trim();
            match key {
                "name" => set_once(&mut name, value, line_no)?,
                "version" => set_once(&mut version, value, line_no)?,
                "arch" => set_once(&mut arch, value, line_no)?,
                "sha256" => set_once(&mut digest, value, line_no)?,
                "license" => set_once(&mut license, value, line_no)?,
                "entrypoint" => set_once(&mut entrypoint, value, line_no)?,
                "requires" => {
                    for item in value.split(',').map(str::trim) {
                        if item.is_empty() || !safe_token(item) {
                            return Err(PackageError::Manifest(line_no + 1, "非法依赖名".into()));
                        }
                        requires.push(item.to_string());
                    }
                }
                _ => return Err(PackageError::Manifest(line_no + 1, format!("未知键 {key}"))),
            }
        }
        let component = Self {
            name: name.ok_or_else(|| missing("name"))?,
            version: version.ok_or_else(|| missing("version"))?,
            arch: arch.ok_or_else(|| missing("arch"))?,
            archive_sha256: digest.ok_or_else(|| missing("sha256"))?,
            license: license.ok_or_else(|| missing("license"))?,
            entrypoint: entrypoint.ok_or_else(|| missing("entrypoint"))?,
            requires,
        };
        component.validate()?;
        Ok(component)
    }

    /// 校验清单字段、目标架构、摘要和许可证策略。
    ///
    /// Validates manifest fields, the target architecture, digest, and license policy.
    pub fn validate(&self) -> Result<(), PackageError> {
        if !safe_token(&self.name) || !safe_token(&self.version) {
            return Err(PackageError::Manifest(0, "非法 name/version".into()));
        }
        if self.arch != "x86_64" {
            return Err(PackageError::Incompatible(format!(
                "unsupported architecture {}",
                self.arch
            )));
        }
        if self.archive_sha256.len() != 64
            || !self
                .archive_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(PackageError::Manifest(
                0,
                "sha256 必须为 64 位十六进制".into(),
            ));
        }
        if !supported_license(&self.license) {
            return Err(PackageError::Manifest(
                0,
                format!("不支持的许可证表达式 {}", self.license),
            ));
        }
        if !safe_relative(&self.entrypoint) {
            return Err(PackageError::Manifest(0, "entrypoint 路径非法".into()));
        }
        let unique: BTreeSet<_> = self.requires.iter().collect();
        if unique.len() != self.requires.len() {
            return Err(PackageError::Manifest(0, "requires 重复".into()));
        }
        Ok(())
    }
}

fn set_once(slot: &mut Option<String>, value: &str, line_no: usize) -> Result<(), PackageError> {
    if slot.is_some() || value.is_empty() {
        return Err(PackageError::Manifest(line_no + 1, "重复或空值".into()));
    }
    *slot = Some(value.to_string());
    Ok(())
}

fn missing(key: &str) -> PackageError {
    PackageError::Manifest(0, format!("缺少 {key}"))
}

/// 组件验证、安装或状态切换失败的原因。
///
/// Describes why component verification, installation, or activation failed.
#[derive(Debug)]
pub enum PackageError {
    /// 文件系统操作失败。
    Io(io::Error),
    /// 清单格式错误及对应行号。
    Manifest(usize, String),
    /// 归档摘要与清单不一致。
    Digest {
        /// 清单声明的摘要。
        expected: String,
        /// 实际计算的摘要。
        actual: String,
    },
    /// 归档包含路径穿越、链接、特殊文件或超额资源。
    UnsafeArchive(String),
    /// 组件或请求与当前平台不兼容。
    Incompatible(String),
    /// 指定组件没有可切换的安装状态。
    NotInstalled(String),
    /// 已保存的状态文件损坏或指向不存在的工件。
    CorruptState {
        /// 状态所属组件名。
        name: String,
        /// 检测到的损坏原因。
        reason: String,
    },
}

impl std::fmt::Display for PackageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O 错误：{error}"),
            Self::Manifest(line, error) => {
                write!(formatter, "清单第 {line} 行：{error}")
            }
            Self::Digest { expected, actual } => {
                write!(formatter, "SHA-256 不匹配：期望 {expected}，实际 {actual}")
            }
            Self::UnsafeArchive(reason) => write!(formatter, "不安全的归档：{reason}"),
            Self::Incompatible(reason) => write!(formatter, "组件不兼容：{reason}"),
            Self::NotInstalled(name) => write!(formatter, "组件未安装：{name}"),
            Self::CorruptState { name, reason } => {
                write!(formatter, "组件状态损坏：{name}：{reason}")
            }
        }
    }
}

impl std::error::Error for PackageError {}

impl From<io::Error> for PackageError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// 已安装组件当前可执行的版本。
///
/// The active version of an installed component.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Installed {
    /// 组件名。
    pub name: String,
    /// 当前激活的版本。
    pub version: String,
    /// 激活版本的安装目录。
    pub path: PathBuf,
}

/// 管理单个组件根目录内的校验、安装、升级、回滚和卸载。
///
/// Manages verification, installation, upgrades, rollback, and removal in one component root.
pub struct ComponentInstaller {
    root: PathBuf,
}

impl ComponentInstaller {
    /// 使用给定组件安装根目录创建管理器。
    ///
    /// Creates an installer rooted at the supplied directory.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// 验证上游归档并原子激活一个组件版本。
    ///
    /// Verifies an upstream archive and atomically activates a component version.
    pub fn install(
        &self,
        manifest_path: &Path,
        archive_path: &Path,
    ) -> Result<Installed, PackageError> {
        let manifest_text = fs::read_to_string(manifest_path)?;
        let manifest = ComponentManifest::parse(&manifest_text)?;
        let actual = digest_file(archive_path)?;
        if !actual.eq_ignore_ascii_case(&manifest.archive_sha256) {
            return Err(PackageError::Digest {
                expected: manifest.archive_sha256.clone(),
                actual,
            });
        }
        self.ensure_layout()?;
        let previous_state = self.read_state_optional(&manifest.name)?;
        let destination = self.component_path(&manifest.name, &manifest.version);
        if destination.exists() {
            self.verify_existing_artifact(&manifest, &manifest_text, &destination)?;
            self.activate_state(&manifest, previous_state.as_ref())?;
            return Ok(Installed {
                name: manifest.name,
                version: manifest.version,
                path: destination,
            });
        }
        let staging = self.root.join(format!(
            ".staging-{}-{}-{}",
            manifest.name,
            std::process::id(),
            now_nanos()
        ));
        if staging.exists() {
            return Err(PackageError::Incompatible("staging path exists".into()));
        }
        fs::create_dir(&staging)?;
        let extracted = extract_archive(archive_path, &staging);
        if let Err(error) = extracted {
            let _ = fs::remove_dir_all(&staging);
            return Err(error);
        }
        if verify_entrypoint(&staging.join(&manifest.entrypoint)).is_err() {
            let _ = fs::remove_dir_all(&staging);
            return Err(PackageError::Incompatible(
                "entrypoint is not an executable regular file".into(),
            ));
        }
        if let Err(error) = fs::write(staging.join(MANIFEST_NAME), &manifest_text) {
            let _ = fs::remove_dir_all(&staging);
            return Err(error.into());
        }
        if let Some(parent) = destination.parent() {
            if let Err(error) = fs::create_dir_all(parent) {
                let _ = fs::remove_dir_all(&staging);
                return Err(error.into());
            }
        }
        let state_changed = previous_state
            .as_ref()
            .map(|state| state.current != manifest.version)
            .unwrap_or(true);
        let pending_state = if state_changed {
            match self.write_state_temporary(&manifest, previous_state.as_ref()) {
                Ok(path) => Some(path),
                Err(error) => {
                    let _ = fs::remove_dir_all(&staging);
                    return Err(error);
                }
            }
        } else {
            None
        };
        if let Err(error) = fs::rename(&staging, &destination) {
            let _ = fs::remove_dir_all(&staging);
            if let Some(path) = pending_state {
                let _ = fs::remove_file(path);
            }
            return Err(error.into());
        }
        if let Some(path) = pending_state {
            if let Err(error) = fs::rename(path, self.state_path(&manifest.name)) {
                let _ = fs::remove_dir_all(&destination);
                return Err(error.into());
            }
        }
        Ok(Installed {
            name: manifest.name,
            version: manifest.version,
            path: destination,
        })
    }

    /// 将当前组件切换到上一次激活的版本。
    ///
    /// Switches the active component back to its previously activated version.
    pub fn rollback(&self, name: &str) -> Result<Installed, PackageError> {
        let state = self.read_state(name)?;
        let previous = state
            .previous
            .clone()
            .ok_or_else(|| PackageError::NotInstalled(name.into()))?;
        self.verify_installed(name, &previous)?;
        let pending = self.write_state_temporary_values(name, &previous, Some(&state.current))?;
        if let Err(error) = fs::rename(&pending, self.state_path(name)) {
            let _ = fs::remove_file(pending);
            return Err(error.into());
        }
        self.current(name)
    }

    /// 只卸载指定组件及其状态，不修改其他组件。
    ///
    /// Removes only the named component and its state.
    pub fn uninstall(&self, name: &str) -> Result<(), PackageError> {
        if !safe_token(name) {
            return Err(PackageError::Incompatible("invalid component name".into()));
        }
        let state_path = self.state_path(name);
        self.read_state(name)?;
        let component_root = self.root.join(COMPONENT_DIR).join(name);
        let trash = self.root.join(format!(".uninstall-{name}-{}", now_nanos()));
        if component_root.exists() {
            let metadata = fs::symlink_metadata(&component_root)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(PackageError::Incompatible(
                    "component root is not a real directory".into(),
                ));
            }
            fs::rename(&component_root, &trash)?;
        }
        if let Err(error) = fs::remove_file(state_path) {
            if trash.exists() {
                let _ = fs::rename(&trash, &component_root);
            }
            return Err(error.into());
        }
        if trash.exists() {
            fs::remove_dir_all(trash)?;
        }
        Ok(())
    }

    /// 返回并验证指定组件当前的激活版本。
    ///
    /// Returns and verifies the active version of a component.
    pub fn current(&self, name: &str) -> Result<Installed, PackageError> {
        let state = self.read_state(name)?;
        self.verify_installed(name, &state.current)?;
        Ok(Installed {
            name: name.into(),
            path: self.component_path(name, &state.current),
            version: state.current,
        })
    }

    fn component_path(&self, name: &str, version: &str) -> PathBuf {
        self.root.join(COMPONENT_DIR).join(name).join(version)
    }

    fn state_path(&self, name: &str) -> PathBuf {
        self.root.join(STATE_DIR).join(format!("{name}.state"))
    }

    fn read_state(&self, name: &str) -> Result<InstallState, PackageError> {
        self.read_state_optional(name)?
            .ok_or_else(|| PackageError::NotInstalled(name.into()))
    }

    fn read_state_optional(&self, name: &str) -> Result<Option<InstallState>, PackageError> {
        if !safe_token(name) {
            return Err(PackageError::Incompatible("invalid component name".into()));
        }
        if !self.ensure_existing_layout()? {
            return Ok(None);
        }
        let text = match fs::read_to_string(self.state_path(name)) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let mut current = None;
        let mut previous = None;
        for (line_no, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| PackageError::CorruptState {
                    name: name.into(),
                    reason: format!("第 {} 行缺失 =", line_no + 1),
                })?;
            match key {
                "current" if current.is_none() => current = nonempty(value),
                "previous" if previous.is_none() => previous = nonempty(value),
                "current" | "previous" => {
                    return Err(PackageError::CorruptState {
                        name: name.into(),
                        reason: format!("第 {} 行重复键", line_no + 1),
                    })
                }
                _ => {
                    return Err(PackageError::CorruptState {
                        name: name.into(),
                        reason: format!("第 {} 行未知键", line_no + 1),
                    })
                }
            }
        }
        let current = current.ok_or_else(|| PackageError::CorruptState {
            name: name.into(),
            reason: "缺少 current".into(),
        })?;
        if !safe_token(&current) || previous.as_deref().is_some_and(|value| !safe_token(value)) {
            return Err(PackageError::CorruptState {
                name: name.into(),
                reason: "版本名非法".into(),
            });
        }
        if previous.as_deref() == Some(current.as_str()) {
            return Err(PackageError::CorruptState {
                name: name.into(),
                reason: "current 与 previous 相同".into(),
            });
        }
        Ok(Some(InstallState { current, previous }))
    }

    fn write_state_temporary(
        &self,
        manifest: &ComponentManifest,
        state: Option<&InstallState>,
    ) -> Result<PathBuf, PackageError> {
        let previous = state
            .and_then(|state| (state.current != manifest.version).then_some(state.current.as_str()))
            .or_else(|| state.and_then(|state| state.previous.as_deref()));
        self.write_state_temporary_values(&manifest.name, &manifest.version, previous)
    }

    fn write_state_temporary_values(
        &self,
        name: &str,
        current: &str,
        previous: Option<&str>,
    ) -> Result<PathBuf, PackageError> {
        let target = self.state_path(name);
        let temporary = target.with_extension(format!("tmp-{}", now_nanos()));
        let body = format!("current={}\nprevious={}\n", current, previous.unwrap_or(""));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        if let Err(error) = file
            .write_all(body.as_bytes())
            .and_then(|_| file.sync_all())
        {
            drop(file);
            let _ = fs::remove_file(&temporary);
            return Err(error.into());
        }
        Ok(temporary)
    }

    fn activate_state(
        &self,
        manifest: &ComponentManifest,
        state: Option<&InstallState>,
    ) -> Result<(), PackageError> {
        if state.map(|state| state.current.as_str()) == Some(manifest.version.as_str()) {
            return Ok(());
        }
        let pending = self.write_state_temporary(manifest, state)?;
        if let Err(error) = fs::rename(&pending, self.state_path(&manifest.name)) {
            let _ = fs::remove_file(pending);
            return Err(error.into());
        }
        Ok(())
    }

    fn verify_existing_artifact(
        &self,
        manifest: &ComponentManifest,
        expected_text: &str,
        destination: &Path,
    ) -> Result<(), PackageError> {
        let metadata = fs::symlink_metadata(destination)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(PackageError::Incompatible(
                "component destination is not a real directory".into(),
            ));
        }
        let stored_text = fs::read_to_string(destination.join(MANIFEST_NAME)).map_err(|error| {
            PackageError::CorruptState {
                name: manifest.name.clone(),
                reason: format!("读取已安装清单失败：{error}"),
            }
        })?;
        if stored_text != expected_text {
            return Err(PackageError::Incompatible(format!(
                "{} {} 已存在且工件不同",
                manifest.name, manifest.version
            )));
        }
        verify_entrypoint(&destination.join(&manifest.entrypoint)).map_err(|reason| {
            PackageError::CorruptState {
                name: manifest.name.clone(),
                reason,
            }
        })?;
        Ok(())
    }

    fn verify_installed(&self, name: &str, version: &str) -> Result<(), PackageError> {
        if !safe_token(name) || !safe_token(version) {
            return Err(PackageError::CorruptState {
                name: name.into(),
                reason: "组件名或版本名非法".into(),
            });
        }
        let path = self.component_path(name, version);
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                PackageError::CorruptState {
                    name: name.into(),
                    reason: format!("版本 {version} 的目录不存在"),
                }
            } else {
                PackageError::Io(error)
            }
        })?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(PackageError::CorruptState {
                name: name.into(),
                reason: format!("版本 {version} 不是真实目录"),
            });
        }
        let text = fs::read_to_string(path.join(MANIFEST_NAME)).map_err(|error| {
            PackageError::CorruptState {
                name: name.into(),
                reason: format!("读取清单失败：{error}"),
            }
        })?;
        let manifest =
            ComponentManifest::parse(&text).map_err(|error| PackageError::CorruptState {
                name: name.into(),
                reason: format!("清单无效：{error}"),
            })?;
        if manifest.name != name || manifest.version != version {
            return Err(PackageError::CorruptState {
                name: name.into(),
                reason: "清单与安装路径不一致".into(),
            });
        }
        verify_entrypoint(&path.join(&manifest.entrypoint)).map_err(|reason| {
            PackageError::CorruptState {
                name: name.into(),
                reason,
            }
        })?;
        Ok(())
    }

    fn ensure_layout(&self) -> Result<(), PackageError> {
        ensure_real_directory(&self.root)?;
        ensure_real_directory(&self.root.join(COMPONENT_DIR))?;
        ensure_real_directory(&self.root.join(STATE_DIR))
    }

    fn ensure_existing_layout(&self) -> Result<bool, PackageError> {
        match fs::symlink_metadata(&self.root) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(PackageError::Incompatible(
                    "install root is not a real directory".into(),
                ))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        }
        for path in [
            self.root.join(COMPONENT_DIR),
            self.root.join(STATE_DIR),
        ] {
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
                Ok(_) => {
                    return Err(PackageError::Incompatible(format!(
                        "reserved path is not a real directory: {}",
                        path.display()
                    )))
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(true)
    }
}

struct InstallState {
    current: String,
    previous: Option<String>,
}

fn ensure_real_directory(path: &Path) -> Result<(), PackageError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(PackageError::Incompatible(format!(
            "not a real directory: {}",
            path.display()
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path)?;
            let metadata = fs::symlink_metadata(path)?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                Ok(())
            } else {
                Err(PackageError::Incompatible(format!(
                    "not a real directory: {}",
                    path.display()
                )))
            }
        }
        Err(error) => Err(error.into()),
    }
}

fn verify_entrypoint(path: &Path) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("entrypoint metadata: {error}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("entrypoint is not a regular file".into());
    }
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err("entrypoint has no execute permission".into());
    }
    Ok(())
}

fn extract_archive(path: &Path, destination: &Path) -> Result<(), PackageError> {
    let decoder = GzDecoder::new(BufReader::new(File::open(path)?));
    let mut archive = Archive::new(decoder);
    let mut entry_count = 0usize;
    let mut unpacked_bytes = 0u64;
    let mut seen = BTreeSet::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        entry_count = entry_count
            .checked_add(1)
            .ok_or_else(|| PackageError::UnsafeArchive("entry count overflow".into()))?;
        if entry_count > MAX_ARCHIVE_ENTRIES {
            return Err(PackageError::UnsafeArchive(format!(
                "归档条目超过 {MAX_ARCHIVE_ENTRIES}"
            )));
        }
        let relative = entry.path()?.into_owned();
        if !safe_relative_path(&relative) {
            return Err(PackageError::UnsafeArchive(relative.display().to_string()));
        }
        if relative == Path::new(MANIFEST_NAME) {
            return Err(PackageError::UnsafeArchive("归档占用保留清单路径".into()));
        }
        if !seen.insert(relative.clone()) {
            return Err(PackageError::UnsafeArchive(format!(
                "归档包含重复路径 {}",
                relative.display()
            )));
        }
        let kind = entry.header().entry_type();
        if !(kind.is_file() || kind.is_dir()) {
            return Err(PackageError::UnsafeArchive(format!(
                "unsupported entry type {}",
                relative.display()
            )));
        }
        let size = entry.header().size()?;
        unpacked_bytes = unpacked_bytes
            .checked_add(size)
            .ok_or_else(|| PackageError::UnsafeArchive("unpacked byte count overflow".into()))?;
        if unpacked_bytes > MAX_UNPACKED_BYTES {
            return Err(PackageError::UnsafeArchive(format!(
                "解包大小超过 {MAX_UNPACKED_BYTES} 字节"
            )));
        }
        let mode = entry.header().mode()?;
        if mode & 0o7000 != 0 {
            return Err(PackageError::UnsafeArchive(format!(
                "特殊权限位 {}",
                relative.display()
            )));
        }
        let target = destination.join(&relative);
        if kind.is_dir() {
            fs::create_dir_all(target)?;
        } else {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            entry.unpack(target)?;
        }
    }
    Ok(())
}

fn digest_file(path: &Path) -> Result<String, PackageError> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(encoded)
}

fn safe_relative(path: &str) -> bool {
    safe_relative_path(Path::new(path))
}

fn safe_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && path
            .components()
            .all(|part| matches!(part, PathComponent::Normal(_)))
}

fn safe_token(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn supported_license(expression: &str) -> bool {
    let mut found = false;
    for token in expression
        .split(|character: char| character.is_whitespace() || matches!(character, '(' | ')'))
        .filter(|token| !token.is_empty())
    {
        if matches!(token, "AND" | "OR" | "WITH") {
            continue;
        }
        found = true;
        if !SUPPORTED_LICENSES.contains(&token) {
            return false;
        }
    }
    found
}

fn nonempty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!("compat-pkg-{tag}-{}", now_nanos()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn archive(dir: &Path, version: &str) -> (PathBuf, String) {
        archive_with_mode(dir, version, 0o755)
    }

    fn archive_with_mode(dir: &Path, version: &str, mode: u32) -> (PathBuf, String) {
        let path = dir.join(format!("{version}.tar.gz"));
        let file = File::create(&path).unwrap();
        let encoder = GzEncoder::new(file, Compression::default());
        let mut tar = tar::Builder::new(encoder);
        let data = format!("#!/bin/sh\necho {version}\n").into_bytes();
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(mode);
        header.set_cksum();
        tar.append_data(&mut header, "bin/wine", data.as_slice())
            .unwrap();
        tar.into_inner().unwrap().finish().unwrap();
        let digest = digest_file(&path).unwrap();
        (path, digest)
    }

    fn symlink_archive(dir: &Path) -> (PathBuf, String) {
        let path = dir.join("symlink.tar.gz");
        let file = File::create(&path).unwrap();
        let encoder = GzEncoder::new(file, Compression::default());
        let mut tar = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        tar.append_link(&mut header, "bin/wine", "../../escape")
            .unwrap();
        tar.into_inner().unwrap().finish().unwrap();
        let digest = digest_file(&path).unwrap();
        (path, digest)
    }

    fn manifest(dir: &Path, version: &str, digest: &str) -> PathBuf {
        let path = dir.join(format!("{version}.component.manifest"));
        fs::write(
            &path,
            format!(
                "name=wine\nversion={version}\narch=x86_64\nsha256={digest}\nlicense=LGPL-2.1-or-later\nentrypoint=bin/wine\nrequires=linux-abi-1,vulkan-1\n"
            ),
        )
        .unwrap();
        path
    }

    fn transient_entries(root: &Path) -> Vec<String> {
        if !root.exists() {
            return Vec::new();
        }
        fs::read_dir(root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".staging-") || name.starts_with(".uninstall-"))
            .collect()
    }

    #[test]
    fn install_upgrade_rollback_and_uninstall_are_atomic() {
        let temp = TestDir::new("lifecycle");
        let root = temp.path().join("root");
        let installer = ComponentInstaller::new(&root);
        let (archive1, digest1) = archive(temp.path(), "1.0");
        let manifest1 = manifest(temp.path(), "1.0", &digest1);
        let first = installer.install(&manifest1, &archive1).unwrap();
        assert!(first.path.join("bin/wine").is_file());
        assert_eq!(installer.install(&manifest1, &archive1).unwrap(), first);
        let (archive2, digest2) = archive(temp.path(), "2.0");
        let manifest2 = manifest(temp.path(), "2.0", &digest2);
        installer.install(&manifest2, &archive2).unwrap();
        assert_eq!(installer.current("wine").unwrap().version, "2.0");
        assert_eq!(installer.rollback("wine").unwrap().version, "1.0");
        assert_eq!(installer.current("wine").unwrap().version, "1.0");
        installer.uninstall("wine").unwrap();
        assert!(installer.current("wine").is_err());
        assert!(!root.join(COMPONENT_DIR).join("wine").exists());
        assert!(transient_entries(&root).is_empty());
    }

    #[test]
    fn digest_or_unsafe_archive_failure_changes_nothing() {
        let temp = TestDir::new("reject");
        let root = temp.path().join("root");
        let installer = ComponentInstaller::new(&root);
        let (archive_path, _digest) = archive(temp.path(), "1.0");
        let bad = manifest(temp.path(), "1.0", &"0".repeat(64));
        assert!(matches!(
            installer.install(&bad, &archive_path),
            Err(PackageError::Digest { .. })
        ));
        assert!(installer.current("wine").is_err());
        assert!(!root.exists());

        let path = temp.path().join("unsafe.tar.gz");
        let file = File::create(&path).unwrap();
        let encoder = GzEncoder::new(file, Compression::default());
        let mut tar = tar::Builder::new(encoder);
        let data = b"bad";
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.as_mut_bytes()[..9].copy_from_slice(b"../escape");
        header.set_cksum();
        tar.append(&header, &data[..]).unwrap();
        tar.into_inner().unwrap().finish().unwrap();
        let unsafe_digest = digest_file(&path).unwrap();
        let good = manifest(temp.path(), "1.0", &unsafe_digest);
        assert!(matches!(
            installer.install(&good, &path),
            Err(PackageError::UnsafeArchive(_))
        ));
        assert!(installer.current("wine").is_err());
        assert!(transient_entries(&root).is_empty());

        let (link_archive, link_digest) = symlink_archive(temp.path());
        let link_manifest = manifest(temp.path(), "1.0", &link_digest);
        assert!(matches!(
            installer.install(&link_manifest, &link_archive),
            Err(PackageError::UnsafeArchive(_))
        ));
        assert!(installer.current("wine").is_err());
        assert!(transient_entries(&root).is_empty());
    }

    #[test]
    fn duplicate_version_with_different_artifact_is_rejected() {
        let temp = TestDir::new("duplicate");
        let root = temp.path().join("root");
        let installer = ComponentInstaller::new(&root);
        let (archive1, digest1) = archive(temp.path(), "1.0");
        let manifest1 = manifest(temp.path(), "1.0", &digest1);
        installer.install(&manifest1, &archive1).unwrap();
        let (archive2, digest2) = archive(temp.path(), "2.0");
        let conflicting = manifest(temp.path(), "1.0", &digest2);
        assert!(matches!(
            installer.install(&conflicting, &archive2),
            Err(PackageError::Incompatible(_))
        ));
        assert_eq!(installer.current("wine").unwrap().version, "1.0");
        assert!(transient_entries(&root).is_empty());
    }

    #[test]
    fn manifest_rejects_wrong_arch_unknown_keys_bad_hash_and_license() {
        let bad =
            "name=wine\nversion=1\narch=aarch64\nsha256=00\nlicense=MIT\nentrypoint=bin/wine\n";
        assert!(ComponentManifest::parse(bad).is_err());
        let unknown = format!(
            "name=wine\nversion=1\narch=x86_64\nsha256={}\nlicense=MIT\nentrypoint=bin/wine\nfoo=bar\n",
            "a".repeat(64)
        );
        assert!(ComponentManifest::parse(&unknown).is_err());
        let bad_license = format!(
            "name=wine\nversion=1\narch=x86_64\nsha256={}\nlicense=Proprietary\nentrypoint=bin/wine\n",
            "a".repeat(64)
        );
        assert!(ComponentManifest::parse(&bad_license).is_err());
        let parent_name = format!(
            "name=..\nversion=1\narch=x86_64\nsha256={}\nlicense=MIT\nentrypoint=bin/wine\n",
            "a".repeat(64)
        );
        assert!(ComponentManifest::parse(&parent_name).is_err());
        let parent_version = format!(
            "name=wine\nversion=..\narch=x86_64\nsha256={}\nlicense=MIT\nentrypoint=bin/wine\n",
            "a".repeat(64)
        );
        assert!(ComponentManifest::parse(&parent_version).is_err());
        let combined = format!(
            "name=dxvk\nversion=2\narch=x86_64\nsha256={}\nlicense=Zlib OR MIT\nentrypoint=bin/dxvk\n",
            "a".repeat(64)
        );
        assert!(ComponentManifest::parse(&combined).is_ok());
    }

    #[test]
    fn component_names_cannot_escape_the_install_root() {
        let temp = TestDir::new("names");
        let installer = ComponentInstaller::new(temp.path().join("root"));
        assert!(matches!(
            installer.current("../outside"),
            Err(PackageError::Incompatible(_))
        ));
        assert!(matches!(
            installer.uninstall("../outside"),
            Err(PackageError::Incompatible(_))
        ));
        assert!(matches!(
            installer.current(".."),
            Err(PackageError::Incompatible(_))
        ));
    }

    #[test]
    fn entrypoint_must_be_executable_and_layout_must_not_be_a_symlink() {
        let temp = TestDir::new("entrypoint");
        let root = temp.path().join("root");
        let installer = ComponentInstaller::new(&root);
        let (archive, digest) = archive_with_mode(temp.path(), "1.0", 0o644);
        let manifest = manifest(temp.path(), "1.0", &digest);
        assert!(matches!(
            installer.install(&manifest, &archive),
            Err(PackageError::Incompatible(_))
        ));
        assert!(installer.current("wine").is_err());
        assert!(transient_entries(&root).is_empty());

        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        let link = temp.path().join("linked-root");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let linked = ComponentInstaller::new(&link);
        assert!(matches!(
            linked.current("wine"),
            Err(PackageError::Incompatible(_))
        ));
    }
}
