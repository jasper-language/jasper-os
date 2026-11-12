//! Bounded executable/interpreter registry for the Linux compatibility service.
//!
//! The logical path is a discovery key, not a Jasper authorization token. Callers
//! must still authorize process creation and image execution through the native
//! compatibility profile. This registry binds normalized paths and expected image
//! lengths to one System A/B root; executable bytes stay owned by that root.
//!
//! 有界 Linux 兼容可执行/解释器登记表。逻辑路径只用于发现，不是 Jasper 授权凭据；
//! 调用方仍须通过原生兼容 Profile 授权进程创建与映像执行。

extern crate alloc;

use core::fmt;

/// Maximum normalized logical path, including the leading slash.
pub const MAX_LOGICAL_PATH: usize = 256;
/// Maximum distinct image records held by one registry.
pub const MAX_IMAGES: usize = 128;
/// Maximum executable bindings held by one registry.
pub const MAX_PROGRAMS: usize = 64;
/// Maximum aggregate declared image length accepted by one registry.
pub const MAX_REGISTERED_BYTES: usize = 256 * 1024 * 1024;

/// System root that supplied an image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemImage {
    A,
    B,
}

/// Stable executable binding identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramId(u64);

impl ProgramId {
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Absolute logical path without `.`, `..`, repeated separators or a trailing slash.
///
/// 规范化逻辑路径。它不表达对象身份、可见性或执行权。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LogicalPath {
    bytes: [u8; MAX_LOGICAL_PATH],
    len: u16,
}

impl LogicalPath {
    /// Normalizes one absolute discovery path, failing closed on traversal.
    pub fn parse(path: &[u8]) -> Result<Self, RegistryError> {
        if path.is_empty() || path[0] != b'/' || path.len() > MAX_LOGICAL_PATH || path.contains(&0)
        {
            return Err(RegistryError::InvalidPath);
        }
        let mut bytes = [0; MAX_LOGICAL_PATH];
        let mut len = 0usize;
        for component in path.split(|byte| *byte == b'/') {
            if component.is_empty() || component == b"." {
                continue;
            }
            if component == b".." {
                return Err(RegistryError::InvalidPath);
            }
            bytes[len] = b'/';
            len += 1;
            let end = len
                .checked_add(component.len())
                .filter(|end| *end <= MAX_LOGICAL_PATH)
                .ok_or(RegistryError::InvalidPath)?;
            bytes[len..end].copy_from_slice(component);
            len = end;
        }
        if len == 0 {
            return Err(RegistryError::InvalidPath);
        }
        Ok(Self {
            bytes,
            len: len as u16,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

impl fmt::Debug for LogicalPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(core::str::from_utf8(self.as_bytes()).unwrap_or("<non-utf8-path>"))
    }
}

/// A resolved executable/interpreter pair. Resolution is not authorization.
#[derive(Clone, Copy)]
pub struct ResolvedProgram<'a> {
    pub id: ProgramId,
    pub path: LogicalPath,
    pub origin: SystemImage,
    pub executable_path: &'a [u8],
    pub executable_len: usize,
    pub interpreter_path: &'a [u8],
    pub interpreter_len: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryError {
    InvalidPath,
    EmptyImage,
    ProgramConflict,
    ImageConflict,
    UnknownPath,
    Capacity,
    IdExhausted,
}

struct ImageRecord {
    id: u64,
    path: LogicalPath,
    origin: SystemImage,
    len: usize,
}

struct ProgramRecord {
    id: ProgramId,
    path: LogicalPath,
    origin: SystemImage,
    executable: u64,
    interpreter: u64,
}

/// Transactional, bounded path-to-image registry.
pub struct ExecutableRegistry {
    images: alloc::vec::Vec<ImageRecord>,
    programs: alloc::vec::Vec<ProgramRecord>,
    next_image: u64,
    next_program: u64,
}

impl ExecutableRegistry {
    pub const fn new() -> Self {
        Self {
            images: alloc::vec::Vec::new(),
            programs: alloc::vec::Vec::new(),
            next_image: 1,
            next_program: 1,
        }
    }

    /// Registers one executable/interpreter pair from one selected System root.
    ///
    /// Repeating an identical registration is idempotent. A path rebound to different
    /// bytes is rejected instead of silently changing discovery behavior.
    pub fn register_program(
        &mut self,
        origin: SystemImage,
        executable_path: &[u8],
        executable_len: usize,
        interpreter_path: &[u8],
        interpreter_len: usize,
    ) -> Result<ProgramId, RegistryError> {
        let executable_path = LogicalPath::parse(executable_path)?;
        let interpreter_path = LogicalPath::parse(interpreter_path)?;
        if executable_len == 0 || interpreter_len == 0 {
            return Err(RegistryError::EmptyImage);
        }
        if executable_path == interpreter_path {
            return Err(RegistryError::ProgramConflict);
        }

        let executable_match = self.find_image(origin, executable_path, executable_len)?;
        let interpreter_match = self.find_image(origin, interpreter_path, interpreter_len)?;
        let executable_id = executable_match.unwrap_or(self.next_image);
        let interpreter_id = if let Some(image_id) = interpreter_match {
            image_id
        } else {
            self.next_image
                .checked_add(u64::from(executable_match.is_none()))
                .ok_or(RegistryError::IdExhausted)?
        };
        if executable_id == 0 || interpreter_id == 0 || executable_id == interpreter_id {
            return Err(RegistryError::IdExhausted);
        }
        if let Some(program) = self
            .programs
            .iter()
            .find(|program| program.origin == origin && program.path == executable_path)
        {
            return if program.executable == executable_id && program.interpreter == interpreter_id {
                Ok(program.id)
            } else {
                Err(RegistryError::ProgramConflict)
            };
        }

        let new_images =
            usize::from(executable_match.is_none()) + usize::from(interpreter_match.is_none());
        let added_bytes = executable_match
            .is_none()
            .then_some(executable_len)
            .unwrap_or(0)
            .saturating_add(
                interpreter_match
                    .is_none()
                    .then_some(interpreter_len)
                    .unwrap_or(0),
            );
        let stored_bytes = self
            .images
            .iter()
            .fold(0usize, |total, image| total.saturating_add(image.len));
        if self.images.len().saturating_add(new_images) > MAX_IMAGES
            || self.programs.len() == MAX_PROGRAMS
            || stored_bytes.saturating_add(added_bytes) > MAX_REGISTERED_BYTES
        {
            return Err(RegistryError::Capacity);
        }
        if self
            .next_image
            .checked_add(new_images as u64)
            .is_none_or(|next| next == 0)
            || self.next_program.checked_add(1).is_none()
        {
            return Err(RegistryError::IdExhausted);
        }
        self.images
            .try_reserve(new_images)
            .map_err(|_| RegistryError::Capacity)?;
        self.programs
            .try_reserve(1)
            .map_err(|_| RegistryError::Capacity)?;

        if executable_match.is_none() {
            self.images.push(ImageRecord {
                id: executable_id,
                path: executable_path,
                origin,
                len: executable_len,
            });
            self.next_image += 1;
        }
        if interpreter_match.is_none() {
            self.images.push(ImageRecord {
                id: interpreter_id,
                path: interpreter_path,
                origin,
                len: interpreter_len,
            });
            self.next_image += 1;
        }
        let id = ProgramId(self.next_program);
        self.next_program += 1;
        self.programs.push(ProgramRecord {
            id,
            path: executable_path,
            origin,
            executable: executable_id,
            interpreter: interpreter_id,
        });
        Ok(id)
    }

    /// Resolves registered image metadata by normalized logical path.
    ///
    /// Success means the selected root declares these images; it grants no execution rights.
    pub fn resolve(
        &self,
        origin: SystemImage,
        path: &[u8],
    ) -> Result<ResolvedProgram<'_>, RegistryError> {
        let path = LogicalPath::parse(path)?;
        let program = self
            .programs
            .iter()
            .find(|program| program.origin == origin && program.path == path)
            .ok_or(RegistryError::UnknownPath)?;
        let executable = self
            .image(program.executable)
            .ok_or(RegistryError::ImageConflict)?;
        let interpreter = self
            .image(program.interpreter)
            .ok_or(RegistryError::ImageConflict)?;
        Ok(ResolvedProgram {
            id: program.id,
            path: program.path,
            origin,
            executable_path: executable.path.as_bytes(),
            executable_len: executable.len,
            interpreter_path: interpreter.path.as_bytes(),
            interpreter_len: interpreter.len,
        })
    }

    pub fn program_count(&self) -> usize {
        self.programs.len()
    }

    pub fn image_count(&self) -> usize {
        self.images.len()
    }

    fn find_image(
        &self,
        origin: SystemImage,
        path: LogicalPath,
        len: usize,
    ) -> Result<Option<u64>, RegistryError> {
        let mut matches = self
            .images
            .iter()
            .filter(|image| image.origin == origin && image.path == path);
        let found = matches.next();
        if found.is_some_and(|image| image.len != len) || matches.next().is_some() {
            return Err(RegistryError::ImageConflict);
        }
        Ok(found.map(|image| image.id))
    }

    fn image(&self, id: u64) -> Option<&ImageRecord> {
        self.images.iter().find(|image| image.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logical_paths_normalize_without_becoming_authority() {
        let path = LogicalPath::parse(b"//usr//bin/./printf").unwrap();
        assert_eq!(path.as_bytes(), b"/usr/bin/printf");
        assert!(LogicalPath::parse(b"usr/bin/printf").is_err());
        assert!(LogicalPath::parse(b"/usr/../bin/printf").is_err());
        assert!(LogicalPath::parse(b"/").is_err());
        assert!(LogicalPath::parse(&[b'/', 0]).is_err());
    }

    #[test]
    fn duplicate_registration_is_idempotent_and_reuses_interpreter_record() {
        let mut registry = ExecutableRegistry::new();
        let first = registry
            .register_program(
                SystemImage::A,
                b"/usr/bin/printf",
                b"printf-image".len(),
                b"/lib64/ld-linux-x86-64.so.2",
                b"ld-image".len(),
            )
            .unwrap();
        let second = registry
            .register_program(
                SystemImage::A,
                b"//usr/bin/./printf",
                b"printf-image".len(),
                b"/lib64//ld-linux-x86-64.so.2",
                b"ld-image".len(),
            )
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(registry.program_count(), 1);
        assert_eq!(registry.image_count(), 2);
        let resolved = registry
            .resolve(SystemImage::A, b"/usr/bin/printf")
            .unwrap();
        assert_eq!(resolved.executable_len, b"printf-image".len());
        assert_eq!(resolved.interpreter_len, b"ld-image".len());
    }

    #[test]
    fn conflicting_rebind_fails_without_mutating_registry() {
        let mut registry = ExecutableRegistry::new();
        registry
            .register_program(
                SystemImage::A,
                b"/usr/bin/printf",
                b"first".len(),
                b"/lib64/ld-linux-x86-64.so.2",
                b"loader".len(),
            )
            .unwrap();
        assert_eq!(
            registry.register_program(
                SystemImage::A,
                b"/usr/bin/printf",
                b"second".len(),
                b"/lib64/ld-linux-x86-64.so.2",
                b"loader".len(),
            ),
            Err(RegistryError::ImageConflict)
        );
        assert_eq!(registry.program_count(), 1);
        assert_eq!(registry.image_count(), 2);
    }

    #[test]
    fn system_roots_have_independent_discovery_namespaces() {
        let mut registry = ExecutableRegistry::new();
        registry
            .register_program(
                SystemImage::A,
                b"/usr/bin/tool",
                b"a".len(),
                b"/lib64/ld.so",
                b"loader-a".len(),
            )
            .unwrap();
        registry
            .register_program(
                SystemImage::B,
                b"/usr/bin/tool",
                b"b".len(),
                b"/lib64/ld.so",
                b"loader-b".len(),
            )
            .unwrap();
        assert_eq!(
            registry
                .resolve(SystemImage::A, b"/usr/bin/tool")
                .unwrap()
                .executable_len,
            b"a".len()
        );
        assert_eq!(
            registry
                .resolve(SystemImage::B, b"/usr/bin/tool")
                .unwrap()
                .executable_len,
            b"b".len()
        );
    }

    #[test]
    fn aggregate_declared_lengths_fail_closed() {
        let mut registry = ExecutableRegistry::new();
        assert_eq!(
            registry.register_program(
                SystemImage::A,
                b"/usr/bin/large",
                MAX_REGISTERED_BYTES,
                b"/lib64/ld.so",
                b"loader".len(),
            ),
            Err(RegistryError::Capacity)
        );
        assert_eq!(registry.program_count(), 0);
        assert_eq!(registry.image_count(), 0);
    }
}
