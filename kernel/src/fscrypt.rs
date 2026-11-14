//! Bounded, filesystem-neutral fscrypt keyring and AES-XTS data transform.
//!
//! The compatibility VFS does not yet model arbitrary directories, but the
//! Android fscrypt UAPI still has to behave honestly.  This module owns the
//! cryptographic key hierarchy independently from each backing object:
//!
//! * v1 master keys use fscrypt's AES-128-ECB file-key KDF.
//! * v2 master keys use HKDF-SHA512 and return a derived key identifier.
//! * encrypted contents use AES-256-XTS with one tweak per 4 KiB data unit.
//!
//! Keys never live in an object's policy record.  Removing the last keyring
//! claim therefore locks every policy that references it, and subsequent file
//! I/O fails with ENOKEY instead of silently reading ciphertext.

use crate::sync::SpinLock;
use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes256};
use hmac::{Hmac, Mac};
use kernel_core::security::BootId;
use sha2::{Digest, Sha512};
use xts_mode::{get_tweak_default, Xts128};

pub(crate) const KEY_SPEC_TYPE_DESCRIPTOR: u32 = 1;
pub(crate) const KEY_SPEC_TYPE_IDENTIFIER: u32 = 2;
pub(crate) const MAX_KEY_BYTES: usize = 64;
pub(crate) const FILE_NONCE_BYTES: usize = 16;

const DATA_UNIT_BYTES: usize = kernel_core::frame::FRAME_SIZE as usize;
const MAX_KEYS: usize = 4;
const MAX_KEY_USERS: usize = 4;
const HKDF_CONTEXT_KEY_IDENTIFIER: u8 = 1;
const HKDF_CONTEXT_PER_FILE_ENC_KEY: u8 = 2;

type HmacSha512 = Hmac<Sha512>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FscryptError {
    Invalid,
    Permission,
    NoKey,
    NoSpace,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KeySpecifier {
    pub(crate) kind: u32,
    pub(crate) bytes: [u8; 32],
}

impl KeySpecifier {
    pub(crate) const fn descriptor(bytes: [u8; 8]) -> Self {
        let mut value = [0u8; 32];
        let mut index = 0;
        while index < bytes.len() {
            value[index] = bytes[index];
            index += 1;
        }
        Self {
            kind: KEY_SPEC_TYPE_DESCRIPTOR,
            bytes: value,
        }
    }

    pub(crate) const fn identifier(bytes: [u8; 16]) -> Self {
        let mut value = [0u8; 32];
        let mut index = 0;
        while index < bytes.len() {
            value[index] = bytes[index];
            index += 1;
        }
        Self {
            kind: KEY_SPEC_TYPE_IDENTIFIER,
            bytes: value,
        }
    }

    pub(crate) fn is_valid(self) -> bool {
        match self.kind {
            KEY_SPEC_TYPE_DESCRIPTOR => self.bytes[8..].iter().all(|byte| *byte == 0),
            KEY_SPEC_TYPE_IDENTIFIER => true,
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Policy {
    V1 {
        contents_mode: u8,
        filenames_mode: u8,
        flags: u8,
        descriptor: [u8; 8],
    },
    V2 {
        contents_mode: u8,
        filenames_mode: u8,
        flags: u8,
        log2_data_unit_size: u8,
        identifier: [u8; 16],
    },
}

impl Policy {
    pub(crate) fn validate(self) -> Result<(), FscryptError> {
        let (contents_mode, filenames_mode, flags) = match self {
            Self::V1 {
                contents_mode,
                filenames_mode,
                flags,
                ..
            }
            | Self::V2 {
                contents_mode,
                filenames_mode,
                flags,
                ..
            } => (contents_mode, filenames_mode, flags),
        };
        // This synthetic regular-file backend implements contents encryption;
        // filename CTS will be used by the directory VFS when it grows that
        // surface.  Accept the UAPI mode here but reject an unsupported content
        // transform instead of pretending it was applied.
        if contents_mode != 1
            || !matches!(filenames_mode, 1 | 4 | 5 | 6 | 7 | 8 | 9 | 10)
            || flags & !0x03 != 0
        {
            return Err(FscryptError::Invalid);
        }
        if let Self::V2 {
            log2_data_unit_size,
            ..
        } = self
        {
            if !matches!(log2_data_unit_size, 0 | 12) {
                return Err(FscryptError::Invalid);
            }
        }
        Ok(())
    }

    pub(crate) fn key_specifier(self) -> KeySpecifier {
        match self {
            Self::V1 { descriptor, .. } => KeySpecifier::descriptor(descriptor),
            Self::V2 { identifier, .. } => KeySpecifier::identifier(identifier),
        }
    }
}

#[derive(Clone, Copy)]
struct StoredKey {
    spec: KeySpecifier,
    raw: [u8; MAX_KEY_BYTES],
    raw_len: u8,
    users: [u32; MAX_KEY_USERS],
    user_len: u8,
}

struct Keyring {
    entries: [Option<StoredKey>; MAX_KEYS],
    next_nonce: u64,
}

static KEYRING: SpinLock<Keyring> = SpinLock::new(Keyring {
    entries: [None; MAX_KEYS],
    next_nonce: 1,
});

fn hmac_sha512(key: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut mac = <HmacSha512 as hmac::KeyInit>::new_from_slice(key)
        .expect("HMAC-SHA512 accepts arbitrary key lengths");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

fn hkdf_extract(master_key: &[u8]) -> [u8; 64] {
    let salt = [0u8; 64];
    hmac_sha512(&salt, &[master_key])
}

fn hkdf_expand(prk: [u8; 64], context: u8, info: &[u8]) -> [u8; 64] {
    hmac_sha512(&prk, &[b"fscrypt\0", &[context], info, &[1]])
}

fn identifier_for_raw_key(raw: &[u8]) -> [u8; 16] {
    let expanded = hkdf_expand(hkdf_extract(raw), HKDF_CONTEXT_KEY_IDENTIFIER, &[]);
    let mut identifier = [0u8; 16];
    identifier.copy_from_slice(&expanded[..16]);
    identifier
}

fn boot_material(boot: BootId) -> [u8; 32] {
    let mut hash = Sha512::new();
    hash.update(b"jasper-fscrypt-boot-material-v1");
    hash.update(boot.words[0].to_le_bytes());
    hash.update(boot.words[1].to_le_bytes());
    let digest = hash.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest[..32]);
    output
}

pub(crate) fn pwsalt(boot: BootId) -> [u8; 16] {
    let value = boot_material(boot);
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&value[..16]);
    salt
}

pub(crate) fn next_file_nonce(boot: BootId, object_id: u64) -> [u8; 16] {
    let sequence = {
        let mut ring = KEYRING.lock();
        let value = ring.next_nonce;
        ring.next_nonce = ring.next_nonce.wrapping_add(1).max(1);
        value
    };
    let mut hash = Sha512::new();
    hash.update(b"jasper-fscrypt-file-nonce-v1");
    hash.update(boot.words[0].to_le_bytes());
    hash.update(boot.words[1].to_le_bytes());
    hash.update(object_id.to_le_bytes());
    hash.update(sequence.to_le_bytes());
    let digest = hash.finalize();
    let mut nonce = [0u8; FILE_NONCE_BYTES];
    nonce.copy_from_slice(&digest[..FILE_NONCE_BYTES]);
    nonce
}

pub(crate) fn add_key(
    requested: KeySpecifier,
    raw: &[u8],
    uid: u32,
    has_sys_admin: bool,
) -> Result<KeySpecifier, FscryptError> {
    if !requested.is_valid()
        || !(16..=MAX_KEY_BYTES).contains(&raw.len())
        || raw.len() % 16 != 0
    {
        return Err(FscryptError::Invalid);
    }
    if requested.kind == KEY_SPEC_TYPE_DESCRIPTOR && !has_sys_admin {
        return Err(FscryptError::Permission);
    }
    let spec = if requested.kind == KEY_SPEC_TYPE_IDENTIFIER {
        KeySpecifier::identifier(identifier_for_raw_key(raw))
    } else {
        requested
    };
    let mut ring = KEYRING.lock();
    if let Some(existing) = ring
        .entries
        .iter_mut()
        .flatten()
        .find(|entry| entry.spec == spec)
    {
        if &existing.raw[..existing.raw_len as usize] != raw {
            return Err(FscryptError::NoKey);
        }
        if !existing.users[..existing.user_len as usize].contains(&uid) {
            if existing.user_len as usize == MAX_KEY_USERS {
                return Err(FscryptError::NoSpace);
            }
            existing.users[existing.user_len as usize] = uid;
            existing.user_len += 1;
        }
        return Ok(spec);
    }
    let Some(slot) = ring.entries.iter_mut().find(|entry| entry.is_none()) else {
        return Err(FscryptError::NoSpace);
    };
    let mut stored = StoredKey {
        spec,
        raw: [0; MAX_KEY_BYTES],
        raw_len: raw.len() as u8,
        users: [0; MAX_KEY_USERS],
        user_len: 1,
    };
    stored.raw[..raw.len()].copy_from_slice(raw);
    stored.users[0] = uid;
    *slot = Some(stored);
    Ok(spec)
}

fn take_key(spec: KeySpecifier) -> Option<([u8; MAX_KEY_BYTES], u8)> {
    KEYRING
        .lock()
        .entries
        .iter()
        .flatten()
        .find(|entry| entry.spec == spec)
        .map(|entry| (entry.raw, entry.raw_len))
}

pub(crate) fn remove_key(
    spec: KeySpecifier,
    uid: u32,
    all_users: bool,
    has_sys_admin: bool,
) -> Result<u32, FscryptError> {
    if !spec.is_valid() {
        return Err(FscryptError::Invalid);
    }
    if spec.kind == KEY_SPEC_TYPE_DESCRIPTOR && !has_sys_admin {
        return Err(FscryptError::Permission);
    }
    if spec.kind == KEY_SPEC_TYPE_IDENTIFIER && all_users && !has_sys_admin {
        return Err(FscryptError::Permission);
    }
    let mut ring = KEYRING.lock();
    let Some(index) = ring
        .entries
        .iter()
        .position(|entry| entry.is_some_and(|entry| entry.spec == spec))
    else {
        return Err(FscryptError::NoKey);
    };
    let Some(mut key) = ring.entries[index] else {
        return Err(FscryptError::NoKey);
    };
    if spec.kind == KEY_SPEC_TYPE_DESCRIPTOR {
        let mut key = key;
        key.raw.fill(0);
        ring.entries[index] = None;
        return Ok(0);
    }
    let Some(user_index) = key.users[..key.user_len as usize]
        .iter()
        .position(|candidate| *candidate == uid)
    else {
        return Err(FscryptError::NoKey);
    };
    if all_users {
        key.raw.fill(0);
        ring.entries[index] = None;
        return Ok(0);
    }
    let len = key.user_len as usize;
    for index in user_index..len - 1 {
        key.users[index] = key.users[index + 1];
    }
    key.users[len - 1] = 0;
    key.user_len -= 1;
    if key.user_len == 0 {
        key.raw.fill(0);
        ring.entries[index] = None;
        Ok(0)
    } else {
        ring.entries[index] = Some(key);
        Ok(2)
    }
}

pub(crate) fn key_status(spec: KeySpecifier, uid: u32) -> Result<(u32, u32, u32), FscryptError> {
    if !spec.is_valid() {
        return Err(FscryptError::Invalid);
    }
    let ring = KEYRING.lock();
    let Some(key) = ring
        .entries
        .iter()
        .flatten()
        .find(|entry| entry.spec == spec)
    else {
        return Ok((1, 0, 0));
    };
    if spec.kind == KEY_SPEC_TYPE_DESCRIPTOR {
        return Ok((2, 0, 0));
    }
    let added_by_self = key.users[..key.user_len as usize].contains(&uid);
    Ok((2, u32::from(added_by_self), u32::from(key.user_len)))
}

pub(crate) fn key_added_by(spec: KeySpecifier, uid: u32) -> bool {
    let ring = KEYRING.lock();
    ring.entries
        .iter()
        .flatten()
        .find(|entry| entry.spec == spec)
        .is_some_and(|entry| entry.users[..entry.user_len as usize].contains(&uid))
}

fn derive_v1_key(master: &[u8], nonce: &[u8; 16]) -> [u8; MAX_KEY_BYTES] {
    let cipher = Aes128::new(&Array(*nonce));
    let mut output = [0u8; MAX_KEY_BYTES];
    for (index, chunk) in master.chunks_exact(16).take(4).enumerate() {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        let mut encrypted = Array::from(block);
        cipher.encrypt_block(&mut encrypted);
        output[index * 16..(index + 1) * 16].copy_from_slice(&encrypted);
    }
    output
}

fn derive_v2_key(master: &[u8], nonce: &[u8; 16]) -> [u8; MAX_KEY_BYTES] {
    hkdf_expand(hkdf_extract(master), HKDF_CONTEXT_PER_FILE_ENC_KEY, nonce)
}

fn derive_file_key(policy: Policy, master: &[u8], nonce: &[u8; 16]) -> [u8; MAX_KEY_BYTES] {
    match policy {
        Policy::V1 { .. } => derive_v1_key(master, nonce),
        Policy::V2 { .. } => derive_v2_key(master, nonce),
    }
}

pub(crate) struct FileCipher {
    key: [u8; MAX_KEY_BYTES],
}

impl FileCipher {
    pub(crate) fn new(policy: Policy, nonce: [u8; 16]) -> Result<Self, FscryptError> {
        let spec = policy.key_specifier();
        let (raw, raw_len) = take_key(spec).ok_or(FscryptError::NoKey)?;
        let master = &raw[..raw_len as usize];
        if matches!(policy, Policy::V1 { .. }) && master.len() < MAX_KEY_BYTES {
            return Err(FscryptError::NoKey);
        }
        Ok(Self {
            key: derive_file_key(policy, master, &nonce),
        })
    }

    fn apply(&self, data_unit_index: u64, data: &mut [u8], decrypt: bool) {
        debug_assert_eq!(data.len(), DATA_UNIT_BYTES);
        let mut key_1 = [0u8; 32];
        let mut key_2 = [0u8; 32];
        key_1.copy_from_slice(&self.key[..32]);
        key_2.copy_from_slice(&self.key[32..]);
        let cipher_1 = Aes256::new(&Array(key_1));
        let cipher_2 = Aes256::new(&Array(key_2));
        let xts = Xts128::<Aes256>::new(cipher_1, cipher_2);
        let tweak = get_tweak_default(data_unit_index as u128);
        if decrypt {
            xts.decrypt_sector(data, tweak);
        } else {
            xts.encrypt_sector(data, tweak);
        }
    }

    pub(crate) fn encrypt(&self, data_unit_index: u64, data: &mut [u8]) {
        self.apply(data_unit_index, data, false);
    }

    pub(crate) fn decrypt(&self, data_unit_index: u64, data: &mut [u8]) {
        self.apply(data_unit_index, data, true);
    }
}
