//! jaso-crc：crc 的 `.jaso` 模块封装。
//! The crc crate as a `.jaso` module.
//!
//! 每个导出 `(data, len) -> 校验值`：`crc32_iso_hdlc`、`crc32_iscsi`（CRC-32C）、`crc16_ibm_sdlc`、`crc64_ecma_182`。
#![no_std]
#![no_main]

use crc::{Crc, CRC_16_IBM_SDLC, CRC_32_ISCSI, CRC_32_ISO_HDLC, CRC_64_ECMA_182};
use jaso_module as _;

static C32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);
static C32C: Crc<u32> = Crc::<u32>::new(&CRC_32_ISCSI);
static C16: Crc<u16> = Crc::<u16>::new(&CRC_16_IBM_SDLC);
static C64: Crc<u64> = Crc::<u64>::new(&CRC_64_ECMA_182);

/// CRC-32（ISO-HDLC，即常见的 CRC-32）。
///
/// # Safety
/// `data` 可读 `len` 字节。
#[no_mangle]
pub unsafe extern "C" fn crc32_iso_hdlc(data: *const u8, len: usize) -> u32 {
    C32.checksum(core::slice::from_raw_parts(data, len))
}

/// CRC-32C（iSCSI）。
///
/// # Safety
/// `data` 可读 `len` 字节。
#[no_mangle]
pub unsafe extern "C" fn crc32_iscsi(data: *const u8, len: usize) -> u32 {
    C32C.checksum(core::slice::from_raw_parts(data, len))
}

/// CRC-16（IBM-SDLC）。
///
/// # Safety
/// `data` 可读 `len` 字节。
#[no_mangle]
pub unsafe extern "C" fn crc16_ibm_sdlc(data: *const u8, len: usize) -> u16 {
    C16.checksum(core::slice::from_raw_parts(data, len))
}

/// CRC-64（ECMA-182）。
///
/// # Safety
/// `data` 可读 `len` 字节。
#[no_mangle]
pub unsafe extern "C" fn crc64_ecma_182(data: *const u8, len: usize) -> u64 {
    C64.checksum(core::slice::from_raw_parts(data, len))
}
