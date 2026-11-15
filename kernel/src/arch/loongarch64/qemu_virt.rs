//! Explicit QEMU `loongarch64/virt` platform contract.
//!
//! The direct-boot ABI supplies an EFI System Table in `$a2`; its configuration
//! table names the firmware DTB. These values and the IOCSR protocol belong to
//! QEMU's machine contract, isolated here so generic LoongArch memory and CPU
//! topology never treat them as hardware facts for another board.

/// Root `compatible` emitted by the QEMU `virt` machine.
pub const MACHINE_COMPATIBLE: &str = "linux,dummy-loongson3";
/// Maximum DTB size accepted before allocating a parser view.
pub const FDT_LIMIT: usize = 1024 * 1024;

/// EFI System Table signature, little-endian `"IBI SYST"`.
pub const EFI_SYSTEM_TABLE_SIGNATURE: u64 = 0x5453_5953_2049_4249;
pub const EFI_SYSTEM_TABLE_NR_TABLES: u64 = 104;
pub const EFI_SYSTEM_TABLE_CONFIG_TABLES: u64 = 112;
pub const EFI_CONFIG_TABLE_ENTRY_BYTES: u64 = 24;
/// Firmware supplies a short configuration table. Exceeding this audit budget
/// is malformed or hostile input, not a larger hardware topology.
pub const EFI_CONFIG_TABLE_BUDGET: u64 = 64;
/// Raw GUID `b1b621d5-f19c-41a5-830b-d9152c69aae0`
/// (`DEVICE_TREE_GUID` from the EFI boot ABI).
pub const EFI_DEVICE_TREE_GUID: [u8; 16] = [
    0xd5, 0x21, 0xb6, 0xb1, 0x9c, 0xf1, 0xa5, 0x41, 0x83, 0x0b, 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0,
];

pub const IOCSR_IPI_STATUS: u64 = 0x1000;
pub const IOCSR_IPI_EN: u64 = 0x1004;
pub const IOCSR_IPI_CLEAR: u64 = 0x100c;
pub const IOCSR_IPI_SEND: u64 = 0x1040;
pub const IOCSR_MBUF_SEND: u64 = 0x1048;
