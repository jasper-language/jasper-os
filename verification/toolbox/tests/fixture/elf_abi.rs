// 携带 ABI 章的最小 x86_64 ELF 夹具（issue #8），由 Proptest/Miri 测试与 cargo-fuzz 目标共用。
// Minimal x86_64 ELF fixture carrying an ABI stamp, shared by the property tests and the fuzz target.
//
// 布局（全部小端）：文件头 0..64、一个程序头 64..120（PT_LOAD，代码 0x1000..0x1100，可读可执行）、
// 节头表 0x1000（空节 / .shstrtab / .note.jasper.abi，各 64 字节）、节名字符串表 0x1100、ABI 章 0x1200。
// 与 `kernel_core::elf` 单元测试中的构造器字段一致，但独立维护，避免测试依赖内核私有函数。

/// 夹具 e_machine（x86_64）。
pub const FIXTURE_MACHINE: u16 = 62;
/// 夹具总字节数。
pub const FIXTURE_LEN: usize = 0x3000;
/// 节头表偏移。
pub const FIXTURE_SHOFF: usize = 0x1000;
/// 节名字符串表偏移。
pub const FIXTURE_STRTAB: usize = 0x1100;
/// ABI 章偏移。
pub const FIXTURE_NOTE: usize = 0x1200;
/// 节名字符串表内容：下标 1 = ".shstrtab"，下标 11 = ".note.jasper.abi"。
pub const FIXTURE_NAMES: &[u8] = b"\0.shstrtab\0.note.jasper.abi\0";
/// 代码段虚拟地址（也是入口）。
pub const FIXTURE_CODE: u64 = 0x1000_0040_0000;

fn put(b: &mut [u8], off: usize, v: &[u8]) {
    b[off..off + v.len()].copy_from_slice(v);
}

/// 写第 `index` 个节头：(sh_name, sh_type, sh_offset, sh_size)。
pub fn fixture_section(b: &mut [u8], index: usize, name: u32, ty: u32, off: u64, size: u64) {
    let s = FIXTURE_SHOFF + index * 64;
    put(b, s, &name.to_le_bytes());
    put(b, s + 4, &ty.to_le_bytes());
    put(b, s + 24, &off.to_le_bytes());
    put(b, s + 32, &size.to_le_bytes());
}

/// 构造一个合法 ELF，ABI 章内容为 `note`（可以是非法章，用来测拒绝）。
pub fn fixture_elf(note: &[u8; 28]) -> Vec<u8> {
    let mut b = vec![0u8; FIXTURE_LEN];
    put(&mut b, 0, b"\x7fELF");
    b[4] = 2; // ELFCLASS64
    b[5] = 1; // 小端
    b[6] = 1; // EV_CURRENT
    put(&mut b, 16, &2u16.to_le_bytes()); // ET_EXEC
    put(&mut b, 18, &FIXTURE_MACHINE.to_le_bytes());
    put(&mut b, 24, &FIXTURE_CODE.to_le_bytes());
    put(&mut b, 32, &64u64.to_le_bytes()); // e_phoff
    put(&mut b, 40, &(FIXTURE_SHOFF as u64).to_le_bytes()); // e_shoff
    put(&mut b, 54, &56u16.to_le_bytes()); // e_phentsize
    put(&mut b, 56, &1u16.to_le_bytes()); // e_phnum
    put(&mut b, 58, &64u16.to_le_bytes()); // e_shentsize
    put(&mut b, 60, &3u16.to_le_bytes()); // e_shnum
    put(&mut b, 62, &1u16.to_le_bytes()); // e_shstrndx
    // 程序头：PT_LOAD，R+X，文件 0x1000 起 0x100 字节映射到代码地址。
    put(&mut b, 64, &1u32.to_le_bytes());
    put(&mut b, 68, &5u32.to_le_bytes());
    put(&mut b, 72, &0x1000u64.to_le_bytes());
    put(&mut b, 80, &FIXTURE_CODE.to_le_bytes());
    put(&mut b, 96, &0x100u64.to_le_bytes());
    put(&mut b, 104, &0x100u64.to_le_bytes());
    fixture_section(&mut b, 1, 1, 3, FIXTURE_STRTAB as u64, FIXTURE_NAMES.len() as u64);
    fixture_section(&mut b, 2, 11, 7, FIXTURE_NOTE as u64, 28);
    put(&mut b, FIXTURE_STRTAB, FIXTURE_NAMES);
    put(&mut b, FIXTURE_NOTE, note);
    b
}
