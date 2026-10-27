//! format 0 → format 1 的一次性迁移（SPEC §15）。
//! One-time migration of format 0 files to format 1.
//!
//! format 0 只有 Native 一种、单镜像：头部偏移 32 是映像大小，段种类 1–5 与 format 1 的布局相同。
//! 迁移读出 format 0 的清单、映像段、导出与重定位（先校验其完整性摘要与段的边界），
//! 按 format 1 重新写出：平台记录取 jasper-os 原生平台、调用约定照抄清单的 `core.abi`；
//! 清单缺 `core.stage` 时按 format 0 头部的阶段补上一行。
//!
//! **迁移不改变模块代码的约定**：清单里的 `core.abi = c.v0` / `core.host = jaso.host.v0` 原样保留，
//! 只认 `c.v1` 的装载器会以 `platform.mismatch`（字段 abi）拒绝它——旧调用约定的模块须重新编译才能运行。
//! 原签名覆盖的是 format 0 的字节，迁移后必然失效，所以不保留；需要签名时由调用者重新签名。

use alloc::vec::Vec;

use crate::build::{Builder, SegmentIn};
use crate::{digest_of, Arch, JasoError, Stage, DIGEST_OFFSET, EXPORT_SIZE, HEADER_SIZE, MAGIC, MAX_SECTIONS, RELOC_SIZE, SECTION_SIZE};

/// 迁移错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrateError {
    /// 不是合格的 format 0 文件（附原因）。
    NotFormat0(&'static str),
    /// 迁移结果没有通过 format 1 校验。
    Format(JasoError),
}

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(o..o + 8)?.try_into().ok()?))
}

/// 把一个 format 0 文件迁移为 format 1（未签名）。
pub fn from_v0(bytes: &[u8]) -> Result<Vec<u8>, MigrateError> {
    let bad = MigrateError::NotFormat0;
    if bytes.len() < HEADER_SIZE || bytes[..8] != MAGIC {
        return Err(bad("头部"));
    }
    if u16_at(bytes, 8) != Some(0) || u16_at(bytes, 10) != Some(1) {
        return Err(bad("不是 format 0 的 Native 文件"));
    }
    let arch = u16_at(bytes, 12).and_then(Arch::from_u16).ok_or(bad("指令集"))?;
    let stage = Stage::from_u8(bytes[14]).ok_or(bad("装载阶段"))?;
    if u32_at(bytes, 28) != Some(bytes.len() as u32) || bytes[DIGEST_OFFSET..DIGEST_OFFSET + 32] != digest_of(bytes) {
        return Err(bad("长度或完整性摘要"));
    }
    let count = u32_at(bytes, 20).ok_or(bad("头部"))?;
    let dir = u32_at(bytes, 24).ok_or(bad("头部"))? as usize;
    if count == 0 || count > MAX_SECTIONS || dir < HEADER_SIZE {
        return Err(bad("段目录"));
    }
    let mut manifest = None;
    let mut b = Builder::native(arch, stage, &[]);
    for i in 0..count as usize {
        let o = dir + i * SECTION_SIZE;
        let field = |k: usize| u32_at(bytes, o + k).ok_or(bad("段目录越界"));
        let (kind, flags, off, size, vaddr, mem) = (field(0)?, field(4)?, field(8)?, field(12)?, field(16)?, field(20)?);
        let end = off.checked_add(size).ok_or(bad("段越界"))? as usize;
        let data = bytes.get(off as usize..end).ok_or(bad("段越界"))?;
        match kind {
            1 => manifest = Some(data),
            2 => b.segments.push(SegmentIn { vaddr, mem_size: mem, flags, data: data.to_vec() }),
            3 => {
                let n = u32_at(data, 0).ok_or(bad("导出表"))? as usize;
                for k in 0..n {
                    let e = 4 + k * EXPORT_SIZE;
                    let (no, nl, value) = (
                        u32_at(data, e).ok_or(bad("导出表"))? as usize,
                        u32_at(data, e + 4).ok_or(bad("导出表"))? as usize,
                        u32_at(data, e + 8).ok_or(bad("导出表"))?,
                    );
                    let name = data.get(no..no.checked_add(nl).ok_or(bad("导出名"))?).ok_or(bad("导出名"))?;
                    b.exports.push((name.to_vec(), value));
                }
            }
            4 => {
                let n = u32_at(data, 0).ok_or(bad("重定位表"))? as usize;
                for k in 0..n {
                    let r = 4 + k * RELOC_SIZE;
                    b.relocs.push((u32_at(data, r).ok_or(bad("重定位表"))?, u64_at(data, r + 8).ok_or(bad("重定位表"))?));
                }
            }
            5 => {} // 原签名迁移后必然失效
            _ => return Err(bad("未知段种类")),
        }
    }
    let mut text = manifest.ok_or(bad("缺清单"))?.to_vec();
    let has_stage = core::str::from_utf8(&text)
        .map_err(|_| bad("清单不是 UTF-8"))?
        .lines()
        .any(|l| l.split_once('=').is_some_and(|(k, _)| k.trim() == "core.stage"));
    if !has_stage {
        if !text.is_empty() && !text.ends_with(b"\n") {
            text.push(b'\n');
        }
        text.extend_from_slice(b"core.stage = ");
        text.extend_from_slice(stage.name().as_bytes());
        text.push(b'\n');
    }
    b.manifest = text;
    b.finish().map_err(MigrateError::Format)
}
