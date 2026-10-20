//! 错误文本的本地化渲染：把系统调用的返回值变成人类可读的中文或英文。
//! Localized rendering of error texts: turn a system-call return value into human-readable Chinese or English.
//!
//! # 职责
//! * 定义与语言无关的错误文本条目 [`ErrorText`] 与语言选择 [`Lang`]
//! * 按系统调用返回约定（`ret < 0` ⇒ 错误码 ID 为 `-ret`）在**已按 ID 升序排列**的表里二分查找
//! * 把「不是错误」「未登记的 ID」作为显式的 [`RenderError`] 返回，绝不猜测文本
//!
//! # 边界
//! 只做查找与选择，不解析登记表、不生成代码、不打印。表由构建期依据系统接口登记表生成；
//! 本模块没有全局状态、没有锁、不分配内存，因此可在任意上下文（含中断与多处理器）调用。
//! 语言只是显示层的选择，**不是**授权或 ABI 的一部分：错误码的身份永远是登记表里的数字 ID 与规范名。
//!
//! # 为什么放在 kernel-core
//! 错误码属于内核的纯机制，渲染规则与 ISA、终端、日志格式无关；放在这里可以在宿主上完整测试。
//! This module only looks up and selects text; it owns no state and performs no allocation.

/// 输出语言。
/// Output language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    /// 中文。
    /// Chinese.
    Zh,
    /// 英文。
    /// English.
    En,
}

/// 一个错误码的人类可读文本。
/// Human-readable text for one error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorText {
    /// 错误码 ID（登记表中 `error` 种类的稳定数字）。
    /// Stable error-code ID from the registry.
    pub id: u32,
    /// 规范名（`system.<领域>.error.<代码>`）。
    /// Canonical name.
    pub name: &'static str,
    /// 中文文本。
    /// Chinese text.
    pub zh: &'static str,
    /// 英文文本。
    /// English text.
    pub en: &'static str,
}

/// 渲染失败的原因。
/// Why rendering failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderError {
    /// 返回值不是错误（`ret >= 0`）。
    /// The return value is not an error (`ret >= 0`).
    NotAnError,
    /// 错误表里没有这个 ID。
    /// The error table has no entry for this ID.
    Unknown {
        /// 从返回值解出的错误码 ID。
        /// Error-code ID decoded from the return value.
        id: u32,
    },
}

/// 表是否严格按 ID 升序且无重复。
///
/// [`render_error`] 依赖这个前提做二分查找；构建期生成器保证它成立，宿主测试也锁定它。
/// Whether the table is strictly ascending by ID (the precondition of [`render_error`]).
pub fn table_is_sorted_unique(table: &[ErrorText]) -> bool {
    table.windows(2).all(|w| w[0].id < w[1].id)
}

/// 把一个系统调用返回值渲染成指定语言的错误文本。
///
/// `ret >= 0` ⇒ [`RenderError::NotAnError`]；`ret < 0` 时错误码为 `-ret`，
/// 表中不存在该 ID ⇒ [`RenderError::Unknown`]。查找是二分查找，要求 `table` 已按 ID 升序且无重复
/// （可用 [`table_is_sorted_unique`] 检查）。
/// Renders a system-call return value, treating `-(id)` as an error code.
pub fn render_error(table: &[ErrorText], ret: i64, lang: Lang) -> Result<&'static str, RenderError> {
    if ret >= 0 {
        return Err(RenderError::NotAnError);
    }
    // 错误码是 u32；超出 u32 的负值不可能出现在表里（ID 0 也从不登记），按未知码报告。
    let Ok(id) = u32::try_from(ret.unsigned_abs()) else {
        return Err(RenderError::Unknown { id: 0 });
    };
    match table.binary_search_by_key(&id, |e| e.id) {
        Ok(i) => Ok(match lang {
            Lang::Zh => table[i].zh,
            Lang::En => table[i].en,
        }),
        Err(_) => Err(RenderError::Unknown { id }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: &[ErrorText] = &[
        ErrorText { id: 4097, name: "system.error.unsupported", zh: "不支持的接口", en: "Unsupported interface" },
        ErrorText { id: 4098, name: "system.error.rights_denied", zh: "权限不足", en: "Permission denied" },
        ErrorText { id: 4101, name: "system.handle.error.invalid", zh: "句柄无效", en: "Invalid handle" },
    ];

    #[test]
    fn renders_the_same_code_in_both_languages() {
        assert_eq!(render_error(TABLE, -4098, Lang::Zh), Ok("权限不足"));
        assert_eq!(render_error(TABLE, -4098, Lang::En), Ok("Permission denied"));
        assert_eq!(render_error(TABLE, -4101, Lang::En), Ok("Invalid handle"));
    }

    #[test]
    fn rejects_non_errors_and_unknown_codes() {
        assert_eq!(render_error(TABLE, 0, Lang::Zh), Err(RenderError::NotAnError));
        assert_eq!(render_error(TABLE, 7, Lang::En), Err(RenderError::NotAnError));
        assert_eq!(render_error(TABLE, -4095, Lang::Zh), Err(RenderError::Unknown { id: 4095 }));
        assert_eq!(render_error(TABLE, -9999, Lang::En), Err(RenderError::Unknown { id: 9999 }));
    }

    #[test]
    fn identifies_unsorted_or_duplicated_tables() {
        assert!(table_is_sorted_unique(TABLE), "生成器的输出必须有序且唯一");
        assert!(table_is_sorted_unique(&[]), "空表平凡有序");
        const UNSORTED: &[ErrorText] = &[
            ErrorText { id: 4098, name: "a", zh: "甲", en: "A" },
            ErrorText { id: 4097, name: "b", zh: "乙", en: "B" },
        ];
        const DUPLICATED: &[ErrorText] = &[
            ErrorText { id: 4097, name: "a", zh: "甲", en: "A" },
            ErrorText { id: 4097, name: "b", zh: "乙", en: "B" },
        ];
        assert!(!table_is_sorted_unique(UNSORTED), "乱序表必须被识别");
        assert!(!table_is_sorted_unique(DUPLICATED), "重复 ID 必须被识别");
    }
}
