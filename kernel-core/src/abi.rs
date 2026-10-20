//! 系统接口登记表（M3.2）：「名字是身份，数字是 ABI」的解析、校验与冻结检查。
//!
//! # 职责
//! * 解析登记表文本（`abi/system-ids.txt`）：每行一个接口，**数字 ID 由人显式写出**
//! * 校验：ID 唯一、名字唯一、名字符合命名约定（词法、保留根、受控动词、禁用词）
//! * 冻结检查：与 `abi/system-ids.lock`（已发布接口）比对——已发布的条目不得删除、改号、改名、改种类
//!
//! # 为什么放在 kernel-core
//! 内核的 `build.rs` 在构建期调用这里的函数：校验不过就**构建失败**；这些规则本身用宿主单元测试锁死。
//! 生成器**只读取与校验**，从不按名字排序、哈希或自动分配编号——新增接口只能由人追加新 ID。
//!
//! # 行格式（登记表用制表符分隔，`#` 开头为注释）
//! `ID 种类 名字 版本 副作用 中文显示名 英文显示名`，例如：
//! `3	op	system.time.now	1	read	时间·读取当前时刻	Current time`
//! 种类：`op`（可调用）/ `error`（错误码，系统调用以 `-(ID)` 返回）。
//! 中文显示名内部可以含空格；英文显示名是第 6 个字段之后的**整行剩余部分**（首尾修剪），
//! 因此内部可以含单个空格。旧格式的 6 列行仍可解析（英文显示名为空串），只用于兼容锁文件。
//!
//! 中文与英文显示名在登记表中必须同时存在；英文名只允许可打印 ASCII，以便错误文本在任何输出设备上稳定呈现。
//! Display names exist in both Chinese and English; English names are restricted to printable ASCII.

/// 一条登记记录（借用原始文本，无分配）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbiLine<'a> {
    /// 稳定数字 ID（> 0）。
    pub id: u32,
    /// 种类：`op` 或 `error`。
    pub kind: &'a str,
    /// 规范名。
    pub name: &'a str,
    /// 主版本。
    pub version: u16,
    /// 副作用：`none` / `read` / `write` / `irreversible`（错误码填 `none`）。
    pub effects: &'a str,
    /// 中文显示名。
    pub display_zh: &'a str,
    /// 英文显示名（登记表必填；锁文件旧行缺省为空串）。English display name.
    pub display_en: &'a str,
}

/// 登记表错误（带行号，供构建期诊断）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiError {
    /// 字段数不足或无法解析。
    Malformed { line: usize },
    /// ID 为 0 或重复。
    DuplicateId { line: usize, id: u32 },
    /// 名字重复。
    DuplicateName { line: usize },
    /// 名字违反命名约定。
    BadName { line: usize, reason: &'static str },
    /// 种类或副作用取值非法。
    BadField { line: usize, reason: &'static str },
    /// 登记表行缺少英文显示名（锁文件旧行不受此约束）。
    MissingDisplayEn { line: usize },
    /// 英文显示名违反格式规则。
    BadDisplayEn { line: usize, reason: &'static str },
    /// 已冻结（已发布）的条目被删除。
    FrozenRemoved { id: u32 },
    /// 已冻结的条目被改号、改名或改种类。
    FrozenChanged { id: u32 },
}

/// 受控动词（命名约定：操作的末段必须是其中之一，或登记过的惯例词）。
pub const VERBS: &[&str] = &[
    "create", "destroy", "open", "close", "duplicate", "restrict", "get", "list", "query", "set", "update", "read",
    "write", "send", "recv", "map", "unmap", "protect", "submit", "enter", "cancel", "wait", "signal", "spawn", "exit",
    "kill", "yield", "load", "unload", "start", "stop", "watch", "unwatch",
];
/// 惯例词（与动词同等对待）。
pub const IDIOMS: &[&str] = &["now"];
/// 允许的根。
pub const ROOTS: &[&str] = &["system", "compat", "jasper", "vendor", "app", "x"];
/// 名字中禁止出现的段（架构名与历史概念；`compat` 根除外）。
pub const FORBIDDEN_SEGMENTS: &[&str] = &["x86", "x86_64", "amd64", "aarch64", "arm64", "riscv", "fd", "errno", "pid"];

/// 检查一个规范名是否符合命名约定（词法 + 根 + 禁用段 + 末段角色）。
pub fn lint_name(name: &str, kind: &str) -> Result<(), &'static str> {
    if name.is_empty() || name.len() > 128 {
        return Err("长度须为 1..=128");
    }
    let segs: heapless_split::Segs<'_> = heapless_split::Segs::new(name);
    let mut count = 0usize;
    let mut root = "";
    let mut last = "";
    let mut has_error_seg = false;
    for (i, seg) in segs.enumerate() {
        count += 1;
        if seg.is_empty() || seg.len() > 32 {
            return Err("段为空或超过 32 字节");
        }
        let b = seg.as_bytes();
        if !b[0].is_ascii_lowercase() {
            return Err("段必须以小写字母开头");
        }
        if !b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_') || seg.contains("__") {
            return Err("段只能含小写字母、数字、单个下划线");
        }
        if i == 0 {
            root = seg;
        }
        if seg == "error" {
            has_error_seg = true;
        }
        if root != "compat" && FORBIDDEN_SEGMENTS.contains(&seg) {
            return Err("名字含架构名或历史概念");
        }
        last = seg;
    }
    if !(2..=8).contains(&count) {
        return Err("段数须为 2..=8");
    }
    if !ROOTS.contains(&root) {
        return Err("未登记的根");
    }
    match kind {
        "op" if !(VERBS.contains(&last) || IDIOMS.contains(&last)) => Err("操作末段不是受控动词或惯例词"),
        "error" if !has_error_seg => Err("错误名必须形如 <领域>.error.<代码>"),
        _ => Ok(()),
    }
}

/// 不分配内存的「按 `.` 切分」迭代器（kernel-core 零依赖，不用 alloc）。
mod heapless_split {
    /// 段迭代器。
    pub struct Segs<'a> {
        rest: Option<&'a str>,
    }
    impl<'a> Segs<'a> {
        /// 从完整名字构造。
        pub fn new(s: &'a str) -> Self {
            Segs { rest: Some(s) }
        }
    }
    impl<'a> Iterator for Segs<'a> {
        type Item = &'a str;
        fn next(&mut self) -> Option<&'a str> {
            let r = self.rest?;
            match r.find('.') {
                Some(i) => {
                    self.rest = Some(&r[i + 1..]);
                    Some(&r[..i])
                }
                None => {
                    self.rest = None;
                    Some(r)
                }
            }
        }
    }
}

/// 英文显示名的格式规则；合法返回 `None`，否则返回给构建期的原因。
///
/// 规则：非空；只含可打印 ASCII（0x20–0x7E）；首尾无空白；不含连续两个空格；不含 `#`。
/// Format rules for the English display name.
fn display_en_problem(s: &str) -> Option<&'static str> {
    if !s.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return Some("英文显示名只能含可打印 ASCII（0x20–0x7E）");
    }
    if s.trim() != s {
        return Some("英文显示名首尾不得有空白");
    }
    if s.contains("  ") {
        return Some("英文显示名不得含连续空格");
    }
    if s.contains('#') {
        return Some("英文显示名不得含 #");
    }
    None
}

/// 把一行切成前 6 个字段与可选的剩余部分（英文显示名）。
///
/// 登记表按制表符分隔：第 6 个制表符之后的整行剩余部分就是英文显示名（中文名因此可以含空格）。
/// 旧格式（少于 6 个制表符）退回按空白切分，剩余部分为空——锁文件的 6 列旧行走这条路径。
/// Splits a registry line into six fields plus the optional English display name.
fn split_fields(line: &str) -> Option<([&str; 6], Option<&str>)> {
    if line.bytes().filter(|&b| b == b'\t').count() >= 5 {
        let mut it = line.splitn(7, '\t');
        let f0 = it.next()?;
        let f1 = it.next()?;
        let f2 = it.next()?;
        let f3 = it.next()?;
        let f4 = it.next()?;
        let f5 = it.next()?;
        Some(([f0, f1, f2, f3, f4, f5], it.next()))
    } else {
        let mut it = line.split_whitespace();
        let f0 = it.next()?;
        let f1 = it.next()?;
        let f2 = it.next()?;
        let f3 = it.next()?;
        let f4 = it.next()?;
        let f5 = it.next()?;
        Some(([f0, f1, f2, f3, f4, f5], None))
    }
}

/// 解析一行；注释与空行返回 `Ok(None)`。
///
/// 英文显示名缺失时返回空串（只有锁文件旧行允许缺失；登记表的强制检查在 [`validate`] 中）。
pub fn parse_line(line_no: usize, raw: &str) -> Result<Option<AbiLine<'_>>, AbiError> {
    let trailing_blank = raw.len() != raw.trim_end().len();
    let line = raw.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    let (fields, rest) = split_fields(line).ok_or(AbiError::Malformed { line: line_no })?;
    let malformed = || AbiError::Malformed { line: line_no };
    let id: u32 = fields[0].trim().parse().map_err(|_| malformed())?;
    let kind = fields[1].trim();
    let name = fields[2].trim();
    let version: u16 = fields[3].trim().parse().map_err(|_| malformed())?;
    let effects = fields[4].trim();
    let display_zh = fields[5].trim();
    let display_en = match rest {
        None => "",
        Some(raw_rest) => {
            let trimmed = raw_rest.trim();
            // `raw.trim()` 已经吃掉行尾空白，因此行尾空白要从原始行单独判断。
            if raw_rest != trimmed || trailing_blank {
                return Err(AbiError::BadDisplayEn { line: line_no, reason: "英文显示名首尾不得有空白" });
            }
            trimmed
        }
    };
    Ok(Some(AbiLine { id, kind, name, version, effects, display_zh, display_en }))
}

/// 校验整张登记表；成功时返回条目数。`visit` 依次收到每条合法记录（构建期用来生成代码）。
pub fn validate<'a>(text: &'a str, mut visit: impl FnMut(&AbiLine<'a>)) -> Result<usize, AbiError> {
    let mut n = 0usize;
    for (i, raw) in text.lines().enumerate() {
        let line_no = i + 1;
        let Some(rec) = parse_line(line_no, raw)? else {
            continue;
        };
        if rec.id == 0 {
            return Err(AbiError::DuplicateId { line: line_no, id: 0 });
        }
        if !matches!(rec.kind, "op" | "error") {
            return Err(AbiError::BadField { line: line_no, reason: "种类须为 op 或 error" });
        }
        if !matches!(rec.effects, "none" | "read" | "write" | "irreversible") {
            return Err(AbiError::BadField { line: line_no, reason: "副作用取值非法" });
        }
        if rec.version == 0 {
            return Err(AbiError::BadField { line: line_no, reason: "版本须 ≥ 1" });
        }
        lint_name(rec.name, rec.kind).map_err(|reason| AbiError::BadName { line: line_no, reason })?;
        // 登记表强制中英齐全：英文显示名是构建期生成错误渲染表的必需列。
        if rec.display_en.is_empty() {
            return Err(AbiError::MissingDisplayEn { line: line_no });
        }
        if let Some(reason) = display_en_problem(rec.display_en) {
            return Err(AbiError::BadDisplayEn { line: line_no, reason });
        }
        // 与之前所有记录比较唯一性（登记表规模很小，O(n²) 足够且无需分配）
        for (j, prev_raw) in text.lines().enumerate().take(i) {
            if let Ok(Some(p)) = parse_line(j + 1, prev_raw) {
                if p.id == rec.id {
                    return Err(AbiError::DuplicateId { line: line_no, id: rec.id });
                }
                if p.name == rec.name {
                    return Err(AbiError::DuplicateName { line: line_no });
                }
            }
        }
        visit(&rec);
        n += 1;
    }
    Ok(n)
}

/// 冻结检查：锁文件里的每条记录必须在登记表中以**相同的 ID、种类、名字**存在。
///
/// 锁文件格式与登记表相同（只比对前三个字段）。新增接口不影响检查；删除或改动已发布接口则失败。
pub fn check_frozen(registry: &str, lock: &str) -> Result<usize, AbiError> {
    let mut n = 0usize;
    for (i, raw) in lock.lines().enumerate() {
        let Some(frozen) = parse_line(i + 1, raw)? else {
            continue;
        };
        let mut found = None;
        for (j, r) in registry.lines().enumerate() {
            if let Ok(Some(rec)) = parse_line(j + 1, r) {
                if rec.id == frozen.id {
                    found = Some(rec);
                    break;
                }
            }
        }
        match found {
            None => return Err(AbiError::FrozenRemoved { id: frozen.id }),
            Some(rec) if rec.kind != frozen.kind || rec.name != frozen.name => {
                return Err(AbiError::FrozenChanged { id: frozen.id })
            }
            Some(_) => n += 1,
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REG: &str = "# 注释\n\
1\top\tsystem.task.exit\t1\tirreversible\t任务·退出\tExit task\n\
3\top\tsystem.time.now\t1\tread\t时间·当前时刻\tCurrent time\n\
4097\terror\tsystem.error.unsupported\t1\tnone\t不支持的接口\tUnsupported interface\n";

    #[test]
    fn valid_registry_passes_and_visits_in_order() {
        let mut ids = [0u32; 3];
        let mut en = [""; 3];
        let mut k = 0;
        let n = validate(REG, |r| {
            ids[k] = r.id;
            en[k] = r.display_en;
            k += 1;
        })
        .unwrap();
        assert_eq!(n, 3);
        assert_eq!(ids, [1, 3, 4097]);
        assert_eq!(en, ["Exit task", "Current time", "Unsupported interface"]);
    }

    #[test]
    fn display_en_keeps_inner_spaces_and_chinese_keeps_its_spaces() {
        // 英文名内部的单个空格被完整保留；中文名内部也可以含空格（制表符分隔，不会被切成两个字段）。
        let reg = "23\top\tsystem.process.spawn\t1\twrite\t进程·创建子进程（映像 + 调用子集）\tSpawn child process\n";
        let mut seen = None;
        validate(reg, |r| seen = Some((r.display_zh, r.display_en))).unwrap();
        assert_eq!(seen, Some(("进程·创建子进程（映像 + 调用子集）", "Spawn child process")));
    }

    #[test]
    fn missing_or_malformed_display_en_is_rejected() {
        assert_eq!(
            validate("1\top\tsystem.task.exit\t1\tirreversible\t任务·退出\n", |_| {}),
            Err(AbiError::MissingDisplayEn { line: 1 }),
            "登记表缺英文名"
        );
        let bad = [
            ("1\top\tsystem.task.exit\t1\tirreversible\t任务·退出\tExit 任务\n", "非 ASCII"),
            ("1\top\tsystem.task.exit\t1\tirreversible\t任务·退出\t Exit task\n", "首部空白"),
            ("1\top\tsystem.task.exit\t1\tirreversible\t任务·退出\tExit task \n", "尾部空白"),
            ("1\top\tsystem.task.exit\t1\tirreversible\t任务·退出\tExit  task\n", "连续空格"),
            ("1\top\tsystem.task.exit\t1\tirreversible\t任务·退出\tExit #task\n", "含 #"),
        ];
        for (line, what) in bad {
            assert!(
                matches!(validate(line, |_| {}), Err(AbiError::BadDisplayEn { line: 1, .. })),
                "{what} 应被拒绝"
            );
        }
    }

    #[test]
    fn rejects_duplicates_and_bad_names() {
        let dup_id = "1\top\tsystem.task.exit\t1\tirreversible\ta\tExit task\n\
1\top\tsystem.task.yield\t1\tnone\tb\tYield task\n";
        assert_eq!(validate(dup_id, |_| {}), Err(AbiError::DuplicateId { line: 2, id: 1 }));
        let dup_name = "1\top\tsystem.task.exit\t1\tirreversible\ta\tExit task\n\
2\top\tsystem.task.exit\t1\tnone\tb\tExit task\n";
        assert_eq!(validate(dup_name, |_| {}), Err(AbiError::DuplicateName { line: 2 }));
        assert!(matches!(validate("5\top\tsystem.task.go\t1\tnone\tx\tGo\n", |_| {}), Err(AbiError::BadName { .. })), "非受控动词");
        assert!(matches!(validate("5\top\tsystem.x86.read\t1\tnone\tx\tRead\n", |_| {}), Err(AbiError::BadName { .. })), "架构名");
        assert!(matches!(validate("5\top\tsystem.fd.close\t1\tnone\tx\tClose\n", |_| {}), Err(AbiError::BadName { .. })), "历史概念");
        assert!(matches!(validate("5\top\tSystem.task.exit\t1\tnone\tx\tExit task\n", |_| {}), Err(AbiError::BadName { .. })), "大写");
        assert!(
            matches!(validate("5\terror\tsystem.task.oops\t1\tnone\tx\tOops\n", |_| {}), Err(AbiError::BadName { .. })),
            "错误名缺 error 段"
        );
        assert!(
            matches!(validate("5\top\tsystem.time.now\t1\tfast\tx\tNow\n", |_| {}), Err(AbiError::BadField { .. })),
            "副作用"
        );
        assert!(lint_name("compat.posix.fd.close", "op").is_ok(), "compat 根允许历史概念");
    }

    #[test]
    fn frozen_entries_cannot_be_removed_renumbered_or_renamed() {
        // 锁文件仍是 6 列（空格或制表符分隔均可），没有英文显示名也必须通过解析与冻结检查。
        let lock = "1 op system.task.exit 1 irreversible 任务·退出\n3 op system.time.now 1 read 时间\n";
        let locked = parse_line(1, "1 op system.task.exit 1 irreversible 任务·退出\n").unwrap().unwrap();
        assert_eq!(locked.display_en, "", "锁文件旧行的英文显示名为空");
        assert_eq!(check_frozen(REG, lock), Ok(2), "新增 4097 不影响冻结检查");
        let removed = "3 op system.time.now 1 read x\n";
        assert_eq!(check_frozen(removed, lock), Err(AbiError::FrozenRemoved { id: 1 }));
        let renamed = "1 op system.task.kill 1 irreversible x\n3 op system.time.now 1 read x\n";
        assert_eq!(check_frozen(renamed, lock), Err(AbiError::FrozenChanged { id: 1 }));
        let renumbered = "2 op system.task.exit 1 irreversible x\n3 op system.time.now 1 read x\n";
        assert_eq!(check_frozen(renumbered, lock), Err(AbiError::FrozenRemoved { id: 1 }));
    }
}
