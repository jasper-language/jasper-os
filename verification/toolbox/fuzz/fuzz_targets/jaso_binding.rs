#![no_main]
//! `jasper.import` 判定（SPEC §9.4）：任意字节不 panic；放行时每个非生命周期导出都恰有一行 `fn`，`fn` 只声明这些导出，`cap` 都在清单里。
use jaso::binding::check;
use jaso::Manifest;

const MANIFEST: &str = "core.name = m\ncore.version = 1.0.0\ncore.abi = c.v1\ncore.stage = runtime\ncore.requires = log, alloc\ncore.exports = jaso_init, f_one, f_two\n";

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let m = Manifest::parse(MANIFEST).unwrap();
    if check(data, &m).is_err() {
        return;
    }
    let text = core::str::from_utf8(data).expect("放行的绑定必须是 UTF-8");
    let effective = || text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#'));
    let fns: Vec<&str> = effective().filter_map(|l| l.strip_prefix("fn ")).map(|r| r.split('(').next().unwrap().trim()).collect();
    assert_eq!(fns.len(), 2, "导出与 fn 行必须一一对应");
    assert!(fns.contains(&"f_one") && fns.contains(&"f_two"));
    for c in effective().filter_map(|l| l.strip_prefix("cap ")) {
        assert!(matches!(c.trim(), "log" | "alloc"), "能力不得超出清单");
    }
    assert!(!data.contains(&b'*') || effective().all(|l| !l.contains('*')), "绑定里不能有裸指针");
});
