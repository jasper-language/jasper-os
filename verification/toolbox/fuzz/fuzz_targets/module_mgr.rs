#![no_main]
//! issue #6 第一片补链：既有 ModuleManager 的任意 load / unload / unload_all 序列——
//! 已装载集合恒对 requires 闭包且依赖排在前面、init 失败不装载、被依赖时拒绝卸载、逆序全部卸载。
use kernel_core::module::{ModuleDescriptor, ModuleError, ModuleManager};

static MA: ModuleDescriptor = ModuleDescriptor { name: "ma", requires: &[], init: || Ok(()), fini: || {} };
static MB: ModuleDescriptor = ModuleDescriptor { name: "mb", requires: &["ma"], init: || Ok(()), fini: || {} };
static MC: ModuleDescriptor = ModuleDescriptor { name: "mc", requires: &["ma", "mb"], init: || Ok(()), fini: || {} };
static MD: ModuleDescriptor = ModuleDescriptor { name: "md", requires: &[], init: || Ok(()), fini: || {} };
static ME: ModuleDescriptor = ModuleDescriptor { name: "me", requires: &["md"], init: || Err("boom"), fini: || {} };
static POOL: [&ModuleDescriptor; 5] = [&MA, &MB, &MC, &MD, &ME];

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut mm: ModuleManager<3> = ModuleManager::new();
    for &b in data.iter().take(64) {
        let d = POOL[(b >> 2) as usize % 5];
        match b & 3 {
            0 | 1 => {
                let before = mm.len();
                match mm.load(d) {
                    Ok(()) => assert_eq!(mm.len(), before + 1),
                    Err(ModuleError::InitFailed(n, _)) => assert!(n == "me" && !mm.is_loaded("me")),
                    Err(_) => assert_eq!(mm.len(), before),
                }
            }
            2 => {
                let user = mm.loaded().find(|m| m.requires.contains(&d.name)).map(|m| m.name);
                let was = mm.is_loaded(d.name);
                match mm.unload(d.name) {
                    Ok(()) => assert!(was && user.is_none() && !mm.is_loaded(d.name)),
                    Err(ModuleError::InUse(_, u)) => assert_eq!(Some(u), user),
                    Err(e) => assert!(e == ModuleError::NotLoaded && !was),
                }
            }
            _ => {
                let n = mm.len();
                assert_eq!(mm.unload_all(), n);
                assert!(mm.is_empty());
            }
        }
        let names: Vec<&str> = mm.loaded().map(|m| m.name).collect();
        for (i, m) in mm.loaded().enumerate() {
            for r in m.requires {
                assert!(names[..i].contains(r));
            }
        }
        assert!(!mm.is_loaded("me"));
    }
});
