#![no_main]
//! issue #7：启动阶段跟踪器与静态计划相对参照模型的差分（任意操作序列）；补链 capacity 记录 parse/encode。
use kernel_core::boot_stage::{plan_check, CaseSpec, PlanItem, Stage, StageError, Tracker, GRAPH};
use kernel_core::capacity::{encode, parse, RECORD_LEN};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    // 前 32 字节当作不可信的启动容量记录。The first 32 bytes are an untrusted capacity record.
    if data.len() >= RECORD_LEN {
        let r: [u8; RECORD_LEN] = data[..RECORD_LEN].try_into().unwrap();
        if let Ok(ov) = parse(&r) {
            assert_eq!(encode(ov), r);
            assert_eq!(parse(&encode(ov)), Ok(ov));
        }
    }
    // issue #7 第二片：同一串字节解释成计划，与真实跟踪器走一遍的结论比较。
    let items: Vec<PlanItem<()>> = data
        .iter()
        .map(|&b| {
            let s = Stage::ALL[(b & 0x0f) as usize % Stage::COUNT];
            match b >> 5 {
                0..=4 => PlanItem::Stage(s),
                5 | 6 => PlanItem::Case(CaseSpec { name: s.name(), requires: s.bit(), summary: "", timing: false }, ()),
                _ => PlanItem::Finish(()),
            }
        })
        .collect();
    let mut walk = Tracker::new();
    let mut names = std::collections::HashSet::new();
    let mut ok = false;
    for (i, item) in items.iter().enumerate() {
        match item {
            PlanItem::Stage(s) => {
                if walk.begin(*s).is_err() || walk.complete(*s).is_err() {
                    break;
                }
            }
            PlanItem::Case(spec, _) => {
                if spec.requires & !walk.done_mask() != 0 || !names.insert(spec.name) {
                    break;
                }
            }
            PlanItem::Finish(_) => {
                ok = i + 1 == items.len();
                break;
            }
        }
    }
    assert_eq!(plan_check(&[&items[..]]).is_ok(), ok);
    // 其余每字节一次操作：低 4 位选阶段，高位选 begin/complete/fail。
    let mut t = Tracker::new();
    let (mut started, mut done, mut running, mut failed) = (0u32, 0u32, None::<Stage>, None::<Stage>);
    for &b in data.iter().skip(RECORD_LEN.min(data.len())) {
        let s = Stage::ALL[(b & 0x0f) as usize % Stage::COUNT];
        match b >> 6 {
            0 | 1 => {
                let expect = if let Some(f) = failed {
                    Err(StageError::Halted { failed: f })
                } else if let Some(r) = running {
                    Err(StageError::Busy { running: r })
                } else if started & s.bit() != 0 {
                    Err(StageError::Duplicate(s))
                } else if GRAPH[s.index()].requires & !done != 0 {
                    let m = GRAPH[s.index()].requires & !done;
                    Err(StageError::MissingDependency { stage: s, missing: Stage::ALL[m.trailing_zeros() as usize] })
                } else {
                    started |= s.bit();
                    running = Some(s);
                    Ok(())
                };
                assert_eq!(t.begin(s), expect);
            }
            2 => {
                let ok = running == Some(s);
                assert_eq!(t.complete(s).is_ok(), ok);
                if ok {
                    done |= s.bit();
                    running = None;
                }
            }
            _ => {
                let ok = running == Some(s);
                assert_eq!(t.fail(s).is_ok(), ok);
                if ok {
                    failed = Some(s);
                    running = None;
                }
            }
        }
        assert_eq!(t.done_mask(), done);
        assert_eq!(t.failed(), failed);
        for k in Stage::ALL {
            if done & k.bit() != 0 {
                assert_eq!(GRAPH[k.index()].requires & !done, 0);
            }
        }
    }
});
