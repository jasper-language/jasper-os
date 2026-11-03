// issue #3：任意操作序列下 TimerTable 的不变量（计数守恒、陈旧身份无效、交付至多一次）。
// Arbitrary operation sequences keep TimerTable invariants.
#![no_main]
use kernel_core::timer_event::*;
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut t = TimerTable::<8>::new();
    let mut budgets = [OwnerBudget::new(5), OwnerBudget::new(5)];
    let mut ids: [Option<TimerId>; 16] = [None; 16];
    let mut closed: [Option<TimerId>; 16] = [None; 16];
    let mut arb = Arbiter::new();
    for chunk in data.chunks_exact(10) {
        let owner = u32::from(chunk[1] & 1);
        let k = (chunk[1] >> 1) as usize % 16;
        let x = u64::from_le_bytes(chunk[2..10].try_into().unwrap());
        let urgency = if x & 1 == 0 { Urgency::Precise } else { Urgency::Tolerant { slack_ns: x >> 48 } };
        match chunk[0] % 6 {
            0 => if let Ok(id) = t.create(owner, &mut budgets[owner as usize]) {
                for c in closed.iter().flatten() { assert!(c.slot != id.slot || c.generation < id.generation); }
                ids[k] = Some(id);
            },
            1 => if let Some(id) = ids[k] {
                let r = Request { at: x >> 8, urgency, period_ns: (x >> 2) & 0xff };
                if t.arm(id, owner, r).is_ok() { assert_eq!(t.armed_request(id), Some(r)); arb.offer(r.at, r.urgency); }
            },
            2 => if let Some(id) = ids[k] { if t.cancel(id, owner).is_ok() { assert_eq!(t.armed_request(id), None); } },
            3 => if let Some(id) = ids[k] {
                if t.close(id, owner, &mut budgets[owner as usize]).is_ok() { closed[k] = Some(id); ids[k] = None; }
            },
            4 => if let Some(id) = ids[k] {
                let before = t.armed_request(id);
                match t.expire(id, x >> 8) {
                    Ok(Some(f)) => {
                        let r = before.unwrap();
                        assert!(r.at <= x >> 8 && f.at == r.at);
                        match f.next { None => assert_eq!(t.armed_request(id), None), Some(n) => assert!(n > x >> 8 && (n - r.at) % r.period_ns == 0) }
                    }
                    Ok(None) => assert_eq!(t.armed_request(id), before),
                    Err(Error::Overflow) => assert_eq!(t.armed_request(id), before),
                    Err(e) => panic!("{e:?}"),
                }
            },
            _ => if let Some(id) = closed[k] {
                assert_eq!(t.expire(id, u64::MAX), Ok(None));
                assert_eq!(t.cancel(id, owner), Err(Error::Stale));
            },
        }
        assert!(t.armed() <= t.live() && t.live() <= 8);
        assert_eq!(t.live() as u32, budgets[0].used() + budgets[1].used());
        if let Some(at) = arb.program_at() { assert!(arm_delay(at, x, 100_000_000) >= 1); }
    }
});
