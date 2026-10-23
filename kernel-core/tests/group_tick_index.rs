// Author: chatgpt. Compare indexed live-group updates against full-table ticks.
use kernel_core::sched::{limit::CpuLimit, runlist::{Link, RunLists}};
#[derive(Clone, Copy, Debug)]
struct Op { slot: usize, kind: u8, wants: u16, limit: u32 }
fn replay(ops: &[Op]) -> bool {
    let mut links = [Link::EMPTY; 8];
    let mut index = RunLists::<1>::new();
    let mut indexed = [None; 8];
    let mut reference = [None; 8];
    let mut refs = [0u8; 8];
    for op in ops {
        let s = op.slot;
        match op.kind {
            0 if refs[s] == 0 => {
                refs[s] = 1;
                indexed[s] = Some(CpuLimit::new(op.limit, 4).unwrap());
                reference[s] = indexed[s];
                if index.place(&mut links, s, Some(0)).is_err() { return false; }
            }
            1 if refs[s] > 0 && refs[s] < 3 => refs[s] += 1,
            2 if refs[s] > 0 => {
                refs[s] -= 1;
                if refs[s] == 0 {
                    if index.remove(&mut links, s).is_err() { return false; }
                    indexed[s] = None; reference[s] = None;
                }
            }
            3 => {
                for g in index.iter(&links, 0) {
                    indexed[g].as_mut().unwrap().on_tick(g == s, op.wants & (1 << g) != 0);
                }
                for (g, limit) in reference.iter_mut().enumerate() {
                    if let Some(limit) = limit { limit.on_tick(g == s, op.wants & (1 << g) != 0); }
                }
            }
            4 if refs[s] > 0 => {
                indexed[s].as_mut().unwrap().charge(); reference[s].as_mut().unwrap().charge();
            }
            5 if refs[s] > 0 => {
                indexed[s].as_mut().unwrap().set_limit(op.limit).unwrap();
                reference[s].as_mut().unwrap().set_limit(op.limit).unwrap();
            }
            _ => {}
        }
        if indexed != reference { return false; } // Includes private tokens and throttle history.
        let expected: Vec<_> = (0..8).filter(|&g| refs[g] > 0).collect();
        if index.iter(&links, 0).collect::<Vec<_>>() != expected || index.len(0) != expected.len() { return false; }
    }
    true
}
#[test]
fn live_index_preserves_idle_refill_debt_and_reuse_with_shrinking() {
    let mut seed = 0x47524f5550544943u64;
    let mut ops = Vec::new();
    for _ in 0..20_000 {
        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
        ops.push(Op { slot: (seed % 8) as usize, kind: ((seed >> 8) % 6) as u8,
            wants: (seed >> 16) as u16, limit: 1 + ((seed >> 32) % 1000) as u32 });
    }
    if !replay(&ops) {
        let mut i = 0;
        while i < ops.len() {
            let mut smaller = ops.clone(); smaller.remove(i);
            if !replay(&smaller) { ops = smaller; } else { i += 1; }
        }
        panic!("minimal group index mismatch: {ops:?}");
    }
}
