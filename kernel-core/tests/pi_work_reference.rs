// Author: chatgpt. Prior full recompute is the independent output reference.
use kernel_core::sched::{Qos, inherit::{resolve, resolve_measured}};
fn old(base: &[Option<Qos>], waits: &[Option<usize>], on: bool, eff: &mut [Option<Qos>]) {
    let n = base.len().min(waits.len()).min(eff.len());
    eff[..n].copy_from_slice(&base[..n]);
    if !on { return; }
    for (i, b) in base[..n].iter().enumerate() {
        let Some(q) = *b else { continue };
        let mut next = waits[i]; let mut steps = 0;
        while let Some(j) = next {
            if j >= n || steps >= n { break; }
            if let Some(e) = eff[j] { eff[j] = Some(e.higher(q)); }
            next = waits[j]; steps += 1;
        }
    }
}
#[derive(Clone, Debug)]
struct Case { base: Vec<Option<Qos>>, waits: Vec<Option<usize>>, len: usize, on: bool }
fn matches(c: &Case) -> bool {
    let mut expected = vec![Some(Qos::Background); c.len];
    let mut plain = expected.clone(); let mut measured = expected.clone();
    old(&c.base, &c.waits, c.on, &mut expected);
    resolve(&c.base, &c.waits, c.on, &mut plain);
    let work = resolve_measured(&c.base, &c.waits, c.on, &mut measured);
    plain == expected && measured == expected && work.calls == 1 && !work.overflow
}
#[test]
fn fixed_seed_graphs_match_old_outputs_with_shrinking() {
    let mut seed = 0x5049574f524bu64;
    for _ in 0..20_000 {
        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
        let n = (seed % 13) as usize;
        let mut c = Case { base: Vec::new(), waits: Vec::new(), len: ((seed >> 8) % 14) as usize, on: seed & 16 != 0 };
        for i in 0..n {
            seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
            c.base.push(if seed & 1 == 0 { None } else { Some(Qos::ALL[(seed >> 4) as usize % 4]) });
            if i % 3 != 0 || seed & 32 != 0 { c.waits.push(if seed & 2 == 0 { None } else { Some(((seed >> 8) % 15) as usize) }); }
        }
        if !matches(&c) {
            while !c.base.is_empty() {
                let mut small = c.clone(); small.base.pop();
                if matches(&small) { break; } c = small;
            }
            panic!("minimal failing base-prefix: {c:?}");
        }
    }
}
#[test]
fn actual_walks_and_defensive_stops_are_counted() {
    let base = [Some(Qos::Interactive), Some(Qos::Background), None];
    let waits = [Some(1), Some(2), None]; let mut eff = [None; 3];
    let w = resolve_measured(&base, &waits, true, &mut eff);
    assert_eq!((w.calls,w.slots,w.live,w.steps,w.max_walk,w.truncated), (1,6,2,3,2,0));
    let w = resolve_measured(&base, &[Some(0),Some(9),None], true, &mut eff);
    assert_eq!((w.steps,w.max_walk,w.truncated), (3,3,2));
    let w = resolve_measured(&base, &waits, false, &mut eff);
    assert_eq!((w.slots,w.live,w.steps), (3,0,0));
}

#[test]
fn isolated_exit_preserves_all_other_effective_classes() {
    let mut seed = 0x455849544c454d4du64;
    for _ in 0..20_000 {
        let mut base = [None; 12]; let mut waits = [None; 12];
        for i in 0..12 {
            seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
            base[i] = if seed & 1 == 0 { None } else { Some(Qos::ALL[(seed >> 8) as usize % 4]) };
            waits[i] = if seed & 2 == 0 { None } else { Some(((seed >> 16) % 15) as usize) };
        }
        let exiting = (seed % 12) as usize;
        if waits[exiting].is_some() || waits.iter().any(|w| *w == Some(exiting)) { continue; }
        let mut before = [None; 12]; let mut after = [None; 12];
        resolve(&base, &waits, true, &mut before);
        base[exiting] = None;
        resolve(&base, &waits, true, &mut after);
        for i in 0..12 { if i != exiting { assert_eq!(before[i], after[i], "seed={seed:#x} exiting={exiting} graph={waits:?}"); } }
    }
}
