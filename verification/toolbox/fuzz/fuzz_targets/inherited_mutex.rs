#![no_main]
use kernel_core::inherited_mutex::{Claim, State};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut state = State::new();
    let mut expected = None;
    for chunk in data.chunks_exact(2).take(128) {
        let who = chunk[1] % 3 + 1;
        match chunk[0] % 4 {
            0 => match state.claim(who, expected.is_some()) {
                Claim::Acquired { .. } => expected = Some(who),
                Claim::WaitFor(owner) => assert_eq!(expected, Some(owner)),
                Claim::Recursive => assert_eq!(expected, Some(who)),
                Claim::Closed => assert!(state.is_closed()),
            },
            1 => if state.release(who, None).is_ok() { expected = None; },
            2 => { let old = state.close(); assert_eq!(old, expected.take()); },
            _ => {}
        }
        assert_eq!(state.owner(), expected);
    }
});
