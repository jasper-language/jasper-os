use kernel_core::memory_object::Usage;
use proptest::prelude::*;
proptest! {
    #[test]
    fn production_usage_matches_u128_reference(m in any::<u64>(), p in any::<u64>(), am in any::<u64>(), ap in any::<u64>(), lm in any::<u64>(), lp in any::<u64>()) {
        let old = Usage { mapped:m, pinned:p };
        let mut actual = old;
        let accepted = m as u128 + am as u128 <= lm as u128 && p as u128 + ap as u128 <= lp as u128;
        let result = actual.reserve(am,ap,Usage { mapped:lm,pinned:lp });
        prop_assert_eq!(result.is_ok(), accepted);
        if accepted { prop_assert_eq!(actual.mapped as u128,m as u128+am as u128); prop_assert_eq!(actual.pinned as u128,p as u128+ap as u128); prop_assert!(actual.release(am,ap).is_ok()); }
        prop_assert_eq!(actual,old);
    }
}
#[test]
fn serialized_admission_never_overcommits() {
    loom::model(|| {
        let state = loom::sync::Arc::new(loom::sync::Mutex::new((Usage::default(),0u32)));
        let mut threads = Vec::new();
        for _ in 0..2 {
            let state = state.clone();
            threads.push(loom::thread::spawn(move || {
                let mut guard = state.lock().unwrap();
                if guard.0.reserve(1,1,Usage { mapped:1,pinned:1 }).is_ok() { guard.1 += 1; }
            }));
        }
        for t in threads { t.join().unwrap(); }
        let mut guard = state.lock().unwrap();
        assert_eq!(guard.1,1); assert_eq!(guard.0,Usage { mapped:1,pinned:1 });
        guard.0.release(1,1).unwrap(); assert_eq!(guard.0,Usage::default());
    });
}
proptest! {
    #[test]
    fn sqe_reserved_flag_classification_is_total(flags in any::<u32>()) {
        use kernel_core::extension_abi::{check_sqe_flags,FlagError,SQE_REGISTERED_BUFFER};
        let expected=if flags==0 { Ok(()) } else if flags==SQE_REGISTERED_BUFFER { Err(FlagError::Unsupported) } else { Err(FlagError::Invalid) };
        prop_assert_eq!(check_sqe_flags(flags),expected);
    }
}
