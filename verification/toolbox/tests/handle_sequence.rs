//! Actual HandleTable methods; generated sequences shrink to smaller failures.
use kernel_core::object::{HandleTable,HandleError,Rights};
use proptest::prelude::*;
proptest! {
    #![proptest_config(ProptestConfig { failure_persistence: None, ..ProptestConfig::default() })]
    #[test]
    fn transfer_restrict_remove_matches_single_owner_reference(steps in prop::collection::vec((any::<u8>(),any::<u32>()),1..65)) {
        let mut tables=[HandleTable::<u8,2>::new(),HandleTable::<u8,2>::new()];
        let mut live=None;
        let mut stale=Vec::new();
        for (op,bits) in steps {
            let requested=Rights::from_bits_truncate(bits);
            match live {
                None => { let owner=(op as usize)&1; let h=tables[owner].put(7,requested).unwrap();live=Some((owner,h,requested)); }
                Some((owner,h,rights)) => match op%3 {
                    0 => {
                        let result=tables[owner].reduce_rights(h,requested);
                        if rights.contains(requested) { prop_assert_eq!(result,Ok(()));live=Some((owner,h,requested)); }
                        else { prop_assert_eq!(result,Err(HandleError::RightsDenied)); }
                    }
                    1 => {
                        let (left,right)=tables.split_at_mut(1);
                        let result=if owner==0 {left[0].transfer_to(h,&mut right[0])} else {right[0].transfer_to(h,&mut left[0])};
                        if rights.contains(Rights::TRANSFER) {
                            let moved=result.unwrap();stale.push((owner,h));live=Some((owner^1,moved,rights));
                        } else { prop_assert_eq!(result,Err(HandleError::RightsDenied)); }
                    }
                    _ => { prop_assert_eq!(tables[owner].remove(h),Ok(7));stale.push((owner,h));live=None; }
                }
            }
            prop_assert_eq!(tables[0].len()+tables[1].len(),usize::from(live.is_some()));
            if let Some((owner,h,rights))=live { prop_assert_eq!(tables[owner].get(h),Ok((&7,rights))); }
            for &(owner,h) in &stale { prop_assert_eq!(tables[owner].get(h),Err(HandleError::Invalid)); }
        }
    }
}

#[test]
fn concurrent_restrict_and_transfer_preserve_single_owner() {
    loom::model(|| {
        let mut tables=[HandleTable::<u8,2>::new(),HandleTable::<u8,2>::new()];
        let handle=tables[0].put(7,Rights::READ.union(Rights::TRANSFER)).unwrap();
        let state=loom::sync::Arc::new(loom::sync::Mutex::new((tables,0usize,handle)));
        let reduce=state.clone();
        let a=loom::thread::spawn(move || {
            let mut s=reduce.lock().unwrap();let owner=s.1;let h=s.2;
            s.0[owner].reduce_rights(h,Rights::READ).unwrap();
        });
        let transfer=state.clone();
        let b=loom::thread::spawn(move || {
            let mut s=transfer.lock().unwrap();let owner=s.1;let h=s.2;
            let (left,right)=s.0.split_at_mut(1);
            let moved=if owner==0 {left[0].transfer_to(h,&mut right[0])}else{right[0].transfer_to(h,&mut left[0])};
            if let Ok(next)=moved {s.1=owner^1;s.2=next;}
        });
        a.join().unwrap();b.join().unwrap();
        let s=state.lock().unwrap();assert_eq!(s.0[0].len()+s.0[1].len(),1);
        assert_eq!(s.0[s.1].get(s.2),Ok((&7,Rights::READ)));
    });
}
