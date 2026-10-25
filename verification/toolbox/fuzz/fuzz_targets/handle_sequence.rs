#![no_main]
use kernel_core::object::{HandleTable,Rights,HandleError};
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut tables=[HandleTable::<u8,2>::new(),HandleTable::<u8,2>::new()];let mut live=None;
    for chunk in data.chunks_exact(5).take(64) {
        let rights=Rights::from_bits_truncate(u32::from_le_bytes(chunk[1..5].try_into().unwrap()));
        match live {
            None => {let owner=(chunk[0] as usize)&1;let h=tables[owner].put(7,rights).unwrap();live=Some((owner,h,rights));}
            Some((owner,h,old)) => match chunk[0]%3 {
                0 => {let result=tables[owner].reduce_rights(h,rights);if old.contains(rights) {assert!(result.is_ok());live=Some((owner,h,rights));} else {assert_eq!(result,Err(HandleError::RightsDenied));}}
                1 => {let (a,b)=tables.split_at_mut(1);let result=if owner==0 {a[0].transfer_to(h,&mut b[0])}else{b[0].transfer_to(h,&mut a[0])};if old.contains(Rights::TRANSFER) {let next=result.unwrap();assert!(tables[owner].get(h).is_err());live=Some((owner^1,next,old));}else{assert_eq!(result,Err(HandleError::RightsDenied));}}
                _ => {assert_eq!(tables[owner].remove(h),Ok(7));assert!(tables[owner].get(h).is_err());live=None;}
            }
        }
        assert_eq!(tables[0].len()+tables[1].len(),usize::from(live.is_some()));
        if let Some((owner,h,rights))=live {assert_eq!(tables[owner].get(h),Ok((&7,rights)));}
    }
});
