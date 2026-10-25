use kernel_core::object::{HandleTable,Rights,HandleError};
#[test]
fn transfer_without_authority_preserves_source() {
    let mut a=HandleTable::<u8,2>::new();let mut b=HandleTable::<u8,2>::new();
    let h=a.put(7,Rights::READ).unwrap();
    assert_eq!(a.transfer_to(h,&mut b),Err(HandleError::RightsDenied));
    assert_eq!(a.get(h),Ok((&7,Rights::READ)));assert_eq!(b.len(),0);
}
