use kernel_core::subscription_abi::*;
use proptest::prelude::*;
proptest! {
 #![proptest_config(ProptestConfig {failure_persistence:None,..ProptestConfig::default()})]
 #[test]
 fn descriptor_matches_wire_reference(version in any::<u16>(),size in any::<u16>(),capacity in any::<u32>(),ptr in any::<u64>(),reserved in any::<u64>()) {
  let mut bytes=[0;WAIT_BYTES];bytes[..2].copy_from_slice(&version.to_le_bytes());bytes[2..4].copy_from_slice(&size.to_le_bytes());bytes[4..8].copy_from_slice(&capacity.to_le_bytes());bytes[8..16].copy_from_slice(&ptr.to_le_bytes());bytes[16..24].copy_from_slice(&reserved.to_le_bytes());
  let expected=version==1 && size==24 && (1..=16).contains(&capacity) && reserved==0 && (ptr as u128+capacity as u128*32)<=u64::MAX as u128;
  prop_assert_eq!(WaitArgs::decode(&bytes).is_some(),expected);
  // Also force valid header to exercise acceptance rather than mostly rejection.
  bytes[..2].copy_from_slice(&1u16.to_le_bytes());bytes[2..4].copy_from_slice(&24u16.to_le_bytes());bytes[16..24].fill(0);let cap=(capacity%16)+1;bytes[4..8].copy_from_slice(&cap.to_le_bytes());
  prop_assert_eq!(WaitArgs::decode(&bytes).is_some(),ptr as u128+cap as u128*32<=u64::MAX as u128);
 }
}
proptest! {
 #![proptest_config(ProptestConfig {failure_persistence:None,..ProptestConfig::default()})]
 #[test]
 fn source_capability_keeps_all_64_bits(target in any::<u64>(),kind in 0u32..4,mutated in 0usize..24) {
  let mut b=[0u8;SOURCE_BYTES];b[..2].copy_from_slice(&1u16.to_le_bytes());b[2..4].copy_from_slice(&24u16.to_le_bytes());b[4..8].copy_from_slice(&kind.to_le_bytes());b[8..16].copy_from_slice(&target.to_le_bytes());
  prop_assert_eq!(SourceArgs::decode(&b),Some(SourceArgs {target,kind}));
  b[mutated]^=0x80;
  if let Some(decoded)=SourceArgs::decode(&b) {prop_assert_eq!(decoded.target,u64::from_le_bytes(b[8..16].try_into().unwrap()));prop_assert!(decoded.kind<=3);}
 }
}
