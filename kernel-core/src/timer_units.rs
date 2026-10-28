//! Checked one-shot timer conversion for RT-2. Hardware callers must recheck
//! absolute deadlines after an IRQ; no physical clock accuracy is assumed here.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Error { Uncalibrated, OutOfRange }
/// Ceiling avoids intentionally programming an IRQ before the requested delay.
/// Zero delay still uses one count (hardware zero commonly disables the timer).
/// Reject large delays rather than silently truncating a hardware u32 counter.
pub fn oneshot_counts(delay_ns:u64, counts_per_second:u64)->Result<u32,Error> {
 if counts_per_second==0 {return Err(Error::Uncalibrated);}
 let count=(u128::from(delay_ns)*u128::from(counts_per_second)).div_ceil(1_000_000_000).max(1);
 u32::try_from(count).map_err(|_|Error::OutOfRange)
}
#[cfg(test)]
mod tests {
 use super::*;
 #[test] fn ceil_nonzero_and_overflow_contract() {
  assert_eq!(oneshot_counts(0,0),Err(Error::Uncalibrated));
  assert_eq!(oneshot_counts(0,1),Ok(1));
  assert_eq!(oneshot_counts(1,1),Ok(1));
  assert_eq!(oneshot_counts(1_000_000_001,3),Ok(4));
  assert_eq!(oneshot_counts(1_000_000_000,u32::MAX as u64),Ok(u32::MAX));
  assert_eq!(oneshot_counts(1_000_000_001,u32::MAX as u64),Err(Error::OutOfRange));
  assert_eq!(oneshot_counts(u64::MAX,u64::MAX),Err(Error::OutOfRange));
 }
}

/// Fractional elapsed time survives IRQs; repeated IRQ timestamps do not create
/// legacy tick credits. Independent of IRQ count and of timer delivery reason.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct PeriodicCredit {at:u64,period:u64,remainder:u64}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum CreditError {ZeroPeriod,TimeReversed}
impl PeriodicCredit {
 pub fn new(at:u64,period:u64)->Result<Self,CreditError> {
  if period==0 {return Err(CreditError::ZeroPeriod);}
  Ok(Self {at,period,remainder:0})
 }
 pub fn advance(&mut self,now:u64)->Result<u64,CreditError> {
  let elapsed=now.checked_sub(self.at).ok_or(CreditError::TimeReversed)?;
  let total=u128::from(elapsed)+u128::from(self.remainder);
  let ticks=(total/u128::from(self.period)) as u64;
  self.remainder=(total%u128::from(self.period)) as u64;self.at=now;
  Ok(ticks)
 }
}
#[cfg(test)]
mod credit_tests {
 use super::*;
 #[test] fn fractional_and_duplicate_irqs_do_not_mint_ticks() {
  assert_eq!(PeriodicCredit::new(0,0),Err(CreditError::ZeroPeriod));
  let mut x=PeriodicCredit::new(0,10).unwrap();
  for at in [1,1,2,9,9] {assert_eq!(x.advance(at),Ok(0));}
  assert_eq!(x.advance(10),Ok(1));assert_eq!(x.advance(10),Ok(0));
  let old=x;assert_eq!(x.advance(9),Err(CreditError::TimeReversed));assert_eq!(x,old);
  assert_eq!(x.advance(u64::MAX),Ok((u64::MAX-10)/10));
 }
}

/// Calibrated counter delta → nanoseconds, rounded down: `floor(elapsed * 1e9 / hz)`.
/// `None` when uncalibrated (`hz == 0`) or when the result does not fit `u64`;
/// never wraps or truncates. Monotone in `elapsed` for a fixed `hz`.
pub fn counter_ns(elapsed:u64, hz:u64)->Option<u64> {
 if hz==0 {return None;}
 u64::try_from(u128::from(elapsed)*1_000_000_000/u128::from(hz)).ok()
}
#[cfg(test)]
mod counter_tests {
 use super::*;
 #[test] fn floor_uncalibrated_and_overflow_contract() {
  assert_eq!(counter_ns(5,0),None);
  assert_eq!(counter_ns(0,1),Some(0));
  assert_eq!(counter_ns(3,1_000_000_000),Some(3));
  assert_eq!(counter_ns(1,3),Some(333_333_333));
  assert_eq!(counter_ns(2_000_000_000,2_000_000_000),Some(1_000_000_000));
  assert_eq!(counter_ns(u64::MAX,1_000_000_000),Some(u64::MAX));
  assert_eq!(counter_ns(u64::MAX,999_999_999),None);
  assert_eq!(counter_ns(u64::MAX,u64::MAX),Some(1_000_000_000));
 }
}
#[cfg(kani)]
mod counter_proofs {
 use super::*;
 #[kani::proof]
 fn uncalibrated_is_none() {let e:u64=kani::any();assert_eq!(counter_ns(e,0),None);}
 /// Full 128-bit symbolic division does not converge; bounded 8-bit operands.
 #[kani::proof]
 #[kani::solver(cadical)]
 fn floor_is_exact_and_monotone_bounded() {
  let e:u8=kani::any();let d:u8=kani::any();let hz:u8=kani::any();kani::assume(hz>0);
  let (e,hz)=(u64::from(e),u64::from(hz));
  let n=counter_ns(e,hz).unwrap();
  let p=u128::from(e)*1_000_000_000;
  assert!(u128::from(n)*u128::from(hz)<=p && p<(u128::from(n)+1)*u128::from(hz));
  assert!(counter_ns(e+u64::from(d),hz).unwrap()>=n);
 }
}
