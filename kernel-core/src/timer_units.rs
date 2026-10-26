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
