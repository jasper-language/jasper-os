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
pub enum CreditError {ZeroPeriod,TimeReversed,Overflow}
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

/// Per-CPU elapsed-tick ledger across idle switch-ins. Ticks that elapsed while
/// the idle flow was current are settled as idle before a task is switched in,
/// so the next timer event charges the incoming task (and its CPU group) only
/// ticks after the switch. Settled ticks are still delivered with that next
/// event (per-CPU tick counters, device quotas): no tick is minted or lost.
/// Failed calls leave the ledger unchanged.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct CreditLedger {clock:PeriodicCredit,idle_pending:u64}
impl CreditLedger {
 pub fn new(at:u64,period:u64)->Result<Self,CreditError> {Ok(Self {clock:PeriodicCredit::new(at,period)?,idle_pending:0})}
 /// Idle → task switch at `now`: ticks to account as idle; kept for delivery.
 pub fn settle_idle(&mut self,now:u64)->Result<u64,CreditError> {
  let mut clock=self.clock;let ticks=clock.advance(now)?;
  let pending=self.idle_pending.checked_add(ticks).ok_or(CreditError::Overflow)?;
  self.clock=clock;self.idle_pending=pending;Ok(ticks)
 }
 /// Timer event at `now`: (ticks to charge the current runner, ticks to deliver).
 pub fn event(&mut self,now:u64)->Result<(u64,u64),CreditError> {
  let mut clock=self.clock;let ticks=clock.advance(now)?;
  let delivered=ticks.checked_add(self.idle_pending).ok_or(CreditError::Overflow)?;
  self.clock=clock;self.idle_pending=0;Ok((ticks,delivered))
 }
 /// Settled idle ticks not yet delivered.
 pub const fn idle_pending(&self)->u64 {self.idle_pending}
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
 #[test] fn idle_stretch_is_settled_not_charged_and_still_delivered() {
  assert_eq!(CreditLedger::new(0,0),Err(CreditError::ZeroPeriod));
  let mut l=CreditLedger::new(0,10).unwrap();
  assert_eq!(l.settle_idle(155),Ok(15));assert_eq!(l.idle_pending(),15);
  assert_eq!(l.event(160),Ok((1,16)));assert_eq!(l.idle_pending(),0);
  assert_eq!(l.event(160),Ok((0,0)));
  let old=l;assert_eq!(l.settle_idle(159),Err(CreditError::TimeReversed));assert_eq!(l,old);
  assert_eq!(l.event(159),Err(CreditError::TimeReversed));assert_eq!(l,old);
  assert_eq!(l.settle_idle(165),Ok(0));assert_eq!(l.settle_idle(171),Ok(1));assert_eq!(l.event(180),Ok((1,2)));
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
#[cfg(kani)]
mod ledger_proofs {
 use super::*;
 /// 128-bit symbolic division: bounded 8-bit timestamps and periods.
 #[kani::proof]
 #[kani::solver(cadical)]
 fn idle_settle_conserves_and_bounds_charge_bounded() {
  let (o,i,r,p):(u8,u8,u8,u8)=(kani::any(),kani::any(),kani::any(),kani::any());kani::assume(p>0);
  let (o,s,t,p)=(u64::from(o),u64::from(o)+u64::from(i),u64::from(o)+u64::from(i)+u64::from(r),u64::from(p));
  let mut l=CreditLedger::new(o,p).unwrap();
  let k=l.settle_idle(s).unwrap();assert_eq!(l.idle_pending(),k);
  let (c,d)=l.event(t).unwrap();
  assert_eq!(d,c+k);assert_eq!(l.idle_pending(),0);
  assert!(c*p<(t-s)+p);
  assert_eq!(k+c,(t-o)/p);
 }
 #[kani::proof]
 fn failures_leave_ledger_unchanged() {
  let (o,b,p):(u64,u64,u64)=(kani::any(),kani::any(),kani::any());kani::assume(p>0 && b>0 && b<=o);
  let mut l=CreditLedger::new(o,p).unwrap();let before=l;
  assert_eq!(l.settle_idle(o-b),Err(CreditError::TimeReversed));assert_eq!(l,before);
  assert_eq!(l.event(o-b),Err(CreditError::TimeReversed));assert_eq!(l,before);
  assert_eq!(CreditLedger::new(o,0),Err(CreditError::ZeroPeriod));
 }
}
