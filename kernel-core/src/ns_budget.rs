//! Absolute-period budget in monotonic nanoseconds. Caller serializes owner
//! transitions and supplies the exact executed interval; IRQ count is irrelevant.
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub struct Budget {pub quota:u64,pub period:u64,pub remaining:u64,pub next:u64,pub enabled:bool}
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum Error {Shape,Overflow,TimeReversed}
impl Budget {
 pub fn new(now:u64,quota:u64,period:u64)->Result<Self,Error> {
  if quota==0 || period==0 || quota>period {return Err(Error::Shape);}
  Ok(Self {quota,period,remaining:quota,next:now.checked_add(period).ok_or(Error::Overflow)?,enabled:true})
 }
 /// Charge only the overlap with the latest period, after advancing any skipped
 /// boundaries. Skipped periods cannot accumulate quota; all errors are atomic.
 pub fn settle(&mut self,start:u64,end:u64,running:bool)->Result<(),Error> {
  if end<start {return Err(Error::TimeReversed);}
  if !self.enabled {return Ok(());}
  let mut copy=*self;
  if end>=copy.next {
   let periods=(end-copy.next)/copy.period+1;
   copy.next=copy.next.checked_add(periods.checked_mul(copy.period).ok_or(Error::Overflow)?).ok_or(Error::Overflow)?;
   copy.remaining=copy.quota;
   if running {copy.remaining=copy.remaining.saturating_sub(end-start.max(copy.next-copy.period));}
  }else if running {copy.remaining=copy.remaining.saturating_sub(end-start);}
  *self=copy;Ok(())
 }
 pub fn disable(&mut self){self.enabled=false;self.remaining=0;}
}
pub fn utilisation(quota:u64,period:u64)->Result<u32,Error> {
 if quota==0 || period==0 || quota>period {return Err(Error::Shape);}
 Ok((u128::from(quota)*1000).div_ceil(u128::from(period)) as u32)
}
#[cfg(test)]mod tests {
 use super::*;
 #[test]fn owner_intervals_and_no_free_refresh(){
  let mut b=Budget::new(0,3,10).unwrap();b.settle(0,2,true).unwrap();assert_eq!(b.remaining,1);
  b.settle(2,8,false).unwrap();assert_eq!(b.remaining,1);b.settle(8,9,true).unwrap();assert_eq!(b.remaining,0);
  b.settle(9,12,true).unwrap();assert_eq!((b.remaining,b.next),(1,20));
  b.settle(12,52,false).unwrap();assert_eq!((b.remaining,b.next),(3,60));
  b.disable();assert!(!b.enabled);assert_eq!((b.remaining,b.next),(0,60));
 }
 #[test]fn failure_atomic_and_full_width(){
  assert_eq!(utilisation(u64::MAX,u64::MAX),Ok(1000));
  let mut b=Budget::new(u64::MAX-10,1,5).unwrap();let old=b;
  assert_eq!(b.settle(u64::MAX-10,u64::MAX,true),Err(Error::Overflow));assert_eq!(b,old);
  assert_eq!(b.settle(9,8,true),Err(Error::TimeReversed));assert_eq!(b,old);
 }
}
