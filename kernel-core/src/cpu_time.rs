//! CPU residency measured in one monotonic reference clock, independent of local IRQ counts.
//! Author: chatgpt. A switch charges the preceding state before publishing the next state.
#[derive(Clone,Copy,Debug,Default,PartialEq,Eq)]
pub struct Totals { pub busy:u64,pub idle:u64 }
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Error { TimeReversed, Overflow }
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Ledger { at:u64,busy:bool,totals:Totals }
impl Ledger {
    pub const fn new(at:u64,busy:bool)->Self { Self {at,busy,totals:Totals {busy:0,idle:0}} }
    pub fn transition(&mut self,now:u64,busy:bool)->Result<(),Error> {
        let elapsed=now.checked_sub(self.at).ok_or(Error::TimeReversed)?;
        let mut next=self.totals;
        if self.busy {next.busy=next.busy.checked_add(elapsed).ok_or(Error::Overflow)?;}
        else {next.idle=next.idle.checked_add(elapsed).ok_or(Error::Overflow)?;}
        *self=Self {at:now,busy,totals:next};Ok(())
    }
    pub fn snapshot(self,now:u64)->Result<Totals,Error> {
        let mut copy=self;copy.transition(now,self.busy)?;Ok(copy.totals)
    }
    pub fn reset(&mut self,now:u64)->Result<(),Error> {
        if now<self.at {return Err(Error::TimeReversed);}
        *self=Self::new(now,self.busy);Ok(())
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;
    #[kani::proof]
    fn one_interval_is_atomic() {
        let start:u64=kani::any();let end:u64=kani::any();let busy:bool=kani::any();
        let mut ledger=Ledger::new(start,busy);let old=ledger;
        let result=ledger.transition(end,!busy);
        if end<start {assert_eq!(result,Err(Error::TimeReversed));assert_eq!(ledger,old);}
        else {assert!(result.is_ok());let totals=ledger.snapshot(end).unwrap();
            assert_eq!(totals.busy,if busy {end-start}else{0});
            assert_eq!(totals.idle,if busy {0}else{end-start});}
    }
}
