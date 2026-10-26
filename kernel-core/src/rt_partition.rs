//! Partitioned RT admission arithmetic. The caller derives loads from canonical
//! scheduler task records; this module stores no second reservation table.
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum Error { Shape, Capacity, Overflow }
/// Conservative utilisation (ceil), with explicit rejection and no mutation.
pub fn utilisation(quota:u32,period:u32)->Result<u32,Error> {
    if quota==0 || period==0 || quota>period {return Err(Error::Shape);}
    Ok((u64::from(quota)*1000).div_ceil(u64::from(period)) as u32)
}
/// Select the least-loaded allowed CPU; deterministic lower-index tie break.
/// `loads` must already exclude this task's old reservation when reconfiguring.
/// Failure leaves the caller's old reservation and all loads untouched.
pub fn place<const N:usize>(loads:&[u32;N],allowed:u64,quota:u32,period:u32,limit:u32)->Result<usize,Error> {
    let added=utilisation(quota,period)?;
    if limit==0 || limit>1000 {return Err(Error::Shape);}
    let mut best=None;
    for (cpu,load) in loads.iter().copied().enumerate().take(64) {
        if allowed & (1u64<<cpu)==0 {continue;}
        let sum=load.checked_add(added).ok_or(Error::Overflow)?;
        if sum<=limit && best.is_none_or(|old:usize|load<loads[old]) {best=Some(cpu);}
    }
    best.ok_or(Error::Capacity)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn conservative_shape_and_placement() {
        assert_eq!(utilisation(1,3),Ok(334));
        for (q,p) in [(0,1),(1,0),(2,1)] {assert_eq!(utilisation(q,p),Err(Error::Shape));}
        assert_eq!(place(&[600,200],3,3,10,900),Ok(1));
        assert_eq!(place(&[600,200],1,3,10,900),Ok(0));
        assert_eq!(place(&[600,200],0,3,10,900),Err(Error::Capacity));
        assert_eq!(place(&[0,0],3,1,10,900),Ok(0));
    }
    #[test]
    fn failed_reconfiguration_preserves_input_and_full_width_math() {
        let loads=[850,900];let saved=loads;
        assert_eq!(place(&loads,3,1,10,900),Err(Error::Capacity));assert_eq!(loads,saved);
        assert_eq!(utilisation(u32::MAX,u32::MAX),Ok(1000));
        assert_eq!(place(&[u32::MAX],1,1,1,900),Err(Error::Overflow));
        assert_eq!(place(&[0;65],1u64<<63,1,10,900),Ok(63));
    }
}

/// Earliest absolute deadline, stable slot tie-break. Caller filters readiness,
/// partition ownership and positive remaining budget before constructing input.
pub fn edf(candidates:impl IntoIterator<Item=(usize,u64)>)->Option<usize> {
    candidates.into_iter().min_by_key(|(slot,deadline)|(*deadline,*slot)).map(|(slot,_)|slot)
}
#[cfg(test)]
mod edf_tests {
 use super::*;
 #[test] fn earliest_deadline_and_stable_ties() {
  assert_eq!(edf([]),None);assert_eq!(edf([(9,7),(2,3),(1,3)]),Some(1));
  assert_eq!(edf([(1,u64::MAX),(2,u64::MAX-1)]),Some(2));
 }
}
