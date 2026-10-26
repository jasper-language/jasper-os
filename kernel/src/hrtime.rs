//! Calibrated shared counter domain. x86 TSC is calibrated against PIT during
//! boot, before AP startup. Physical clock precision/synchronisation is a platform
//! assumption, not established by the arithmetic tests or TCG execution.
use core::sync::atomic::{AtomicBool,Ordering};
use kernel_core::sync::Atomic64;
static HZ:Atomic64=Atomic64::new(0);
static EPOCH:Atomic64=Atomic64::new(0);
static ENABLED:AtomicBool=AtomicBool::new(false);
pub fn install(epoch:u64,hz:u64){if hz>0 {EPOCH.store(epoch,Ordering::Relaxed);HZ.store(hz,Ordering::Release);}}
pub fn ready()->bool{HZ.load(Ordering::Acquire)>0}
#[cfg(target_arch="x86_64")]
fn counter()->u64 {
 let lo:u32;let hi:u32;
 unsafe {core::arch::asm!("lfence","rdtsc","lfence",out("eax")lo,out("edx")hi,options(nostack));}
 (u64::from(hi)<<32)|u64::from(lo)
}
#[cfg(not(target_arch="x86_64"))]
fn counter()->u64{crate::arch::cycles()}
pub fn now()->Option<u64>{
 let hz=HZ.load(Ordering::Acquire);if hz==0{return None;}
 let elapsed=counter().checked_sub(EPOCH.load(Ordering::Relaxed))?;
 u64::try_from(u128::from(elapsed)*1_000_000_000/u128::from(hz)).ok()
}
pub fn enable(){assert!(ready());ENABLED.store(true,Ordering::Release);}
pub fn enabled()->bool{ENABLED.load(Ordering::Acquire)}
pub const fn tick_ns()->u64{1_000_000_000/crate::config::ACTIVE.clock.timer_hz as u64}
