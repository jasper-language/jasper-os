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
pub fn now()->Option<u64>{
 let hz=HZ.load(Ordering::Acquire);if hz==0{return None;}
 let elapsed=crate::arch::clock_counter().checked_sub(EPOCH.load(Ordering::Relaxed))?;
 kernel_core::timer_units::counter_ns(elapsed,hz)
}
pub fn enable(){assert!(ready());ENABLED.store(true,Ordering::Release);}
pub fn enabled()->bool{ENABLED.load(Ordering::Acquire)}
pub const fn tick_ns()->u64{1_000_000_000/crate::config::ACTIVE.clock.timer_hz as u64}
