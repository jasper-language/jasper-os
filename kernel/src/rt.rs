//! Immutable boot RT capacity. Reservations and runtime budgets live only in
//! scheduler Task records; this module contains no parallel task/account table.
use core::sync::atomic::{AtomicUsize,Ordering};
use kernel_core::capacity::InstallError;
static CAPACITY:AtomicUsize=AtomicUsize::new(0);
// Task storage already includes RT fields in the task-capacity memory charge.
pub const BYTES_PER_RT:usize=0;
pub fn install(capacity:usize)->Result<usize,Option<InstallError>> {
 if capacity==0 {return Err(Some(InstallError::Empty));}
 CAPACITY.compare_exchange(0,capacity,Ordering::AcqRel,Ordering::Acquire)
  .map(|_|capacity).map_err(|_|Some(InstallError::AlreadyInstalled))
}
/// 启动期回滚：把尚未使用的实时容量恢复到安装前，重复回滚是空操作。
/// Boot rollback for unused real-time capacity; repeating it is a no-op.
pub fn rollback_boot() -> bool {
    let installed = CAPACITY.load(Ordering::Acquire);
    installed == 0
        || CAPACITY
            .compare_exchange(installed, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
}
pub fn capacity()->usize {CAPACITY.load(Ordering::Acquire)}
pub(crate) fn admission_capacity()->usize {capacity()}
