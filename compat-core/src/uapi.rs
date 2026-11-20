//! Linux UAPI values that are protocol facts rather than Jasper capacities.
//!
//! These values are consumed only by optional Linux compatibility adapters.
//! They do not define Jasper-native limits or grant resource admission.

/// Linux `UIO_MAXIOV` / `IOV_MAX` for one vectored operation.
pub const LINUX_UIO_MAXIOV: usize = 1024;

/// Linux futex2 `FUTEX_WAITV_MAX`.
pub const LINUX_FUTEX_WAITV_MAX: usize = 128;

/// Linux `MAX_ARG_STRLEN` for one `execve` argument or environment string.
pub const LINUX_MAX_ARG_STRLEN: usize = 128 * 1024;

/// Linux `IORING_MAX_ENTRIES`.
pub const LINUX_IO_URING_MAX_ENTRIES: u32 = 32_768;
