# Issue 94 Time64/Time128 status

Updated: 2026-11-24.

Status: **architecture baseline; no multi-source trusted-time implementation
or physical precision claim.**

The stable defaults are:

- Time64 monotonic nanoseconds for scheduling, deadlines and high-frequency
  events;
- signed Time64 absolute time with an explicit epoch and scale;
- optional Time128 `(i64 seconds, u64 binary fraction)` for precision/lifetime
  cases that need it;
- raw counter samples remain bound to hardware domain, frequency and
  generation;
- conversion overflow and precision loss are explicit errors, never silent
  wrapping or truncation.

The current x86 wall clock reads CMOS RTC at one-second resolution. TSC is
calibrated for monotonic nanoseconds, but that does not make wall time a
trusted nanosecond clock. QEMU and unit arithmetic are not physical timing
qualification.

Time sources will be layered without a new time authority:

- Kernel: clock reads, counter domains, deadlines/wakeups and controlled
  calibration application;
- Service: NTP/NTS/PTP/GNSS/RTC provider management, multi-source selection,
  uncertainty, holdover and time-scale conversion;
- Exokernel: only a concrete constrained hardware timestamp protocol if the
  normal kernel/service contracts cannot represent it;
- Compatibility: preserves POSIX/Linux layouts and maps them to the same
  facts.

The following are open: frozen serialization and epoch, 64/128 tear-free
snapshot, TAI/UTC and leap-second policy, multi-source authentication and
fault matrix, drift/uncertainty contracts, real provider integration, and
physical accuracy tests. Required candidate classes are ≤1 ms general,
≤1 μs high precision and ≤10 ns professional, with the stated uncertainty
and reference-clock evidence; none is claimed here.
