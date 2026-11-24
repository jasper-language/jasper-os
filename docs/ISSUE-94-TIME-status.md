# Issue 94 Time64/Time128 status

Updated: 2026-11-24.

Status: **width-explicit representation primitives implemented; no
multi-source trusted-time implementation or physical precision claim.**

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

`kernel_core::time128` now contains `Time64` and `Time128` representation
types with checked arithmetic, floor-normalized negative seconds, and a
documented round-to-nearest nanosecond conversion. The unit tests cover
negative epochs, representative round trips and fixed 8/16-byte layout. This
is not yet wired into the native ABI or scheduler, and no provider or physical
accuracy claim follows from it.

`kernel_core::clock_contract` now supplies the first coherent clock contract:

- semantic scale and epoch are separate typed facts;
- raw counters remain bound to their hardware domain and boot generation;
- quality distinguishes measured nanosecond resolution/uncertainty/age from
  explicitly unknown values, so unknown is never serialized as zero;
- unsigned monotonic and signed Unix facts each expose Time64 and Time128 views
  produced from one source value;
- a `ClockSnapshotCell` publishes the complete identity and width pair under
  one lock, avoiding a torn 64/128 read on CPUs without a 128-bit atomic;
- non-monotonic publications, stale boot generations, invalid scale/epoch
  combinations, untrusted TAI/UTC publication and sequence exhaustion fail
  closed.

This still does not create a running multi-source time service. The cell must be
fed by the existing kernel monotonic source and future providers, and
RTC/NTP/NTS/PTP/GNSS access, TAI/UTC leap-second policy, uncertainty estimation
and physical accuracy evidence remain open.

Time sources will be layered without a new time authority:

- Kernel: clock reads, counter domains, deadlines/wakeups and controlled
  calibration application;
- Service: NTP/NTS/PTP/GNSS/RTC provider management, multi-source selection,
  uncertainty, holdover and time-scale conversion;
- Exokernel: only a concrete constrained hardware timestamp protocol if the
  normal kernel/service contracts cannot represent it;
- Compatibility: preserves POSIX/Linux layouts and maps them to the same
  facts.

The following are open: frozen external serialization, live kernel/provider
wiring, TAI/UTC and leap-second policy, multi-source authentication and fault
matrix, drift/uncertainty estimation, and physical accuracy tests. Required
candidate classes are ≤1 ms general, ≤1 μs high precision and ≤10 ns
professional, with the stated uncertainty and reference-clock evidence; none is
claimed here.
