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

The kernel now has a live `clock_fact` vertical fed by the existing monotonic
scheduler clock. One source read produces both Time64 and Time128 values in the
coherent snapshot cell. Linux compatibility `clock_gettime(CLOCK_MONOTONIC)`
consumes that Time64 value, so 64/128 views do not independently drift. The
runtime reports boot epoch, source, resolution, explicit unknown uncertainty,
untrusted/unsynchronized state, and both widths. This wiring establishes the
fact-source path only; it does not authenticate wall time or claim nanosecond
physical accuracy.

`service.time` now has an independently deployed process projection over that
fact. `user/timed` receives one bootstrap Channel and the least capabilities
needed for `system.abi.get` and the kernel monotonic read. Its versioned
response carries Time64 and an exactly derived Time128 view, with idempotent
replay, request conflict rejection, explicit deadline expiry, service
generation and missing-capability failure. `user/timeprobe` exercises the
process boundary end to end. This remains an untrusted monotonic projection;
it does not publish Unix/TAI time and does not replace the kernel read or
deadline enforcement boundary.

QEMU/OVMF evidence for this process boundary is retained at
`evidence/issue60-service-time-20261124-r2`: describe, sample, exact
Time64/Time128 coherence, replay, deadline, protocol rejection, restart and
missing-capability denial all pass with the first program exiting at code zero
and reclaiming its resources. It is not evidence of clock accuracy or wall-time
trust.

Time sources will be layered without a new time authority:

- Kernel: clock reads, counter domains, deadlines/wakeups and controlled
  calibration application;
- Service: NTP/NTS/PTP/GNSS/RTC provider management, multi-source selection,
  uncertainty, holdover and time-scale conversion;
- Exokernel: only a concrete constrained hardware timestamp protocol if the
  normal kernel/service contracts cannot represent it;
- Compatibility: preserves POSIX/Linux layouts and maps them to the same
  facts.

`kernel_core::clock_provider` now implements the service-layer selection
contract for independently supplied provider evidence:

- provider identity is `(source class, source ID, generation)`;
- replacement requires a strictly newer generation, and revocation must match
  the exact live generation so old evidence cannot resurrect;
- scale and epoch must match the request before a source is considered;
- TAI/UTC publication requires at least an authenticated provider;
- synchronized, holdover and unverified states are explicit;
- holdover requires a known age inside a known provider limit and explicit
  permission from the selection request;
- authenticated absolute-time selection can require a measured uncertainty;
- candidates are ranked by trust, synchronization state, uncertainty,
  resolution, sample age, stable provider priority and source identity;
- a missing eligible source returns an explicit fail-closed error.

The contract accepts provider facts only. It does not contain a simulated NTP,
NTS, PTP, GNSS, cellular or RTC feed, and no live provider is registered by the
kernel. Real protocol authentication, leap-second data, drift estimation,
holdover prediction and physical accuracy evidence remain open.

The following are open: frozen external serialization, live provider wiring,
TAI/UTC and leap-second policy, multi-source authentication and fault-matrix
execution, drift/uncertainty estimation, and physical accuracy tests. Required
candidate classes are ≤1 ms general, ≤1 μs high precision and ≤10 ns
professional, with the stated uncertainty and reference-clock evidence; none is
claimed here.
