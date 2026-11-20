# DC-2 Linux Device UAPI adapter status

Updated: 2026-11-20

Status: **software contract slice passed; DC-2 remains open.**

## Implemented

`kernel-core/sys/linux_device_uapi.rs` defines a versioned `/dev` endpoint
contract backed by one existing `DriverHostBroker` pass:

- a versioned `DeviceNodeId` and `UapiVersion`;
- Linux open access modes are checked locally without becoming a second
  authorization source;
- ioctl, read, write, poll and mmap requests all use the admitted
  `PassToken` through `begin`/`begin_bounded`;
- DMA resource units are charged from caller-supplied page budgets, and MMIO
  and IRQ requests use the existing broker request classes;
- mapped buffers and in-flight requests are generation-bound to the pass and
  have one terminal; close cancels locally owned requests and buffers;
- reset, crash, revocation and stale pass errors map to a closed/device-gone
  result rather than falling back to a native handle or bypassing Device Broker;
- Linux errno values and vendor ioctl payload formats are intentionally not
  part of this kernel contract; the compatibility layer may interpret them at
  the boundary.

`DriverHostBroker::pass_facts` exposes immutable facts such as device identity,
host/pass generations, rights and resource ceilings. The pass token remains the
only mutable authority.

## Verification

```text
cargo test --locked -p kernel-core linux_device_uapi --lib
5 passed; 0 failed

cargo check --locked -p jasper-kernel --target x86_64-unknown-none
PASS
```

Negative coverage includes wrong UAPI major, invalid node, read/write access
violation, missing DMA-write admission, resource capacity rejection before
request publication, reset generation invalidation, idempotent close and full
local request/buffer cleanup.

## Remaining gates

- No unmodified Linux user-space device component has completed a real
  `/dev`/ioctl/mmap/poll/buffer lifecycle through this adapter.
- The compatibility process and native VFS/Device Service transport must be
  wired to this contract without exposing vendor commands as native ABI.
- Real MMIO/DMA/IRQ/IOMMU, driver crash/reset, hotplug, suspend/resume and
  non-Pixel hardware matrices remain required.
- DC-2 cannot be marked done from this software state machine.
