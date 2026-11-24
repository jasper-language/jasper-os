# Issue 21--79 architecture reconciliation

Updated: 2026-11-24.

This record reconciles the private Jasper-OS issue set updated since
2026-11-23 with the current implementation. It is an audit record only and
does not change the authoritative DAG or its scheduling policy.

## Reviewed issue set

The review covered the bodies and all comments of Issues 21, 23, 25--29, 33,
39, 41, 45, 46, 49, 56, and 58--79: 36 distinct issues. The source is the
private `DarkMagier/jasper-os` repository. Public evidence and implementation
were cross-checked at the current public-main worktree.

The highest-risk guidance is:

- 65 and 66: native correctness and security audits;
- 67: whole-kernel performance, capacity and scaling governance;
- 68 and 69: unified security audit and baseline;
- 70--77: native public framework ownership;
- 78: Headless First standard startup;
- 79: physical performance baseline and the separation of general-purpose and
  real-time execution policy.

## Later issue wave

A subsequent private-repository update added Issues 80--93 and added comments
to Issues 17, 25, 41, 49, 51, 53, 70, 71 and 72. These are long-term
architecture and framework requirements explicitly marked as not changing the
authoritative DAG, ABI or current schedule.

- 80: AI-Native Contracts. AI actors have no intrinsic privilege; model or
  tool output never authorizes an effect; discovery, capture, action, export,
  persistence and delegation remain separate rights.
- 81: Computer Use consumes native semantic contracts and may use visual
  compatibility only through separately authorized provider paths. A denied
  native operation is not grounds for visual fallback.
- 82--92: application integration, credentials, globalization, continuity,
  location/sensors, telephony, synchronization, endpoint management, personal
  information, health, native system utilities and native framework boundaries.
  They reuse #39/#58/#69/#70/#71/#72 and do not create parallel security,
  scheduling, device, configuration or observability authorities.
- 93: terminal dependency selection prefers pinned `os-terminal` + Swash,
  `noto-sans-mono-bitmap` and Ratatui, while preserving the independent
  Headless/emergency console path and avoiding new kernel ABI.

None of these updates changes the current Wine/Metal execution order or
promotes a framework from design to implementation.

## Binding architecture decisions

1. Jasper-OS remains one Rust modular-monolithic kernel. `Kernel`, `Exokernel`,
   `Service` and `Compatibility` are governance and execution domains; they are
   not an obligation to duplicate the same authority in separate layers.
2. The kernel remains the sole authority for subjects, capabilities,
   Handle/Rights conversion, policy enforcement, memory and device ownership,
   generations, revocation and audit.
3. Compatibility runtimes execute unmodified upstream programs through the
   Linux ABI. They cannot define a native Jasper ABI, bypass native resource
   accounting, or become a second security or device authority.
4. Wine, DXVK, VKD3D-Proton, Metal2Vulkan, JVM and .NET are compatibility
   workloads. Bugs they expose are repaired in the native mechanism shared by
   all callers; compatibility-specific workarounds are not accepted when they
   weaken or fragment the native contract.
5. #67 does not authorize broad performance optimization before functional
   architecture is stable. Performance data is currently a reproducible
   baseline and a regression signal.
6. #68 and #69 require reuse of the existing authorization, capability,
   security-context and audit mechanisms. A parallel compatibility audit
   authority or a second security policy engine is a design conflict.
7. #70--77 establish long-term ownership boundaries for native public
   frameworks. They do not justify creating duplicate scheduling, memory,
   device, audit or lifecycle authorities while the compatibility DAG is open.
8. #78 requires the standard startup path to remain Headless First. Textual
   boot and bounded diagnostics remain available independently of the desktop
   and UI services.
9. #79 records physical evidence without promoting it to product or real-time
   acceptance. The current work does not resume the closed physical
   performance-testing phase.

## Current DAG and implementation position

The authoritative DAG has 124 nodes: 86 done, 9 core-passed, 11 in progress,
6 planned, 4 blocked on hardware, 4 excluded, 1 continuous, 2 assumption-only
and 1 proof-only.

The relevant compatibility state remains evidence-driven:

- `COMPAT-WINE-1`: in progress. Unmodified Wine executes `cmd.exe`; DXVK and
  VKD3D-Proton execution paths now work in the bounded verification profile.
- `COMPAT-GRAPHICS-1`: core-passed. SwiftShader compute passes; Metal2Vulkan
  render-to-texture and WSI/present do not yet pass.
- `COMPAT-D3D-1`: core-passed. D3D11 offscreen and desktop WSI pass. D3D12
  offscreen now passes a real Wine/VKD3D-Proton/lavapipe run with exact pixel
  readback and a separate steady-state resource check; physical GPU, D3D12 WSI
  and conformance remain open.
- `ISSUE-20-UNIXLIKE` and `COMPAT-CONFORMANCE-1` are not promoted by these
  bounded results.

No node status is changed by this document.

## Differences found and dispositions

### Resolved native difference: Linux `brk`

The compatibility heap previously had a fixed 64 MiB virtual ceiling and was
not based on live mappings. VKD3D-Proton exceeded it while building its
allocator state. The implementation now computes the first live mapping or
reservation above the current heap end. Admission still comes from the normal
process and physical-frame quotas.

The fixed range is removed. The result is a native virtual-range rule shared
by every Linux workload, not a VKD3D exception.

### Native work-slice limits are not Linux range limits

`MAX_MAP_PAGES` remains useful as an internal work-slice or fixed-map capacity,
but it is not a valid Linux syscall range limit. Batched materialization may
continue, while a single `mmap` or `mprotect` contract must remain coherent and
atomic. The implementation no longer rejects a large Linux range solely
because it exceeds the internal work slice.

### D3D12 resource accounting

The first D3D12 run initializes the Wine prefix and compatibility caches and
therefore is not a valid steady-state measurement. The verification profile
now executes the same probe twice: the first run establishes state, and the
second must prove both the exact pixel marker and resource reclamation.

This follows the existing JVM, .NET and WSI steady-state pattern. It does not
relax the resource gate.

### PE preferred-base fault outside the D3D12 probe

`wineboot` can still terminate a helper at its PE preferred base
`0x7ff600003670` while the main D3D12 probe continues and completes. This is a
real loader/desktop compatibility defect, but it cannot be hidden by treating
the D3D12 probe pass as proof that Wine desktop startup is complete.

### Metal2Vulkan render

Compute succeeds with the upstream loader and SwiftShader. The render example
reaches fragment work and then page-faults while reading JIT/instruction data.
The existing compute result is retained, but it cannot promote the render,
WSI, present or hardware-display gates.

The render reproduction must use the current native `mmap`, `mprotect`,
reservation and range-protection implementation. If the previous fault no
longer reproduces, the new result must still produce pixels and reclaim
resources before the render gate can change.

## Execution order

The current functional sequence is:

1. finish the Wine/VKD3D-Proton D3D12 software acceptance record;
2. reproduce Metal2Vulkan render with the current native ABI mechanisms and
   repair only the shared native defect;
3. complete Metal2Vulkan render-to-texture and bounded WSI/present evidence;
4. keep physical GPU, Pixel 6a display, D3D12 conformance and long-term
   performance work as separate gates.

This order does not alter the authoritative DAG.
