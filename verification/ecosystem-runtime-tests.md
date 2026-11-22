# Ecosystem runtime acceptance

This report separates host baselines from execution on Jasper-OS. A host
baseline is not evidence that the Jasper kernel supports the same program.

JVM, .NET/CoreCLR and Android Framework are external user-space frameworks.
They may run only under the Linux compatibility stack and never imply a native
Jasper framework ABI. See `docs/native-ecosystem-independence.md`.

## Jasper-OS UEFI

### Upstream Toybox

The upstream Toybox source tree was built as a static PIE and staged into the
System A/B ext4 fixture without changing Toybox source. Jasper executed three
commands through its real CPL3, argv/auxv, Linux syscall and root-image path:

- `uname -a`
- `printf`
- `sha256sum /usr/lib/x86_64-linux-gnu/libc.so.6`

Evidence: `evidence/android-toybox-pie-20261115-042720`.

Result: all three commands exited zero and the QEMU run reached
`root_execution_complete` with `qemu_rc=33`.

The static runner reports `resources=false` because the verification static
loader retains a bounded mapping accounting difference after process reap.
That is a separate Jasper resource-accounting gap; it does not turn the command
exit result into a fabricated success.

### Android Toybox binary

The Android 34 AOSP system image was downloaded and its system/APEX partitions
extracted. Its unmodified `/system/bin/toybox` and `/system/bin/linker64` were
staged in Jasper's root image and executed through the real Linux ABI.

Evidence: `evidence/android-bionic-toybox-diag-20261115-061237`.

Result: the Bionic linker ran 555 and 552 system calls for two Toybox launches;
both processes exited zero. Jasper then reached `root_execution_complete` with
`qemu_rc=33`. The same boot also ran the upstream static Toybox commands and
the AOSP Binder test below, so this is a Jasper result rather than a host
baseline.

Bionic's 8.8 GiB `PROT_NONE` arena exposed a kernel allocation bug: automatic
anonymous mappings could be placed inside a lazy address reservation. Later
`mprotect` then attempted to materialize an already-mapped page and returned
`ENOMEM`. Jasper now avoids both concrete mappings and lazy reservations when
choosing an automatic `mmap` address. `mprotect` also no longer allocates a
temporary vector on its normal success path.

### AOSP Binder driver test

The unmodified AOSP
`frameworks/native/libs/binder/tests/binderDriverInterfaceTest.cpp` was built as
static PIE against a minimal header shim. The test itself still opens
`/dev/binder` and exercises the kernel UAPI.

Evidence: `evidence/android-toybox-binder-20261115-053048`.

Result: **20/20 tests passed**, the test process exited zero, and the Jasper
health gate reached `root_execution_complete` with `qemu_rc=33`.

During this test the Binder compatibility layer was corrected for:

- 32-bit ioctl request normalization for signed-upward ABI values;
- legacy context-manager/node handling and handle zero;
- local reference notifications;
- nonblocking `BINDER_WRITE_READ` returning `EAGAIN`;
- `BC_FREE_BUFFER` with a zero pointer;
- the Android freeze-notification command and reply words;
- context-manager PING transaction reply packing.

The test binary uses an explicit exit wrapper after `RUN_ALL_TESTS()` because
the current Jasper glibc/static-PIE teardown path faults at `ip=0x202` after
the test suite returns. The AOSP test code and Binder assertions are unchanged;
this wrapper is recorded as a separate exit-path gap.

### Wine command execution on Jasper

Unmodified Ubuntu Wine 10.0 executed under the Jasper Linux/POSIX ABI through
the real UEFI/root-image path. Wine loaded its preloader, wineserver, PE
`start.exe`, `ntdll.dll`, `kernel32.dll`, `kernelbase.dll`, `win32u.dll`,
`imm32.dll`, and `cmd.exe`. The command `cmd.exe /c echo WINE_CMD_OK` executed
the built-in, wrote through the inherited standard-output handle, and exited
zero.

Evidence: `evidence/compat-wine-steady-r116`.

The immediately repeated command also completed with `resources=true`,
including zero retained frames and zero shared-mapping growth. This establishes
the POSIX runtime steady state separately from the still-pending D3D/Vulkan
execution path.

## Host baselines

### Wine

Ubuntu Wine 10.0 was extracted into user space without installing or modifying
Wine. A real WINEPREFIX was created and `wine cmd /c echo WINE_CMD_OK`
completed with rc 0.

### Direct3D to Vulkan

DXVK 3.1.1 and VKD3D-Proton 3.1 were used from their release artifacts:

- D3D11 device creation and a real offscreen triangle draw succeeded on the
  NVIDIA RTX 3060; 1152 non-zero pixels were read back.
- D3D12 device creation succeeded with VKD3D-Proton; the probe reported one
  device node.

This is a host baseline.

### Metal2Vulkan

The upstream `metal2vulkan` runtime was built and run on the real Vulkan
device. Both official examples passed:

- compute dispatch: `output[0..4] = [0.0, 3.0, 6.0, 9.0]`
- render-to-texture: all 8x8 texels matched the expected clear/draw pattern.

This result is a host baseline only. In Jasper's software Vulkan path,
`scripts/compat-graphics-software-check.sh` now proves the unmodified loader,
SwiftShader ICD and compute example execute with all 1000 outputs correct and
resources returned to baseline. The render example reaches the fragment
pipeline but page-faults at `ip=0x100086f1909d` while reading
`0x10006e4ba4f0`; it remains pending.

### Darling

Darling `v0.1.20260608` was extracted. The official launcher requires
setuid-root/namespace privileges, so a privileged isolated container was used
as the host baseline. Darling's `/bin/echo` ran and printed `DARLING_EXEC_OK`.
The host user-space launcher without container privileges was blocked before
that point. A separate Jasper guest launcher/mount diagnostic is recorded in
`evidence/darling-jasper-mount-r12/README.md`; No complete Darling result is claimed for Jasper.

The release's `debs_20260608.zip` asset was downloaded and verified as
`sha256=27469ef3932da2e91dd7fb34b70e3628a3e54b7af9fb5480051f44af35eca1fd`;
its observed packages are `amd64` `0.1.20260609~noble`. Darling remains
excluded by Issue #31 and research-only under Issue #55. The separate
container, Mach-O/mldr/dyld, darlingserver/RPC, Linux ABI, GUI/WindowServer,
Metal/Vulkan and resource gates are frozen in
`verification/darling-research.toml` and
`docs/DARLING-RESEARCH-MATRIX.md`; none is claimed as a Jasper guest pass.

### Java VM

The unmodified OpenJDK 21 host JVM ran a Java class and printed
`JVM_OK value=499500`.

The unmodified OpenJDK 21 runtime also completed a Jasper UEFI guest run from
the bounded `/data/runtimes/openjdk` compatibility namespace. The fixture
covered interpreted/JIT startup, Java threads, a 1 MiB allocation with real GC,
and file output. The measured run printed
`JVM_PROBE_OK value=499500 thread=true gc=true file=true java=21.0.13.1`,
exited zero, reclaimed resources, and reached
`JSR-LIFE-HEALTH result=root_execution_complete`.

The JVM acceptance profile exposes the documented baseline `max,-avx,-avx2`
CPU model. OpenJDK deliberately probes AVX signal preservation by faulting on a
null pointer; the compatibility layer does not yet deliver synchronous
`SIGSEGV` to guest handlers, so AVX-enabled JVM startup remains a separate ABI
gate and is not claimed by this pass.

An unmodified AOSP Android 34 ART runtime was extracted from the system image
and APEX payload. Its `dalvikvm64 -showversion` baseline printed
`ART version 2.1.0 x86_64`. The upstream multi-DEX APK
`AndroidAutoBuildAPK-v18.apk` is now validated by AOSP `aapt2` and executed
from a real Jasper UEFI System-root image through Bionic, Linux ABI and
unmodified ART. The measured APK run exited 0 with `syscalls=23154` and
`resources=true`. Android Activity/Framework lifecycle remains pending. The
real Android 34 framework-root preflight finds app_process64, servicemanager,
installd, framework.jar, services.jar, am.jar and a structurally valid
framework-res.apk/resources.arsc. `init.zygote64.rc` starts app_process64 with
`--zygote --start-system-server`; separate zygote64/system_server binaries are
not required by modern Android. The static preflight follows the stock
`init.rc` linker-config generation chain and accepts AOSP's empty UID/GID-1000
passwd file, so `container_ready=true` with no static omissions. Activity
startup cannot be claimed until the process chain actually runs.

### .NET/CoreCLR

The unmodified Microsoft Linux x64 runtime is a compatibility target only.
Jasper-OS does not define a native .NET/CoreCLR/C# framework or ABI.

The unmodified Microsoft .NET Runtime `10.0.15` completed a Jasper UEFI guest
run as a self-contained Linux x64 application from
`/data/runtimes/dotnet`. The fixture exercised CoreCLR startup, JIT execution,
managed threads, Task/thread-pool work, a forced GC, managed exceptions, file
I/O, and AF_UNIX stream sockets. The measured run printed
`DOTNET_PROBE_OK runtime=10.0.15 checksum=150015000 thread=true task=true gc=true exception=true file=true socket=true`,
exited zero, reclaimed resources, and reached
`JSR-LIFE-HEALTH result=root_execution_complete`.

The runtime manifest is generated from the Windows-host-independent publish
tree using the unmodified SDK's `dotnet publish --self-contained` path. Jasper
validates every staged file's length and SHA-256 before installing it into the
bounded runtime cache.

`System.Diagnostics.Process`/`posix_spawn` remains outside this runtime-baseline
claim. Its vfork parent resumption, exec confirmation, and wait/wake semantics
belong to the POSIX/Linux semantic-conformance track rather than the CoreCLR
acceptance gate.

## Remaining Jasper work

- Provide a general root-image namespace for Android `/system`, `/apex` and
  framework paths instead of the current bounded Linux fixture.
- Run Android Activity/Framework lifecycle, resources/configuration, graphics,
  input and audio for an installed APK through that path.
- Stage Wine/DXVK/VKD3D and Metal2Vulkan in a Jasper guest with a real GPU or
  an explicit virtual Vulkan device; the current UEFI QEMU fixture has no
  virtio-gpu/Vulkan device.
- Deliver synchronous guest signals, including the AVX-preservation `SIGSEGV`
  probe, without terminating the Linux process.
- Complete POSIX process-creation semantics used by `posix_spawn`, including
  vfork shared-stack lifetime, exec confirmation, child reaping and wait wakeup.

These are compatibility gaps, not passing results.
