# VMX failure-close regression evidence

Date: 2026-11-18.

QEMU/KVM ran the focused `hwv2-verify` image with nested Intel VMX enabled.
The control-path changes replace unsafe VMREAD fallbacks with fail-closed errors;
the normal six-exit path and host XState restoration remain intact.

```text
[JSR-HWV2-XSTATE] host_xcr0=0x7 guest_xcr0=0x3 invalid_rejected=4 host_restored=true failed=0
[JSR-HWV2] backend=Vmx entered=true vmxoff=true vmcs=true ept=true cpuid=1 rdtsc=1 msr=1 io=1 ept_exit=1 exception=1 exits=6 tsc=true xsave=true state_saved=true failed=0
qemu_rc=33
```

This verifies the successful VMX path is not regressed. It does not inject a
VMREAD hardware failure; that negative-injection matrix remains open.
