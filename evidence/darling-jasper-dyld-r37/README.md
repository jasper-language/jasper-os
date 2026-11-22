# Darling Jasper Mach-O/dyld gate r37

Date: 2026-11-22

Mode: `compat-darling`

This is a real UEFI Jasper guest run of the pinned unmodified Darling
`0.1.20260609~noble` stack. It is a diagnostic milestone, not a Darling
success result.

The launcher and darlingserver complete bounded namespace, mount, procfs and
AF_UNIX initialization. mldr then checks in with darlingserver, publishes
dyld and executable path metadata, exercises Mach port RPC, retrieves
vchroot and uid/gid state, maps real Mach-O segments and enters dyld.

The staged payload then reports:

```text
dyld: Library not loaded: /usr/lib/libobjc.A.dylib
abort_with_payload: reason: dyld: No shared cache present
```

The health chain reaches `JSR-LIFE-HEALTH result=root_execution_complete`.
No `DARLING_JASPER_GUEST_OK`, completed dyld handoff, WindowServer or Metal
result is claimed.
