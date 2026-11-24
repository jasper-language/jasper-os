# Darling namespace capability audit

Date: 2026-11-22

This is a host feasibility check for the pinned Darling research release. It is
not a Jasper guest pass.

The `debs_20260608.zip` release archive was verified as:

```text
sha256=27469ef3932da2e91dd7fb34b70e3628a3e54b7af9fb5480051f44af35eca1fd
```

The extracted launcher correctly rejected a non-root-owned setuid copy:

```text
Sorry, the binary is not setuid root, which is mandatory.
Darling needs this in order to create mount and PID namespaces and to perform mounts.
```

A user-namespace bubblewrap environment with UID/GID 0 reached the next gate,
but the host kernel denied Darling's request to create UTS and IPC namespaces:

```text
Cannot unshare UTS and IPC namespaces to create darling-init: Operation not permitted
```

The input payload remains accepted by
`scripts/prepare-darling-research-tree.sh`, which verifies the release digest
and the eight curated ELF/Mach-O payloads. Launching an unmodified Darling
prefix still requires Jasper namespace, mount/overlay and setuid-launch
authorization semantics; no `DARLING_JASPER_GUEST_OK` result is claimed.
