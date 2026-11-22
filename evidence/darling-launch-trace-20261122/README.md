# Darling privileged host trace

Date: 2026-11-22

This is a `--privileged` Ubuntu 24.04 container trace of the pinned Darling
launcher. It is a host-only research baseline, not a Jasper guest result.

The observed launch sequence is:

```text
setuid(0)
setgid(0)
unshare(CLONE_NEWUTS|CLONE_NEWIPC)
clone(...SIGCHLD...)
setresgid/setresuid(0,0,0)
vfork ... multiple helper initializers
unshare(CLONE_NEWNS)
umount2("/dev/shm", 0)
mount("tmpfs", "/dev/shm", ...)
mount(NULL, "/", MS_REC|MS_SLAVE)
mount("overlay", DPREFIX, "overlay", 0, "lowerdir=...")
```

The container reached the overlay mount and failed with `EINVAL` because the
host environment did not admit that overlay configuration. The trace still
establishes the required Jasper ABI/foundation order: UTS/IPC namespace,
vfork/reap, mount namespace, tmpfs/slave remount, then overlay/vchroot.

No `DARLING_JASPER_GUEST_OK` or Mach-O handoff is claimed.
