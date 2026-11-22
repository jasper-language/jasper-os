# Darling release audit: v0.1.20260608

Date: 2026-11-22.

This audit records immutable upstream facts only. It does not claim that
Darling ran on Jasper-OS.

## Source of truth

- Repository: <https://github.com/darlinghq/darling>
- Release: `v0.1.20260608`
- Tag commit: `e947f0d5a3c6bba27e3631d9bf0da2a9840e6894`
- GitHub release published: `2026-06-09T04:41:09Z`
- Repository license: GPL-3.0; submodules require individual review

## Downloaded package archive

```text
URL=https://github.com/darlinghq/darling/releases/download/v0.1.20260608/debs_20260608.zip
bytes=118018438
sha256=27469ef3932da2e91dd7fb34b70e3628a3e54b7af9fb5480051f44af35eca1fd
```

The SHA-256 matched the digest published by the GitHub release API. The ZIP
contains 22 files grouped under `debs_20260609/`; the package version observed
inside the archive is `0.1.20260609~noble` rather than the tag date.

## Package observations

```text
Package: darling-core
Version: 0.1.20260609~noble
Architecture: amd64
Depends: libc6 (>= 2.38), libc6-i386 (>= 2.38), libgcc-s1 (>= 3.0),
         libstdc++6 (>= 12), xdg-user-dirs

Package: darling-cli
Depends: libc6 (>= 2.2.5), libfuse2t64 (>= 2.2), darling-system,
         darling-cli-gui-common, darling-cli-python2-common

Package: darling
Depends: darling-cli, darling-python2, darling-ruby, darling-perl,
         darling-gui, darling-gui-stubs, darling-pyobjc
```

The archive contains:

```text
-rwsr-xr-x root/root 31648 ./usr/bin/darling
-rwxr-xr-x root/root 2384544 ./usr/bin/darlingserver
-rwxr-xr-x root/root 295168 ./usr/libexec/darling/sbin/launchd
-rwxr-xr-x root/root 158664
  ./usr/libexec/darling/usr/libexec/darling/mldr
```

The setuid-root launcher, namespace/overlayfs design, external FUSE/X11/GL/GUI
dependencies and separate Mach-O/dyld/darlingserver stack are why the Jasper
route remains gated in `verification/darling-research.toml`.
