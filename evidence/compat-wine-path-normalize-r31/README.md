# Wine path normalization probe r31

Date: 2026-11-22

This run exercises the unmodified Ubuntu Wine `10.0~repack-12ubuntu1`
preloader through the Jasper Linux ABI with an explicit Wine
`WINEDEBUG=+server,+heap` diagnostic environment.
That diagnostic toggle was local to the probe and is restored to `-all` in the
committed production path.

The run is intentionally not a pass: Wine still terminates with glibc
`free(): invalid pointer` after creating the wineserver temporary state.

It records the narrower path-semantics result:

- the compatibility VFS accepts Wine's absolute path containing `..`
  components;
- `/usr/share/wine/nls/c_20127.nls`, `locale.nls` and `l_intl.nls` open and
  `fstat` through stable virtual file handles;
- the previous three `err:environ:read_nls_file failed` lines are absent.

QEMU was terminated by the 90-second harness timeout after the expected Wine
abort, so the wrapper-level exit is non-zero. The serial log is retained
because it contains the relevant syscall and process evidence.

Reproduce:

```text
ISSUE21_UEFI_MODE=compat-wine \
JASPER_ANDROID_TREE=/home/auth/Documents/jasper/compat-wine/root \
ISSUE21_QEMU_CPUS=4-7 \
ISSUE21_QEMU_SMP=2 \
ISSUE21_UEFI_TIMEOUT=90 \
bash scripts/issue21-uefi-boot-check.sh
```
