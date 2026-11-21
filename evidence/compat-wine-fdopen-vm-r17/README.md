# Wine prefix bootstrap diagnostic

This run uses the ABI build VM, the unmodified Ubuntu Wine 10.0 tree and the
Jasper UEFI path. It is negative evidence, not a Wine pass.

The run reaches `/data/wineprefix`, creates the wineserver temp-state file,
passes `fcntl(F_GETFL)` and `fstat` for the writable cache fd, then aborts in
glibc with `free(): invalid pointer` and process exit code 134.

The serial log records the exact `JSR-WINE-*` path, fd and filesystem
diagnostics needed for the next heap-corruption investigation.
