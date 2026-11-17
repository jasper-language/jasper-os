# Ubuntu glibc getrandom virtio-rng fallback

Command:

```text
COMPAT_PTHREAD_CPUS=4 \
  CARGO_BUILD_JOBS=2 taskset -c 4-7 bash scripts/compat-pthread-sample.sh
```

Result:

```text
compat-pthread: PASS cpus=4
qemu_rc=33
[JSR-COMPAT-RNG] source=virtio-rng forced=true queue_size=8 bdf=00:03.0
jasper-pthread-ok
[JSR-COMPAT-PTHREAD] ... exit_zero=true ... resources=true failed=0
```

The QEMU CPU advertises RDRAND, but `compat-rng-force` deliberately bypasses it.
The unmodified Ubuntu glibc `getrandom()` calls therefore complete through the
bounded virtio-rng queue, and two 32-byte requests are non-zero and different.

CPU 1 also passed in `evidence/compat-pthread-20261117-193004`. An earlier run
at `evidence/compat-pthread-20261117-192549` demonstrated the fallback but
failed its resource assertion; that run is retained as diagnostic evidence and
is not counted as acceptance.
