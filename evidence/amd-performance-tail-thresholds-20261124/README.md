# Extended latency tails and threshold counts

This build extends the two-row final benchmark summary with:

- P99.99 (`p9999`),
- P99.999 (`p99999`),
- exact counts above 1 us, 10 us, and 50 us,
- an explicit spike classification.

Spikes are reported as `SPIKE=unattributed` until the observability framework
can correlate a sample with interrupt, lock, scheduler, or migration evidence.
The benchmark does not invent a cause.

## Image

- Kernel SHA-256:
  `956b9e47e335b49e61d5243b6a032f7db9b266a59273bfb4d2d5b1630437f4fe`
- OVMF reached BSP-only startup and emitted one million samples with both new
  percentile fields and all three threshold counts.
- The same summary explicitly reports `PARALLEL_MATRIX=not_run` when fewer than
  two CPUs are online. It never presents BSP-only results as 16-thread SMP
  evidence.

P99.999 has a `low_tail_count` confidence at one million samples and requires
ten million samples for the recommended confidence level. The value remains
reported rather than hidden.

Raw control serial is in `normal/serial.log`. Physical evidence still requires
the AMD machine to fetch this image and reach the final summary.
