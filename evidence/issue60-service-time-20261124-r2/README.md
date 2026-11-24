# Issue 60 service.time QEMU acceptance

Date: 2026-11-24.

The QEMU/OVMF acceptance runs `user/timeprobe` as the production first program.
The probe starts the independently built `user/timed` ELF, exchanges versioned
requests over a real native Channel, and checks:

- describe and sampled monotonic facts;
- exact Time64/Time128 coherence;
- idempotent replay and request-ID conflict rejection;
- explicit deadline expiry and malformed-version rejection;
- clean restart with a new service generation;
- denial when the time/ABI capabilities are absent;
- complete first-program resource reclamation.

Result:

```text
[JSR-SERVICE-TIME] describe=true sample=true replay=true deadline=true
protocol=true conflict=true restart=true denied_capability=true
time64_time128_coherent=true ok=true
[JSR-PROD] first_program state=Some(Exited { code: 0 }) reclaimed=true
```

Artifact hashes:

```text
daee1151e3daad9669e7fe55b98a307dd68016b5df605aa8379e8cc7b6b59b53  serial.log
19b8d5c59e421f037fe563007c7254eb8d98bc221b278c3db3e5fdbbfd52e273  qemu.rc
2b0282b13dfcc1b6ec97ff31904b2af03efa320a7061ec5e6b9d03f5b6634506  kernel-build.log
```

`qemu.rc=33` is the expected successful debug-exit value. This is a functional
service-boundary result, not a wall-clock trust or physical precision claim.
