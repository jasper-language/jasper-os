# LC-5 software supply and production-preflight slice

Date: 2026-11-18.

This run verifies the software portion of LC-5 without claiming that a production
release ceremony or real TPM provisioning has occurred.

## Passed checks

```text
release-policy: PASS channels=stable,lts sources>=2 signatures=2-of-3
release-repro: PASS target=x86_64-unknown-none affinity=4-11
sha256=3002b82ee1559d59920e33b5c1ac55ee5e9f14e966d9cc0bf1456e77f861a30c
release-supply-check: PASS threshold=2 signers=3 revocation=true
revocation_snapshot_epoch=2 rotation=true https_sources=2 offline_sources=1
tamper_rejected=true
release-remote-audit-check: PASS append=true idempotent=true
tamper_rejected=true auth_rejected=true index_rejected=true
https_required=true tls_verified=true
jasper-lifecycle-staging::tests::threshold_source_stages_two_distinct_signatures
PASS
```

The separate-signing flow prepares one canonical manifest from three public
keys, signs identical manifest bytes in independent invocations, rejects an
undeclared fourth key before publishing a signature, rejects signature
overwrites, and verifies the collected 2-of-3 set against the fixed policy.

The lifecycle integration test supplies a canonical `manifest.sigset` through a
real directory source and requires the threshold policy before artifacts enter
the staging coordinator.

## Production preflight remains closed

`scripts/release-production-preflight.py --inventory` correctly returned
`NOT READY` with:

```text
tpm-access tpm-getcap tpm-nvread tpm-nvreadpublic tpm-nvincrement
tpm-nv-index release-trust governance-trust remote-audit-endpoint
```

The host discovers a TPM 2.0 device, but the current account cannot access
`/dev/tpmrm0`, `tpm2-tools` is absent, and no Jasper-specific NV counter,
production release/governance trust roots, or immutable production audit sink
has been provisioned. Test keys and loopback services are not production
qualification.

Commands:

```text
PATH=/home/auth/.cargo/bin:$PATH python3 scripts/check-release-policy.py
PATH=/home/auth/.cargo/bin:$PATH bash scripts/release-repro-check.sh
PATH=/home/auth/.cargo/bin:$PATH bash scripts/release-supply-check.sh
PATH=/home/auth/.cargo/bin:$PATH cargo test --locked \
  -p jasper-lifecycle-staging --lib \
  threshold_source_stages_two_distinct_signatures
python3 scripts/release-production-preflight.py --inventory
```
