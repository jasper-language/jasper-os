# LC-5 2-of-3 release threshold acceptance

Date: 2026-11-17

The release manifest schema is now `jasper.release-artifact/v2`. The signed
message includes the stable/LTS release metadata, payload and SBOM identities,
the ordered signer fingerprints, their signature filenames, and a threshold of
two.

The supply drill generated three independent Ed25519 signers and covered:

```text
3-of-3 accepted
2-of-3 accepted
1-of-3 rejected: threshold not met
duplicate signature file rejected
tampered manifest rejected by Ed25519 verification
revoked declared signer rejected
B/C/D trust-root rotation accepted at 2-of-3
two authenticated HTTPS sources and one offline copy matched byte-for-byte
```

Commands:

```text
python3 scripts/check-release-policy.py
release-policy: PASS channels=stable,lts sources>=2 signatures=2-of-3

bash scripts/release-revocations-check.sh
release-revocations-check: PASS signed=true monotonic=true replay_rejected=true rollback_rejected=true dual_copy=true audit=true

bash scripts/release-supply-check.sh
release-supply-check: PASS threshold=2 signers=3 revocation=true
  revocation_snapshot_epoch=2 rotation=true https_sources=2
  offline_sources=1 tamper_rejected=true
```

This closes the repository-side 2-of-3 signature verification slice only. It
does not provide production HSM/offline custody, TPM monotonic storage, remote
immutable audit retention, signed release ceremonies, or a complete LTS patch
backport and re-upgrade lifecycle. LC-5 therefore remains in progress.
