# LC-3 P0-QEMU-FAULT-V1 acceptance

The declared fault-injection profile used real OVMF, GPT, ESP FAT32, System
A/B and shared Data ext4 images. The following scripts all passed:

```text
issue21-ab-rollback-check.sh
  PASS candidate_attempts=3 fallback=A
  evidence/issue21-lc3-final-ab-r2

issue21-trial-powercut-check.sh
  PASS cuts=3 recovered=A
  evidence/issue21-lc3-final-powercut-r2

issue21-confirm-cut-check.sh
  PASS prior_generation=3 reconfirmed_generation=5
  evidence/issue21-lc3-final-confirm-cut-r2

issue21-control-copy-cut-check.sh
  PASS recovered_generation=2 confirmed=B
  evidence/issue21-lc3-final-copy-cut-r2
```

The confirm-cut flow writes and verifies a random 64 KiB Data payload before
confirmation and after recovery. This proves the P0 QEMU profile only; physical
disk, TPM/Secure Boot and multi-vendor firmware qualification remain separate.
