# Issue 95 ProxyDHCP kernel-loading fix

QEMU UEFI PXE contract: **PASS**.

The previous loader selected the normal DHCP ACK server and never requested the
kernel. The fixed loader:

- prefers PXE Reply, then ProxyDHCP offer, then DHCP ACK;
- reads DHCP option 54 when `siaddr` is zero, as used by ProxyDHCP;
- prints the selected TFTP server and source.

Observed QEMU path:

```text
PXE TFTP server 10.0.2.2 selected from dhcp-ack
UEFI bootloader started
Jumping to kernel entry point at VirtAddr(0x1000002aa70)
[JSR-BOOT] jasper-os rust kernel 0.0.1 x86_64
[JSR-CLOCK-FACT] scale=monotonic ... time64_ns=74041279 ... time128_fraction=1365820524603125476 ... uncertainty=unknown
```

SHA-256:

```text
61e9aaad21bacb98abfcfe02306c6322559db3ab68303e3fae3e4cc191042782  bootloader.efi
0bf4ac7fceb6b56e2fa0ebf41ac11e5065c0418d43507c110e64a30763a166f8  kernel-x86_64
```
