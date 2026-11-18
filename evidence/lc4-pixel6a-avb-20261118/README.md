# LC-4 Pixel 6a Android boot image / AVB verification

Date: 2026-11-18.

This is a read-only host preflight over the matching Pixel 6a factory
`boot.img`. It does not invoke fastboot, flash, erase or change a slot.

Input SHA-256:

```text
43f53f67a292bd8341fc73ec1329b06232b581669ea11b64d5d795cb6090fffa
```

Command:

```text
PIXEL6A_BOOT_IMAGE=/home/auth/Documents/jasper/pixel6a-evidence/factory-image/boot.img \
PIXEL6A_AVB_OUT="$PWD/evidence/lc4-pixel6a-avb-20261118" \
bash scripts/pixel6a-avb-check.sh
```

The embedded AVB metadata uses SHA-256 with RSA-4096. Verification covers the
AVB header hash, RSA PKCS#1 v1.5 signature, public-key encoding and the salted
`boot` partition hash descriptor.

```text
positive.log:
avb-verify: PASS partition=boot version=4 kernel_size=16565921
original_image_size=16588800 rollback_index=1764892800
signer_sha256=9ac4174153d45e4545b0f49e22fe63273999b6ac1cb6949c3a9f03ec8807eee9
content_sha256=c13cf17b0d0254cd40a1921615f0a971789a21de630e6fbc93296ac9b9266e27

tampered.log:
avb-verify: FAIL: AVB protected content hash does not match

bad-signature.log:
avb-verify: FAIL: AVB RSA signature is invalid

wrong-partition.log:
avb-verify: FAIL: AVB partition descriptor is missing
```

The loopback/negative runs preserve valid AVB metadata while changing one
kernel byte, change only the RSA signature, or request a descriptor that is not
present. All are rejected before producing lifecycle facts.

This evidence closes neither LC-4 nor any hardware DAG node. Jasper signer
trust/revocation, AVB rollback storage, chain-partition traversal, firmware
write, failed-firmware recovery and the physical device matrix remain pending.
