# Android APK container and ART execution

Date: 2026-11-18.

The upstream APK was validated with the AOSP build-tools `aapt2`, then executed
through the real Jasper-OS UEFI root-image, Bionic linker, Linux ABI and
unmodified AOSP ART runtime.

APK identity:

```text
sha256=22c31a97b1e551d2814df0e9d2f59c5da93f37c9b43e2e03ac0f84c4359c0d05
bytes=5319080
package=com.example.androidautobuildapk
launcher=com.example.androidautobuildapk.MainActivity
sdk=21/32
dex=classes.dex,classes2.dex,classes3.dex
```

The host-side APK preflight checks ZIP integrity and duplicate names, required
manifest/resource/multidex entries, package identity, SDK levels and the
launcher Activity from the binary manifest. It is an input gate, not a Jasper
runtime result.

Real UEFI/QEMU result:

```text
[JSR-LIFE-ROOT-DYNAMIC] program=android-apk-upstream
  path=/system/bin/dalvikvm64 interpreter=/system/bin/linker64
  mapped=true interpreter_syscalls=true syscalls=23154
  exit_zero=true resources=true failed=0
[JSR-LIFE-HEALTH] result=root_execution_complete
qemu_rc=33
```

Kernel SHA-256:
`f2f9a822bcc1cf5fd5683d37893e55bdaa1f6beb53fafaf8fc5c2cc3183bd177`.

Command:

```text
JASPER_ANDROID_TREE=/home/auth/.cache/jasper-abi-runtime-test/android-system-image/art-test-v1 \
ANDROID_AAPT2=/home/auth/.cache/jasper-abi-runtime-test/android-buildtools/sdk34/android-14/aapt2 \
JASPER_BUILD_ALLOW_VBOX=1 JASPER_BUILD_CPUS=4-5 \
ISSUE21_UEFI_MODE=android-apk ISSUE21_UEFI_TIMEOUT=600 \
ISSUE21_QEMU_CPUS=6-7 ISSUE21_QEMU_SMP=2 \
bash scripts/issue21-uefi-boot-check.sh
```

This proves an upstream APK container and one multi-DEX Java entry can be
loaded and executed by unmodified ART on Jasper. It does **not** prove Android
Activity/Framework lifecycle, resources/configuration delivery, graphics,
input or audio. `COMPAT-APK-1` therefore remains incomplete.
