# Jasper-OS CPL3 UI Service launch

This run embeds the independently built `user/ui-service` ELF in the x86_64
Jasper-OS verification kernel. The host and Service use a real Channel pair;
the Service consumes one JSUI v1 Scene frame and emits a JSUI Error frame with
payload `service.ui.error.engine_unavailable`, then exits 69.

The marker below is a fail-closed result. It is not a rendered frame and does
not mark UI-OS-1 complete.

```text
[JSR-USERTEXT] task=ui-service bytes=50 text=ui-service: ready protocol=1 engine=blocked-no-std
[JSR-UI-PROCESS] started=true channel=true request_queued=true blocked=true exit=69 response=true terminal_alive=true resources=true checks=9 failed=0
```

```text
qemu_rc=33
engine_commit=4194117011f13fdc063977683162fd5a145c85d7
```

Reproduction:

```bash
JASPER_BUILD_ALLOW_VBOX=1 JASPER_BUILD_CPUS=4-5 \
  UI_PROCESS_QEMU_CPUS=6-7 bash scripts/ui-process-check.sh
```

The generated disk image is intentionally omitted from the committed evidence;
`artifacts.sha256` records the kernel ELF and image hashes from this run.
