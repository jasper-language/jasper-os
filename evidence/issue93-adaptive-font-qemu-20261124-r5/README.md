# Issue 93 adaptive terminal metrics QEMU acceptance

Date: 2026-11-24.

This QEMU/OVMF run uses the real native framebuffer terminal with the pinned
Noto bitmap raster selected from the actual framebuffer height:

- 16 px / 10x20 cells for 800x600-class modes;
- 20 px / 12x24 cells for 1080p-and-larger modes.

The automated input path verifies native CLI startup, help, update status,
history recall through the terminal input path, Ctrl-C, EOF, exit code zero and
complete first-program resource reclamation.

```text
Jasper-OS native CLI
native-help-ok
system-update-ok
native-echo=history
^C
native-bye
[JSR-PROD] first_program state=Some(Exited { code: 0 }) reclaimed=true
```

Artifact hashes:

```text
e72dadf04862c34b6860d3698e2da1e9b6b76886d8a1f28b05959a0939a768c1  serial.log
19b8d5c59e421f037fe563007c7254eb8d98bc221b278c3db3e5fdbbfd52e273  qemu.rc
0233754226c5fbce126fb94f9a344da84943dffbb3a99c802947b303b4bbaa5f  kernel-build.log
```

`qemu.rc=33` is the expected successful debug-exit value. This is a functional
text-terminal slice, not a complete EDID/DPI/display-mode or full CJK
qualification.
