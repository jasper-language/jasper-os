# Wine D3D11 WSI service desktop r106

Date: 2026-11-23.

Status: **failed; no Jasper guest WSI pass is claimed**.

The fixture now binds itself to a dedicated `__wineservice_winstation`
process window station before loading `d3d11.dll`. Explorer launch is disabled
for this profile, and `uxtheme.dll` is part of the tracked Wine module closure.

The guest confirms the intended setup:

```text
D3D11_WSI_DESKTOP service=true
0024:err:win:get_desktop_window failed to start explorer c0000135
0024:err:win:get_desktop_window failed to create desktop window
0024:err:class:NtUserRegisterClassExWOW Failed to get shared session object for window class
D3D11_WSI_PROBE_FAIL stage=register-window-class
```

This moves the failure past explorer and past the previously missing
`uxtheme.dll`. The remaining blocker is the missing Wine desktop display-driver
bridge that creates the service-desktop top-level window and its shared session
object. The probe has not yet reached DXGI swapchain creation, Vulkan WSI or
Present, so this transcript is not evidence of a D3D/Vulkan semantic failure.

The QEMU transaction restored its resource baseline and emitted no kernel panic.
See `docs/COMPAT-D3D11-WSI-status.md` for the remaining gate.
