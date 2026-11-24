#define COBJMACROS
#include <windows.h>
#include <d3d11.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

/*
 * Verification build:
 *   x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -Werror \
 *     -Wl,--disable-dynamicbase -o d3d11-probe.exe d3d11_probe.c -ld3d11
 *
 * The fixed base is intentional for the current bounded Jasper user window.
 */

static int fail(const char *stage, HRESULT result)
{
    printf("D3D11_PROBE_FAIL stage=%s hr=0x%08lx\n",
           stage, (unsigned long)result);
    return 1;
}

static int run_probe(void)
{
    D3D11_TEXTURE2D_DESC texture_desc = {0};
    D3D11_MAPPED_SUBRESOURCE mapped = {0};
    D3D_FEATURE_LEVEL feature_level = 0;
    ID3D11RenderTargetView *render_target = NULL;
    ID3D11Texture2D *texture = NULL;
    ID3D11Texture2D *staging = NULL;
    ID3D11DeviceContext *context = NULL;
    ID3D11Device *device = NULL;
    const FLOAT clear_color[4] = {0.125f, 0.25f, 0.5f, 1.0f};
    const unsigned char *pixel;
    HRESULT result;

    result = D3D11CreateDevice(
        NULL,
        D3D_DRIVER_TYPE_HARDWARE,
        NULL,
        0,
        NULL,
        0,
        D3D11_SDK_VERSION,
        &device,
        &feature_level,
        &context);
    if (FAILED(result)) return fail("create-device", result);

    texture_desc.Width = 16;
    texture_desc.Height = 16;
    texture_desc.MipLevels = 1;
    texture_desc.ArraySize = 1;
    texture_desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    texture_desc.SampleDesc.Count = 1;
    texture_desc.Usage = D3D11_USAGE_DEFAULT;
    texture_desc.BindFlags = D3D11_BIND_RENDER_TARGET;
    result = ID3D11Device_CreateTexture2D(
        device, &texture_desc, NULL, &texture);
    if (FAILED(result)) return fail("create-target", result);
    result = ID3D11Device_CreateRenderTargetView(
        device, (ID3D11Resource *)texture, NULL, &render_target);
    if (FAILED(result)) return fail("create-view", result);

    ID3D11DeviceContext_ClearRenderTargetView(
        context, render_target, clear_color);

    texture_desc.Usage = D3D11_USAGE_STAGING;
    texture_desc.BindFlags = 0;
    texture_desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    result = ID3D11Device_CreateTexture2D(
        device, &texture_desc, NULL, &staging);
    if (FAILED(result)) return fail("create-staging", result);
    ID3D11DeviceContext_CopyResource(
        context,
        (ID3D11Resource *)staging,
        (ID3D11Resource *)texture);
    result = ID3D11DeviceContext_Map(
        context, (ID3D11Resource *)staging, 0, D3D11_MAP_READ, 0, &mapped);
    if (FAILED(result)) return fail("map", result);

    pixel = (const unsigned char *)mapped.pData;
    if (pixel[0] != 32 || pixel[1] != 64 ||
        pixel[2] != 128 || pixel[3] != 255) {
        printf("D3D11_PROBE_FAIL stage=pixel pixel=%u,%u,%u,%u\n",
               pixel[0], pixel[1], pixel[2], pixel[3]);
        return 1;
    }
    printf(
        "D3D11_PROBE_OK feature=0x%x pixel=%u,%u,%u,%u\n",
        (unsigned)feature_level,
        pixel[0], pixel[1], pixel[2], pixel[3]);

    ID3D11DeviceContext_Unmap(
        context, (ID3D11Resource *)staging, 0);
    ID3D11Texture2D_Release(staging);
    ID3D11RenderTargetView_Release(render_target);
    ID3D11Texture2D_Release(texture);
    ID3D11DeviceContext_Release(context);
    ID3D11Device_Release(device);
    return 0;
}

/*
 * Run the actual probe on Wine's service window station so headless D3D
 * validation does not require an X11/Wayland display server. The service
 * desktop is a real Wine window station and still exercises win32u/driver
 * initialization; it only avoids spawning explorer.exe.
 */
static int run_on_service_desktop(void)
{
    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION process = {0};
    WCHAR module[MAX_PATH];
    WCHAR command[MAX_PATH + 32];
    HANDLE standard_handles[3];
    DWORD exit_code = 1;

    if (!GetModuleFileNameW(NULL, module, ARRAYSIZE(module))) {
        return fail("locate-self", HRESULT_FROM_WIN32(GetLastError()));
    }
    if (swprintf(command, ARRAYSIZE(command), L"\"%ls\" --service-child", module) < 0) {
        return fail("build-service-command", HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER));
    }

    standard_handles[0] = GetStdHandle(STD_INPUT_HANDLE);
    standard_handles[1] = GetStdHandle(STD_OUTPUT_HANDLE);
    standard_handles[2] = GetStdHandle(STD_ERROR_HANDLE);
    for (size_t i = 0; i < ARRAYSIZE(standard_handles); i++) {
        if (standard_handles[i] && standard_handles[i] != INVALID_HANDLE_VALUE) {
            SetHandleInformation(standard_handles[i], HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
        }
    }

    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = standard_handles[0];
    startup.hStdOutput = standard_handles[1];
    startup.hStdError = standard_handles[2];
    startup.lpDesktop = L"__wineservice_winstation\\Default";

    if (!CreateProcessW(NULL, command, NULL, NULL, TRUE, 0, NULL, NULL,
                        &startup, &process)) {
        return fail("spawn-service-child", HRESULT_FROM_WIN32(GetLastError()));
    }
    WaitForSingleObject(process.hProcess, INFINITE);
    GetExitCodeProcess(process.hProcess, &exit_code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return exit_code == 0 ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (argc == 1) return run_on_service_desktop();
    if (argc == 2 && !strcmp(argv[1], "--service-child")) return run_probe();
    return fail("arguments", E_INVALIDARG);
}
