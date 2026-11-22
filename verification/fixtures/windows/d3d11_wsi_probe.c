#define COBJMACROS
#include <windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

/*
 * Verification build:
 *   x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -Werror \
 *     -Wl,--disable-dynamicbase -o d3d11-wsi-probe.exe \
 *     d3d11_wsi_probe.c -ld3d11 -ldxgi -lole32 -luuid
 *
 * The fixed PE base is intentional for Jasper's current bounded user window.
 * A pass requires every layer to succeed: service desktop, HWND creation,
 * DXGI swapchain/backbuffer, D3D11 clear/readback and Present returning S_OK.
 */

static int fail(const char *stage, HRESULT result)
{
    printf("D3D11_WSI_PROBE_FAIL stage=%s hr=0x%08lx\n",
           stage, (unsigned long)result);
    return 1;
}

static void pump_messages(void)
{
    MSG message;

    while (PeekMessageW(&message, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
}

static int run_probe(void)
{
    static const WCHAR class_name[] = L"JasperD3D11WsiProbe";
    static const WCHAR window_name[] = L"Jasper D3D11 WSI Probe";
    DXGI_SWAP_CHAIN_DESC1 swap_desc = {0};
    D3D11_TEXTURE2D_DESC staging_desc = {0};
    D3D11_MAPPED_SUBRESOURCE mapped = {0};
    D3D_FEATURE_LEVEL feature_level = 0;
    IDXGISwapChain1 *swapchain = NULL;
    IDXGIFactory2 *factory = NULL;
    IDXGIAdapter *adapter = NULL;
    IDXGIDevice *dxgi_device = NULL;
    ID3D11RenderTargetView *render_target = NULL;
    ID3D11DeviceContext *context = NULL;
    ID3D11Texture2D *backbuffer = NULL;
    ID3D11Texture2D *staging = NULL;
    ID3D11Device *device = NULL;
    HINSTANCE instance = GetModuleHandleW(NULL);
    const FLOAT clear_color[4] = {0.125f, 0.25f, 0.5f, 1.0f};
    const unsigned char *pixel;
    unsigned pixel_r;
    unsigned pixel_g;
    unsigned pixel_b;
    unsigned pixel_a;
    WNDCLASSW window_class = {0};
    ATOM class_atom = 0;
    HWND window = NULL;
    HRESULT result = S_OK;
    const char *stage = "register-window-class";

    window_class.lpfnWndProc = DefWindowProcW;
    window_class.hInstance = instance;
    window_class.lpszClassName = class_name;
    class_atom = RegisterClassW(&window_class);
    if (!class_atom && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return fail("register-window-class", HRESULT_FROM_WIN32(GetLastError()));
    }

    stage = "create-window";
    window = CreateWindowExW(
        0,
        class_name,
        window_name,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        64,
        64,
        NULL,
        NULL,
        instance,
        NULL);
    if (!window) {
        result = HRESULT_FROM_WIN32(GetLastError());
        goto out;
    }
    ShowWindow(window, SW_SHOWNOACTIVATE);
    UpdateWindow(window);
    pump_messages();

    stage = "create-device";
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
    if (FAILED(result)) goto out;

    stage = "query-dxgi-device";
    result = ID3D11Device_QueryInterface(
        device, &IID_IDXGIDevice, (void **)&dxgi_device);
    if (FAILED(result)) goto out;
    stage = "get-adapter";
    result = IDXGIDevice_GetAdapter(dxgi_device, &adapter);
    if (FAILED(result)) goto out;
    stage = "get-factory";
    result = IDXGIAdapter_GetParent(
        adapter, &IID_IDXGIFactory2, (void **)&factory);
    if (FAILED(result)) goto out;

    stage = "create-swapchain";
    swap_desc.Width = 64;
    swap_desc.Height = 64;
    swap_desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    swap_desc.SampleDesc.Count = 1;
    swap_desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    swap_desc.BufferCount = 2;
    swap_desc.Scaling = DXGI_SCALING_STRETCH;
    swap_desc.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
    swap_desc.AlphaMode = DXGI_ALPHA_MODE_IGNORE;
    result = IDXGIFactory2_CreateSwapChainForHwnd(
        factory,
        (IUnknown *)device,
        window,
        &swap_desc,
        NULL,
        NULL,
        &swapchain);
    if (FAILED(result)) goto out;

    stage = "get-backbuffer";
    result = IDXGISwapChain1_GetBuffer(
        swapchain, 0, &IID_ID3D11Texture2D, (void **)&backbuffer);
    if (FAILED(result)) goto out;
    stage = "create-render-target";
    result = ID3D11Device_CreateRenderTargetView(
        device, (ID3D11Resource *)backbuffer, NULL, &render_target);
    if (FAILED(result)) goto out;
    ID3D11DeviceContext_ClearRenderTargetView(
        context, render_target, clear_color);

    staging_desc.Width = 64;
    staging_desc.Height = 64;
    staging_desc.MipLevels = 1;
    staging_desc.ArraySize = 1;
    staging_desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    staging_desc.SampleDesc.Count = 1;
    staging_desc.Usage = D3D11_USAGE_STAGING;
    staging_desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    stage = "create-staging";
    result = ID3D11Device_CreateTexture2D(
        device, &staging_desc, NULL, &staging);
    if (FAILED(result)) goto out;
    ID3D11DeviceContext_CopyResource(
        context,
        (ID3D11Resource *)staging,
        (ID3D11Resource *)backbuffer);
    stage = "map-backbuffer";
    result = ID3D11DeviceContext_Map(
        context, (ID3D11Resource *)staging, 0, D3D11_MAP_READ, 0, &mapped);
    if (FAILED(result)) goto out;
    pixel = (const unsigned char *)mapped.pData;
    if (pixel[0] != 32 || pixel[1] != 64 ||
        pixel[2] != 128 || pixel[3] != 255) {
        printf("D3D11_WSI_PROBE_FAIL stage=pixel pixel=%u,%u,%u,%u\n",
               pixel[0], pixel[1], pixel[2], pixel[3]);
        result = E_FAIL;
        goto out;
    }
    pixel_r = pixel[0];
    pixel_g = pixel[1];
    pixel_b = pixel[2];
    pixel_a = pixel[3];
    stage = "present";
    ID3D11DeviceContext_Unmap(context, (ID3D11Resource *)staging, 0);
    mapped.pData = NULL;

    result = IDXGISwapChain1_Present(swapchain, 1, 0);
    if (result != S_OK) goto out;
    pump_messages();

    printf(
        "D3D11_WSI_PROBE_OK feature=0x%x hwnd=1 swapchain=1 "
        "buffer=1 present=1 pixel=%u,%u,%u,%u size=64x64\n",
        (unsigned)feature_level,
        pixel_r, pixel_g, pixel_b, pixel_a);

out:
    if (mapped.pData && context && staging) {
        ID3D11DeviceContext_Unmap(context, (ID3D11Resource *)staging, 0);
    }
    if (staging) ID3D11Texture2D_Release(staging);
    if (render_target) ID3D11RenderTargetView_Release(render_target);
    if (backbuffer) ID3D11Texture2D_Release(backbuffer);
    if (swapchain) IDXGISwapChain1_Release(swapchain);
    if (factory) IDXGIFactory2_Release(factory);
    if (adapter) IDXGIAdapter_Release(adapter);
    if (dxgi_device) IDXGIDevice_Release(dxgi_device);
    if (context) ID3D11DeviceContext_Release(context);
    if (device) ID3D11Device_Release(device);
    if (window) DestroyWindow(window);
    if (class_atom) UnregisterClassW(class_name, instance);

    if (SUCCEEDED(result)) return 0;
    return fail(stage, result);
}

/*
 * Run on Wine's service desktop so this probe exercises win32u and a real
 * HWND/swapchain without requiring explorer.exe or an X11/Wayland launcher.
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
        return fail("build-service-command",
                    HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER));
    }

    standard_handles[0] = GetStdHandle(STD_INPUT_HANDLE);
    standard_handles[1] = GetStdHandle(STD_OUTPUT_HANDLE);
    standard_handles[2] = GetStdHandle(STD_ERROR_HANDLE);
    for (size_t i = 0; i < ARRAYSIZE(standard_handles); i++) {
        if (standard_handles[i] && standard_handles[i] != INVALID_HANDLE_VALUE) {
            SetHandleInformation(
                standard_handles[i], HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
        }
    }

    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = standard_handles[0];
    startup.hStdOutput = standard_handles[1];
    startup.hStdError = standard_handles[2];
    startup.lpDesktop = L"__wineservice_winstation\\Default";

    if (!CreateProcessW(
            NULL,
            command,
            NULL,
            NULL,
            TRUE,
            0,
            NULL,
            NULL,
            &startup,
            &process)) {
        return fail("spawn-service-child",
                    HRESULT_FROM_WIN32(GetLastError()));
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
