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

static void write_line(const char *line)
{
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written = 0;
    if (output && output != INVALID_HANDLE_VALUE) {
        WriteFile(output, line, (DWORD)strlen(line), &written, NULL);
    }
}

static int fail(const char *stage, HRESULT result)
{
    char line[192];
    snprintf(line, sizeof(line),
             "D3D11_WSI_PROBE_FAIL stage=%s hr=0x%08lx\n",
             stage, (unsigned long)result);
    write_line(line);
    return 1;
}

static void stage_ok(const char *stage)
{
    printf("D3D11_WSI_STAGE stage=%s ok=true\n", stage);
    fflush(stdout);
}

static LONG WINAPI log_exception(EXCEPTION_POINTERS *info)
{
    printf("D3D11_WSI_EXCEPTION code=0x%08lx address=%p\n",
           (unsigned long)info->ExceptionRecord->ExceptionCode,
           info->ExceptionRecord->ExceptionAddress);
    fflush(stdout);
    return EXCEPTION_CONTINUE_SEARCH;
}

static void log_atexit(void)
{
    printf("D3D11_WSI_EXIT atexit=true\n");
    fflush(stdout);
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
    typedef HRESULT (WINAPI *CreateDeviceFn)(
        IDXGIAdapter *,
        D3D_DRIVER_TYPE,
        HMODULE,
        UINT,
        const D3D_FEATURE_LEVEL *,
        UINT,
        UINT,
        ID3D11Device **,
        D3D_FEATURE_LEVEL *,
        ID3D11DeviceContext **);
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
    HMODULE d3d11_module = NULL;
    CreateDeviceFn create_device = NULL;
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
        WS_POPUP | WS_VISIBLE,
        0,
        0,
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
    if (!SetWindowPos(window, NULL, 0, 0, 64, 64,
                      SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED)) {
        result = HRESULT_FROM_WIN32(GetLastError());
        stage = "set-window-geometry";
        goto out;
    }
    ShowWindow(window, SW_SHOWNOACTIVATE);
    UpdateWindow(window);
    pump_messages();

    stage = "create-device";
    d3d11_module = LoadLibraryW(L"d3d11.dll");
    if (!d3d11_module) {
        result = HRESULT_FROM_WIN32(GetLastError());
        goto out;
    }
    create_device = (CreateDeviceFn)(void *)GetProcAddress(
        d3d11_module, "D3D11CreateDevice");
    if (!create_device) {
        result = HRESULT_FROM_WIN32(GetLastError());
        stage = "resolve-d3d11";
        goto out;
    }
    result = create_device(
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
    stage_ok("create-device");

    stage = "query-dxgi-device";
    result = ID3D11Device_QueryInterface(
        device, &IID_IDXGIDevice, (void **)&dxgi_device);
    if (FAILED(result)) goto out;
    stage_ok("query-dxgi-device");
    stage = "get-adapter";
    result = IDXGIDevice_GetAdapter(dxgi_device, &adapter);
    if (FAILED(result)) goto out;
    stage_ok("get-adapter");
    stage = "get-factory";
    result = IDXGIAdapter_GetParent(
        adapter, &IID_IDXGIFactory2, (void **)&factory);
    if (FAILED(result)) goto out;
    stage_ok("get-factory");

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
    stage_ok("create-swapchain");

    stage = "get-backbuffer";
    result = IDXGISwapChain1_GetBuffer(
        swapchain, 0, &IID_ID3D11Texture2D, (void **)&backbuffer);
    if (FAILED(result)) goto out;
    stage_ok("get-backbuffer");
    stage = "create-render-target";
    result = ID3D11Device_CreateRenderTargetView(
        device, (ID3D11Resource *)backbuffer, NULL, &render_target);
    if (FAILED(result)) goto out;
    stage_ok("create-render-target");
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
    stage_ok("create-staging");
    ID3D11DeviceContext_CopyResource(
        context,
        (ID3D11Resource *)staging,
        (ID3D11Resource *)backbuffer);
    stage = "map-backbuffer";
    result = ID3D11DeviceContext_Map(
        context, (ID3D11Resource *)staging, 0, D3D11_MAP_READ, 0, &mapped);
    if (FAILED(result)) goto out;
    stage_ok("map-backbuffer");
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

    stage_ok("unmap-staging");
    {
        RECT client = {0};
        GetClientRect(window, &client);
        printf("D3D11_WSI_WINDOW visible=%u iconic=%u client=%ldx%ld\n",
               (unsigned)IsWindowVisible(window),
               (unsigned)IsIconic(window),
               (long)(client.right - client.left),
               (long)(client.bottom - client.top));
        fflush(stdout);
    }
    printf("D3D11_WSI_VTABLE present=%p next=%p\n",
           (void *)swapchain->lpVtbl->Present,
           (void *)swapchain->lpVtbl->GetBuffer);
    fflush(stdout);
    stage_ok("before-present");
    result = IDXGISwapChain1_Present(swapchain, 0, 0);
    if (result != S_OK) goto out;
    stage_ok("present");
    pump_messages();

    {
        char line[192];
        snprintf(
            line, sizeof(line),
            "D3D11_WSI_PROBE_OK feature=0x%x hwnd=1 swapchain=1 "
            "buffer=1 present=1 pixel=%u,%u,%u,%u size=64x64\n",
            (unsigned)feature_level,
            pixel_r, pixel_g, pixel_b, pixel_a);
        write_line(line);
    }

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
    if (d3d11_module) FreeLibrary(d3d11_module);

    if (SUCCEEDED(result)) return 0;
    return fail(stage, result);
}

/*
 * Bind the current process and thread to Wine's service window station before
 * creating any user objects. Wine handles this desktop without launching
 * explorer.exe, while still exercising the real win32u HWND path.
 */
static int run_on_service_desktop(void)
{
    static const WCHAR station_name[] = L"__wineservice_winstation";
    static const WCHAR desktop_name[] = L"Default";
    HWINSTA station;
    HDESK desktop;
    DWORD error;

    station = CreateWindowStationW(station_name, 0, WINSTA_ALL_ACCESS, NULL);
    if (!station && GetLastError() == ERROR_OBJECT_ALREADY_EXISTS) {
        station = OpenWindowStationW(station_name, FALSE, WINSTA_ALL_ACCESS);
    }
    if (!station) {
        return fail("open-service-winstation",
                    HRESULT_FROM_WIN32(GetLastError()));
    }
    if (!SetProcessWindowStation(station)) {
        error = GetLastError();
        CloseHandle(station);
        return fail("set-service-winstation", HRESULT_FROM_WIN32(error));
    }
    CloseHandle(station);

    desktop = CreateDesktopW(desktop_name, NULL, NULL, 0, GENERIC_ALL, NULL);
    if (!desktop && GetLastError() == ERROR_OBJECT_ALREADY_EXISTS) {
        desktop = OpenDesktopW(desktop_name, 0, FALSE, GENERIC_ALL);
    }
    if (!desktop) {
        return fail("open-service-desktop",
                    HRESULT_FROM_WIN32(GetLastError()));
    }
    if (!SetThreadDesktop(desktop)) {
        error = GetLastError();
        CloseHandle(desktop);
        return fail("set-service-desktop", HRESULT_FROM_WIN32(error));
    }
    CloseHandle(desktop);

    printf("D3D11_WSI_DESKTOP service=true\n");
    return run_probe();
}

int main(int argc, char **argv)
{
    (void)argv;
    setvbuf(stdout, NULL, _IONBF, 0);
    atexit(log_atexit);
    AddVectoredExceptionHandler(1, log_exception);
    if (argc == 1) return run_on_service_desktop();
    return fail("arguments", E_INVALIDARG);
}
