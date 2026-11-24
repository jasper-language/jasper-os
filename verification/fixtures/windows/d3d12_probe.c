#define INITGUID
#define COBJMACROS
#include <windows.h>
#include <d3d12.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

/*
 * Verification build:
 *   x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -Werror \
 *     -Wl,--disable-dynamicbase,--no-insert-timestamp \
 *     -o d3d12-probe.exe d3d12_probe.c \
 *     -ldxguid -luuid
 *
 * The fixed image base is required only by the current bounded Jasper user
 * window. It is not part of the eventual D3D12 acceptance profile.
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
             "D3D12_PROBE_FAIL stage=%s hr=0x%08lx\n",
             stage, (unsigned long)result);
    write_line(line);
    return 1;
}

#define RELEASE(object) do { \
    if ((object) != NULL) { \
        IUnknown_Release((IUnknown *)(object)); \
        (object) = NULL; \
    } \
} while (0)

static void transition(
    ID3D12GraphicsCommandList *list,
    ID3D12Resource *resource,
    D3D12_RESOURCE_STATES before,
    D3D12_RESOURCE_STATES after)
{
    D3D12_RESOURCE_BARRIER barrier = {0};
    barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
    barrier.Flags = D3D12_RESOURCE_BARRIER_FLAG_NONE;
    barrier.Transition.pResource = resource;
    barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
    barrier.Transition.StateBefore = before;
    barrier.Transition.StateAfter = after;
    ID3D12GraphicsCommandList_ResourceBarrier(list, 1, &barrier);
}

static int run_probe(void)
{
    typedef HRESULT (WINAPI *CreateDeviceFn)(
        IUnknown *,
        D3D_FEATURE_LEVEL,
        REFIID,
        void **);
    D3D12_HEAP_PROPERTIES default_heap = {0};
    D3D12_HEAP_PROPERTIES readback_heap = {0};
    D3D12_RESOURCE_DESC texture_desc = {0};
    D3D12_RESOURCE_DESC buffer_desc = {0};
    D3D12_CLEAR_VALUE clear_value = {0};
    D3D12_DESCRIPTOR_HEAP_DESC heap_desc = {0};
    D3D12_CPU_DESCRIPTOR_HANDLE rtv_handle = {0};
    D3D12_TEXTURE_COPY_LOCATION source = {0};
    D3D12_TEXTURE_COPY_LOCATION destination = {0};
    D3D12_COMMAND_QUEUE_DESC queue_desc = {0};
    const FLOAT clear_color[4] = {0.125f, 0.25f, 0.5f, 1.0f};
    const UINT64 fence_value = 1;
    const UINT row_pitch = D3D12_TEXTURE_DATA_PITCH_ALIGNMENT;
    const UINT64 readback_bytes = (UINT64)row_pitch * 16;
    ID3D12CommandAllocator *allocator = NULL;
    ID3D12GraphicsCommandList *list = NULL;
    ID3D12DescriptorHeap *rtv_heap = NULL;
    ID3D12Resource *texture = NULL;
    ID3D12Resource *staging = NULL;
    ID3D12CommandQueue *queue = NULL;
    ID3D12Fence *fence = NULL;
    ID3D12Device *device = NULL;
    ID3D12CommandList *lists[1];
    HMODULE d3d12_module = NULL;
    CreateDeviceFn create_device = NULL;
    void *mapped = NULL;
    const unsigned char *pixel;
    HANDLE event = NULL;
    HRESULT result;
    DWORD wait_result;

    d3d12_module = LoadLibraryW(L"d3d12.dll");
    if (!d3d12_module) return fail("load-d3d12", HRESULT_FROM_WIN32(GetLastError()));
    create_device = (CreateDeviceFn)(void *)GetProcAddress(
        d3d12_module, "D3D12CreateDevice");
    if (!create_device) return fail("resolve-d3d12", HRESULT_FROM_WIN32(GetLastError()));
    result = create_device(
        NULL,
        D3D_FEATURE_LEVEL_11_0,
        &IID_ID3D12Device,
        (void **)&device);
    if (FAILED(result)) return fail("create-device", result);

    queue_desc.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
    queue_desc.Priority = D3D12_COMMAND_QUEUE_PRIORITY_NORMAL;
    queue_desc.Flags = D3D12_COMMAND_QUEUE_FLAG_NONE;
    result = ID3D12Device_CreateCommandQueue(
        device, &queue_desc, &IID_ID3D12CommandQueue, (void **)&queue);
    if (FAILED(result)) return fail("create-queue", result);
    result = ID3D12Device_CreateCommandAllocator(
        device,
        D3D12_COMMAND_LIST_TYPE_DIRECT,
        &IID_ID3D12CommandAllocator,
        (void **)&allocator);
    if (FAILED(result)) return fail("create-allocator", result);
    result = ID3D12Device_CreateCommandList(
        device,
        0,
        D3D12_COMMAND_LIST_TYPE_DIRECT,
        allocator,
        NULL,
        &IID_ID3D12GraphicsCommandList,
        (void **)&list);
    if (FAILED(result)) return fail("create-command-list", result);
    result = ID3D12GraphicsCommandList_Close(list);
    if (FAILED(result)) return fail("close-created-command-list", result);

    default_heap.Type = D3D12_HEAP_TYPE_DEFAULT;
    default_heap.CPUPageProperty = D3D12_CPU_PAGE_PROPERTY_UNKNOWN;
    default_heap.MemoryPoolPreference = D3D12_MEMORY_POOL_UNKNOWN;
    default_heap.CreationNodeMask = 1;
    default_heap.VisibleNodeMask = 1;
    texture_desc.Dimension = D3D12_RESOURCE_DIMENSION_TEXTURE2D;
    texture_desc.Alignment = 0;
    texture_desc.Width = 16;
    texture_desc.Height = 16;
    texture_desc.DepthOrArraySize = 1;
    texture_desc.MipLevels = 1;
    texture_desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    texture_desc.SampleDesc.Count = 1;
    texture_desc.SampleDesc.Quality = 0;
    texture_desc.Layout = D3D12_TEXTURE_LAYOUT_UNKNOWN;
    texture_desc.Flags = D3D12_RESOURCE_FLAG_ALLOW_RENDER_TARGET;
    clear_value.Format = texture_desc.Format;
    memcpy(clear_value.Color, clear_color, sizeof(clear_color));
    result = ID3D12Device_CreateCommittedResource(
        device,
        &default_heap,
        D3D12_HEAP_FLAG_NONE,
        &texture_desc,
        D3D12_RESOURCE_STATE_COPY_DEST,
        &clear_value,
        &IID_ID3D12Resource,
        (void **)&texture);
    if (FAILED(result)) return fail("create-texture", result);

    readback_heap.Type = D3D12_HEAP_TYPE_READBACK;
    readback_heap.CPUPageProperty = D3D12_CPU_PAGE_PROPERTY_UNKNOWN;
    readback_heap.MemoryPoolPreference = D3D12_MEMORY_POOL_UNKNOWN;
    readback_heap.CreationNodeMask = 1;
    readback_heap.VisibleNodeMask = 1;
    buffer_desc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    buffer_desc.Alignment = 0;
    buffer_desc.Width = readback_bytes;
    buffer_desc.Height = 1;
    buffer_desc.DepthOrArraySize = 1;
    buffer_desc.MipLevels = 1;
    buffer_desc.Format = DXGI_FORMAT_UNKNOWN;
    buffer_desc.SampleDesc.Count = 1;
    buffer_desc.SampleDesc.Quality = 0;
    buffer_desc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
    buffer_desc.Flags = D3D12_RESOURCE_FLAG_NONE;
    result = ID3D12Device_CreateCommittedResource(
        device,
        &readback_heap,
        D3D12_HEAP_FLAG_NONE,
        &buffer_desc,
        D3D12_RESOURCE_STATE_COPY_DEST,
        NULL,
        &IID_ID3D12Resource,
        (void **)&staging);
    if (FAILED(result)) return fail("create-staging", result);

    heap_desc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_RTV;
    heap_desc.NumDescriptors = 1;
    heap_desc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_NONE;
    heap_desc.NodeMask = 0;
    result = ID3D12Device_CreateDescriptorHeap(
        device, &heap_desc, &IID_ID3D12DescriptorHeap, (void **)&rtv_heap);
    if (FAILED(result)) return fail("create-rtv-heap", result);
    rtv_heap->lpVtbl->GetCPUDescriptorHandleForHeapStart(rtv_heap, &rtv_handle);
    ID3D12Device_CreateRenderTargetView(device, texture, NULL, rtv_handle);

    result = ID3D12CommandAllocator_Reset(allocator);
    if (FAILED(result)) return fail("reset-allocator", result);
    result = ID3D12GraphicsCommandList_Reset(list, allocator, NULL);
    if (FAILED(result)) return fail("reset-command-list", result);

    transition(
        list,
        texture,
        D3D12_RESOURCE_STATE_COPY_DEST,
        D3D12_RESOURCE_STATE_RENDER_TARGET);
    ID3D12GraphicsCommandList_OMSetRenderTargets(list, 1, &rtv_handle, FALSE, NULL);
    ID3D12GraphicsCommandList_ClearRenderTargetView(list, rtv_handle, clear_color, 0, NULL);
    transition(
        list,
        texture,
        D3D12_RESOURCE_STATE_RENDER_TARGET,
        D3D12_RESOURCE_STATE_COPY_SOURCE);

    source.pResource = texture;
    source.Type = D3D12_TEXTURE_COPY_TYPE_SUBRESOURCE_INDEX;
    source.SubresourceIndex = 0;
    destination.pResource = staging;
    destination.Type = D3D12_TEXTURE_COPY_TYPE_PLACED_FOOTPRINT;
    destination.PlacedFootprint.Offset = 0;
    destination.PlacedFootprint.Footprint.Format = texture_desc.Format;
    destination.PlacedFootprint.Footprint.Width = 16;
    destination.PlacedFootprint.Footprint.Height = 16;
    destination.PlacedFootprint.Footprint.Depth = 1;
    destination.PlacedFootprint.Footprint.RowPitch = row_pitch;
    ID3D12GraphicsCommandList_CopyTextureRegion(
        list, &destination, 0, 0, 0, &source, NULL);

    result = ID3D12GraphicsCommandList_Close(list);
    if (FAILED(result)) return fail("close-command-list", result);
    result = ID3D12Device_CreateFence(
        device,
        0,
        D3D12_FENCE_FLAG_NONE,
        &IID_ID3D12Fence,
        (void **)&fence);
    if (FAILED(result)) return fail("create-fence", result);
    event = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (event == NULL) return fail("create-event", HRESULT_FROM_WIN32(GetLastError()));
    result = ID3D12Fence_SetEventOnCompletion(fence, fence_value, event);
    if (FAILED(result)) return fail("set-fence-event", result);

    lists[0] = (ID3D12CommandList *)list;
    ID3D12CommandQueue_ExecuteCommandLists(queue, 1, lists);
    result = ID3D12CommandQueue_Signal(queue, fence, fence_value);
    if (FAILED(result)) return fail("signal-fence", result);
    wait_result = WaitForSingleObject(event, INFINITE);
    if (wait_result != WAIT_OBJECT_0) {
        return fail("wait-fence", HRESULT_FROM_WIN32(GetLastError()));
    }

    result = ID3D12Resource_Map(staging, 0, NULL, &mapped);
    if (FAILED(result)) return fail("map-staging", result);
    pixel = (const unsigned char *)mapped;
    if (pixel[0] != 32 || pixel[1] != 64 ||
        pixel[2] != 128 || pixel[3] != 255) {
        char line[160];
        snprintf(line, sizeof(line),
                 "D3D12_PROBE_FAIL stage=pixel pixel=%u,%u,%u,%u\n",
                 pixel[0], pixel[1], pixel[2], pixel[3]);
        write_line(line);
        ID3D12Resource_Unmap(staging, 0, NULL);
        FreeLibrary(d3d12_module);
        return 1;
    }
    {
        char line[192];
        snprintf(
            line, sizeof(line),
            "D3D12_PROBE_OK pixel=32,64,128,255 observed=%u,%u,%u,%u row_pitch=%u\n",
            pixel[0], pixel[1], pixel[2], pixel[3], row_pitch);
        write_line(line);
    }
    ID3D12Resource_Unmap(staging, 0, NULL);

    if (event != NULL) CloseHandle(event);
    RELEASE(fence);
    RELEASE(queue);
    RELEASE(staging);
    RELEASE(texture);
    RELEASE(rtv_heap);
    RELEASE(list);
    RELEASE(allocator);
    RELEASE(device);
    FreeLibrary(d3d12_module);
    return 0;
}

/*
 * Bind the current process and thread to Wine's service desktop before any
 * D3D12 module initialization can request a foreign desktop.
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

    write_line("D3D12_DESKTOP service=true\n");
    return run_probe();
}

int main(int argc, char **argv)
{
    (void)argv;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 1) return run_on_service_desktop();
    return fail("arguments", E_INVALIDARG);
}
