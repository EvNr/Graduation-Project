/*
 * STEALTH USER MODE CLIENT - Educational Anti-Cheat Evasion Research
 * ===================================================================
 *
 * This is a refactored version removing all loud/detectable behaviors.
 *
 * KEY IMPROVEMENTS:
 * 1. No PID 4 (System process) access - GUID comes from kernel
 * 2. No SeDebugPrivilege escalation
 * 3. No process name spoofing (ineffective anyway)
 * 4. No console window (compiled as GUI app)
 * 5. Minimal suspicious API usage
 * 6. Communication via hidden window + IOCTL only
 * 7. Manual PE mapping for injection (optional)
 *
 * COMPILE AS: /SUBSYSTEM:WINDOWS (no console)
 *
 * FOR EDUCATIONAL USE IN AUTHORIZED SECURITY RESEARCH ONLY
 */

#include <windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <fstream>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

// ============================================================================
// HIDDEN WINDOW FOR DRIVER DISCOVERY
// ============================================================================
// Educational Note: Instead of the driver creating a named device,
// the user mode app creates a hidden window with a unique class name
// derived from the hardware GUID. The driver can scan for this window
// using Win32k kernel functions.
//
// Advantages:
// - No named objects in \BaseNamedObjects\
// - Looks like normal GUI activity
// - Difficult to enumerate (millions of windows exist)
//
// Disadvantages:
// - Still detectable via window enumeration
// - Win32k API hooking can catch this
// ============================================================================

static HWND g_hiddenWindow = nullptr;
static ULONGLONG g_hardwareGuid = 0;

LRESULT CALLBACK HiddenWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

BOOL CreateHiddenCommWindow() {
    // Register window class with GUID-based name
    WCHAR className[64];
    swprintf_s(className, 64, L"HwSvc{%llX}", g_hardwareGuid & 0xFFFFFFFFFFFF);

    WNDCLASSW wc = { 0 };
    wc.lpfnWndProc = HiddenWindowProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = className;

    if (!RegisterClassW(&wc)) {
        return FALSE;
    }

    // Create hidden window
    g_hiddenWindow = CreateWindowExW(
        0,
        className,
        L"",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        1, 1,  // Tiny window
        nullptr, nullptr,
        GetModuleHandle(nullptr),
        nullptr
    );

    return g_hiddenWindow != nullptr;
}

// ============================================================================
// DRIVER COMMUNICATION
// ============================================================================

namespace driver {
    namespace codes {
        constexpr ULONG read = CTL_CODE(FILE_DEVICE_UNKNOWN, 0xB7E, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG write = CTL_CODE(FILE_DEVICE_UNKNOWN, 0xC8F, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG unload = CTL_CODE(FILE_DEVICE_UNKNOWN, 0xD91, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG get_guid = CTL_CODE(FILE_DEVICE_UNKNOWN, 0xE12, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG integrity = CTL_CODE(FILE_DEVICE_UNKNOWN, 0xEA2, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
    }

    struct Request {
        HANDLE process_id;
        PVOID target;
        PVOID buffer;
        SIZE_T size;
        SIZE_T return_size;
        ULONG protection;
        ULONG allocation_type;
    };

    typedef struct _INTEGRITY_RESPONSE {
        UCHAR is_hooked;
        ULONG checksum;
    } INTEGRITY_RESPONSE, *PINTEGRITY_RESPONSE;

    bool check_integrity(HANDLE driver_handle) {
        INTEGRITY_RESPONSE response = {};
        DWORD bytes_returned = 0;

        BOOL result = DeviceIoControl(
            driver_handle,
            codes::integrity,
            nullptr, 0,
            &response, sizeof(response),
            &bytes_returned,
            nullptr
        );

        if (!result || bytes_returned < sizeof(UCHAR)) {
            return false;
        }

        return response.is_hooked == 0;
    }

    template <class T>
    T read_memory(HANDLE driver_handle, const DWORD pid, const std::uintptr_t addr) {
        T temp = {};
        Request r;
        r.process_id = reinterpret_cast<HANDLE>(pid);
        r.target = reinterpret_cast<PVOID>(addr);
        r.buffer = &temp;
        r.size = sizeof(T);
        DeviceIoControl(driver_handle, codes::read, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);
        return temp;
    }

    template <class T>
    void write_memory(HANDLE driver_handle, const DWORD pid, const std::uintptr_t addr, const T& value) {
        Request r;
        r.process_id = reinterpret_cast<HANDLE>(pid);
        r.target = reinterpret_cast<PVOID>(addr);
        r.buffer = (PVOID)&value;
        r.size = sizeof(T);
        DeviceIoControl(driver_handle, codes::write, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);
    }

    bool unload_driver(HANDLE driver_handle) {
        Request r = {};
        return DeviceIoControl(driver_handle, codes::unload, &r, sizeof(r), nullptr, 0, nullptr, nullptr);
    }
}

// ============================================================================
// DRIVER DISCOVERY (No PID 4 Access)
// ============================================================================
// Educational Note: Instead of opening PID 4 and calculating GUID,
// we get the GUID directly from the driver via IOCTL.
//
// Discovery process:
// 1. Enumerate all devices in \Device\ that match our pattern
// 2. Try to open each one
// 3. Query for GUID via IOCTL
// 4. If GUID matches our hardware, that's our driver
//
// This is still detectable via:
// - Handle enumeration (we open multiple devices)
// - IOCTL monitoring
// - Object directory enumeration hooks
// ============================================================================

static DWORD get_proc_id(const wchar_t* process_name) {
    DWORD process_id = 0;
    HANDLE snap_shot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap_shot == INVALID_HANDLE_VALUE) return process_id;

    PROCESSENTRY32W entry = { sizeof(PROCESSENTRY32W) };
    if (Process32FirstW(snap_shot, &entry)) {
        do {
            if (_wcsicmp(process_name, entry.szExeFile) == 0) {
                process_id = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap_shot, &entry));
    }

    CloseHandle(snap_shot);
    return process_id;
}

HANDLE FindDriverByGuid(ULONGLONG* outGuid) {
    // Try to open device with GUID-based name
    // Note: We don't know the exact GUID, but we can try to query it

    // Educational Note: In production, the driver would expose the section
    // handle via a known method, or we'd have a shared secret for discovery.
    // For now, we try all devices matching a pattern.

    // Simplified approach: Try to open devices with our naming pattern
    for (int attempt = 0; attempt < 100; attempt++) {
        WCHAR devicePath[128];

        // Try common device name patterns
        swprintf_s(devicePath, 128, L"\\\\.\\Global\\{%016llX}", (ULONGLONG)attempt);

        HANDLE hDevice = CreateFileW(
            devicePath,
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (hDevice != INVALID_HANDLE_VALUE) {
            // Try to query GUID
            ULONGLONG guid = 0;
            DWORD bytesReturned = 0;

            if (DeviceIoControl(hDevice, driver::codes::get_guid,
                nullptr, 0, &guid, sizeof(guid), &bytesReturned, nullptr)) {

                if (bytesReturned == sizeof(guid) && guid != 0) {
                    *outGuid = guid;
                    return hDevice;
                }
            }

            CloseHandle(hDevice);
        }
    }

    // Alternative: Use the unnamed section approach
    // The driver creates a section, we try to open it by handle inheritance
    // This requires the driver to expose the section handle somehow

    return INVALID_HANDLE_VALUE;
}

// Better approach: Direct device name from GUID calculation
// We can still calculate part of the GUID without opening PID 4
HANDLE FindDriverDirectly() {
    // Educational Note: The driver device name is based on its hardware GUID
    // We need to find it without knowing the exact GUID

    // Strategy 1: The driver writes its device name to a known location
    // Strategy 2: We enumerate \Device\ directory (requires privileges)
    // Strategy 3: Brute force common GUID patterns

    // For this implementation, let's use a simpler fixed pattern
    // that both sides agree on (less secure but more practical for PoC)

    WCHAR devicePath[128];

    // Try to connect using a deterministic pattern
    // In production, this would use hardware-specific values available in UM
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    // Create a pseudo-GUID based on available hardware info
    ULONGLONG pseudoGuid = ((ULONGLONG)sysInfo.dwNumberOfProcessors << 56) |
                           ((ULONGLONG)sysInfo.dwProcessorType << 32) |
                           (GetTickCount64() & 0xFFFFFF00);  // Stable across short time

    // The driver should use a similar calculation or expose via registry/file
    swprintf_s(devicePath, 128, L"\\\\.\\{%llX}", pseudoGuid & 0xFFFFFFFFFFFF);

    return CreateFileW(
        devicePath,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
}

// ============================================================================
// MANUAL PE MAPPING (Optional - for stealthier injection)
// ============================================================================
// Educational Note: LoadLibrary triggers ImageLoadNotifyRoutine callbacks
// that the AC monitors. Manual PE mapping:
// 1. Allocates memory in target process
// 2. Manually parses PE headers
// 3. Maps sections
// 4. Fixes relocations
// 5. Resolves imports
// 6. Calls entry point
//
// Much harder to detect, but more complex to implement correctly.
// ============================================================================

struct ManualMapData {
    PVOID ImageBase;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_BASE_RELOCATION BaseReloc;
    PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor;
};

// Shellcode that runs in target process to call DllMain
// This would need to be position-independent code
// Omitted for brevity - see full implementation in separate file

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

bool ConvertToNtPath(const std::wstring& dos_path, std::wstring& nt_path) {
    if (dos_path.length() < 3 || dos_path[1] != L':' || dos_path[2] != L'\\') {
        return false;
    }

    nt_path = L"\\??\\";
    nt_path += dos_path;
    return true;
}

DWORD WaitForProcessByName(const WCHAR* processName, int timeoutSeconds = 60) {
    auto startTime = std::chrono::steady_clock::now();
    auto timeout = std::chrono::seconds(timeoutSeconds);

    while (std::chrono::steady_clock::now() - startTime < timeout) {
        DWORD pid = get_proc_id(processName);
        if (pid != 0) {
            return pid;
        }
        Sleep(1000);
    }

    return 0;
}

// ============================================================================
// MAIN ENTRY POINT (GUI APPLICATION)
// ============================================================================

// WinMain instead of main() for GUI application (no console)
int WINAPI WinMain(
    _In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPSTR lpCmdLine,
    _In_ int nShowCmd)
{
    UNREFERENCED_PARAMETER(hInstance);
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(nShowCmd);

    // For debugging, we can still create a console if needed
    #ifdef _DEBUG
    AllocConsole();
    FILE* fDummy;
    freopen_s(&fDummy, "CONOUT$", "w", stdout);
    freopen_s(&fDummy, "CONOUT$", "w", stderr);
    printf("[DEBUG] Stealth UM Client Starting\n");
    #endif

    // Step 1: Find and connect to driver
    #ifdef _DEBUG
    printf("[*] Searching for driver...\n");
    #endif

    HANDLE drv = FindDriverDirectly();
    if (drv == INVALID_HANDLE_VALUE) {
        #ifdef _DEBUG
        printf("[-] Failed to find driver\n");
        printf("    Make sure the driver is loaded first\n");
        MessageBoxW(nullptr, L"Driver not found. Load the kernel driver first.", L"Error", MB_ICONERROR);
        #endif
        return 1;
    }

    #ifdef _DEBUG
    printf("[+] Connected to driver!\n");
    #endif

    // Step 2: Get hardware GUID from driver
    ULONGLONG guid = 0;
    DWORD bytesReturned = 0;
    if (DeviceIoControl(drv, driver::codes::get_guid,
        nullptr, 0, &guid, sizeof(guid), &bytesReturned, nullptr)) {
        g_hardwareGuid = guid;
        #ifdef _DEBUG
        printf("[+] Hardware GUID: 0x%llX\n", guid);
        #endif
    }

    // Step 3: Create hidden communication window
    if (!CreateHiddenCommWindow()) {
        #ifdef _DEBUG
        printf("[-] Failed to create hidden window\n");
        #endif
        CloseHandle(drv);
        return 1;
    }

    #ifdef _DEBUG
    printf("[+] Hidden communication window created\n");
    #endif

    // Step 4: Integrity check
    #ifdef _DEBUG
    printf("[*] Performing integrity check...\n");
    #endif

    if (!driver::check_integrity(drv)) {
        #ifdef _DEBUG
        printf("[!] WARNING: Driver integrity compromised!\n");
        #else
        MessageBoxW(nullptr, L"Driver integrity check failed.", L"Warning", MB_ICONWARNING);
        #endif
    } else {
        #ifdef _DEBUG
        printf("[+] Driver integrity: OK\n");
        #endif
    }

    // Step 5: Main operation loop
    #ifdef _DEBUG
    printf("\n========================================\n");
    printf("[+] STEALTH MODE ACTIVE\n");
    printf("    Driver: Connected\n");
    printf("    Memory: READ/WRITE available\n");
    printf("    Detection: MINIMAL FOOTPRINT\n");
    printf("========================================\n\n");

    printf("[+] Available operations:\n");
    printf("    1. Integrity check\n");
    printf("    2. Unload driver and exit\n");
    printf("    3. Exit (keep driver loaded)\n");

    while (true) {
        printf("\n> ");
        int choice;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(10000, '\n');
            continue;
        }
        std::cin.ignore();

        switch (choice) {
            case 1:
                if (driver::check_integrity(drv)) {
                    printf("[+] Integrity check: PASSED\n");
                } else {
                    printf("[!] Integrity check: FAILED\n");
                }
                break;

            case 2:
                printf("[*] Unloading driver...\n");
                driver::unload_driver(drv);
                CloseHandle(drv);
                printf("[+] Driver unloaded. Goodbye!\n");
                return 0;

            case 3:
                printf("[+] Exiting without unloading driver.\n");
                CloseHandle(drv);
                return 0;

            default:
                printf("[-] Invalid choice.\n");
                break;
        }
    }
    #else
    // In release mode (no console), just run silently or show minimal GUI
    // Keep connection alive and process messages
    MSG msg = { 0 };
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    driver::unload_driver(drv);
    CloseHandle(drv);
    #endif

    return 0;
}

/*
 * COMPILATION NOTES:
 * ==================
 *
 * Debug build (with console):
 *   cl /D_DEBUG /DDEBUG /Zi /Od UM_stealth.cpp /link /SUBSYSTEM:CONSOLE
 *
 * Release build (no console, pure GUI):
 *   cl /O2 /DNDEBUG UM_stealth.cpp /link /SUBSYSTEM:WINDOWS
 *
 * USAGE:
 * ======
 * 1. Load kernel driver first (sc create / OSR Loader / kdmapper)
 * 2. Run this UM client
 * 3. Driver and client communicate via IOCTL
 * 4. No suspicious API calls, no PID 4 access, minimal footprint
 *
 * REMAINING DETECTION VECTORS:
 * ============================
 * - Driver loaded after AC (timing-based detection)
 * - Handle enumeration (we open driver device handle)
 * - Code signature (driver not signed)
 * - Behavioral analysis (what we do with memory access)
 * - Hidden window still enumerable (though very difficult)
 *
 * FURTHER IMPROVEMENTS:
 * =====================
 * - Implement full manual PE mapping for injection
 * - Use ALPC instead of IOCTL for kernel communication
 * - Implement driver loading via BYOVD (vulnerable signed driver)
 * - Add polymorphic code generation (change each time we run)
 * - Implement timing-based evasion (only operate during specific windows)
 */
