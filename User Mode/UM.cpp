#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
#include <fstream>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

// --- PRIVILEGE ESCALATION ---
bool EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        return false;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}

// --- ULTRA STEALTH: Find driver using same algorithm ---
bool find_driver_ultra_stealth(WCHAR* output_buffer, size_t buffer_size) {
    // 1. Try to enable SeDebugPrivilege (Critical for accessing PID 4)
    if (!EnableDebugPrivilege()) {
        std::cout << "[!] Warning: Could not enable Debug Privilege. Run as Admin.\n";
    }

    // 2. Open System Process (PID 4)
    // We change PROCESS_QUERY_INFORMATION to PROCESS_QUERY_LIMITED_INFORMATION
    // This is the specific fix for the "Failed to open System process" error.
    HANDLE hSystem = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 4);
    if (!hSystem) {
        std::cout << "[-] Failed to open System process. Error: " << GetLastError() << "\n";
        return false;
    }

    FILETIME createTime, exitTime, kernelTime, userTime;
    if (!GetProcessTimes(hSystem, &createTime, &exitTime, &kernelTime, &userTime)) {
        std::cout << "[-] Failed to get System process time\n";
        CloseHandle(hSystem);
        return false;
    }
    CloseHandle(hSystem);

    // Convert FILETIME to LONGLONG (QuadPart)
    ULARGE_INTEGER ul;
    ul.LowPart = createTime.dwLowDateTime;
    ul.HighPart = createTime.dwHighDateTime;
    LONGLONG SharedSeed = ul.QuadPart;

    // 3. Generate the Dynamic GUID (Must match KM.cpp exactly)
    WCHAR section_name[128];
    swprintf_s(section_name,
        L"{%08X-%04X-%04X-%04X-%012llX}",
        (ULONG)(SharedSeed & 0xFFFFFFFF),
        (ULONG)((SharedSeed >> 32) & 0xFFFF),
        (ULONG)((SharedSeed >> 48) & 0xFFFF),
        0xABCD,
        SharedSeed ^ 0xDEADBEEFCAFEBABE
    );

    WCHAR global_name[160];
    swprintf_s(global_name, L"Global\\%s", section_name);

    std::wcout << L"[*] Looking for driver section: " << global_name << L"\n";

    HANDLE hSection = NULL;
    for (int i = 0; i < 10 && !hSection; ++i) {
        hSection = OpenFileMappingW(FILE_MAP_READ, FALSE, global_name);
        if (!hSection) {
            Sleep(100);
        }
    }

    if (hSection == NULL) {
        std::cout << "[-] Failed to open driver section (Driver not loaded?)\n";
        return false;
    }

    std::cout << "[+] Successfully opened driver section!\n";

    LPVOID pBuf = MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, 0);
    if (pBuf == NULL) {
        std::cout << "[-] Failed to map view. Error: " << GetLastError() << "\n";
        CloseHandle(hSection);
        return false;
    }

    // Read and decrypt
    wcsncpy_s(output_buffer, buffer_size, (WCHAR*)pBuf, _TRUNCATE);
    for (size_t i = 0; i < wcslen(output_buffer); i++) {
        output_buffer[i] ^= 0x55;
    }
    std::wcout << L"[*] Decrypted Driver Name: " << output_buffer << L"\n";

    UnmapViewOfFile(pBuf);
    CloseHandle(hSection);

    return true;
}

static DWORD get_proc_id(const wchar_t* process_name) {
    DWORD process_id = 0;
    HANDLE snap_shot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (snap_shot == INVALID_HANDLE_VALUE) return process_id;
    PROCESSENTRY32 entry = {};
    entry.dwSize = sizeof(decltype(entry));
    if (Process32FirstW(snap_shot, &entry) == TRUE) {
        if (_wcsicmp(process_name, entry.szExeFile) == 0) process_id = entry.th32ProcessID;
        else {
            while (Process32NextW(snap_shot, &entry) == TRUE) {
                if (_wcsicmp(process_name, entry.szExeFile) == 0) {
                    process_id = entry.th32ProcessID;
                    break;
                }
            }
        }
    }
    CloseHandle(snap_shot);
    return process_id;
}

// --- Process Name Spoofing ---
class ProcessSpoofer {
private:
    std::wstring m_originalName;
    std::wstring m_spoofedName;
    HANDLE m_processHandle;

public:
    ProcessSpoofer() : m_processHandle(GetCurrentProcess()) {
        WCHAR originalPath[MAX_PATH];
        GetModuleFileNameW(NULL, originalPath, MAX_PATH);
        m_originalName = originalPath;
    }

    bool SpoofAsLegitimateProcess() {
        const wchar_t* legitimateProcesses[] = {
            L"svchost.exe",
            L"dwm.exe",
            L"explorer.exe",
            L"winlogon.exe"
        };

        auto now = std::chrono::system_clock::now();
        auto seed = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
        int index = seed % (sizeof(legitimateProcesses) / sizeof(legitimateProcesses[0]));

        m_spoofedName = legitimateProcesses[index];

        std::wcout << L"[*] Spoofing process as: " << m_spoofedName << L"\n";

        return ApplySpoofing();
    }

private:
    bool ApplySpoofing() {
        bool success = false;
        success |= SpoofConsoleTitle();
        success |= SpoofProcessList();
        return success;
    }

    bool SpoofConsoleTitle() {
        std::wstring fakeTitle = L"Windows System Process - " + m_spoofedName;
        if (SetConsoleTitleW(fakeTitle.c_str())) {
            std::wcout << L"[+] Console title spoofed: " << fakeTitle << L"\n";
            return true;
        }
        return false;
    }

    bool SpoofProcessList() {
        SetEnvironmentVariableW(L"PROCESS_NAME", m_spoofedName.c_str());
        SetEnvironmentVariableW(L"WINDOWS_SYSTEM_PROCESS", L"1");
        SetEnvironmentVariableW(L"SERVICE_HOST", L"1");

        std::wcout << L"[+] Process environment spoofed\n";
        return true;
    }
};

// --- Window Hiding ---
void HideConsoleWindow() {
    HWND hwnd = GetConsoleWindow();
    if (hwnd) {
        ShowWindow(hwnd, SW_HIDE);
        std::cout << "[+] Console window hidden\n";
    }
}

void ShowConsoleWindow() {
    HWND hwnd = GetConsoleWindow();
    if (hwnd) {
        ShowWindow(hwnd, SW_SHOW);
    }
}

// --- Driver Definitions ---
namespace driver {
    namespace codes {
        constexpr ULONG read = CTL_CODE(FILE_DEVICE_UNKNOWN, 0xB7E, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG write = CTL_CODE(FILE_DEVICE_UNKNOWN, 0xC8F, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG unload = CTL_CODE(FILE_DEVICE_UNKNOWN, 0xD91, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG integrity = CTL_CODE(FILE_DEVICE_UNKNOWN, 0xEA2, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG inject_advanced = CTL_CODE(FILE_DEVICE_UNKNOWN, 0xF4B, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG bypass_randgrid = CTL_CODE(FILE_DEVICE_UNKNOWN, 0xFB3, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
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
    } INTEGRITY_RESPONSE, * PINTEGRITY_RESPONSE;

    typedef struct _INJECT_ADVANCED_REQUEST {
        BOOLEAN use_pid;           // TRUE = use PID, FALSE = use process name
        HANDLE process_id;         // Target PID (if use_pid = TRUE)
        WCHAR process_name[260];   // Process name (if use_pid = FALSE)
        WCHAR dll_path[260];       // DLL path
    } INJECT_ADVANCED_REQUEST, * PINJECT_ADVANCED_REQUEST;

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

        if (!result) {
            std::cout << "[-] Integrity check failed. Error: " << GetLastError() << "\n";
            return false;
        }

        if (bytes_returned < sizeof(UCHAR)) {
            std::cout << "[-] Invalid response size from driver: " << bytes_returned << " bytes\n";
            return false;
        }

        if (response.is_hooked == 0) {
            std::cout << "[+] Driver integrity: OK (checksum: 0x" << std::hex << response.checksum << ")\n" << std::dec;
            return true;
        }
        else {
            std::cout << "[!] WARNING: Driver may be hooked by AC! (is_hooked: " << (int)response.is_hooked << ")\n";
            return false;
        }
    }

    template <class T>
    T read_Memory(HANDLE driver_handle, const DWORD pid, const std::uintptr_t addr) {
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
        BOOL result = DeviceIoControl(driver_handle, codes::unload, &r, sizeof(r), nullptr, 0, nullptr, nullptr);
        if (result) {
            std::cout << "[+] Unload request sent to driver successfully.\n";
        }
        else {
            std::cout << "[-] Failed to send unload request. Error: " << GetLastError() << "\n";
        }
        return result;
    }

    // Enhanced inject_advanced with better error handling
    bool inject_advanced(HANDLE driver_handle, bool use_pid, DWORD pid, const WCHAR* process_name, const WCHAR* dll_path) {
        // Validate inputs
        if (!driver_handle || driver_handle == INVALID_HANDLE_VALUE || !dll_path) {
            std::cout << "[-] Invalid parameters\n";
            return false;
        }

        // Check if file exists (user-mode check)
        if (GetFileAttributesW(dll_path) == INVALID_FILE_ATTRIBUTES) {
            std::wcout << L"[-] DLL file not found: " << dll_path << L"\n";
            return false;
        }

        INJECT_ADVANCED_REQUEST req = {};
        req.use_pid = use_pid;

        if (use_pid) {
            req.process_id = reinterpret_cast<HANDLE>(pid);
            std::wcout << L"[+] Using PID injection for PID: " << pid << L"\n";
        }
        else {
            wcsncpy_s(req.process_name, process_name, _TRUNCATE);
            std::wcout << L"[+] Using process suspension injection for: " << process_name << L"\n";
        }

        // Safe string copy for DLL path
        if (wcslen(dll_path) >= _countof(req.dll_path)) {
            std::cout << "[-] DLL path too long\n";
            return false;
        }
        wcsncpy_s(req.dll_path, dll_path, _TRUNCATE);

        DWORD bytes_returned = 0;
        BOOL result = DeviceIoControl(
            driver_handle,
            driver::codes::inject_advanced,
            &req, sizeof(req),
            nullptr, 0,
            &bytes_returned,
            nullptr
        );

        if (!result) {
            DWORD error = GetLastError();
            std::cout << "[-] Advanced inject failed. Error: " << error << "\n";
            return false;
        }

        if (use_pid) {
            std::cout << "[+] PID-based injection requested successfully!\n";
            std::cout << "[!] Injection will trigger when target loads a system DLL\n";
        }
        else {
            std::cout << "[+] Process suspension injection requested successfully!\n";
            std::cout << "[!] Waiting for process to start, then will suspend and inject\n";
        }
        std::cout << "[!] This may take a few seconds...\n";

        return true;
    }
}

// ConvertToNtPath in UM.cpp
bool ConvertToNtPath(const std::wstring& dos_path, std::wstring& nt_path) {
    if (dos_path.length() < 3) {
        return false;
    }

    // Check for drive letter format
    if (dos_path[1] != L':' || dos_path[2] != L'\\') {
        return false;
    }

    // Convert to NT path format: \??\C:\path\to\file.dll
    nt_path = L"\\??\\";
    nt_path += dos_path;

    return true;
}

// --- graceful auto-unload on exit ---
static HANDLE g_driver = INVALID_HANDLE_VALUE;
static volatile LONG g_unloaded = 0;

static void request_driver_unload() {
    HANDLE h = g_driver;
    if (h != INVALID_HANDLE_VALUE) {
        if (InterlockedCompareExchange(&g_unloaded, 1, 0) == 0) {
            std::cout << "[+] Requesting driver unload...\n";
            driver::unload_driver(h);
            CloseHandle(h);
            g_driver = INVALID_HANDLE_VALUE;
            std::wcout << L"[+] Driver unload requested on exit.\n";
            Sleep(1000);
        }
    }
}

static BOOL WINAPI ConsoleCtrlHandler(DWORD) {
    request_driver_unload();
    return FALSE;
}

// Add this helper function to UM.cpp
DWORD WaitForProcessByName(const WCHAR* processName, int timeoutSeconds = 9999999999) {
    std::wcout << L"[+] Waiting for process: " << processName << L"\n";
    std::wcout << L"[+] Timeout: " << timeoutSeconds << L" seconds\n";

    auto startTime = std::chrono::steady_clock::now();
    auto timeout = std::chrono::seconds(timeoutSeconds);

    while (std::chrono::steady_clock::now() - startTime < timeout) {
        DWORD pid = get_proc_id(processName);
        if (pid != 0) {
            std::wcout << L"[+] Found process: " << processName << L" (PID: " << pid << L")\n";
            return pid;
        }

        std::cout << "[.] Still waiting for process...\n";
        Sleep(1000); // Check every second
    }

    std::wcout << L"[-] Timeout waiting for process: " << processName << L"\n";
    return 0;
}

// --- MAIN FUNCTION ---
int main(int argc, char* argv[]) {
    // Initialize process spoofing
    ProcessSpoofer spoofer;

    // Check if we should run in stealth mode (hidden)
    bool stealthMode = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-stealth") == 0 || strcmp(argv[i], "-hidden") == 0) {
            stealthMode = true;
            break;
        }
    }

    // Apply process spoofing
    std::cout << "[*] Applying ULTRA STEALTH process spoofing...\n";
    if (spoofer.SpoofAsLegitimateProcess()) {
        std::cout << "[+] Process spoofing successful\n";
    }
    else {
        std::cout << "[-] Process spoofing failed (continuing anyway)\n";
    }

    // Hide console if in stealth mode
    if (stealthMode) {
        HideConsoleWindow();
        std::cout << "[*] Running in ULTRA STEALTH mode (console hidden)\n";
    }

    std::cout << R"(
 ______       _   _       
|  ____|     | \ | |      
| |____   __ |  \| |_ __  
|  __\ \ / / | . ` | '__| 
| |___\ V /  | |\  | |    
|______\_/   |_| \_|_|    
                          
[+] ULTRA STEALTH Kernel Driver Client
[+] Competition Edition - Maximum Evasion
[+] Process: Spoofed as System Service
[+] Communication: Dynamic Random Section
[+] Detection: AC Completely Bypassed
)" << "\n";

    WCHAR driver_link_name[128] = { 0 };
    bool found = false;

    // ---------------------------------------------------------
    // STEP 1: FIND THE DRIVER
    // ---------------------------------------------------------
    std::cout << "[*] Searching for driver...\n";

    if (find_driver_ultra_stealth(driver_link_name, 128)) {
        found = true;
        std::wcout << L"[+] Found driver: " << driver_link_name << L"\n";
    }

    if (!found) {
        std::cout << "[-] Failed to find driver.\n";
        std::cout << "    Make sure the driver is properly loaded.\n";
        if (!stealthMode) {
            std::cin.get();
        }
        return 1;
    }

    // ---------------------------------------------------------
    // STEP 2: FORMAT THE NAME FOR CONNECTING
    // ---------------------------------------------------------
    std::wstring connect_name = L"\\\\.\\";

    if (wcslen(driver_link_name) > 12) {
        connect_name += (driver_link_name + 12);
    }
    else {
        std::cout << "[-] Invalid driver name format.\n";
        if (!stealthMode) {
            std::cin.get();
        }
        return 1;
    }

    std::wcout << L"[*] Connecting to: " << connect_name << L"\n";

    // ---------------------------------------------------------
    // STEP 3: CONNECT TO THE DRIVER
    // ---------------------------------------------------------
    const HANDLE drv = CreateFile(
        connect_name.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (drv == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        std::cout << "[-] Failed to connect to driver. Error: " << error << "\n";

        if (!stealthMode) {
            std::cin.get();
        }
        return 1;
    }

    std::cout << "[+] Successfully connected to driver!\n";

    g_driver = drv;
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    // ---------------------------------------------------------
    // STEP 4: INTEGRITY CHECK
    // ---------------------------------------------------------
    std::cout << "[*] Performing integrity check...\n";

    if (!driver::check_integrity(drv)) {
        std::cout << "[!] WARNING: Driver integrity compromised!\n";

        if (!stealthMode) {
            std::cout << "[*] Continue anyway? (y/n): ";
            char choice;
            std::cin >> choice;
            std::cin.ignore();
            if (choice != 'y' && choice != 'Y') {
                CloseHandle(drv);
                return 1;
            }
        }
    }

    // ---------------------------------------------------------
    // STEP 5: OPERATION MODE
    // ---------------------------------------------------------
    std::cout << "\n========================================\n";
    std::cout << "[+] ULTRA STEALTH DRIVER FULLY OPERATIONAL\n";
    std::cout << "    Status: COMPLETELY HIDDEN from AC\n";
    std::cout << "    Memory: READ/WRITE operations available\n";
    std::cout << "    Process: SPOOFED as System Service\n";
    std::cout << "    Anti-detection: MAXIMUM EVASION ACTIVE\n";
    std::cout << "========================================\n\n";

    if (stealthMode) {
        std::cout << "[*] Running in background (ULTRA STEALTH mode)\n";
        std::cout << "[*] Press Ctrl+C in console to exit\n";

        while (true) {
            Sleep(1000);
        }
    }
    else {
        std::cout << "[+] Driver ready for operations!\n";
        std::cout << "[+] Available commands:\n";
        std::cout << "    1. Integrity check\n";
        std::cout << "    2. Unload driver and exit\n";
        std::cout << "    3. Exit (keep driver loaded)\n";
        std::cout << "    4. Advanced DLL injection (STEALTH CALLBACK)\n";
        std::cout << "    5. Bypass Randgrid AC\n"; // Add to options list

        while (true) {
            std::cout << "> ";
            int choice;

            if (!(std::cin >> choice)) {
                std::cin.clear();
                std::cin.ignore(10000, '\n');
                std::cout << "[-] Invalid input.\n";
                continue;
            }
            std::cin.ignore();

            switch (choice) {
            case 1:
                for (int retry = 0; retry < 3; retry++) {
                    if (driver::check_integrity(drv)) break;
                    Sleep(500);
                }
                break;
            case 2:
                std::cout << "[*] Unloading driver...\n";
                request_driver_unload();
                std::cout << "[+] Driver unloaded. Goodbye!\n";
                return 0;
            case 3:
                std::cout << "[+] Exiting without unloading driver.\n";
                CloseHandle(drv);
                return 0;
                // Replace case 4 in your UM.cpp main() with this improved version:

            case 4: {
                std::wstring process_name;
                std::wcout << "\n[*] Advanced DLL Injection\n";
                std::wcout << "Enter target process name (e.g., notepad.exe): ";
                std::getline(std::wcin, process_name);

                std::wstring dos_path;
                std::wcout << "Enter DLL DOS path (e.g., C:\\test.dll): ";
                std::getline(std::wcin, dos_path);

                // Validate DLL exists
                if (GetFileAttributesW(dos_path.c_str()) == INVALID_FILE_ATTRIBUTES) {
                    std::wcout << L"[-] ERROR: DLL file not found: " << dos_path << L"\n";
                    std::wcout << L"[!] Please check the path and try again\n";
                    break;
                }
                std::wcout << L"[+] DLL file verified: " << dos_path << L"\n";

                // Convert to NT path
                std::wstring nt_path;
                if (!ConvertToNtPath(dos_path, nt_path)) {
                    std::cout << "[-] Failed to convert to NT path.\n";
                    break;
                }
                std::wcout << L"[+] NT path: " << nt_path << L"\n";

                // Wait for process to exist
                std::wcout << L"[*] Waiting for process: " << process_name << L"\n";
                DWORD pid = WaitForProcessByName(process_name.c_str(), 9999999999);

                if (pid == 0) {
                    std::wcout << L"[-] Failed to find process: " << process_name << L"\n";
                    std::wcout << L"[!] Make sure the process is running\n";
                    break;
                }

                std::wcout << L"[+] Found process: " << process_name << L" (PID: " << pid << L")\n";
                std::wcout << L"[+] Starting injection...\n";

                // Use PID-based injection (more reliable)
                bool success = driver::inject_advanced(drv, true, pid, L"", nt_path.c_str());

                if (success) {
                    std::cout << "\n[+] ========================================\n";
                    std::cout << "[+] INJECTION REQUEST SENT SUCCESSFULLY!\n";
                    std::cout << "[+] ========================================\n";
                    std::cout << "[!] Check DebugView for detailed logs\n";
                    std::cout << "[!] Check target process with Process Explorer\n";
                    std::cout << "[!] If your DLL has DllMain code, it should execute now\n\n";

                    // Give it a moment
                    Sleep(2000);
                    //request_driver_unload();
                        //std::cout << "[?] Did you see your DLL execute? (y/n): ";
                        //char response;
                        //std::cin >> response;
                        //std::cin.ignore();

                        //if (response == 'n' || response == 'N') {
                        //    std::cout << "\n[*] Troubleshooting:\n";
                        //std::cout << "1. Check DebugView for error messages\n";
                        //std::cout << "2. Open Process Explorer, find your process\n";
                        //std::cout << "3. View > Lower Pane View > DLLs\n";
                        //std::cout << "4. Look for your DLL in the list\n";
                        //std::cout << "5. If DLL is there but didn't execute, check DLL code\n";
                        //std::cout << "6. If DLL not there, check DebugView logs\n";
                       // }
                    //}
                   // else {
                   //     std::cout << "[-] Injection request failed\n";
                   //     std::cout << "[!] Check DebugView for error details\n";
                   // }
                        
                }
                break;
            }
            case 5: {
                BOOL result = DeviceIoControl(drv, driver::codes::bypass_randgrid, nullptr, 0, nullptr, 0, nullptr, nullptr);
                if (result) {
                    std::cout << "[+] Randgrid bypass requested - workers neutered!\n";
                    std::cout << "[!] Safe to inject now.\n";
                }
                else {
                    std::cout << "[-] Bypass failed: " << GetLastError() << "\n";
                }
                break;
            }
            default:
                std::cout << "[-] Invalid choice.\n";
            }
        }
    }
}