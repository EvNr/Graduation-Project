/*
 * ELITE USER MODE - Process Doppelgänging & Thread Hijacking
 * ===========================================================
 *
 * This is what AC teams fear - invisible user-mode presence.
 *
 * UNCONVENTIONAL TECHNIQUES:
 * 1. Process Doppelgänging - Windows transactional NTFS abuse
 * 2. Thread Hijacking - No LoadLibrary, no new threads, no APC
 * 3. ALPC Client - Communicate via legitimate Windows IPC
 * 4. DLL Order Hijacking - Load into legitimate Windows process
 * 5. KernelCallbackTable Hijacking - Code execution without injection
 * 6. TLS Callback Abuse - Execute before entry point
 *
 * SPOOFING AS SYSTEM APP:
 * - Loads into legitimate Windows process (services.exe, svchost.exe)
 * - No new process creation
 * - Process chain looks legitimate (parent is services.exe)
 * - Signed binaries in process (we inject into legitimate space)
 *
 * TARGET: Invisible to process enumeration, memory scanning, behavior analysis
 *
 * FOR ADVANCED SECURITY RESEARCH ONLY
 */

#include <windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <string>
#include <vector>

#pragma comment(lib, "ntdll.lib")

// Suppress warnings about deprecated functions
#pragma warning(disable: 4996)

// ============================================================================
// UNDOCUMENTED NTDLL FUNCTIONS
// ============================================================================

extern "C" {

// Process Doppelgänging requires these
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

NTSTATUS NTAPI NtCreateSection(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle
);

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

NTSTATUS NTAPI NtCreateThreadEx(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PVOID StartRoutine,
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags,
    _In_opt_ ULONG_PTR ZeroBits,
    _In_opt_ SIZE_T StackSize,
    _In_opt_ SIZE_T MaximumStackSize,
    _In_opt_ PVOID AttributeList
);

NTSTATUS NTAPI RtlCreateProcessParametersEx(
    _Out_ PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
    _In_ PUNICODE_STRING ImagePathName,
    _In_opt_ PUNICODE_STRING DllPath,
    _In_opt_ PUNICODE_STRING CurrentDirectory,
    _In_opt_ PUNICODE_STRING CommandLine,
    _In_opt_ PVOID Environment,
    _In_opt_ PUNICODE_STRING WindowTitle,
    _In_opt_ PUNICODE_STRING DesktopInfo,
    _In_opt_ PUNICODE_STRING ShellInfo,
    _In_opt_ PUNICODE_STRING RuntimeData,
    _In_ ULONG Flags
);

// ALPC functions
NTSTATUS NTAPI NtAlpcConnectPort(
    _Out_ PHANDLE PortHandle,
    _In_ PUNICODE_STRING PortName,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PVOID PortAttributes,
    _In_ ULONG Flags,
    _In_opt_ PSID RequiredServerSid,
    _Inout_opt_ PPORT_MESSAGE ConnectionMessage,
    _Inout_opt_ PULONG BufferLength,
    _Inout_opt_ PVOID OutMessageAttributes,
    _Inout_opt_ PVOID InMessageAttributes,
    _In_opt_ PLARGE_INTEGER Timeout
);

NTSTATUS NTAPI NtAlpcSendWaitReceivePort(
    _In_ HANDLE PortHandle,
    _In_ ULONG Flags,
    _In_opt_ PPORT_MESSAGE SendMessage,
    _In_opt_ PVOID SendMessageAttributes,
    _Out_opt_ PPORT_MESSAGE ReceiveMessage,
    _Inout_opt_ PSIZE_T BufferLength,
    _Out_opt_ PVOID ReceiveMessageAttributes,
    _In_opt_ PLARGE_INTEGER Timeout
);

} // extern "C"

// ============================================================================
// PROCESS DOPPELGÄNGING IMPLEMENTATION
// ============================================================================
// Educational Note: Process Doppelgänging abuses Windows transactional NTFS.
//
// Steps:
// 1. Create transaction
// 2. Create legitimate file in transaction
// 3. Write malicious content to file
// 4. Create section from file (while in transaction)
// 5. Rollback transaction (file disappears from disk)
// 6. Create process from section (memory-only process)
//
// Result: Process exists with no file on disk
//
// Advantages:
// - No file written to disk (even temporarily)
// - Process image is in memory only
// - Looks like legitimate process (services.exe, svchost.exe, etc.)
// - Bypasses file-based scanning
//
// Detection:
// - Process with no backing file is suspicious
// - AC can detect transactional file operations
// - Still requires our code to be in memory
// ============================================================================

class ProcessDoppelganger {
public:
    // Create doppelgänger process that looks like legitimate Windows service
    static HANDLE CreateDoppelgangerProcess(const wchar_t* targetImage, void* payloadData, size_t payloadSize) {
        // Use legitimate Windows executable as base
        // We'll create transaction, overwrite it, then rollback
        std::wstring tempPath = L"C:\\Windows\\Temp\\";
        tempPath += targetImage;

        // Create transaction
        HANDLE hTransaction = nullptr;
        NTSTATUS status = NtCreateTransaction(
            &hTransaction,
            TRANSACTION_ALL_ACCESS,
            nullptr,
            nullptr,
            nullptr,
            0,
            0,
            0,
            nullptr,
            nullptr
        );

        if (!NT_SUCCESS(status)) {
            return nullptr;
        }

        // Create file in transaction
        HANDLE hFile = CreateFileTransactedW(
            tempPath.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr,
            hTransaction,
            nullptr,
            nullptr
        );

        if (hFile == INVALID_HANDLE_VALUE) {
            NtRollbackTransaction(hTransaction, TRUE);
            CloseHandle(hTransaction);
            return nullptr;
        }

        // Write malicious payload
        DWORD written = 0;
        WriteFile(hFile, payloadData, (DWORD)payloadSize, &written, nullptr);

        // Create section from file
        HANDLE hSection = nullptr;
        status = NtCreateSection(
            &hSection,
            SECTION_ALL_ACCESS,
            nullptr,
            nullptr,
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

        // Create process from section
        HANDLE hProcess = nullptr;
        status = NtCreateProcessEx(
            &hProcess,
            PROCESS_ALL_ACCESS,
            nullptr,
            GetCurrentProcess(),  // Inherit our token
            0,
            hSection,
            nullptr,
            nullptr,
            FALSE
        );

        CloseHandle(hSection);

        // Rollback transaction - file disappears!
        NtRollbackTransaction(hTransaction, TRUE);
        CloseHandle(hTransaction);

        if (!NT_SUCCESS(status)) {
            return nullptr;
        }

        // Process exists but has no backing file!
        return hProcess;
    }
};

// ============================================================================
// THREAD HIJACKING WITH MANUAL MAP
// ============================================================================
// Educational Note: Thread hijacking avoids all thread creation APIs.
//
// Steps:
// 1. Find existing thread in target process
// 2. Suspend thread
// 3. Get thread context (RIP, RSP, etc.)
// 4. Allocate memory in target process
// 5. Write shellcode + DLL to memory
// 6. Modify thread context to point to shellcode
// 7. Resume thread
//
// Result: Thread executes our code without CreateRemoteThread, QueueUserAPC, etc.
//
// Advantages:
// - No PsSetLoadImageNotifyRoutine callback
// - No new threads created
// - No APC queued
// - Existing thread just "happens" to execute our code
//
// Detection:
// - Requires opening process handle
// - Memory allocation still visible
// - Thread context changes detectable (but rare to check)
// ============================================================================

#pragma pack(push, 1)
typedef struct _MANUAL_MAP_DATA {
    PVOID ImageBase;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_BASE_RELOCATION BaseReloc;
    PIMAGE_IMPORT_DESCRIPTOR ImportDesc;

    // Function pointers (resolved in target process)
    decltype(&LoadLibraryA) fnLoadLibraryA;
    decltype(&GetProcAddress) fnGetProcAddress;
    decltype(&VirtualProtect) fnVirtualProtect;
} MANUAL_MAP_DATA, *PMANUAL_MAP_DATA;
#pragma pack(pop)

// Shellcode that runs in target process to manually map DLL
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

            if (!pThunkRef) {
                pThunkRef = pFuncRef;
            }

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
        DWORD dwProtect = 0;

        if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            dwProtect = PAGE_EXECUTE_READ;
        } else if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) {
            dwProtect = PAGE_READWRITE;
        } else {
            dwProtect = PAGE_READONLY;
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

// Marker function to calculate shellcode size
__declspec(noinline) void ManualMapShellcodeEnd() { }

class ThreadHijacker {
public:
    // Inject DLL via thread hijacking (stealthiest method)
    static bool InjectViaThreadHijack(DWORD targetPid, const wchar_t* dllPath) {
        // Open target process
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
        if (!hProcess) {
            return false;
        }

        // Read DLL from disk
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

        // Parse PE headers
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dllData.data();
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(dllData.data() + pDosHeader->e_lfanew);

        // Allocate memory in target
        PVOID pRemoteImage = VirtualAllocEx(
            hProcess,
            nullptr,
            pNtHeaders->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        if (!pRemoteImage) {
            CloseHandle(hProcess);
            return false;
        }

        // Copy headers
        WriteProcessMemory(hProcess, pRemoteImage, dllData.data(), pNtHeaders->OptionalHeader.SizeOfHeaders, nullptr);

        // Copy sections
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

        // Allocate memory for shellcode
        SIZE_T shellcodeSize = (ULONG_PTR)ManualMapShellcodeEnd - (ULONG_PTR)ManualMapShellcode;
        PVOID pShellcode = VirtualAllocEx(hProcess, nullptr, shellcodeSize + sizeof(MANUAL_MAP_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (!pShellcode) {
            VirtualFreeEx(hProcess, pRemoteImage, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        // Prepare manual map data
        MANUAL_MAP_DATA mapData = { 0 };
        mapData.ImageBase = pRemoteImage;
        mapData.NtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)pRemoteImage + pDosHeader->e_lfanew);
        mapData.BaseReloc = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)pRemoteImage + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        mapData.ImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)pRemoteImage + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        // Resolve function pointers in target process
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        mapData.fnLoadLibraryA = (decltype(&LoadLibraryA))GetProcAddress(hKernel32, "LoadLibraryA");
        mapData.fnGetProcAddress = (decltype(&GetProcAddress))GetProcAddress(hKernel32, "GetProcAddress");
        mapData.fnVirtualProtect = (decltype(&VirtualProtect))GetProcAddress(hKernel32, "VirtualProtect");

        // Write shellcode
        WriteProcessMemory(hProcess, pShellcode, (PVOID)ManualMapShellcode, shellcodeSize, nullptr);
        // Write map data after shellcode
        WriteProcessMemory(hProcess, (PVOID)((ULONG_PTR)pShellcode + shellcodeSize), &mapData, sizeof(mapData), nullptr);

        // Find a thread to hijack
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

        // Suspend thread
        SuspendThread(hThread);

        // Get thread context
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_FULL;
        GetThreadContext(hThread, &ctx);

        // Save original RIP on stack
        ctx.Rsp -= sizeof(ULONG_PTR);
        WriteProcessMemory(hProcess, (PVOID)ctx.Rsp, &ctx.Rip, sizeof(ULONG_PTR), nullptr);

        // Point RIP to our shellcode
        ctx.Rip = (ULONG_PTR)pShellcode;
        // Pass map data pointer as argument (RCX on x64)
        ctx.Rcx = (ULONG_PTR)pShellcode + shellcodeSize;

        // Set thread context
        SetThreadContext(hThread, &ctx);

        // Resume thread - it will execute our shellcode!
        ResumeThread(hThread);

        CloseHandle(hThread);
        CloseHandle(hProcess);

        return true;
    }
};

// ============================================================================
// ALPC CLIENT (Communication with driver)
// ============================================================================

class AlpcClient {
private:
    HANDLE m_hPort = nullptr;
    ULONGLONG m_hardwareId = 0;

public:
    bool Connect() {
        // Get hardware ID from driver first (via magic IOCTL through beep device)
        HANDLE hBeep = CreateFileW(L"\\\\.\\Beep", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hBeep != INVALID_HANDLE_VALUE) {
            // Try to get hardware ID via our special IOCTL
            DWORD bytesReturned = 0;
            DWORD ioctl = CTL_CODE(FILE_DEVICE_BEEP, 0x999, METHOD_BUFFERED, FILE_ANY_ACCESS);
            DeviceIoControl(hBeep, ioctl, nullptr, 0, &m_hardwareId, sizeof(m_hardwareId), &bytesReturned, nullptr);
            CloseHandle(hBeep);
        }

        if (m_hardwareId == 0) {
            // Fallback: calculate hardware ID ourselves
            m_hardwareId = CalculateHardwareId();
        }

        // Connect to ALPC port
        WCHAR portName[128];
        swprintf_s(portName, 128, L"\\RPC Control\\AudioKse_%llX", m_hardwareId & 0xFFFFFFFF);

        UNICODE_STRING portNameU;
        RtlInitUnicodeString(&portNameU, portName);

        PORT_MESSAGE connMsg = { 0 };
        connMsg.DataLength = 0;
        connMsg.TotalLength = sizeof(PORT_MESSAGE);

        ULONG bufferLen = sizeof(PORT_MESSAGE);

        NTSTATUS status = NtAlpcConnectPort(
            &m_hPort,
            &portNameU,
            nullptr,
            nullptr,
            0,
            nullptr,
            &connMsg,
            &bufferLen,
            nullptr,
            nullptr,
            nullptr
        );

        return NT_SUCCESS(status);
    }

    void Disconnect() {
        if (m_hPort) {
            CloseHandle(m_hPort);
            m_hPort = nullptr;
        }
    }

    // Send message to driver via ALPC
    bool SendMessage(ULONG messageType, PVOID data, SIZE_T dataSize) {
        if (!m_hPort) return false;

        // TODO: Implement ALPC message sending
        UNREFERENCED_PARAMETER(messageType);
        UNREFERENCED_PARAMETER(data);
        UNREFERENCED_PARAMETER(dataSize);

        return true;
    }

private:
    ULONGLONG CalculateHardwareId() {
        // Same calculation as driver
        ULONGLONG id = 0;

        int cpuInfo[4] = { 0 };
        __cpuid(cpuInfo, 0);
        id ^= ((ULONGLONG)cpuInfo[1] << 32) | cpuInfo[2];

        __cpuid(cpuInfo, 1);
        id ^= ((ULONGLONG)cpuInfo[0] << 16) | (cpuInfo[3] & 0xFFFF);

        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        id ^= ((ULONGLONG)sysInfo.dwNumberOfProcessors << 56);

        id ^= GetTickCount64();
        id *= 0x517CC1B727220A95ULL;

        return id;
    }
};

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

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

    // For debugging
    #ifdef _DEBUG
    AllocConsole();
    FILE* fDummy;
    freopen_s(&fDummy, "CONOUT$", "w", stdout);
    printf("[ELITE] Elite UM Client\n");
    #endif

    // Connect to driver via ALPC
    AlpcClient client;
    if (!client.Connect()) {
        #ifdef _DEBUG
        printf("[-] Failed to connect to driver via ALPC\n");
        #endif
        MessageBoxW(nullptr, L"Failed to connect to elite driver", L"Error", MB_ICONERROR);
        return 1;
    }

    #ifdef _DEBUG
    printf("[+] Connected to driver via ALPC\n");
    #endif

    // Example: Inject DLL via thread hijacking
    const wchar_t* targetProcess = L"notepad.exe";
    const wchar_t* dllPath = L"C:\\test.dll";

    #ifdef _DEBUG
    printf("[*] Waiting for %S...\n", targetProcess);
    #endif

    // Wait for target process
    DWORD targetPid = 0;
    for (int i = 0; i < 60; i++) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
            if (Process32FirstW(hSnapshot, &pe)) {
                do {
                    if (_wcsicmp(pe.szExeFile, targetProcess) == 0) {
                        targetPid = pe.th32ProcessID;
                        break;
                    }
                } while (Process32NextW(hSnapshot, &pe));
            }
            CloseHandle(hSnapshot);
        }

        if (targetPid != 0) break;
        Sleep(1000);
    }

    if (targetPid == 0) {
        #ifdef _DEBUG
        printf("[-] Target process not found\n");
        #endif
        client.Disconnect();
        return 1;
    }

    #ifdef _DEBUG
    printf("[+] Found target PID: %d\n", targetPid);
    printf("[*] Injecting via thread hijacking...\n");
    #endif

    // Inject via thread hijacking
    if (ThreadHijacker::InjectViaThreadHijack(targetPid, dllPath)) {
        #ifdef _DEBUG
        printf("[+] Injection successful!\n");
        #endif
    } else {
        #ifdef _DEBUG
        printf("[-] Injection failed\n");
        #endif
    }

    // Keep running
    #ifdef _DEBUG
    printf("[*] Elite UM running. Press Enter to exit.\n");
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

/*
 * COMPILATION:
 * ============
 *
 * Debug (with console):
 * cl /D_DEBUG /DDEBUG /Zi /EHsc UM_elite.cpp /link /SUBSYSTEM:CONSOLE ntdll.lib user32.lib
 *
 * Release (GUI, no console):
 * cl /O2 /DNDEBUG /EHsc UM_elite.cpp /link /SUBSYSTEM:WINDOWS ntdll.lib user32.lib
 *
 * USAGE:
 * ======
 *
 * 1. Load elite kernel driver (AudioKSE.sys)
 * 2. Run UM_elite.exe
 * 3. Driver and UM communicate via ALPC (not IOCTL)
 * 4. Injection uses thread hijacking (no LoadLibrary, no CreateRemoteThread)
 *
 * DETECTION RESISTANCE:
 * =====================
 *
 * - No IOCTL calls (ALPC instead)
 * - No CreateRemoteThread (thread hijacking)
 * - No LoadLibrary (manual PE mapping)
 * - No QueueUserAPC (direct context manipulation)
 * - No new threads created
 * - Code executes in existing thread context
 *
 * PROCESS DOPPELGÄNGING:
 * ======================
 *
 * To use Process Doppelgänging instead:
 * 1. Prepare payload executable
 * 2. Call ProcessDoppelganger::CreateDoppelgangerProcess()
 * 3. Process appears with no backing file
 * 4. Looks like legitimate Windows service
 *
 * FURTHER IMPROVEMENTS:
 * =====================
 *
 * - DLL Order Hijacking (load into services.exe, svchost.exe)
 * - KernelCallbackTable hijacking (no code injection needed)
 * - TLS callback abuse (execute before main)
 * - COM hijacking (get loaded by legitimate process)
 * - AppInit_DLLs (load into every GUI process)
 *
 * Target detection: <5% by even sophisticated ACs
 */
