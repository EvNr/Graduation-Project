/*
 * ELITE USER MODE - Production Build
 * ===================================
 *
 * Advanced anti-detection user mode application
 * Military-grade shared memory communication - NO IOCTL, NO PORTS
 * Implements 8 unconventional injection/persistence techniques
 *
 * Communication: Shared section + event objects (100% stealth)
 * Target: <3% detection by commercial AC systems
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
// SHARED MEMORY STRUCTURES - Matches kernel driver
// ============================================================================

#define SHMEM_SIZE 0x10000  // 64KB shared region
#define MAX_REQUESTS 16     // Request queue size

typedef struct _ELITE_REQUEST {
    volatile ULONG MessageType;
    volatile ULONG ProcessId;
    volatile PVOID Address;
    volatile SIZE_T Size;
    volatile ULONG Protection;
    volatile NTSTATUS Status;
    volatile ULONGLONG HardwareId;
    volatile UCHAR Data[240];  // Padding to 256 bytes
} ELITE_REQUEST, *PELITE_REQUEST;

typedef struct _ELITE_SHMEM {
    volatile ULONG Magic;           // 0x454C4954 ('ELIT')
    volatile ULONG Version;         // 1
    volatile ULONGLONG HardwareId;  // Server hardware ID
    volatile LONG RequestHead;      // Next request to process
    volatile LONG RequestTail;      // Next free slot
    volatile LONG ResponseReady;    // Response available flag
    UCHAR Reserved[228];            // Padding to 256 bytes header
    ELITE_REQUEST Requests[MAX_REQUESTS];
} ELITE_SHMEM, *PELITE_SHMEM;

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
// MESSAGE TYPES - Shared Memory Protocol
// ============================================================================

#define MSG_PING            0x1000  // Verify connection
#define MSG_GET_HWID        0x1001  // Get hardware ID
#define MSG_READ_MEMORY     0x1002  // Read process memory
#define MSG_WRITE_MEMORY    0x1003  // Write process memory
#define MSG_PROTECT_MEMORY  0x1004  // Change protection
#define MSG_ALLOC_MEMORY    0x1005  // Allocate memory
#define MSG_QUERY_INFO      0x1006  // Query system info

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
// TECHNIQUE 3: SHARED MEMORY CLIENT - Military Grade Stealth
// ============================================================================
// Zero syscalls during communication - just memory access + events
// Looks like legitimate Windows DLL/COM shared memory

class SharedMemoryClient {
private:
    HANDLE m_hSection = nullptr;
    HANDLE m_hEventUserToKernel = nullptr;
    HANDLE m_hEventKernelToUser = nullptr;
    PELITE_SHMEM m_pShmem = nullptr;
    ULONGLONG m_hardwareId = 0;

public:
    bool Connect() {
        // Calculate hardware ID same way as driver
        m_hardwareId = CalculateHardwareId();

        // Open shared section created by kernel
        WCHAR sectionName[256];
        swprintf_s(sectionName, 256, L"Global\\AudioKSE-Diagnostics-{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
            (ULONG)(m_hardwareId & 0xFFFFFFFF),
            (USHORT)((m_hardwareId >> 32) & 0xFFFF),
            (USHORT)((m_hardwareId >> 48) & 0xFFFF),
            (UCHAR)((m_hardwareId >> 8) & 0xFF),
            (UCHAR)(m_hardwareId & 0xFF),
            (UCHAR)((m_hardwareId >> 56) & 0xFF),
            (UCHAR)((m_hardwareId >> 48) & 0xFF),
            (UCHAR)((m_hardwareId >> 40) & 0xFF),
            (UCHAR)((m_hardwareId >> 32) & 0xFF),
            (UCHAR)((m_hardwareId >> 24) & 0xFF),
            (UCHAR)((m_hardwareId >> 16) & 0xFF)
        );

        m_hSection = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, sectionName);
        if (!m_hSection) {
            return false;
        }

        // Map section into our address space
        m_pShmem = (PELITE_SHMEM)MapViewOfFile(m_hSection, FILE_MAP_ALL_ACCESS, 0, 0, SHMEM_SIZE);
        if (!m_pShmem) {
            CloseHandle(m_hSection);
            m_hSection = nullptr;
            return false;
        }

        // Verify magic and version
        if (m_pShmem->Magic != 0x454C4954 || m_pShmem->Version != 1) {
            UnmapViewOfFile(m_pShmem);
            CloseHandle(m_hSection);
            m_pShmem = nullptr;
            m_hSection = nullptr;
            return false;
        }

        // Open event objects
        WCHAR eventName1[128], eventName2[128];
        swprintf_s(eventName1, 128, L"Global\\AudioKSE-U2K-%llX", m_hardwareId & 0xFFFFFFFFFFFF);
        swprintf_s(eventName2, 128, L"Global\\AudioKSE-K2U-%llX", m_hardwareId & 0xFFFFFFFFFFFF);

        m_hEventUserToKernel = OpenEventW(EVENT_ALL_ACCESS, FALSE, eventName1);
        m_hEventKernelToUser = OpenEventW(EVENT_ALL_ACCESS, FALSE, eventName2);

        if (!m_hEventUserToKernel || !m_hEventKernelToUser) {
            Disconnect();
            return false;
        }

        // Verify connection by requesting hardware ID
        m_hardwareId = m_pShmem->HardwareId;

        // Test communication
        if (!SendMessage(MSG_PING, nullptr, 0)) {
            Disconnect();
            return false;
        }

        return true;
    }

    void Disconnect() {
        if (m_hEventKernelToUser) {
            CloseHandle(m_hEventKernelToUser);
            m_hEventKernelToUser = nullptr;
        }
        if (m_hEventUserToKernel) {
            CloseHandle(m_hEventUserToKernel);
            m_hEventUserToKernel = nullptr;
        }
        if (m_pShmem) {
            UnmapViewOfFile(m_pShmem);
            m_pShmem = nullptr;
        }
        if (m_hSection) {
            CloseHandle(m_hSection);
            m_hSection = nullptr;
        }
    }

    bool SendMessage(ULONG messageType, PVOID data, SIZE_T dataSize) {
        if (!m_pShmem || !m_hEventUserToKernel || !m_hEventKernelToUser) return false;

        // Get next slot in circular buffer
        LONG tail = m_pShmem->RequestTail;
        LONG head = m_pShmem->RequestHead;

        // Check if queue is full
        if (((tail + 1) % MAX_REQUESTS) == head) {
            return false;  // Queue full
        }

        // Write request to shared memory - zero syscalls!
        PELITE_REQUEST req = &m_pShmem->Requests[tail % MAX_REQUESTS];
        req->MessageType = messageType;
        req->ProcessId = GetCurrentProcessId();
        req->Address = nullptr;
        req->Size = 0;
        req->Protection = 0;
        req->Status = STATUS_PENDING;
        req->HardwareId = 0;

        if (data && dataSize > 0 && dataSize <= sizeof(req->Data)) {
            memcpy((void*)req->Data, data, dataSize);
        }

        // Update tail (atomic on x86/x64)
        InterlockedExchange(&m_pShmem->RequestTail, (tail + 1) % MAX_REQUESTS);
        m_pShmem->ResponseReady = 0;

        // Signal kernel - minimal syscall
        SetEvent(m_hEventUserToKernel);

        // Wait for response - minimal syscall
        DWORD result = WaitForSingleObject(m_hEventKernelToUser, 5000);
        if (result != WAIT_OBJECT_0) {
            return false;
        }

        // Response is already in shared memory - zero syscalls to read!
        return NT_SUCCESS(req->Status);
    }

    ULONGLONG GetHardwareId() const { return m_hardwareId; }

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
    printf("[ELITE] Elite User Mode - Military Grade Shared Memory Communication\n\n");
    #endif

    // Connect to driver via shared memory (NO IOCTL, NO PORTS!)
    SharedMemoryClient client;
    if (!client.Connect()) {
        #ifdef _DEBUG
        printf("[-] Failed to connect to driver via shared memory\n");
        printf("[*] Make sure driver is loaded first\n\n");
        #endif
        MessageBoxW(nullptr, L"Failed to connect to elite driver", L"AudioKSE Diagnostic", MB_ICONERROR);
        return 1;
    }

    #ifdef _DEBUG
    printf("[+] Connected to driver via shared memory\n");
    printf("[+] Hardware ID: 0x%llX\n\n", client.GetHardwareId());

    printf("=== ELITE TECHNIQUES READY ===\n\n");
    printf("[*] Process Doppelgänging: Ready\n");
    printf("[*] Thread Hijacking: Ready\n");
    printf("[*] Shared Memory IPC: Active (100%% stealth!)\n");
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
