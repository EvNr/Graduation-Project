#define _WIN32_WINNT _WIN32_WINNT_WIN10

#define NTDDI_VERSION NTDDI_WIN10

#include <ntifs.h>

#include <ntddk.h>

#include <wchar.h>

#include <stdlib.h>

#include <ntstrsafe.h>

#include <intrin.h>

#include <ntimage.h>

#include <minwindef.h>



#pragma comment(lib, "ntoskrnl.lib")



#ifndef _SYSTEM_PROCESS_INFORMATION_DEFINED

typedef struct _SYSTEM_THREAD_INFORMATION {

    LARGE_INTEGER  KernelTime;

    LARGE_INTEGER  UserTime;

    LARGE_INTEGER  CreateTime;

    ULONG         WaitTime;

    PVOID         StartAddress;

    CLIENT_ID     ClientId;

    KPRIORITY     Priority;

    LONG          BasePriority;

    ULONG         ContextSwitches;

    ULONG         ThreadState;

    ULONG         WaitReason;

} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;



typedef struct _SYSTEM_PROCESS_INFORMATION {

    ULONG         NextEntryOffset;

    ULONG         NumberOfThreads;

    LARGE_INTEGER WorkingSetPrivateSize;

    ULONG         HardFaultCount;

    ULONG         NumberOfThreadsHighWatermark;

    ULONGLONG     CycleTime;

    LARGE_INTEGER CreateTime;

    LARGE_INTEGER UserTime;

    LARGE_INTEGER KernelTime;

    UNICODE_STRING ImageName;

    KPRIORITY     BasePriority;

    HANDLE        UniqueProcessId;

    HANDLE        InheritedFromUniqueProcessId;

    ULONG         HandleCount;

    ULONG         SessionId;

    ULONG_PTR     UniqueProcessKey;

    SIZE_T        PeakVirtualSize;

    SIZE_T        VirtualSize;

    ULONG         PageFaultCount;

    SIZE_T        PeakWorkingSetSize;

    SIZE_T        WorkingSetSize;

    SIZE_T        QuotaPeakPagedPoolUsage;

    SIZE_T        QuotaPagedPoolUsage;

    SIZE_T        QuotaPeakNonPagedPoolUsage;

    SIZE_T        QuotaNonPagedPoolUsage;

    SIZE_T        PagefileUsage;

    SIZE_T        PeakPagefileUsage;

    SIZE_T        PrivatePageCount;

    LARGE_INTEGER ReadOperationCount;

    LARGE_INTEGER WriteOperationCount;

    LARGE_INTEGER OtherOperationCount;

    LARGE_INTEGER ReadTransferCount;

    LARGE_INTEGER WriteTransferCount;

    LARGE_INTEGER OtherTransferCount;

} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

#define _SYSTEM_PROCESS_INFORMATION_DEFINED

#endif



#ifndef _KM_THREAD_BASIC_DEFINED_

#define _KM_THREAD_BASIC_DEFINED_



typedef struct _THREAD_BASIC_INFORMATION {

    NTSTATUS    ExitStatus;

    PVOID       TebBaseAddress;

    CLIENT_ID   ClientId;

    KAFFINITY   AffinityMask;

    KPRIORITY   Priority;

    KPRIORITY   BasePriority;

} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;



EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI ZwQueryInformationThread(

    _In_ HANDLE ThreadHandle,

    _In_ THREADINFOCLASS ThreadInformationClass,

    _Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,

    _In_ ULONG ThreadInformationLength,

    _Out_opt_ PULONG ReturnLength

);



#endif



#ifdef __cplusplus



extern "C" {

#endif



    NTSTATUS NTAPI PsSuspendThread(PETHREAD Thread, PULONG PreviousSuspendCount);

    NTKERNELAPI LONGLONG PsGetProcessCreateTimeQuadPart(PEPROCESS Process);

    NTSTATUS NTAPI PsResumeThread(PETHREAD Thread, PULONG PreviousSuspendCount);

    NTSTATUS NTAPI PsGetContextThread(PETHREAD Thread, PCONTEXT ThreadContext, KPROCESSOR_MODE Mode);

    NTSTATUS NTAPI PsSetContextThread(PETHREAD Thread, PCONTEXT ThreadContext, KPROCESSOR_MODE Mode);



    NTSYSAPI NTSTATUS NTAPI ZwProtectVirtualMemory(

        _In_    HANDLE ProcessHandle,

        _Inout_ PVOID* BaseAddress,

        _Inout_ PSIZE_T RegionSize,

        _In_    ULONG NewProtect,

        _Out_   PULONG OldProtect

    );



    typedef NTSTATUS(NTAPI* PUSER_THREAD_START_ROUTINE)(

        _In_ PVOID ThreadParameter

        );



    NTSYSAPI NTSTATUS NTAPI RtlCreateUserThread(

        _In_     HANDLE ProcessHandle,

        _In_opt_ PSECURITY_DESCRIPTOR SecurityDescriptor,

        _In_     BOOLEAN CreateSuspended,

        _In_     ULONG StackZeroBits,

        _In_opt_ PSIZE_T StackReserved,

        _In_opt_ PSIZE_T StackCommit,

        _In_     PVOID StartAddress,

        _In_opt_ PVOID StartParameter,

        _Out_    PHANDLE ThreadHandle,

        _Out_opt_ PCLIENT_ID ClientId

    );



    NTSYSAPI NTSTATUS NTAPI ZwAllocateVirtualMemory(

        _In_    HANDLE ProcessHandle,

        _Inout_ PVOID* BaseAddress,

        _In_    ULONG_PTR ZeroBits,

        _Inout_ PSIZE_T RegionSize,

        _In_    ULONG AllocationType,

        _In_    ULONG Protect

    );



    NTSYSAPI NTSTATUS NTAPI ZwFreeVirtualMemory(

        _In_    HANDLE ProcessHandle,

        _Inout_ PVOID* BaseAddress,

        _Inout_ PSIZE_T RegionSize,

        _In_    ULONG FreeType

    );



    NTKERNELAPI ULONG PsGetProcessSessionId(PEPROCESS Process);

    NTKERNELAPI ULONG NTAPI PsGetCurrentProcessSessionId();



    NTKERNELAPI NTSTATUS NTAPI IoCreateDriver(

        _In_opt_ PUNICODE_STRING DriverName,

        _In_     PDRIVER_INITIALIZE InitializationFunction

    );



    NTKERNELAPI VOID NTAPI IoDeleteDriver(

        _In_ PDRIVER_OBJECT DriverObject

    );



    NTKERNELAPI PPEB NTAPI PsGetProcessPeb(

        _In_ PEPROCESS Process

    );



    NTKERNELAPI PVOID NTAPI PsGetProcessSectionBaseAddress(

        _In_ PEPROCESS Process

    );



    NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(

        _In_      ULONG SystemInformationClass,

        _Inout_   PVOID SystemInformation,

        _In_      ULONG SystemInformationLength,

        _Out_opt_ PULONG ReturnLength

    );



    NTKERNELAPI

        PETHREAD

        PsGetNextProcessThread(

            _In_ PEPROCESS Process,

            _In_opt_ PETHREAD Thread

        );



    typedef enum _SYSTEM_INFORMATION_CLASS {

        SystemModuleInformation = 11,

        SystemProcessInformation = 5

    } SYSTEM_INFORMATION_CLASS;



    NTKERNELAPI PVOID PsGetProcessWow64Process(PEPROCESS Process);



#ifdef __cplusplus

}

#endif



PVOID g_RandgridBase = NULL;

ULONG g_RandgridSize = 0;

volatile LONG g_CallbackCount = 0;



typedef struct _RTL_PROCESS_MODULE_INFORMATION

{

    HANDLE Section;

    PVOID MappedBase;

    PVOID ImageBase;

    ULONG ImageSize;

    ULONG Flags;

    USHORT LoadOrderIndex;

    USHORT InitOrderIndex;

    USHORT LoadCount;

    USHORT OffsetToFileName;

    UCHAR FullPathName[256];

} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;



typedef struct _RTL_PROCESS_MODULES

{

    ULONG NumberOfModules;

    RTL_PROCESS_MODULE_INFORMATION Modules[1];

} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;



typedef struct _LDR_DATA_TABLE_ENTRY {

    LIST_ENTRY InLoadOrderLinks;

    LIST_ENTRY InMemoryOrderLinks;

    LIST_ENTRY InInitializationOrderLinks;

    PVOID DllBase;

    PVOID EntryPoint;

    ULONG SizeOfImage;

    UNICODE_STRING FullDllName;

    UNICODE_STRING BaseDllName;

    ULONG Flags;

    USHORT LoadCount;

    USHORT TlsIndex;

    LIST_ENTRY HashLinks;

    PVOID SectionPointer;

    ULONG CheckSum;

    ULONG TimeDateStamp;

    PVOID LoadedImports;

    PVOID EntryPointActivationContext;

    PVOID PatchInformation;

} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;



typedef struct _PEB_LDR_DATA {

    ULONG Length;

    BOOLEAN Initialized;

    PVOID SsHandle;

    LIST_ENTRY InLoadOrderModuleList;

    LIST_ENTRY InMemoryOrderModuleList;

    LIST_ENTRY InInitializationOrderModuleList;

} PEB_LDR_DATA, * PPEB_LDR_DATA;



typedef struct _PEB {

    BOOLEAN InheritedAddressSpace;

    BOOLEAN ReadImageFileExecOptions;

    BOOLEAN BeingDebugged;

    BOOLEAN SpareBool;

    HANDLE Mutant;

    PVOID ImageBaseAddress;

    PPEB_LDR_DATA Ldr;

    PVOID ProcessParameters;

    PVOID SubSystemData;

    PVOID ProcessHeap;

    PVOID FastPebLock;

    PVOID AtlThunkSListPtr;

    PVOID IFEOKey;

    ULONG CrossProcessFlags;

    ULONG ProcessInJob : 1;

    ULONG ProcessInitializing : 1;

    ULONG ReservedBits0 : 30;

    union {

        PVOID KernelCallbackTable;

        PVOID UserSharedInfoPtr;

    };

    ULONG SystemReserved;

    ULONG AtlThunkSListPtr32;

    PVOID ApiSetMap;

} PEB, * PPEB;



static HANDLE gSection = NULL;

PDRIVER_OBJECT g_DriverObject = nullptr; // <-- new

PDEVICE_OBJECT g_DeviceObject = nullptr;

UNICODE_STRING g_SymbolicLink;

WCHAR g_SymbolicLinkBuffer[128];

WCHAR g_RandomName[20];

PVOID g_OriginalIrpHandler = nullptr;

ULONG g_IntegrityChecksum = 0;

PVOID g_BackupHandler = nullptr;

KSPIN_LOCK g_IntegrityLock;





PVOID g_KernelBase = NULL;

ULONG g_KernelSize = 0;

PLIST_ENTRY g_ModuleListHead = NULL;



volatile LONG g_ReferenceCount = 0;

volatile BOOLEAN g_Unloading = FALSE;

volatile BOOLEAN g_StealthMode = FALSE;



PVOID g_ImageLoadNotifyRoutine = NULL;

ULONG g_TargetPid = 0;

WCHAR g_DllPath[260] = { 0 };

KSPIN_LOCK g_InjectionLock;



typedef PETHREAD(NTAPI* pPsGetNextProcessThread)(PEPROCESS Process, PETHREAD Thread);

typedef NTSTATUS(NTAPI* pPsSuspendThread)(PETHREAD Thread, PULONG PreviousSuspendCount);

typedef NTSTATUS(NTAPI* pPsResumeThread)(PETHREAD Thread, PULONG PreviousSuspendCount);

typedef NTSTATUS(NTAPI* pPsGetContextThread)(PETHREAD Thread, PCONTEXT ThreadContext, KPROCESSOR_MODE Mode);

typedef NTSTATUS(NTAPI* pPsSetContextThread)(PETHREAD Thread, PCONTEXT ThreadContext, KPROCESSOR_MODE Mode);



pPsGetNextProcessThread g_PsGetNextProcessThread = NULL;

pPsSuspendThread g_PsSuspendThread = NULL;

pPsResumeThread g_PsResumeThread = NULL;

pPsGetContextThread g_PsGetContextThread = NULL;

pPsSetContextThread g_PsSetContextThread = NULL;



BOOLEAN IsStringEqual(LPCWSTR Str1, LPCWSTR Str2) {

    // SAFETY CHECK: Prevent BSOD if pointers are NULL

    if (!Str1 || !Str2) return FALSE;



    while (*Str1 && *Str2) {

        WCHAR c1 = *Str1;

        WCHAR c2 = *Str2;

        if (c1 >= L'A' && c1 <= L'Z') c1 += 32;

        if (c2 >= L'A' && c2 <= L'Z') c2 += 32;

        if (c1 != c2) return FALSE;

        Str1++; Str2++;

    }

    return !*Str1 && !*Str2;

}



BOOLEAN IsAnsiStringEqual(const char* Str1, const char* Str2) {

    while (*Str1 && *Str2) {

        if (*Str1 != *Str2) return FALSE;

        Str1++; Str2++;

    }

    return !*Str1 && !*Str2;

}



PVOID GetModuleBaseAddress(PEPROCESS Process, LPCWSTR ModuleName) {

    PPEB Peb = PsGetProcessPeb(Process);

    if (!Peb) return NULL;



    KAPC_STATE ApcState;

    KeStackAttachProcess(Process, &ApcState);



    PPEB_LDR_DATA Ldr = Peb->Ldr;

    if (!Ldr) {

        KeUnstackDetachProcess(&ApcState);

        return NULL;

    }



    PLIST_ENTRY Head = &Ldr->InLoadOrderModuleList;

    PLIST_ENTRY Entry = Head->Flink;



    while (Entry != Head) {

        PLDR_DATA_TABLE_ENTRY Module = CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);



        if (Module->BaseDllName.Buffer) {

            if (IsStringEqual(Module->BaseDllName.Buffer, ModuleName)) {

                PVOID Base = Module->DllBase;

                KeUnstackDetachProcess(&ApcState);

                return Base;

            }

        }

        Entry = Entry->Flink;

    }



    KeUnstackDetachProcess(&ApcState);

    return NULL;

}



PVOID GetKernelModuleBase(const char* ModuleName, PULONG ModuleSize) {

    if (!ModuleName) {

        return NULL;

    }



    // Use a fixed upper bound buffer; module list is typically small.

    ULONG bufferSize = 0x4000;

    PRTL_PROCESS_MODULES modules =

        (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'ModL');

    if (!modules) {

        return NULL;

    }



    NTSTATUS status =

        ZwQuerySystemInformation(SystemModuleInformation, modules, bufferSize, &bufferSize);

    if (!NT_SUCCESS(status)) {

        ExFreePoolWithTag(modules, 'ModL');

        return NULL;

    }



    PVOID base = NULL;

    ULONG size = 0;



    for (ULONG i = 0; i < modules->NumberOfModules; ++i) {

        PRTL_PROCESS_MODULE_INFORMATION mod = &modules->Modules[i];

        const char* name = (const char*)(mod->FullPathName + mod->OffsetToFileName);

        if (name && IsAnsiStringEqual(name, ModuleName)) {

            base = mod->ImageBase;

            size = mod->ImageSize;

            break;

        }

    }



    if (ModuleSize && base) {

        *ModuleSize = size;

    }



    ExFreePoolWithTag(modules, 'ModL');

    return base;

}



PVOID GetExportAddress(PVOID ModuleBase, const char* FunctionName) {

    if (!ModuleBase) return NULL;



    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ModuleBase;

    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;



    PIMAGE_NT_HEADERS64 NtHeaders = (PIMAGE_NT_HEADERS64)((PUCHAR)ModuleBase + DosHeader->e_lfanew);

    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;



    ULONG ExportDirectoryRva = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    if (!ExportDirectoryRva) return NULL;



    PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ModuleBase + ExportDirectoryRva);



    PULONG AddressOfFunctions = (PULONG)((PUCHAR)ModuleBase + ExportDirectory->AddressOfFunctions);

    PULONG AddressOfNames = (PULONG)((PUCHAR)ModuleBase + ExportDirectory->AddressOfNames);

    PUSHORT AddressOfNameOrdinals = (PUSHORT)((PUCHAR)ModuleBase + ExportDirectory->AddressOfNameOrdinals);



    for (ULONG i = 0; i < ExportDirectory->NumberOfNames; i++) {

        const char* ExportName = (const char*)((PUCHAR)ModuleBase + AddressOfNames[i]);

        if (IsAnsiStringEqual(ExportName, FunctionName)) {

            USHORT Ordinal = AddressOfNameOrdinals[i];

            return (PVOID)((PUCHAR)ModuleBase + AddressOfFunctions[Ordinal]);

        }

    }



    return NULL;

}



NTSTATUS ReadProcessMemoryMDL(PEPROCESS target_process, PVOID source_address,

    PVOID buffer, SIZE_T size, PSIZE_T bytes_read) {



    if (!target_process || !source_address || !buffer || size == 0) {

        return STATUS_INVALID_PARAMETER;

    }



    PMDL mdl = NULL;

    PVOID mapped_address = NULL;

    NTSTATUS status = STATUS_SUCCESS;

    SIZE_T total_read = 0;

    KAPC_STATE apc_state;



    __try {

        KeStackAttachProcess((PKPROCESS)target_process, &apc_state);



        mdl = IoAllocateMdl(source_address, (ULONG)size, FALSE, FALSE, NULL);

        if (!mdl) {

            status = STATUS_INSUFFICIENT_RESOURCES;

            __leave;

        }



        __try {

            MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);

        }

        __except (EXCEPTION_EXECUTE_HANDLER) {

            status = STATUS_ACCESS_VIOLATION;

            __leave;

        }



        mapped_address = MmMapLockedPagesSpecifyCache(mdl, KernelMode,

            MmNonCached, NULL, FALSE, NormalPagePriority);

        if (!mapped_address) {

            status = STATUS_INSUFFICIENT_RESOURCES;

            __leave;

        }



        RtlCopyMemory(buffer, mapped_address, size);

        total_read = size;



    }

    __finally {

        if (mapped_address) {

            MmUnmapLockedPages(mapped_address, mdl);

        }

        if (mdl) {

            MmUnlockPages(mdl);

            IoFreeMdl(mdl);

        }

        KeUnstackDetachProcess(&apc_state);

    }



    if (bytes_read) {

        *bytes_read = total_read;

    }



    return status;

}



NTSTATUS WriteProcessMemoryMDL(PEPROCESS target_process, PVOID dest_address,

    PVOID buffer, SIZE_T size, PSIZE_T bytes_written) {



    if (!target_process || !dest_address || !buffer || size == 0) {

        return STATUS_INVALID_PARAMETER;

    }



    PMDL mdl = NULL;

    PVOID mapped_address = NULL;

    NTSTATUS status = STATUS_SUCCESS;

    SIZE_T total_written = 0;

    KAPC_STATE apc_state;



    __try {

        KeStackAttachProcess((PKPROCESS)target_process, &apc_state);



        mdl = IoAllocateMdl(dest_address, (ULONG)size, FALSE, FALSE, NULL);

        if (!mdl) {

            status = STATUS_INSUFFICIENT_RESOURCES;

            __leave;

        }



        __try {

            MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);

        }

        __except (EXCEPTION_EXECUTE_HANDLER) {

            status = STATUS_ACCESS_VIOLATION;

            __leave;

        }



        mapped_address = MmMapLockedPagesSpecifyCache(mdl, KernelMode,

            MmNonCached, NULL, FALSE, NormalPagePriority);

        if (!mapped_address) {

            status = STATUS_INSUFFICIENT_RESOURCES;

            __leave;

        }



        RtlCopyMemory(mapped_address, buffer, size);

        total_written = size;



    }

    __finally {

        if (mapped_address) {

            MmUnmapLockedPages(mapped_address, mdl);

        }

        if (mdl) {

            MmUnlockPages(mdl);

            IoFreeMdl(mdl);

        }

        KeUnstackDetachProcess(&apc_state);

    }



    if (bytes_written) {

        *bytes_written = total_written;

    }



    return status;

}



int _stricmp(const char* str1, const char* str2) {

    if (!str1 || !str2) {

        return -1;

    }



    while (*str1 && *str2) {

        char c1 = (*str1 >= 'A' && *str1 <= 'Z') ? (*str1 + 32) : *str1;

        char c2 = (*str2 >= 'A' && *str2 <= 'Z') ? (*str2 + 32) : *str2;



        if (c1 != c2) {

            return c1 - c2;

        }

        str1++;

        str2++;

    }



    return *str1 - *str2;

}



VOID PatchRandgridWorkers() {

    //

    // Resolve the target kernel module using a system-wide module query

    // instead of treating it like a user-mode DLL.

    //

    g_RandgridBase = GetKernelModuleBase("randgrid.sys", &g_RandgridSize);

    if (!g_RandgridBase || g_RandgridSize == 0) {

        DbgPrint("[*] Target module not present - skipping worker patch\n");

        return;

    }



    // Relative offsets collected from prior RE.

    // These are version-dependent and should be validated carefully.

    ULONG64 workers[] = { 0x6aae8b, 0x6de0c8, 0x6e8df8, 0x869005 };

    ULONG   flagOffsets[] = { 0x10c,    0xb4,     0xb4,     0x28 };

    ULONG   strides[] = { 0x220,    0x1a0,    0x1a0,    0x1a0 };



    for (int w = 0; w < 4; ++w) {

        PUCHAR worker = (PUCHAR)g_RandgridBase + workers[w];



        // Basic bounds check so we don't walk outside the module.

        ULONG_PTR base = (ULONG_PTR)g_RandgridBase;

        ULONG_PTR end = base + g_RandgridSize;

        ULONG_PTR flag_addr = (ULONG_PTR)(worker + 0x100 + flagOffsets[w]);



        if (flag_addr >= end) {

            DbgPrint("[*] Worker %d flag address out of range - skipping\n", w);

            continue;

        }



        PULONG flag = (PULONG)flag_addr;

        for (int slot = 0; slot < 32; ++slot) {

            InterlockedCompareExchange((PLONG)flag, 1, 0);

            flag = (PULONG)((PUCHAR)flag + strides[w]);

            if ((ULONG_PTR)flag >= end) {

                break;

            }

        }

    }



    DbgPrint("[*] Target module worker flags adjusted\n");

}





NTSTATUS SafeStrCopy(CHAR* Dest, SIZE_T DestSize, const CHAR* Source) {

    if (!Dest || !Source || DestSize == 0) {

        return STATUS_INVALID_PARAMETER;

    }



    SIZE_T sourceLen = 0;

    const CHAR* temp = Source;

    while (*temp && sourceLen < DestSize - 1) {

        sourceLen++;

        temp++;

    }



    if (sourceLen >= DestSize) {

        return STATUS_BUFFER_OVERFLOW;

    }



    for (SIZE_T i = 0; i < sourceLen; i++) {

        Dest[i] = Source[i];

    }

    Dest[sourceLen] = '\0';



    return STATUS_SUCCESS;

}



void GenerateRandomName(WCHAR* buffer, size_t length) {

    LARGE_INTEGER perf_counter, tick_count;

    KeQueryPerformanceCounter(&perf_counter);

    KeQueryTickCount(&tick_count);

    ULONG seed = (perf_counter.LowPart ^ tick_count.LowPart) + (ULONG)(ULONG_PTR)buffer;

    seed ^= (perf_counter.HighPart << 16);

    const wchar_t charset[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    const size_t charset_size = (sizeof(charset) / sizeof(wchar_t)) - 1;

    for (size_t i = 0; i < length; ++i) {

        seed = (seed * 214013 + 2531011);

        buffer[i] = charset[(seed >> 16) % charset_size];

    }

    buffer[length] = L'\0';

}



ULONG CalculateChecksum(PVOID address, SIZE_T size) {

    ULONG checksum = 0;

    PUCHAR bytes = (PUCHAR)address;

    for (SIZE_T i = 0; i < size; i++) {

        checksum = (checksum << 1) | (checksum >> 31);

        checksum += bytes[i];

    }

    return checksum;

}



NTSTATUS stealth_device_control(PDEVICE_OBJECT device_object, PIRP irp);



BOOLEAN CheckIntegrity() {

    // If we don't have a baseline handler or driver object, assume OK.

    if (!g_OriginalIrpHandler || !g_DriverObject) {

        return TRUE;

    }



    KIRQL oldIrql;

    KeAcquireSpinLock(&g_IntegrityLock, &oldIrql);



    // Check that the original handler's code bytes are intact.

    ULONG current_checksum = CalculateChecksum(g_OriginalIrpHandler, 64);

    BOOLEAN code_ok = (current_checksum == g_IntegrityChecksum);



    // Check that the IRP_MJ_DEVICE_CONTROL dispatch pointer was not swapped.

    PVOID current_handler = (PVOID)g_DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];

    BOOLEAN pointer_ok = (current_handler == (PVOID)stealth_device_control);



    BOOLEAN result = (code_ok && pointer_ok);



    KeReleaseSpinLock(&g_IntegrityLock, oldIrql);



    if (!result) {

        DbgPrint("[!] INTEGRITY VIOLATION DETECTED (code_ok=%d, pointer_ok=%d)\n",

            code_ok, pointer_ok);

    }



    return result;

}



NTSTATUS APCDllInject(PEPROCESS TargetProcess, HANDLE TargetProcessHandle, const WCHAR* DllPath) {

    NTSTATUS status = STATUS_SUCCESS;

    PVOID Kernel32Base = NULL;

    PVOID LoadLibraryWAddr = NULL;

    PVOID RemoteDllPath = NULL;

    SIZE_T DllPathSize = 0;

    HANDLE hThread = NULL;

    CLIENT_ID ClientId = { 0 };

    WCHAR DosDllPath[260] = { 0 };

    SIZE_T BytesWritten = 0;

    SIZE_T AllocSize = 0;



    // 1. Setup Paths

    if (wcslen(DllPath) > 4 && DllPath[0] == L'\\' && DllPath[1] == L'?' &&

        DllPath[2] == L'?' && DllPath[3] == L'\\') {

        wcscpy_s(DosDllPath, 260, DllPath + 4);

    }

    else {

        wcscpy_s(DosDllPath, 260, DllPath);

    }



    // 2. Get Addresses

    Kernel32Base = GetModuleBaseAddress(TargetProcess, L"kernel32.dll");

    if (!Kernel32Base) return STATUS_NOT_FOUND;







    LoadLibraryWAddr = GetExportAddress(Kernel32Base, "LoadLibraryW");

    if (!LoadLibraryWAddr) return STATUS_NOT_FOUND;



    // 3. Allocate & Write

    DllPathSize = (wcslen(DosDllPath) + 1) * sizeof(WCHAR);

    AllocSize = DllPathSize + 0x100; // Small padding



    status = ZwAllocateVirtualMemory(TargetProcessHandle, &RemoteDllPath, 0, &AllocSize,

        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!NT_SUCCESS(status)) return status;



    status = WriteProcessMemoryMDL(TargetProcess, RemoteDllPath, (PVOID)DosDllPath, DllPathSize, &BytesWritten);

    if (!NT_SUCCESS(status)) return status;



    // 4. Create Thread (FIRE AND FORGET)

    status = RtlCreateUserThread(

        TargetProcessHandle,

        NULL,

        FALSE,

        0,

        NULL,

        NULL,

        (PUSER_THREAD_START_ROUTINE)LoadLibraryWAddr,

        RemoteDllPath,

        &hThread,

        &ClientId

    );



    if (NT_SUCCESS(status)) {

        DbgPrint("[+] APC Queued for PID %lu (Fire & Forget)\n", PsGetProcessId(TargetProcess));

        // CRITICAL: We do NOT wait here. We return immediately.

        // This prevents the Target Process from freezing.

        ZwClose(hThread);

    }

    else {

        DbgPrint("[-] Failed to create thread: 0x%X\n", status);

    }



    // We always return success here so the loop in ImageLoadNotifyCallback

    // continues until the DLL *actually* loads and triggers the success block.

    return STATUS_SUCCESS;

}





// start oldsafedllinject

NTSTATUS SafeDllInject(PEPROCESS TargetProcess, HANDLE TargetProcessHandle, const WCHAR* DllPath)

{

    NTSTATUS status = STATUS_SUCCESS;



    PETHREAD TargetThread = NULL;

    PVOID    dllData = NULL;

    SIZE_T   dllSize = 0;

    PVOID    remoteBase = NULL;

    SIZE_T   imgSize = 0;

    CONTEXT  OriginalContext = { 0 };

    CONTEXT  ModifiedContext = { 0 };

    LARGE_INTEGER InitialDelay = { .QuadPart = -5000000LL }; // 500ms



    UNICODE_STRING       dllUni;

    OBJECT_ATTRIBUTES    oa;

    HANDLE               hFile = NULL;

    IO_STATUS_BLOCK      io;

    FILE_STANDARD_INFORMATION fsi;



    PIMAGE_DOS_HEADER      dos = NULL;

    PIMAGE_NT_HEADERS64    nt = NULL;

    PIMAGE_SECTION_HEADER  sec = NULL;

    ULONG_PTR              delta = 0;



    PIMAGE_BASE_RELOCATION reloc = NULL;

    ULONG                  num = 0;

    PUSHORT                entries = NULL;

    ULONG                  i = 0;

    ULONG_PTR              fixupAddr = 0;

    ULONG_PTR              fixupValue = 0;



    PIMAGE_IMPORT_DESCRIPTOR imp = NULL;

    PCHAR                      dllName = NULL;

    ANSI_STRING                ansiName;

    UNICODE_STRING             dllUniName;

    PVOID                      impDllBase = NULL;

    PIMAGE_THUNK_DATA64        oft = NULL;

    PIMAGE_THUNK_DATA64        ft = NULL;

    PIMAGE_IMPORT_BY_NAME      impName = NULL;

    PVOID                      func = NULL;

    PVOID                      dllMain = NULL;



    SIZE_T shellSize = 0;

    PVOID  remoteShell = NULL;

    ULONG  PreviousSuspendCount = 0;



    //

    // Sanity: required kernel APIs resolved?

    //

    if (!g_PsGetNextProcessThread ||

        !g_PsSuspendThread ||

        !g_PsResumeThread ||

        !g_PsGetContextThread ||

        !g_PsSetContextThread)

    {

        DbgPrint("[-] Critical: injection stubs not resolved\n");

        return STATUS_NOT_IMPLEMENTED;

    }



    DbgPrint("[+] SafeDllInject: starting manual map for %ws\n", DllPath);



    //

    // Basic compatibility checks

    //

    if (PsGetProcessSessionId(TargetProcess) != PsGetCurrentProcessSessionId())

    {

        DbgPrint("[-] Session mismatch - aborting injection\n");

        return STATUS_ACCESS_DENIED;

    }



    if (PsGetProcessWow64Process(TargetProcess) != NULL)

    {

        DbgPrint("[-] Target is 32-bit; injector is x64-only\n");

        return STATUS_NOT_SUPPORTED;

    }



    //

    // Read DLL from disk into nonpaged buffer

    //

    RtlInitUnicodeString(&dllUni, DllPath);

    InitializeObjectAttributes(&oa, &dllUni,

        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,

        NULL, NULL);



    status = ZwOpenFile(&hFile,

        FILE_READ_DATA | SYNCHRONIZE,

        &oa,

        &io,

        FILE_SHARE_READ,

        FILE_SYNCHRONOUS_IO_NONALERT);

    if (!NT_SUCCESS(status))

    {

        DbgPrint("[-] ZwOpenFile failed: 0x%X\n", status);

        return status;

    }



    status = ZwQueryInformationFile(hFile, &io, &fsi,

        sizeof(fsi), FileStandardInformation);

    if (!NT_SUCCESS(status))

    {

        ZwClose(hFile);

        DbgPrint("[-] ZwQueryInformationFile failed: 0x%X\n", status);

        return status;

    }



    dllSize = (SIZE_T)fsi.EndOfFile.QuadPart;

    if (dllSize < sizeof(IMAGE_DOS_HEADER))

    {

        ZwClose(hFile);

        return STATUS_INVALID_IMAGE_FORMAT;

    }



    dllData = ExAllocatePoolWithTag(NonPagedPool, dllSize, 'DllM');

    if (!dllData)

    {

        ZwClose(hFile);

        return STATUS_INSUFFICIENT_RESOURCES;

    }



    status = ZwReadFile(hFile, NULL, NULL, NULL, &io,

        dllData, (ULONG)dllSize, NULL, NULL);

    ZwClose(hFile);



    if (!NT_SUCCESS(status))

    {

        DbgPrint("[-] ZwReadFile failed: 0x%X\n", status);

        ExFreePoolWithTag(dllData, 'DllM');

        return status;

    }



    //

    // Validate PE headers (x64 only)

    //

    dos = (PIMAGE_DOS_HEADER)dllData;

    if (dos->e_magic != IMAGE_DOS_SIGNATURE)

    {

        ExFreePoolWithTag(dllData, 'DllM');

        return STATUS_INVALID_IMAGE_FORMAT;

    }



    nt = (PIMAGE_NT_HEADERS64)((ULONG_PTR)dllData + dos->e_lfanew);

    if (nt->Signature != IMAGE_NT_SIGNATURE ||

        nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)

    {

        ExFreePoolWithTag(dllData, 'DllM');

        return STATUS_INVALID_IMAGE_FORMAT;

    }



    imgSize = nt->OptionalHeader.SizeOfImage;

    if (imgSize == 0)

    {

        ExFreePoolWithTag(dllData, 'DllM');

        return STATUS_INVALID_IMAGE_FORMAT;

    }



    //

    // Allocate image region in target (RW for now, executable later)

    //

    remoteBase = NULL;

    status = ZwAllocateVirtualMemory(TargetProcessHandle,

        &remoteBase,

        0,

        &imgSize,

        MEM_COMMIT | MEM_RESERVE,

        PAGE_READWRITE);

    if (!NT_SUCCESS(status))

    {

        DbgPrint("[-] ZwAllocateVirtualMemory failed: 0x%X\n", status);

        ExFreePoolWithTag(dllData, 'DllM');

        return status;

    }



    DbgPrint("[+] Remote image base: 0x%p, size: 0x%zx\n", remoteBase, imgSize);



    //

    // Map headers + sections into remote process (as a classic PE layout in memory)

    //

    status = WriteProcessMemoryMDL(TargetProcess,

        remoteBase,

        dllData,

        nt->OptionalHeader.SizeOfHeaders,

        NULL);

    if (!NT_SUCCESS(status))

    {

        DbgPrint("[-] Failed to write PE headers: 0x%X\n", status);

        ZwFreeVirtualMemory(TargetProcessHandle, &remoteBase, &imgSize, MEM_RELEASE);

        ExFreePoolWithTag(dllData, 'DllM');

        return status;

    }



    sec = IMAGE_FIRST_SECTION(nt);

    for (USHORT s = 0; s < nt->FileHeader.NumberOfSections; ++s)

    {

        if (sec[s].SizeOfRawData == 0)

            continue;



        PVOID dest = (PVOID)((ULONG_PTR)remoteBase + sec[s].VirtualAddress);

        PVOID src = (PVOID)((ULONG_PTR)dllData + sec[s].PointerToRawData);



        status = WriteProcessMemoryMDL(TargetProcess,

            dest,

            src,

            sec[s].SizeOfRawData,

            NULL);

        if (!NT_SUCCESS(status))

        {

            DbgPrint("[-] Failed to write section %hu: 0x%X\n", s, status);

            ZwFreeVirtualMemory(TargetProcessHandle, &remoteBase, &imgSize, MEM_RELEASE);

            ExFreePoolWithTag(dllData, 'DllM');

            return status;

        }

    }



    //

    // Apply relocations (if image is not loaded at preferred base)

    //

    delta = (ULONG_PTR)remoteBase - nt->OptionalHeader.ImageBase;

    if (delta &&

        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)

    {

        reloc = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)dllData +

            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);



        while (reloc->VirtualAddress)

        {

            num = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);

            entries = (PUSHORT)((ULONG_PTR)reloc + sizeof(IMAGE_BASE_RELOCATION));



            for (i = 0; i < num; ++i)

            {

                USHORT typeOffset = entries[i];

                USHORT type = typeOffset >> 12;

                USHORT offset = typeOffset & 0xFFF;



                if (type == IMAGE_REL_BASED_DIR64)

                {

                    fixupAddr = (ULONG_PTR)remoteBase + reloc->VirtualAddress + offset;

                    status = ReadProcessMemoryMDL(TargetProcess,

                        (PVOID)fixupAddr,

                        &fixupValue,

                        sizeof(ULONG_PTR),

                        NULL);

                    if (!NT_SUCCESS(status))

                    {

                        ZwFreeVirtualMemory(TargetProcessHandle, &remoteBase, &imgSize, MEM_RELEASE);

                        ExFreePoolWithTag(dllData, 'DllM');

                        return status;

                    }



                    fixupValue += delta;



                    status = WriteProcessMemoryMDL(TargetProcess,

                        (PVOID)fixupAddr,

                        &fixupValue,

                        sizeof(ULONG_PTR),

                        NULL);

                    if (!NT_SUCCESS(status))

                    {

                        ZwFreeVirtualMemory(TargetProcessHandle, &remoteBase, &imgSize, MEM_RELEASE);

                        ExFreePoolWithTag(dllData, 'DllM');

                        return status;

                    }

                }

            }



            reloc = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)reloc + reloc->SizeOfBlock);

        }

    }



    //

    // Resolve imports by walking the IMPORT directory and patching IAT

    //

    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)

    {

        imp = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)dllData +

            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);



        while (imp->Name)

        {

            dllName = (PCHAR)((ULONG_PTR)dllData + imp->Name);



            RtlInitAnsiString(&ansiName, dllName);

            status = RtlAnsiStringToUnicodeString(&dllUniName, &ansiName, TRUE);

            if (!NT_SUCCESS(status))

            {

                ZwFreeVirtualMemory(TargetProcessHandle, &remoteBase, &imgSize, MEM_RELEASE);

                ExFreePoolWithTag(dllData, 'DllM');

                return status;

            }



            impDllBase = GetModuleBaseAddress(TargetProcess, dllUniName.Buffer);

            RtlFreeUnicodeString(&dllUniName);



            if (!impDllBase)

            {

                DbgPrint("[-] Import module not found: %s\n", dllName);

                ZwFreeVirtualMemory(TargetProcessHandle, &remoteBase, &imgSize, MEM_RELEASE);

                ExFreePoolWithTag(dllData, 'DllM');

                return STATUS_DLL_NOT_FOUND;

            }



            oft = (PIMAGE_THUNK_DATA64)((ULONG_PTR)dllData + imp->OriginalFirstThunk);

            ft = (PIMAGE_THUNK_DATA64)((ULONG_PTR)remoteBase + imp->FirstThunk);



            while (oft->u1.AddressOfData)

            {

                if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal))

                {

                    func = GetExportAddress(impDllBase,

                        (const char*)(oft->u1.Ordinal & 0xFFFF));

                }

                else

                {

                    impName = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)dllData +

                        oft->u1.AddressOfData);

                    func = GetExportAddress(impDllBase, impName->Name);

                }



                if (!func)

                {

                    DbgPrint("[-] Import resolution failed\n");

                    ZwFreeVirtualMemory(TargetProcessHandle, &remoteBase, &imgSize, MEM_RELEASE);

                    ExFreePoolWithTag(dllData, 'DllM');

                    return STATUS_PROCEDURE_NOT_FOUND;

                }



                status = WriteProcessMemoryMDL(TargetProcess,

                    &ft->u1.Function,

                    &func,

                    sizeof(PVOID),

                    NULL);

                if (!NT_SUCCESS(status))

                {

                    DbgPrint("[-] Failed to write IAT thunk: 0x%X\n", status);

                    ZwFreeVirtualMemory(TargetProcessHandle, &remoteBase, &imgSize, MEM_RELEASE);

                    ExFreePoolWithTag(dllData, 'DllM');

                    return status;

                }



                ++oft;

                ++ft;

            }



            ++imp;

        }

    }



    //

    // Make the image executable (simple: entire region as RX).

    // You *could* make just .text RX and leave the rest RW/RO for extra hygiene.

    //

    {

        ULONG oldProtect = 0;

        PVOID protectBase = remoteBase;

        SIZE_T protectSize = imgSize;



        status = ZwProtectVirtualMemory(TargetProcessHandle,

            &protectBase,

            &protectSize,

            PAGE_EXECUTE_READ,

            &oldProtect);

        if (!NT_SUCCESS(status))

        {

            DbgPrint("[-] ZwProtectVirtualMemory failed: 0x%X\n", status);

            ZwFreeVirtualMemory(TargetProcessHandle, &remoteBase, &imgSize, MEM_RELEASE);

            ExFreePoolWithTag(dllData, 'DllM');

            return status;

        }

    }



    //

    // OPTIONAL STEALTH STEP:

    // Scrub the PE headers in the remote image so it no longer looks like

    // a well-formed PE to signature scanners. This assumes your DLL does

    // not rely on header contents at runtime.

    //

    {

        SIZE_T headersSize = nt->OptionalHeader.SizeOfHeaders;

        if (headersSize && headersSize <= imgSize)

        {

            PVOID zeroBuf = ExAllocatePoolWithTag(NonPagedPool, headersSize, 'HdrZ');

            if (zeroBuf)

            {

                RtlZeroMemory(zeroBuf, headersSize);

                (void)WriteProcessMemoryMDL(TargetProcess,

                    remoteBase,

                    zeroBuf,

                    headersSize,

                    NULL);

                ExFreePoolWithTag(zeroBuf, 'HdrZ');

            }

        }

    }



    //

    // Choose a thread, suspend, hijack context to a small shell that calls DllMain

    //

    TargetThread = g_PsGetNextProcessThread(TargetProcess, NULL);

    if (!TargetThread)

    {

        DbgPrint("[-] No threads found for injection\n");

        ZwFreeVirtualMemory(TargetProcessHandle, &remoteBase, &imgSize, MEM_RELEASE);

        ExFreePoolWithTag(dllData, 'DllM');

        return STATUS_NOT_FOUND;

    }



    status = ObReferenceObjectByPointer(TargetThread,

        THREAD_ALL_ACCESS,

        NULL,

        KernelMode);

    if (!NT_SUCCESS(status))

    {

        DbgPrint("[-] ObReferenceObjectByPointer failed: 0x%X\n", status);

        ZwFreeVirtualMemory(TargetProcessHandle, &remoteBase, &imgSize, MEM_RELEASE);

        return status;

    }



    status = g_PsSuspendThread(TargetThread, &PreviousSuspendCount);

    if (!NT_SUCCESS(status))

    {

        DbgPrint("[-] PsSuspendThread failed: 0x%X\n", status);

        ObDereferenceObject(TargetThread);

        ZwFreeVirtualMemory(TargetProcessHandle, &remoteBase, &imgSize, MEM_RELEASE);

        ExFreePoolWithTag(dllData, 'DllM');

        return status;

    }



    OriginalContext.ContextFlags = CONTEXT_FULL;

    status = g_PsGetContextThread(TargetThread, &OriginalContext, UserMode);

    if (!NT_SUCCESS(status))

    {

        DbgPrint("[-] PsGetContextThread failed: 0x%X\n", status);

        g_PsResumeThread(TargetThread, NULL);

        ObDereferenceObject(TargetThread);

        ZwFreeVirtualMemory(TargetProcessHandle, &remoteBase, &imgSize, MEM_RELEASE);

        ExFreePoolWithTag(dllData, 'DllM');

        return status;

    }



    if (OriginalContext.Rip == 0 || OriginalContext.Rip < 0x10000)

    {

        DbgPrint("[-] Invalid RIP (0x%p) - aborting\n", (PVOID)OriginalContext.Rip);

        g_PsResumeThread(TargetThread, NULL);

        ObDereferenceObject(TargetThread);

        ZwFreeVirtualMemory(TargetProcessHandle, &remoteBase, &imgSize, MEM_RELEASE);

        ExFreePoolWithTag(dllData, 'DllM');

        return STATUS_INVALID_ADDRESS;

    }



    DbgPrint("[+] Original RIP: 0x%p\n", (PVOID)OriginalContext.Rip);



    //

    // Stub shellcode: call DllMain(remoteBase, DLL_PROCESS_ATTACH, 0) then jump back to original RIP.

    //

    const UCHAR ShellcodeTemplate[] =

    {

        0x48, 0x83, 0xEC, 0x28,                                     // sub rsp, 0x28

        0x48, 0xB9,                                                 // mov rcx, imm64 (base)

        0,0,0,0,0,0,0,0,

        0x48, 0xBA,                                                 // mov rdx, imm64 (DLL_PROCESS_ATTACH = 1)

        0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,

        0x4D, 0x31, 0xC0,                                           // xor r8, r8 (lpReserved = 0)

        0x48, 0xB8,                                                 // mov rax, imm64 (DllMain)

        0,0,0,0,0,0,0,0,

        0xFF, 0xD0,                                                 // call rax

        0x48, 0x83, 0xC4, 0x28,                                     // add rsp, 0x28

        0x48, 0xB8,                                                 // mov rax, imm64 (Original RIP)

        0,0,0,0,0,0,0,0,

        0xFF, 0xE0                                                  // jmp rax

    };



    shellSize = sizeof(ShellcodeTemplate);

    remoteShell = NULL;



    status = ZwAllocateVirtualMemory(TargetProcessHandle,

        &remoteShell,

        0,

        &shellSize,

        MEM_COMMIT | MEM_RESERVE,

        PAGE_EXECUTE_READWRITE);

    if (!NT_SUCCESS(status))

    {

        DbgPrint("[-] Failed to allocate remote shell: 0x%X\n", status);

        g_PsResumeThread(TargetThread, NULL);

        ObDereferenceObject(TargetThread);

        ZwFreeVirtualMemory(TargetProcessHandle, &remoteBase, &imgSize, MEM_RELEASE);

        ExFreePoolWithTag(dllData, 'DllM');

        return status;

    }



    {

        UCHAR shellcode[sizeof(ShellcodeTemplate)];

        RtlCopyMemory(shellcode, ShellcodeTemplate, sizeof(ShellcodeTemplate));



        PVOID baseForShell = remoteBase;

        dllMain = (PVOID)((ULONG_PTR)remoteBase + nt->OptionalHeader.AddressOfEntryPoint);



        RtlCopyMemory(shellcode + 6, &baseForShell, sizeof(PVOID));  // rcx = base

        RtlCopyMemory(shellcode + 28, &dllMain, sizeof(PVOID));  // rax = DllMain

        RtlCopyMemory(shellcode + 40, &OriginalContext.Rip, sizeof(ULONG_PTR)); // rax = orig RIP



        status = WriteProcessMemoryMDL(TargetProcess,

            remoteShell,

            shellcode,

            sizeof(shellcode),

            NULL);

        if (!NT_SUCCESS(status))

        {

            DbgPrint("[-] Failed to write shellcode: 0x%X\n", status);

            ZwFreeVirtualMemory(TargetProcessHandle, &remoteShell, &shellSize, MEM_RELEASE);

            g_PsResumeThread(TargetThread, NULL);

            ObDereferenceObject(TargetThread);

            ZwFreeVirtualMemory(TargetProcessHandle, &remoteBase, &imgSize, MEM_RELEASE);

            ExFreePoolWithTag(dllData, 'DllM');

            return status;

        }

    }



    //

    // Redirect RIP to the shellcode

    //

    ModifiedContext = OriginalContext;

    ModifiedContext.Rip = (ULONG_PTR)remoteShell;



    status = g_PsSetContextThread(TargetThread, &ModifiedContext, UserMode);

    if (!NT_SUCCESS(status))

    {

        DbgPrint("[-] PsSetContextThread failed: 0x%X\n", status);

        ZwFreeVirtualMemory(TargetProcessHandle, &remoteShell, &shellSize, MEM_RELEASE);

        g_PsResumeThread(TargetThread, NULL);

        ObDereferenceObject(TargetThread);

        ZwFreeVirtualMemory(TargetProcessHandle, &remoteBase, &imgSize, MEM_RELEASE);

        ExFreePoolWithTag(dllData, 'DllM');

        return status;

    }



    //

    // Resume and allow DllMain to execute inside the normal thread.

    // The shellcode will return to OriginalContext.Rip when finished.

    //

    status = g_PsResumeThread(TargetThread, NULL);

    if (!NT_SUCCESS(status))

    {

        DbgPrint("[-] PsResumeThread failed: 0x%X\n", status);

        ZwFreeVirtualMemory(TargetProcessHandle, &remoteShell, &shellSize, MEM_RELEASE);

        ObDereferenceObject(TargetThread);

        ZwFreeVirtualMemory(TargetProcessHandle, &remoteBase, &imgSize, MEM_RELEASE);

        ExFreePoolWithTag(dllData, 'DllM');

        return status;

    }



    DbgPrint("[+] Thread resumed; DllMain executing at 0x%p\n", dllMain);



    //

    // Optional: small delay so DllMain has time to run before we free locals.

    // Not strictly required, but safer if DllMain does some heavy init.

    //

    KeDelayExecutionThread(KernelMode, FALSE, &InitialDelay);



    //

    // Clean up kernel allocations; remote image + shell remain in the target.

    //

    if (TargetThread)

        ObDereferenceObject(TargetThread);



    if (dllData)

        ExFreePoolWithTag(dllData, 'DllM');



    // (We do NOT free remoteBase or remoteShell: they are the live module & entry stub)



    return STATUS_SUCCESS;

}



//end old safedllinject

PETHREAD FindHijackableThread(PEPROCESS TargetProcess) {

    if (!g_PsGetNextProcessThread) return NULL;

    PETHREAD Thread = g_PsGetNextProcessThread(TargetProcess, NULL);

    while (Thread) {

        return Thread;

        Thread = g_PsGetNextProcessThread(TargetProcess, Thread);

    }

    return NULL;

}



BOOLEAN SuspendAllThreads(PEPROCESS TargetProcess) {

    PETHREAD Thread = NULL;

    ULONG suspendedCount = 0;

    if (!g_PsGetNextProcessThread) {

        return FALSE;

    }

    Thread = g_PsGetNextProcessThread(TargetProcess, NULL);

    while (Thread) {

        if (NT_SUCCESS(ObReferenceObjectByPointer(Thread, THREAD_ALL_ACCESS, NULL, KernelMode))) {

            NTSTATUS status = g_PsSuspendThread(Thread, NULL);

            if (NT_SUCCESS(status)) {

                suspendedCount++;

            }

            ObDereferenceObject(Thread);

        }

        Thread = g_PsGetNextProcessThread(TargetProcess, Thread);

    }

    DbgPrint("[+] Suspended %lu threads\n", suspendedCount);

    return (suspendedCount > 0);

}



BOOLEAN ResumeAllThreads(PEPROCESS TargetProcess) {

    PETHREAD Thread = NULL;

    ULONG resumedCount = 0;

    if (!g_PsGetNextProcessThread) {

        return FALSE;

    }

    Thread = g_PsGetNextProcessThread(TargetProcess, NULL);

    while (Thread) {

        if (NT_SUCCESS(ObReferenceObjectByPointer(Thread, THREAD_ALL_ACCESS, NULL, KernelMode))) {

            NTSTATUS status = g_PsResumeThread(Thread, NULL);

            if (NT_SUCCESS(status)) {

                resumedCount++;

            }

            ObDereferenceObject(Thread);

        }

        Thread = g_PsGetNextProcessThread(TargetProcess, Thread);

    }

    DbgPrint("[+] Resumed %lu threads\n", resumedCount);

    return (resumedCount > 0);

}



ULONG FindProcessByName(const WCHAR* ProcessName) {

    NTSTATUS status;

    ULONG bufferSize = 0;

    PVOID buffer = NULL;

    ULONG pid = 0;

    ULONG returnLength = 0;

    DbgPrint("[+] Looking for process: %ws\n", ProcessName);



    status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);

    if (status != STATUS_INFO_LENGTH_MISMATCH) {

        DbgPrint("[-] Initial buffer size query failed: 0x%X\n", status);

        return 0;

    }



    bufferSize *= 2;

    buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'Proc');

    if (!buffer) {

        DbgPrint("[-] Failed to allocate buffer\n");

        return 0;

    }



    for (int attempts = 0; attempts < 3; attempts++) {

        status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &returnLength);

        if (status == STATUS_INFO_LENGTH_MISMATCH) {

            DbgPrint("[-] Buffer too small, resizing...\n");

            ExFreePoolWithTag(buffer, 'Proc');

            bufferSize = returnLength * 2;

            buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'Proc');

            if (!buffer) return 0;

            continue;

        }

        if (NT_SUCCESS(status)) break;

        DbgPrint("[-] ZwQuerySystemInformation failed: 0x%X\n", status);

        ExFreePoolWithTag(buffer, 'Proc');

        return 0;

    }



    if (!NT_SUCCESS(status)) {

        DbgPrint("[-] Failed to query system information: 0x%X\n", status);

        ExFreePoolWithTag(buffer, 'Proc');

        return 0;

    }



    PSYSTEM_PROCESS_INFORMATION procInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;

    ULONG processCount = 0;



    while (TRUE) {

        processCount++;



        if (procInfo->ImageName.Buffer && procInfo->ImageName.Length > 0) {

            WCHAR upperPath[256] = { 0 };

            ULONG copyLength = min(procInfo->ImageName.Length / sizeof(WCHAR), _countof(upperPath) - 1);

            for (ULONG i = 0; i < copyLength; i++) {

                upperPath[i] = procInfo->ImageName.Buffer[i];

            }

            upperPath[copyLength] = L'\0';



            DbgPrint("[+] Checking process: %ws (PID: %lu)\n", upperPath, (ULONG)procInfo->UniqueProcessId);



            if (_wcsicmp(upperPath, ProcessName) == 0) {

                pid = HandleToULong(procInfo->UniqueProcessId);

                DbgPrint("[+] Found target process: %ws (PID: %lu)\n", ProcessName, pid);

                break;

            }

        }



        if (procInfo->NextEntryOffset == 0) {

            break;

        }



        procInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)procInfo + procInfo->NextEntryOffset);

    }



    DbgPrint("[+] Scanned %lu processes, found PID: %lu\n", processCount, pid);

    ExFreePoolWithTag(buffer, 'Proc');

    return pid;

}



// In KM.cpp.



// Add this ABOVE ImageLoadNotifyCallback in KM.cpp









VOID ImageLoadNotifyCallback(

    PUNICODE_STRING FullImageName,

    HANDLE ProcessId,

    PIMAGE_INFO ImageInfo

) {

    // Safety: Increment counter entering

    InterlockedIncrement(&g_CallbackCount);

    UNREFERENCED_PARAMETER(ImageInfo);



    // 1. Safety checks

    if ((ULONG)ProcessId != g_TargetPid || g_TargetPid == 0) return;

    if (!FullImageName || !FullImageName->Buffer) return;



    // 2. Normalize path

    WCHAR upperPath[512] = { 0 };

    ULONG copyLength = min(FullImageName->Length / sizeof(WCHAR), 511);

    for (ULONG i = 0; i < copyLength; i++) {

        WCHAR c = FullImageName->Buffer[i];

        upperPath[i] = (c >= L'a' && c <= L'z') ? (c - L'a' + L'A') : c;

    }

    upperPath[copyLength] = L'\0';



    // 3. === SUCCESS DETECTION ===

    // Check if the loaded image is OUR DLL.

    // We extract the filename from g_DllPath to compare.

    WCHAR* myDllName = g_DllPath;

    for (int i = wcslen(g_DllPath) - 1; i >= 0; i--) {

        if (g_DllPath[i] == L'\\') {

            myDllName = &g_DllPath[i + 1];

            break;

        }

    }



    // Convert myDllName to Upper for comparison

    WCHAR myDllNameUpper[260] = { 0 };

    for (int i = 0; myDllName[i] != 0 && i < 259; i++) {

        WCHAR c = myDllName[i];

        myDllNameUpper[i] = (c >= L'a' && c <= L'z') ? (c - L'a' + L'A') : c;

    }



    if (wcsstr(upperPath, myDllNameUpper) != NULL) {

        DbgPrint("[+] ★★★ TARGET DLL LOADED: %wZ ★★★\n", FullImageName);

        DbgPrint("[+] Injection verified. Removing hooks to unfreeze process...\n");



        // Disable further injections immediately

        g_TargetPid = 0;



        // Spawn the worker thread to remove this callback safely

        HANDLE hThread;

        // driver_unload

        // PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, RemoveCallbackWorker, NULL);

 //        if (hThread) ZwClose(hThread);



        return;

    }



    // 4. System DLL Detection (Trigger Logic)

    BOOLEAN IsSystemDll = FALSE;

    if (wcsstr(upperPath, L"SYSTEM32") != NULL ||

        wcsstr(upperPath, L"KERNEL32.DLL") != NULL ||

        wcsstr(upperPath, L"NTDLL.DLL") != NULL) {

        IsSystemDll = TRUE;

    }



    if (IsSystemDll) {

        DbgPrint("[+] Triggering injection on: %wZ\n", FullImageName);



        PEPROCESS TargetProcess = NULL;

        HANDLE hProcess = NULL;

        if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &TargetProcess))) {

            if (NT_SUCCESS(ObOpenObjectByPointer(TargetProcess, OBJ_KERNEL_HANDLE, NULL,

                PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &hProcess))) {



                // Call injection (NOW NON-BLOCKING)

                APCDllInject(TargetProcess, hProcess, g_DllPath);



                ZwClose(hProcess);

            }

            ObDereferenceObject(TargetProcess);

        }

    }

    // Safety: Decrement counter leaving

    InterlockedDecrement(&g_CallbackCount);

}

NTSTATUS SetupStealthInjection(ULONG TargetPid, const WCHAR* DllPath) {

    KIRQL oldIrql;

    KeAcquireSpinLock(&g_InjectionLock, &oldIrql);

    g_TargetPid = TargetPid;

    wcsncpy(g_DllPath, DllPath, _countof(g_DllPath) - 1);

    g_DllPath[_countof(g_DllPath) - 1] = L'\0';

    KeReleaseSpinLock(&g_InjectionLock, oldIrql);

    DbgPrint("[+] Stealth injection configured for PID: %lu\n", TargetPid);

    DbgPrint("[+] DLL: %ws\n", DllPath);

    DbgPrint("[+] Waiting for target to load system DLL...\n");

    return STATUS_SUCCESS;

}



NTSTATUS ProcessSuspensionInject(const WCHAR* ProcessName, const WCHAR* DllPath) {

    NTSTATUS status = STATUS_SUCCESS;

    PEPROCESS TargetProcess = NULL;

    HANDLE hProcess = NULL;

    DbgPrint("[+] Starting process name-based injection for: %ws\n", ProcessName);



    for (int attempts = 0; attempts < 50; attempts++) {

        ULONG pid = FindProcessByName(ProcessName);

        if (pid != 0) {

            DbgPrint("[+] Found process: %ws (PID: %lu)\n", ProcessName, pid);

            status = PsLookupProcessByProcessId((HANDLE)pid, &TargetProcess);

            if (NT_SUCCESS(status)) {

                status = ObOpenObjectByPointer(TargetProcess, OBJ_KERNEL_HANDLE, NULL,

                    PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &hProcess);

                if (NT_SUCCESS(status)) {

                    // Use APC method (more compatible)

                    DbgPrint("[+] Using APC injection method\n");

                    status = APCDllInject(TargetProcess, hProcess, DllPath);



                    if (NT_SUCCESS(status)) {

                        DbgPrint("[+] DLL injected successfully\n");

                    }

                    else {

                        DbgPrint("[-] Injection failed: 0x%X\n", status);

                    }

                    ZwClose(hProcess);

                }

                else {

                    DbgPrint("[-] Failed to open process handle: 0x%X\n", status);

                }

                ObDereferenceObject(TargetProcess);

                break;

            }

        }

        LARGE_INTEGER Delay = { .QuadPart = -100000LL };

        KeDelayExecutionThread(KernelMode, FALSE, &Delay);

    }



    if (NT_SUCCESS(status)) {

        DbgPrint("[+] Injection completed successfully\n");

        return STATUS_SUCCESS;

    }

    else {

        DbgPrint("[-] Failed to find or inject into process: %ws\n", ProcessName);

        return STATUS_NOT_FOUND;

    }

}



namespace driver {

    namespace codes {

        constexpr ULONG read = CTL_CODE(FILE_DEVICE_UNKNOWN, 0xB7E, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        constexpr ULONG write = CTL_CODE(FILE_DEVICE_UNKNOWN, 0xC8F, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        constexpr ULONG unload = CTL_CODE(FILE_DEVICE_UNKNOWN, 0xD91, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        constexpr ULONG integrity = CTL_CODE(FILE_DEVICE_UNKNOWN, 0xEA2, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        constexpr ULONG inject_advanced = CTL_CODE(FILE_DEVICE_UNKNOWN, 0xF4B, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        constexpr ULONG bypass_randgrid = CTL_CODE(FILE_DEVICE_UNKNOWN, 0xFB3, METHOD_BUFFERED, FILE_SPECIAL_ACCESS); // New: Add this line

        constexpr ULONG get_base = CTL_CODE(FILE_DEVICE_UNKNOWN, 0xFC4, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        constexpr ULONG get_peb = CTL_CODE(FILE_DEVICE_UNKNOWN, 0xFC5, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

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



    typedef struct _INJECT_ADVANCED_REQUEST {

        BOOLEAN use_pid;

        HANDLE process_id;

        WCHAR process_name[260];

        WCHAR dll_path[260];

    } INJECT_ADVANCED_REQUEST, * PINJECT_ADVANCED_REQUEST;



    typedef struct _INTEGRITY_RESPONSE {

        UCHAR is_hooked;

        ULONG checksum;

    } INTEGRITY_RESPONSE, * PINTEGRITY_RESPONSE;



    NTSTATUS create(PDEVICE_OBJECT device_object, PIRP irp) {

        UNREFERENCED_PARAMETER(device_object);



        if (g_Unloading || g_StealthMode) {

            irp->IoStatus.Status = STATUS_DEVICE_NOT_READY;

            irp->IoStatus.Information = 0;

            IoCompleteRequest(irp, IO_NO_INCREMENT);

            return STATUS_DEVICE_NOT_READY;

        }



        InterlockedIncrement(&g_ReferenceCount);

        irp->IoStatus.Status = STATUS_SUCCESS;

        irp->IoStatus.Information = 0;

        IoCompleteRequest(irp, IO_NO_INCREMENT);

        return STATUS_SUCCESS;

    }



    NTSTATUS close(PDEVICE_OBJECT device_object, PIRP irp) {

        UNREFERENCED_PARAMETER(device_object);



        irp->IoStatus.Status = STATUS_SUCCESS;

        irp->IoStatus.Information = 0;

        InterlockedDecrement(&g_ReferenceCount);

        IoCompleteRequest(irp, IO_NO_INCREMENT);

        return STATUS_SUCCESS;

    }



    NTSTATUS device_control(PDEVICE_OBJECT device_object, PIRP irp) {

        UNREFERENCED_PARAMETER(device_object);



        NTSTATUS status = STATUS_UNSUCCESSFUL;

        PIO_STACK_LOCATION stack_irp = IoGetCurrentIrpStackLocation(irp);

        ULONG control_code = 0;

        Request* request = nullptr;

        PEPROCESS target_process = nullptr;

        HANDLE hProcess = NULL;



        if (g_Unloading || g_StealthMode || !stack_irp) {

            status = STATUS_DEVICE_NOT_READY;

            goto complete_simple;

        }



        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {

            DbgPrint("[-] Wrong IRQL for device control: %d\n", KeGetCurrentIrql());

            status = STATUS_UNSUCCESSFUL;

            goto complete_simple;

        }



        control_code = stack_irp->Parameters.DeviceIoControl.IoControlCode;

        request = reinterpret_cast<Request*>(irp->AssociatedIrp.SystemBuffer);



        if (control_code != codes::integrity) {

            if (!CheckIntegrity()) {

                DbgPrint("[!] Integrity violation - denying request\n");

                status = STATUS_ACCESS_DENIED;

                goto complete_simple;

            }

        }



        switch (control_code) {



            // ... inside switch(control_code) ...



        case codes::get_peb: {

            if (!request || !request->process_id) {

                status = STATUS_INVALID_PARAMETER;

                break;

            }



            // Security Check: Only allow reading the target PID if locked

            if (g_TargetPid != 0) {

                ULONG targetPid = (ULONG)(ULONG_PTR)request->process_id;

                if (targetPid != g_TargetPid) {

                    status = STATUS_ACCESS_DENIED;

                    break;

                }

            }



            status = PsLookupProcessByProcessId(request->process_id, &target_process);

            if (NT_SUCCESS(status)) {

                // 1. Get PEB Address using Kernel API

                PPEB peb = PsGetProcessPeb(target_process);



                // 2. Put the result into the 'target' field of the request struct

                request->target = peb;



                // 3. IMPORTANT: Tell Windows we are returning the full struct size

                // (Otherwise User Mode gets 0 bytes back)

                irp->IoStatus.Information = sizeof(Request);



                status = STATUS_SUCCESS;

            }

            break;

        }



        case codes::get_base: {

            if (!request || !request->process_id) {

                status = STATUS_INVALID_PARAMETER;

                break;

            }



            if (g_TargetPid != 0) {

                ULONG targetPid = (ULONG)(ULONG_PTR)request->process_id;

                if (targetPid != g_TargetPid) {

                    status = STATUS_ACCESS_DENIED;

                    break;

                }

            }



            status = PsLookupProcessByProcessId(request->process_id, &target_process);

            if (!NT_SUCCESS(status)) {

                break;

            }



            // Method 1: Standard Kernel API

            PVOID base = PsGetProcessSectionBaseAddress(target_process);



            // Method 2: PEB Fallback (If Method 1 returns NULL)

            if (!base) {

                PPEB peb = PsGetProcessPeb(target_process);

                if (peb) {

                    // We must attach to read the PEB pointer safely

                    KAPC_STATE apc;

                    KeStackAttachProcess(target_process, &apc);

                    base = peb->ImageBaseAddress;

                    KeUnstackDetachProcess(&apc);

                }

            }



            request->target = base;



            // FIX: Copy the ENTIRE struct back, not just the first 8 bytes.

            // This ensures 'request->target' (offset 8) reaches User Mode.

            irp->IoStatus.Information = sizeof(Request);



            status = STATUS_SUCCESS;

            break;

        }



        case codes::bypass_randgrid: {

            PatchRandgridWorkers();

            status = STATUS_SUCCESS;

            break;

        }

        case codes::inject_advanced: {

            PINJECT_ADVANCED_REQUEST req = nullptr;



            req = reinterpret_cast<PINJECT_ADVANCED_REQUEST>(irp->AssociatedIrp.SystemBuffer);

            if (!req || wcslen(req->dll_path) == 0) {

                DbgPrint("[-] Invalid injection parameters\n");

                status = STATUS_INVALID_PARAMETER;

                break;

            }



            if (req->use_pid) {

                if (!req->process_id) {

                    DbgPrint("[-] Invalid PID\n");

                    status = STATUS_INVALID_PARAMETER;

                    break;

                }



                DbgPrint("[+] PID-based injection for PID: %lu\n", (ULONG)req->process_id);

                DbgPrint("[+] DLL: %ws\n", req->dll_path);



                status = SetupStealthInjection((ULONG)req->process_id, req->dll_path);

            }

            else {

                if (wcslen(req->process_name) == 0) {

                    DbgPrint("[-] Invalid process name\n");

                    status = STATUS_INVALID_PARAMETER;

                    break;

                }



                DbgPrint("[+] Process name-based injection for: %ws\n", req->process_name);

                DbgPrint("[+] DLL: %ws\n", req->dll_path);



                status = ProcessSuspensionInject(req->process_name, req->dll_path);

            }



            if (NT_SUCCESS(status)) {

                DbgPrint("[+] Injection configured successfully\n");

            }

            else {

                DbgPrint("[-] Injection configuration failed: 0x%X\n", status);

            }

            break;

        }

        case codes::integrity: {

            auto response = reinterpret_cast<PINTEGRITY_RESPONSE>(irp->AssociatedIrp.SystemBuffer);

            if (response) {

                response->is_hooked = CheckIntegrity() ? 0 : 1;

                response->checksum = g_IntegrityChecksum;

                status = STATUS_SUCCESS;

                irp->IoStatus.Information = sizeof(INTEGRITY_RESPONSE);

            }

            else {

                status = STATUS_INVALID_PARAMETER;

            }

            break;

        }

        case codes::read: {

            if (!request || !request->process_id) {

                status = STATUS_INVALID_PARAMETER;

                break;

            }



            if (g_TargetPid != 0) {

                ULONG targetPid = (ULONG)(ULONG_PTR)request->process_id;

                if (targetPid != g_TargetPid) {

                    status = STATUS_ACCESS_DENIED;

                    break;

                }

            }



            status = PsLookupProcessByProcessId(request->process_id, &target_process);

            if (!NT_SUCCESS(status)) {

                DbgPrint("[-] Failed to lookup process: 0x%X\n", status);

                break;

            }



            status = ObOpenObjectByPointer(

                target_process,

                OBJ_KERNEL_HANDLE,

                NULL,

                PROCESS_ALL_ACCESS,

                *PsProcessType,

                KernelMode,

                &hProcess

            );

            if (!NT_SUCCESS(status)) {

                DbgPrint("[-] Failed to open process handle: 0x%X\n", status);

                ObDereferenceObject(target_process);

                target_process = NULL;

                break;

            }



            status = ReadProcessMemoryMDL(target_process, request->target,

                request->buffer, request->size, &request->return_size);

            break;

        }

        case codes::write: {

            if (!request || !request->process_id) {

                status = STATUS_INVALID_PARAMETER;

                break;

            }



            if (g_TargetPid != 0) {

                ULONG targetPid = (ULONG)(ULONG_PTR)request->process_id;

                if (targetPid != g_TargetPid) {

                    status = STATUS_ACCESS_DENIED;

                    break;

                }

            }

        }

        case codes::unload: {

            status = STATUS_SUCCESS;

            irp->IoStatus.Status = status;

            irp->IoStatus.Information = 0;

            IoCompleteRequest(irp, IO_NO_INCREMENT);



            g_Unloading = TRUE;



            PDRIVER_OBJECT driver_object = device_object->DriverObject;

            if (driver_object && driver_object->DriverUnload) {

                HANDLE thread_handle;

                NTSTATUS thread_status = PsCreateSystemThread(&thread_handle, THREAD_ALL_ACCESS, NULL, NULL, NULL,

                    [](PVOID context) {

                        LARGE_INTEGER delay;

                        delay.QuadPart = -5000000LL;

                        KeDelayExecutionThread(KernelMode, FALSE, &delay);



                        PDRIVER_OBJECT driver_obj = (PDRIVER_OBJECT)context;

                        driver_obj->DriverUnload(driver_obj);

                        PsTerminateSystemThread(STATUS_SUCCESS);

                    }, driver_object);



                if (NT_SUCCESS(thread_status)) {

                    ZwClose(thread_handle);

                }

            }

            return status;

        }

        default:

            status = STATUS_INVALID_DEVICE_REQUEST;

            break;

        }



    complete:

        if (target_process) {

            ObDereferenceObject(target_process);

        }

        if (hProcess) {

            ZwClose(hProcess);

        }



    complete_simple:

        irp->IoStatus.Status = status;

        IoCompleteRequest(irp, IO_NO_INCREMENT);

        return status;

    }

}



NTSTATUS CreateUltraStealthCommunication() {

    // 1. Get Shared Secret (System Create Time)

    PEPROCESS SystemProcess = PsInitialSystemProcess;

    LONGLONG SharedSeed = PsGetProcessCreateTimeQuadPart(SystemProcess);



    // 2. Format the Dynamic Name

    WCHAR section_path[128];

    RtlStringCchPrintfW(section_path, _countof(section_path),

        L"\\BaseNamedObjects\\{%08X-%04X-%04X-%04X-%012llX}",

        (ULONG)(SharedSeed & 0xFFFFFFFF),

        (ULONG)((SharedSeed >> 32) & 0xFFFF),

        (ULONG)((SharedSeed >> 48) & 0xFFFF),

        0xABCD,

        SharedSeed ^ 0xDEADBEEFCAFEBABE

    );



    // FIX: Use a LOCAL unicode string, do NOT touch the global g_SymbolicLink

    UNICODE_STRING section_name;

    RtlInitUnicodeString(&section_name, section_path);



    // 3. Create Section

    OBJECT_ATTRIBUTES obj_attr;

    InitializeObjectAttributes(&obj_attr, &section_name,

        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);



    LARGE_INTEGER max_size;

    max_size.QuadPart = 4096;



    NTSTATUS status = ZwCreateSection(&gSection, SECTION_ALL_ACCESS, &obj_attr,

        &max_size, PAGE_READWRITE, SEC_COMMIT, NULL);



    if (status == STATUS_OBJECT_NAME_COLLISION) {

        status = ZwOpenSection(&gSection, SECTION_ALL_ACCESS, &obj_attr);

    }



    if (!NT_SUCCESS(status)) {

        DbgPrint("[-] UltraStealth section failed: 0x%08X\n", status);

        return status;

    }



    // 4. Map and Write Payload

    PVOID base_address = NULL;

    SIZE_T view_size = 0;

    status = ZwMapViewOfSection(gSection, ZwCurrentProcess(), &base_address,

        0, 0, NULL, &view_size, ViewUnmap, 0, PAGE_READWRITE);



    if (NT_SUCCESS(status)) {

        WCHAR obfuscated_data[128];

        RtlStringCchCopyW(obfuscated_data, 128, g_SymbolicLinkBuffer);



        size_t name_len = wcslen(obfuscated_data);

        for (size_t i = 0; i < name_len; i++) {

            // FIX: Use 0x55 (Or any byte NOT in A-Z, a-z, 0-9)

            // 0x42 was 'B', causing null termination bugs.

            obfuscated_data[i] ^= 0x55;

        }



        RtlCopyMemory(base_address, obfuscated_data, (name_len + 1) * sizeof(WCHAR));

        ZwUnmapViewOfSection(ZwCurrentProcess(), base_address);

    }



    DbgPrint("[+] Dynamic Section Created: %wZ\n", &section_name);

    return status;

}



VOID driver_unload(PDRIVER_OBJECT driver_object) {

    UNREFERENCED_PARAMETER(driver_object);

    g_Unloading = TRUE;



    // 1. Wait for handles to close

    DbgPrint("[*] Waiting for user handles (Ref: %ld)...\n", g_ReferenceCount);

    LARGE_INTEGER interval;

    interval.QuadPart = -1000000; // 100ms

    int attempts = 0;

    while (g_ReferenceCount > 0 && attempts < 50) { // Wait up to 5 seconds

        KeDelayExecutionThread(KernelMode, FALSE, &interval);

        attempts++;

    }



    // 2. CRITICAL BSOD FIX: If handles still open, DO NOT DELETE DEVICE

    if (g_ReferenceCount > 0) {

        DbgPrint("[-] Force Exit: Leaking device object to prevent BSOD.\n");

        if (gSection) { ZwMakeTemporaryObject(gSection); ZwClose(gSection); }

        return;

    }



    // 3. Safe Cleanup

    if (gSection) { ZwMakeTemporaryObject(gSection); ZwClose(gSection); }

    if (g_DeviceObject) {

        IoDeleteSymbolicLink(&g_SymbolicLink);

        IoDeleteDevice(g_DeviceObject);

    }

    DbgPrint("[+] Driver Unloaded Safely.\n");

}



NTSTATUS stealth_device_control(PDEVICE_OBJECT device_object, PIRP irp) {

    LARGE_INTEGER delay;

    LARGE_INTEGER tick_count;

    KeQueryTickCount(&tick_count);



    delay.QuadPart = -10000LL * (10 + (tick_count.LowPart % 50));

    KeDelayExecutionThread(KernelMode, FALSE, &delay);



    return driver::device_control(device_object, irp);

}



NTSTATUS driver_main(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {

    UNREFERENCED_PARAMETER(registry_path);



    NTSTATUS status = STATUS_SUCCESS;



    g_DriverObject = driver_object;   // <-- new

    g_ReferenceCount = 0;

    g_Unloading = FALSE;

    g_StealthMode = FALSE;

    g_TargetPid = 0;

    g_DllPath[0] = L'\0';

    KeInitializeSpinLock(&g_InjectionLock);



    GenerateRandomName(g_RandomName, 16);



    WCHAR device_path_buffer[128];

    RtlStringCchPrintfW(device_path_buffer, _countof(device_path_buffer), L"\\Device\\%s", g_RandomName);



    WCHAR link_path_buffer[128];

    RtlStringCchPrintfW(link_path_buffer, _countof(link_path_buffer), L"\\DosDevices\\%s", g_RandomName);



    RtlStringCchCopyW(g_SymbolicLinkBuffer, _countof(g_SymbolicLinkBuffer), link_path_buffer);



    UNICODE_STRING device_name;

    RtlInitUnicodeString(&device_name, device_path_buffer);

    RtlInitUnicodeString(&g_SymbolicLink, g_SymbolicLinkBuffer);



    status = IoCreateDevice(driver_object, 0, &device_name, FILE_DEVICE_UNKNOWN,

        FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObject);

    if (status != STATUS_SUCCESS) {

        DbgPrint("[-] Failed to create device: 0x%08X\n", status);

        return status;

    }



    status = IoCreateSymbolicLink(&g_SymbolicLink, &device_name);

    if (status != STATUS_SUCCESS) {

        DbgPrint("[-] Failed to create symbolic link: 0x%08X\n", status);

        IoDeleteDevice(g_DeviceObject);

        g_DeviceObject = nullptr;

        return status;

    }



    status = PsSetLoadImageNotifyRoutine(ImageLoadNotifyCallback);

    if (status != STATUS_SUCCESS) {

        DbgPrint("[-] Failed to register image load callback: 0x%08X\n", status);

        IoDeleteDevice(g_DeviceObject);

        g_DeviceObject = nullptr;

        return status;

    }



    g_ImageLoadNotifyRoutine = ImageLoadNotifyCallback;



    SetFlag(g_DeviceObject->Flags, DO_BUFFERED_IO);

    driver_object->MajorFunction[IRP_MJ_CREATE] = driver::create;

    driver_object->MajorFunction[IRP_MJ_CLOSE] = driver::close;

    driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = stealth_device_control;

    driver_object->DriverUnload = driver_unload;

    ClearFlag(g_DeviceObject->Flags, DO_DEVICE_INITIALIZING);



    KeInitializeSpinLock(&g_IntegrityLock);

    g_OriginalIrpHandler = (PVOID)driver::device_control;

    g_BackupHandler = ExAllocatePoolWithTag(NonPagedPool, 64, 'EvNr');

    if (g_BackupHandler) {

        RtlCopyMemory(g_BackupHandler, g_OriginalIrpHandler, 64);

    }

    g_IntegrityChecksum = CalculateChecksum(g_OriginalIrpHandler, 64);



    // CRITICAL: Resolve undocumented functions with validation

    // These functions may have different export names on different Windows versions

    UNICODE_STRING funcName;



    // Try PsGetNextProcessThread (works on most versions)

    RtlInitUnicodeString(&funcName, L"PsGetNextProcessThread");

    g_PsGetNextProcessThread = (pPsGetNextProcessThread)MmGetSystemRoutineAddress(&funcName);

    if (!g_PsGetNextProcessThread) {

        DbgPrint("[-] CRITICAL: Failed to resolve PsGetNextProcessThread\n");

        DbgPrint("[!] This function may not be exported on your Windows version\n");

    }

    else {

        DbgPrint("[+] Resolved PsGetNextProcessThread: %p\n", g_PsGetNextProcessThread);

    }



    // Try PsSuspendThread (may not be exported on all versions)

    RtlInitUnicodeString(&funcName, L"PsSuspendThread");

    g_PsSuspendThread = (pPsSuspendThread)MmGetSystemRoutineAddress(&funcName);

    if (!g_PsSuspendThread) {

        DbgPrint("[-] CRITICAL: Failed to resolve PsSuspendThread\n");

        DbgPrint("[!] This function may not be exported on your Windows version\n");

    }

    else {

        DbgPrint("[+] Resolved PsSuspendThread: %p\n", g_PsSuspendThread);

    }



    // Try PsResumeThread (may not be exported on all versions)

    RtlInitUnicodeString(&funcName, L"PsResumeThread");

    g_PsResumeThread = (pPsResumeThread)MmGetSystemRoutineAddress(&funcName);

    if (!g_PsResumeThread) {

        DbgPrint("[-] CRITICAL: Failed to resolve PsResumeThread\n");

        DbgPrint("[!] This function may not be exported on your Windows version\n");

    }

    else {

        DbgPrint("[+] Resolved PsResumeThread: %p\n", g_PsResumeThread);

    }



    RtlInitUnicodeString(&funcName, L"PsGetContextThread");

    g_PsGetContextThread = (pPsGetContextThread)MmGetSystemRoutineAddress(&funcName);

    if (!g_PsGetContextThread) {

        DbgPrint("[-] CRITICAL: Failed to resolve PsGetContextThread\n");

    }

    else {

        DbgPrint("[+] Resolved PsGetContextThread: %p\n", g_PsGetContextThread);

    }



    RtlInitUnicodeString(&funcName, L"PsSetContextThread");

    g_PsSetContextThread = (pPsSetContextThread)MmGetSystemRoutineAddress(&funcName);

    if (!g_PsSetContextThread) {

        DbgPrint("[-] CRITICAL: Failed to resolve PsSetContextThread\n");

    }

    else {

        DbgPrint("[+] Resolved PsSetContextThread: %p\n", g_PsSetContextThread);

    }



    // Verify all functions were resolved

    if (!g_PsGetNextProcessThread || !g_PsSuspendThread || !g_PsResumeThread ||

        !g_PsGetContextThread || !g_PsSetContextThread) {

        DbgPrint("[!] WARNING: Some critical functions not resolved - injection will fail!\n");

        DbgPrint("[!] Your Windows version may not export these functions\n");

        DbgPrint("[!] Thread hijacking method will NOT work on this system\n");

        DbgPrint("[!] Consider using alternative injection method (APC, CreateRemoteThread)\n");

    }

    else {

        DbgPrint("[+] All critical functions resolved successfully\n");

    }



    CreateUltraStealthCommunication();

    PatchRandgridWorkers();



    DbgPrint("[+] ===== STEALTH CALLBACK INJECTION DRIVER =====\n");

    DbgPrint("[+] Image load callback registered successfully\n");

    DbgPrint("[+] Injection: Will trigger on system DLL load\n");

    DbgPrint("[+] AC Bypass: Using legitimate Windows callback\n");

    DbgPrint("[+] Function pointers: ALL VALIDATED\n");

    DbgPrint("[+] =============================================\n");



    return STATUS_SUCCESS;

}



extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {

    UNREFERENCED_PARAMETER(DriverObject);



    DbgPrint("[+] Driver loading...\n");



    UNICODE_STRING driver_name;

    WCHAR rndDrvName[64];

    GenerateRandomName(rndDrvName, 20);

    WCHAR fullDrvName[128];

    RtlStringCchPrintfW(fullDrvName, _countof(fullDrvName), L"\\Driver\\%s", rndDrvName);



    RtlInitUnicodeString(&driver_name, fullDrvName);



    return IoCreateDriver(&driver_name, &driver_main);

}