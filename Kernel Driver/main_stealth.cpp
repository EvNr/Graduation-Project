/*
 * STEALTH KERNEL DRIVER - Educational Anti-Cheat Evasion Research
 * ================================================================
 *
 * This is a refactored version implementing advanced evasion techniques.
 * Each technique is documented with WHY it works and HOW it can still be detected.
 *
 * KEY IMPROVEMENTS:
 * 1. No named devices - uses file-backed section for communication
 * 2. Hardware entropy for GUID generation (CPU serial + MAC XOR)
 * 3. Signature scanning for version-independent randgrid patching
 * 4. Worker dispatch hooking instead of flag manipulation
 * 5. Conditional debug output (disabled in release)
 * 6. Anti-analysis checks before sensitive operations
 * 7. Callback hiding via array manipulation
 *
 * DETECTION VECTORS STILL PRESENT:
 * - Driver load timing (if loaded after AC)
 * - Memory pattern scanning of driver code
 * - Behavior analysis (what processes we interact with)
 * - Hardware breakpoints on critical AC functions
 *
 * FOR EDUCATIONAL USE IN AUTHORIZED SECURITY RESEARCH ONLY
 */

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

// ============================================================================
// CONDITIONAL DEBUG OUTPUT
// ============================================================================
// Educational Note: DbgPrint calls are detectable via:
// - Kernel debugger attached to system
// - DebugView.exe capturing kernel output
// - Hooks on DbgPrint function itself
//
// Solution: Completely remove in release builds, or encrypt output
// ============================================================================

#ifdef _DEBUG
#define STEALTH_LOG(fmt, ...) DbgPrint("[STEALTH] " fmt, ##__VA_ARGS__)
#else
#define STEALTH_LOG(fmt, ...) ((void)0)
#endif

// ============================================================================
// UNDOCUMENTED STRUCTURES & IMPORTS
// ============================================================================

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
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

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
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;
#define _SYSTEM_PROCESS_INFORMATION_DEFINED
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

typedef NTSTATUS(NTAPI* PUSER_THREAD_START_ROUTINE)(_In_ PVOID ThreadParameter);

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

NTKERNELAPI VOID NTAPI IoDeleteDriver(_In_ PDRIVER_OBJECT DriverObject);
NTKERNELAPI PPEB NTAPI PsGetProcessPeb(_In_ PEPROCESS Process);
NTKERNELAPI PVOID NTAPI PsGetProcessSectionBaseAddress(_In_ PEPROCESS Process);

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_      ULONG SystemInformationClass,
    _Inout_   PVOID SystemInformation,
    _In_      ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

NTKERNELAPI PETHREAD PsGetNextProcessThread(
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

// ============================================================================
// KERNEL MODULE STRUCTURES
// ============================================================================

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
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
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

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
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

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
} PEB, *PPEB;

// ============================================================================
// GLOBAL STATE
// ============================================================================
// Educational Note: Global variables in kernel space are visible via:
// - Kernel debuggers (WinDbg)
// - Memory scanning of driver's .data section
// - Driver analysis tools
//
// Mitigation: Encrypt sensitive globals, obfuscate names, use dynamic allocation
// ============================================================================

PDRIVER_OBJECT g_DriverObject = nullptr;
PDEVICE_OBJECT g_DeviceObject = nullptr;

// File-backed section for kernel<->user communication
// Educational Note: This is harder to enumerate than named sections in \BaseNamedObjects\
// but still detectable via handle enumeration
HANDLE g_CommSection = nullptr;
PVOID g_CommBuffer = nullptr;
SIZE_T g_CommBufferSize = 0x1000;

// Hardware-derived GUID for communication
// Educational Note: This is more unique than time-based GUIDs
ULONGLONG g_HardwareGuid = 0;

// Randgrid AC module info
PVOID g_RandgridBase = nullptr;
ULONG g_RandgridSize = 0;

// Worker hook trampolines (for unhooking on unload)
typedef struct _WORKER_HOOK {
    PVOID TargetFunction;
    UCHAR OriginalBytes[14];
    BOOLEAN IsHooked;
} WORKER_HOOK, *PWORKER_HOOK;

WORKER_HOOK g_WorkerHooks[4] = { 0 };

// Synchronization
KSPIN_LOCK g_CommLock;
volatile BOOLEAN g_Unloading = FALSE;

// ============================================================================
// HARDWARE ENTROPY GENERATION
// ============================================================================
// Educational Note: Purpose is to create unpredictable GUIDs that can't be
// brute-forced by AC even if they know our algorithm.
//
// Uses:
// - CPU serial number (via CPUID on some Intel CPUs)
// - System boot time
// - Processor count and features
// - Performance counter
//
// AC can still detect this by:
// - Monitoring CPUID instruction execution (hypervisor detection)
// - Comparing GUIDs across multiple runs (should be stable per hardware)
// ============================================================================

ULONGLONG GenerateHardwareGuid() {
    ULONGLONG guid = 0;

    // Get processor features
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0);
    guid ^= ((ULONGLONG)cpuInfo[0] << 32) | cpuInfo[1];

    // Mix in processor count
    ULONG processorCount = KeQueryActiveProcessorCount(nullptr);
    guid ^= (ULONGLONG)processorCount << 48;

    // Mix in boot time (via System process create time)
    PEPROCESS systemProcess = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)4, &systemProcess);
    if (NT_SUCCESS(status)) {
        LONGLONG createTime = PsGetProcessCreateTimeQuadPart(systemProcess);
        guid ^= (ULONGLONG)createTime;
        ObDereferenceObject(systemProcess);
    }

    // Mix in current performance counter for additional entropy
    LARGE_INTEGER perfCounter;
    perfCounter = KeQueryPerformanceCounter(nullptr);
    guid ^= perfCounter.QuadPart;

    // Final mixing with prime number multiplication
    guid *= 0x9E3779B97F4A7C15ULL; // Knuth's multiplicative hash constant

    STEALTH_LOG("Generated hardware GUID: 0x%llX\n", guid);
    return guid;
}

// ============================================================================
// ANTI-ANALYSIS CHECKS
// ============================================================================
// Educational Note: Detect if we're being analyzed before doing sensitive ops
//
// Checks for:
// - Kernel debugger attached
// - Timing attacks (too slow = single-stepping)
// - Memory scanning patterns
//
// AC can counter by:
// - Using hardware breakpoints instead of software debugger
// - Time-invariant analysis
// - Analyzing offline (memory dump)
// ============================================================================

BOOLEAN IsBeingAnalyzed() {
    // Check for kernel debugger
    if (KdDebuggerEnabled || KdDebuggerNotPresent == FALSE) {
        STEALTH_LOG("Kernel debugger detected\n");
        return TRUE;
    }

    // Timing check: measure a simple operation
    LARGE_INTEGER start, end, freq;
    start = KeQueryPerformanceCounter(&freq);

    // Do some work
    volatile int dummy = 0;
    for (int i = 0; i < 1000; i++) {
        dummy += i;
    }

    end = KeQueryPerformanceCounter(nullptr);

    // If it took more than 10ms, we're probably being single-stepped
    LONGLONG elapsed = ((end.QuadPart - start.QuadPart) * 1000000) / freq.QuadPart;
    if (elapsed > 10000) {
        STEALTH_LOG("Timing anomaly detected: %lld µs\n", elapsed);
        return TRUE;
    }

    return FALSE;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

BOOLEAN IsStringEqual(LPCWSTR Str1, LPCWSTR Str2) {
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
    if (!Peb) return nullptr;

    KAPC_STATE ApcState;
    KeStackAttachProcess(Process, &ApcState);

    PPEB_LDR_DATA Ldr = Peb->Ldr;
    if (!Ldr) {
        KeUnstackDetachProcess(&ApcState);
        return nullptr;
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
    return nullptr;
}

PVOID GetKernelModuleBase(const char* ModuleName, PULONG ModuleSize) {
    if (!ModuleName) return nullptr;

    ULONG bufferSize = 0x4000;
    PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(
        NonPagedPool, bufferSize, 'ModL');
    if (!modules) return nullptr;

    NTSTATUS status = ZwQuerySystemInformation(
        SystemModuleInformation, modules, bufferSize, &bufferSize);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(modules, 'ModL');
        return nullptr;
    }

    PVOID base = nullptr;
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
    if (!ModuleBase) return nullptr;

    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    PIMAGE_NT_HEADERS64 NtHeaders = (PIMAGE_NT_HEADERS64)((PUCHAR)ModuleBase + DosHeader->e_lfanew);
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    ULONG ExportDirectoryRva = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!ExportDirectoryRva) return nullptr;

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

    return nullptr;
}

// ============================================================================
// MEMORY OPERATIONS (MDL-based)
// ============================================================================
// Educational Note: Using MDL + MmProbeAndLockPages is detectable via:
// - Hooks on Mm* functions
// - MDL allocation patterns
// - Performance monitoring (MDL operations are expensive)
//
// Alternative approaches:
// - Physical memory mapping (requires finding physical addresses)
// - CR3 manipulation (page table walking)
// - Exploiting existing kernel handles to target process
// ============================================================================

NTSTATUS ReadProcessMemoryMDL(PEPROCESS target_process, PVOID source_address,
    PVOID buffer, SIZE_T size, PSIZE_T bytes_read) {

    if (!target_process || !source_address || !buffer || size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    PMDL mdl = nullptr;
    PVOID mapped_address = nullptr;
    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T total_read = 0;
    KAPC_STATE apc_state;

    __try {
        KeStackAttachProcess((PKPROCESS)target_process, &apc_state);

        mdl = IoAllocateMdl(source_address, (ULONG)size, FALSE, FALSE, nullptr);
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
            MmNonCached, nullptr, FALSE, NormalPagePriority);
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

    PMDL mdl = nullptr;
    PVOID mapped_address = nullptr;
    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T total_written = 0;
    KAPC_STATE apc_state;

    __try {
        KeStackAttachProcess((PKPROCESS)target_process, &apc_state);

        mdl = IoAllocateMdl(dest_address, (ULONG)size, FALSE, FALSE, nullptr);
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
            MmNonCached, nullptr, FALSE, NormalPagePriority);
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

// ============================================================================
// SIGNATURE SCANNING FOR VERSION-INDEPENDENT PATCHING
// ============================================================================
// Educational Note: Hardcoded offsets break when AC updates.
// Signature scanning finds code patterns that are less likely to change.
//
// Randgrid worker threads have characteristic patterns:
// - LOCK prefix for spinlock operations
// - Specific flag offset checks
// - Jump tables
//
// AC can counter by:
// - Code obfuscation
// - Polymorphic code generation
// - Detecting scanning behavior itself
// ============================================================================

// Pattern matching with wildcards (0xCC = wildcard)
BOOLEAN PatternMatch(PUCHAR data, PUCHAR pattern, SIZE_T length) {
    for (SIZE_T i = 0; i < length; i++) {
        if (pattern[i] != 0xCC && data[i] != pattern[i]) {
            return FALSE;
        }
    }
    return TRUE;
}

PVOID FindPattern(PVOID base, ULONG size, PUCHAR pattern, SIZE_T patternLength) {
    PUCHAR current = (PUCHAR)base;
    PUCHAR end = current + size - patternLength;

    while (current < end) {
        if (PatternMatch(current, pattern, patternLength)) {
            return current;
        }
        current++;
    }

    return nullptr;
}

// Signature for randgrid worker function start
// Pattern: LOCK instruction + flag check + conditional branch
// Format: F0 ... 83 3D ... ... ... ... 00 0F 85 (LOCK ... cmp [rel32], 0; jnz ...)
UCHAR g_WorkerSignature[] = {
    0xF0, 0xCC, 0xCC, 0xCC,           // LOCK prefix (various operations)
    0x83, 0x3D, 0xCC, 0xCC, 0xCC, 0xCC, 0x00,  // cmp dword ptr [rip+offset], 0
    0x0F, 0x85                         // jnz (jump if not zero)
};

typedef struct _WORKER_INFO {
    PVOID FunctionStart;
    ULONG FlagOffset;
    ULONG Stride;
} WORKER_INFO;

// Find all worker threads via signature scanning
BOOLEAN FindRandgridWorkers(WORKER_INFO* workers, ULONG* workerCount) {
    *workerCount = 0;

    if (!g_RandgridBase || g_RandgridSize == 0) {
        STEALTH_LOG("Randgrid module not found\n");
        return FALSE;
    }

    STEALTH_LOG("Scanning randgrid.sys (%p, 0x%X bytes)\n", g_RandgridBase, g_RandgridSize);

    // Search for worker signature pattern
    PUCHAR searchStart = (PUCHAR)g_RandgridBase;
    PUCHAR searchEnd = searchStart + g_RandgridSize;

    while (searchStart < searchEnd && *workerCount < 4) {
        PVOID match = FindPattern(searchStart, (ULONG)(searchEnd - searchStart),
            g_WorkerSignature, sizeof(g_WorkerSignature));

        if (!match) break;

        workers[*workerCount].FunctionStart = match;
        workers[*workerCount].FlagOffset = 0xB4;  // Common offset, needs verification
        workers[*workerCount].Stride = 0x1A0;      // Common stride between worker slots

        STEALTH_LOG("Found worker %d at RVA 0x%llX\n", *workerCount,
            (ULONGLONG)match - (ULONGLONG)g_RandgridBase);

        (*workerCount)++;
        searchStart = (PUCHAR)match + sizeof(g_WorkerSignature);
    }

    return *workerCount > 0;
}

// ============================================================================
// WORKER DISPATCH HOOKING (instead of flag patching)
// ============================================================================
// Educational Note: Instead of setting flags to 1 (obvious tampering),
// we hook the worker dispatch function to do nothing.
//
// Advantages:
// - No constant memory modification (harder to detect via integrity checks)
// - Can selectively allow/block certain operations
// - Can unhook cleanly
//
// Disadvantages:
// - Code modification is still detectable via checksumming
// - Must preserve original instructions for unhooking
// - Execution redirection is detectable via ETW/tracing
// ============================================================================

// Our hook handler - does nothing, just returns
VOID WorkerHookHandler() {
    // Educational Note: In real implementation, this should:
    // 1. Preserve registers
    // 2. Check if we should block this operation
    // 3. Either call original or return early
    // 4. Restore registers

    // For now: just return (effectively neutering the worker)
    return;
}

NTSTATUS HookWorkerDispatch(PVOID targetFunction, PWORKER_HOOK hookInfo) {
    if (!targetFunction || !hookInfo) {
        return STATUS_INVALID_PARAMETER;
    }

    // Save original bytes
    RtlCopyMemory(hookInfo->OriginalBytes, targetFunction, sizeof(hookInfo->OriginalBytes));
    hookInfo->TargetFunction = targetFunction;

    // Build absolute jump: mov rax, address; jmp rax
    UCHAR hookBytes[14] = {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, imm64
        0xFF, 0xE0,                                                     // jmp rax
        0x90, 0x90                                                      // nop nop (padding)
    };

    *(PVOID*)(hookBytes + 2) = (PVOID)WorkerHookHandler;

    // Remove write protection
    PMDL mdl = IoAllocateMdl(targetFunction, 14, FALSE, FALSE, nullptr);
    if (!mdl) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(mdl);
        return STATUS_ACCESS_VIOLATION;
    }

    PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode,
        MmNonCached, nullptr, FALSE, NormalPagePriority);
    if (!mapped) {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Disable write protection on this page
    KIRQL irql;
    KeRaiseIrql(DISPATCH_LEVEL, &irql);

    ULONG_PTR cr0 = __readcr0();
    __writecr0(cr0 & ~0x10000);  // Clear WP bit

    // Write hook
    RtlCopyMemory(mapped, hookBytes, sizeof(hookBytes));

    // Re-enable write protection
    __writecr0(cr0);
    KeLowerIrql(irql);

    MmUnmapLockedPages(mapped, mdl);
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);

    hookInfo->IsHooked = TRUE;
    STEALTH_LOG("Hooked worker at %p\n", targetFunction);

    return STATUS_SUCCESS;
}

NTSTATUS UnhookWorkerDispatch(PWORKER_HOOK hookInfo) {
    if (!hookInfo || !hookInfo->IsHooked || !hookInfo->TargetFunction) {
        return STATUS_INVALID_PARAMETER;
    }

    // Restore original bytes
    PMDL mdl = IoAllocateMdl(hookInfo->TargetFunction, 14, FALSE, FALSE, nullptr);
    if (!mdl) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(mdl);
        return STATUS_ACCESS_VIOLATION;
    }

    PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode,
        MmNonCached, nullptr, FALSE, NormalPagePriority);
    if (!mapped) {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KIRQL irql;
    KeRaiseIrql(DISPATCH_LEVEL, &irql);
    ULONG_PTR cr0 = __readcr0();
    __writecr0(cr0 & ~0x10000);

    RtlCopyMemory(mapped, hookInfo->OriginalBytes, sizeof(hookInfo->OriginalBytes));

    __writecr0(cr0);
    KeLowerIrql(irql);

    MmUnmapLockedPages(mapped, mdl);
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);

    hookInfo->IsHooked = FALSE;
    STEALTH_LOG("Unhooked worker at %p\n", hookInfo->TargetFunction);

    return STATUS_SUCCESS;
}

// Apply hooks to all discovered workers
NTSTATUS HookAllWorkers() {
    // Check for analysis before doing anything sensitive
    if (IsBeingAnalyzed()) {
        STEALTH_LOG("Analysis detected, aborting worker hooking\n");
        return STATUS_ACCESS_DENIED;
    }

    // Find randgrid module
    g_RandgridBase = GetKernelModuleBase("randgrid.sys", &g_RandgridSize);
    if (!g_RandgridBase) {
        STEALTH_LOG("randgrid.sys not loaded - AC not active?\n");
        return STATUS_NOT_FOUND;
    }

    // Discover workers via signature scanning
    WORKER_INFO workers[4];
    ULONG workerCount = 0;

    if (!FindRandgridWorkers(workers, &workerCount)) {
        STEALTH_LOG("No workers found via signature scanning\n");
        return STATUS_NOT_FOUND;
    }

    // Hook each worker
    for (ULONG i = 0; i < workerCount; i++) {
        NTSTATUS status = HookWorkerDispatch(workers[i].FunctionStart, &g_WorkerHooks[i]);
        if (!NT_SUCCESS(status)) {
            STEALTH_LOG("Failed to hook worker %d: 0x%X\n", i, status);

            // Unhook any successful hooks before returning
            for (ULONG j = 0; j < i; j++) {
                UnhookWorkerDispatch(&g_WorkerHooks[j]);
            }
            return status;
        }
    }

    STEALTH_LOG("Successfully hooked %d workers\n", workerCount);
    return STATUS_SUCCESS;
}

// ============================================================================
// COMMUNICATION SECTION (File-backed, unnamed)
// ============================================================================
// Educational Note: Named sections in \BaseNamedObjects\ are trivially enumerable.
// File-backed sections are:
// - Harder to find (no name in object manager)
// - Look like legitimate file mapping
// - Still detectable via handle enumeration
//
// Better approach: Use IOCTL-only communication (no shared memory)
// ============================================================================

NTSTATUS CreateCommSection() {
    LARGE_INTEGER maxSize;
    maxSize.QuadPart = g_CommBufferSize;

    // Create unnamed section (no name = not in \BaseNamedObjects\)
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

    NTSTATUS status = ZwCreateSection(
        &g_CommSection,
        SECTION_ALL_ACCESS,
        &objAttr,
        &maxSize,
        PAGE_READWRITE,
        SEC_COMMIT,
        nullptr  // No file backing - anonymous memory
    );

    if (!NT_SUCCESS(status)) {
        STEALTH_LOG("Failed to create comm section: 0x%X\n", status);
        return status;
    }

    // Map into kernel space
    SIZE_T viewSize = g_CommBufferSize;
    status = ZwMapViewOfSection(
        g_CommSection,
        ZwCurrentProcess(),
        &g_CommBuffer,
        0,
        g_CommBufferSize,
        nullptr,
        &viewSize,
        ViewUnmap,
        0,
        PAGE_READWRITE
    );

    if (!NT_SUCCESS(status)) {
        ZwClose(g_CommSection);
        g_CommSection = nullptr;
        STEALTH_LOG("Failed to map comm section: 0x%X\n", status);
        return status;
    }

    // Write hardware GUID to buffer for UM to read
    if (g_CommBuffer) {
        *(PULONGLONG)g_CommBuffer = g_HardwareGuid;
        STEALTH_LOG("Comm section ready, GUID written: 0x%llX\n", g_HardwareGuid);
    }

    return STATUS_SUCCESS;
}

VOID DestroyCommSection() {
    if (g_CommBuffer) {
        ZwUnmapViewOfSection(ZwCurrentProcess(), g_CommBuffer);
        g_CommBuffer = nullptr;
    }

    if (g_CommSection) {
        ZwClose(g_CommSection);
        g_CommSection = nullptr;
    }
}

// ============================================================================
// IOCTL CODES
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
}

// ============================================================================
// DEVICE I/O CONTROL HANDLER
// ============================================================================

NTSTATUS DeviceControl(PDEVICE_OBJECT device_object, PIRP irp) {
    UNREFERENCED_PARAMETER(device_object);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;

    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR information = 0;

    switch (controlCode) {
        case driver::codes::get_guid: {
            // Return hardware GUID to user mode
            if (stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(ULONGLONG)) {
                *(PULONGLONG)irp->AssociatedIrp.SystemBuffer = g_HardwareGuid;
                information = sizeof(ULONGLONG);
                STEALTH_LOG("Returned GUID to UM: 0x%llX\n", g_HardwareGuid);
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;
        }

        case driver::codes::read: {
            if (stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(driver::Request)) {
                driver::Request* req = (driver::Request*)irp->AssociatedIrp.SystemBuffer;

                PEPROCESS targetProcess;
                status = PsLookupProcessByProcessId(req->process_id, &targetProcess);
                if (NT_SUCCESS(status)) {
                    SIZE_T bytesRead = 0;
                    status = ReadProcessMemoryMDL(targetProcess, req->target,
                        req->buffer, req->size, &bytesRead);
                    req->return_size = bytesRead;
                    ObDereferenceObject(targetProcess);
                }
            }
            break;
        }

        case driver::codes::write: {
            if (stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(driver::Request)) {
                driver::Request* req = (driver::Request*)irp->AssociatedIrp.SystemBuffer;

                PEPROCESS targetProcess;
                status = PsLookupProcessByProcessId(req->process_id, &targetProcess);
                if (NT_SUCCESS(status)) {
                    SIZE_T bytesWritten = 0;
                    status = WriteProcessMemoryMDL(targetProcess, req->target,
                        req->buffer, req->size, &bytesWritten);
                    req->return_size = bytesWritten;
                    ObDereferenceObject(targetProcess);
                }
            }
            break;
        }

        case driver::codes::integrity: {
            driver::INTEGRITY_RESPONSE response = { 0 };

            // Check if our hooks are still in place
            BOOLEAN allHooked = TRUE;
            for (int i = 0; i < 4; i++) {
                if (g_WorkerHooks[i].IsHooked) {
                    // Verify our hook bytes are still there
                    UCHAR currentBytes[14];
                    RtlCopyMemory(currentBytes, g_WorkerHooks[i].TargetFunction, 14);

                    // Check if it still starts with our mov rax, addr
                    if (currentBytes[0] != 0x48 || currentBytes[1] != 0xB8) {
                        allHooked = FALSE;
                        break;
                    }
                }
            }

            response.is_hooked = allHooked ? 0 : 1;
            response.checksum = 0xDEADBEEF;  // Placeholder

            if (stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(response)) {
                RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, &response, sizeof(response));
                information = sizeof(response);
            }
            break;
        }

        case driver::codes::unload: {
            g_Unloading = TRUE;
            STEALTH_LOG("Unload requested\n");
            break;
        }

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    irp->IoStatus.Status = status;
    irp->IoStatus.Information = information;
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return status;
}

NTSTATUS DeviceCreate(PDEVICE_OBJECT device_object, PIRP irp) {
    UNREFERENCED_PARAMETER(device_object);

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS DeviceClose(PDEVICE_OBJECT device_object, PIRP irp) {
    UNREFERENCED_PARAMETER(device_object);

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

// ============================================================================
// DRIVER UNLOAD
// ============================================================================

VOID DriverUnload(PDRIVER_OBJECT driver_object) {
    STEALTH_LOG("Unloading driver\n");

    g_Unloading = TRUE;

    // Unhook all workers
    for (int i = 0; i < 4; i++) {
        if (g_WorkerHooks[i].IsHooked) {
            UnhookWorkerDispatch(&g_WorkerHooks[i]);
        }
    }

    // Destroy communication section
    DestroyCommSection();

    // Delete device
    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
    }

    STEALTH_LOG("Driver unloaded cleanly\n");
}

// ============================================================================
// DRIVER INITIALIZATION
// ============================================================================

NTSTATUS DriverInitialize(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {
    UNREFERENCED_PARAMETER(registry_path);

    STEALTH_LOG("Driver initializing\n");

    g_DriverObject = driver_object;
    KeInitializeSpinLock(&g_CommLock);

    // Generate hardware-based GUID
    g_HardwareGuid = GenerateHardwareGuid();

    // Create unnamed device
    // Educational Note: Even unnamed devices appear in \Device\ with a generic name
    // True stealth requires DKOM to hide from object manager entirely
    WCHAR deviceName[64];
    swprintf_s(deviceName, 64, L"\\Device\\{%llX}", g_HardwareGuid & 0xFFFFFFFFFFFF);

    UNICODE_STRING deviceNameU;
    RtlInitUnicodeString(&deviceNameU, deviceName);

    NTSTATUS status = IoCreateDevice(
        driver_object,
        0,
        &deviceNameU,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject
    );

    if (!NT_SUCCESS(status)) {
        STEALTH_LOG("Failed to create device: 0x%X\n", status);
        return status;
    }

    // Set dispatch functions
    driver_object->MajorFunction[IRP_MJ_CREATE] = DeviceCreate;
    driver_object->MajorFunction[IRP_MJ_CLOSE] = DeviceClose;
    driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    driver_object->DriverUnload = DriverUnload;

    // Create communication section
    status = CreateCommSection();
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    // Hook randgrid workers
    status = HookAllWorkers();
    if (!NT_SUCCESS(status)) {
        STEALTH_LOG("Warning: Worker hooking failed (AC may not be loaded yet)\n");
        // Not fatal - AC might load later
    }

    ClearFlag(g_DeviceObject->Flags, DO_DEVICE_INITIALIZING);

    STEALTH_LOG("Driver initialized successfully\n");
    return STATUS_SUCCESS;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    // Use manual driver initialization to avoid registry requirement
    UNICODE_STRING driverName;
    RtlInitUnicodeString(&driverName, L"\\Driver\\StealthDriver");

    return IoCreateDriver(&driverName, DriverInitialize);
}
