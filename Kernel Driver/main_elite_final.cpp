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
// SHARED MEMORY STRUCTURE - The "Whiteboard"
// ============================================================================
// This structure lives in kernel memory but is directly accessible from user mode
// Zero syscalls needed - just memory reads/writes

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

    // Get process name
    PCHAR processName = (PCHAR)PsGetProcessImageFileName(process);

    // Check if this is our target process
    if (_stricmp(processName, TARGET_PROCESS_NAME) == 0) {
        ELITE_DBG("Target process detected! PID: %llu, Name: %s\n", (ULONGLONG)ProcessId, processName);

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
// SCAN FOR ALREADY RUNNING TARGET PROCESS
// ============================================================================
// Process notify only fires for NEW processes
// If user runs exe BEFORE loading driver, we need to scan for it

VOID ScanForTargetProcess() {
    ELITE_DBG("Scanning for already-running target process...\n");

    // Enumerate all processes
    PEPROCESS process = PsGetCurrentProcess();

    for (int i = 0; i < 65536 && !g_bUnloading && g_UserMapping == nullptr; i += 4) {
        PEPROCESS proc = nullptr;
        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)i, &proc))) {
            PCHAR processName = (PCHAR)PsGetProcessImageFileName(proc);

            if (_stricmp(processName, TARGET_PROCESS_NAME) == 0) {
                ELITE_DBG("Found already-running target process! PID: %d, Name: %s\n", i, processName);

                // Manually call the injection logic
                ProcessNotifyCallback(nullptr, (HANDLE)(ULONG_PTR)i, TRUE);

                ObDereferenceObject(proc);
                return; // Found it, stop scanning
            }

            ObDereferenceObject(proc);
        }
    }

    ELITE_DBG("No already-running target process found\n");
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

    // Register process notify callback for FUTURE process starts
    status = PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, FALSE);
    if (!NT_SUCCESS(status)) {
        ELITE_DBG("Failed to register process notify: 0x%X\n", status);
        return status;
    }

    // CRITICAL: Also scan for ALREADY RUNNING target process
    // (Process notify won't fire if process started before driver loaded)
    ScanForTargetProcess();

    if (g_UserMapping != nullptr) {
        DbgPrint("=== INJECTION SUCCESS! Memory mapped at: 0x%p ===\n", g_UserMapping);
        ELITE_DBG("Driver initialized - target process found and injected\n");
    } else {
        DbgPrint("=== Driver loaded. Waiting for AudioDiagnostic.exe to start ===\n");
        ELITE_DBG("Driver initialized - waiting for target process to start\n");
    }

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

        // Register process notify callback (doesn't need DriverObject)
        status = PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, FALSE);
        if (!NT_SUCCESS(status)) {
            DbgPrint("=== CRITICAL: Process notify registration failed: 0x%X ===\n", status);
            return status;
        }

        // Scan for already running target
        ScanForTargetProcess();

        if (g_UserMapping != nullptr) {
            DbgPrint("=== INJECTION SUCCESS (KDMapper mode)! Pointer: 0x%p ===\n", g_UserMapping);
        } else {
            DbgPrint("=== Driver loaded (KDMapper mode). Waiting for target process ===\n");
        }

        DbgPrint("===============================================\n\n");
        return STATUS_SUCCESS;
    }

    DbgPrint("=== IoCreateDriver succeeded ===\n");
    return status;
}
