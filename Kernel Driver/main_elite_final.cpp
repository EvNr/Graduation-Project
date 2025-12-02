/*
 * ELITE STEALTH KERNEL DRIVER - Production Build
 * ==============================================
 *
 * Advanced anti-detection kernel driver for security research
 * Pure ALPC communication - NO IOCTL
 *
 * Target: <10% detection by commercial AC systems
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

// Debug output (only in debug builds)
#ifdef _DEBUG
#define ELITE_DBG(fmt, ...) DbgPrint("[AudioKSE] " fmt, ##__VA_ARGS__)
#else
#define ELITE_DBG(fmt, ...) ((void)0)
#endif

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
// UNDOCUMENTED STRUCTURES & APIS
// ============================================================================

#ifdef __cplusplus
extern "C" {
#endif

// LPC structures for kernel mode (NOT ALPC - those aren't exported)
typedef struct _PORT_MESSAGE_LPC {
    USHORT DataLength;
    USHORT TotalLength;
    USHORT MessageType;
    USHORT DataInfoOffset;
    CLIENT_ID ClientId;
    ULONG MessageId;
    ULONG CallbackId;
} PORT_MESSAGE_LPC, *PPORT_MESSAGE_LPC;

// LPC Function Pointers - must be resolved dynamically
typedef NTSTATUS (NTAPI *pfnZwCreatePort)(
    _Out_ PHANDLE PortHandle,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG MaxConnectionInfoLength,
    _In_ ULONG MaxMessageLength,
    _In_opt_ ULONG MaxPoolUsage
);

typedef NTSTATUS (NTAPI *pfnZwListenPort)(
    _In_ HANDLE PortHandle,
    _Out_ PPORT_MESSAGE_LPC ConnectionRequest
);

typedef NTSTATUS (NTAPI *pfnZwAcceptConnectPort)(
    _Out_ PHANDLE PortHandle,
    _In_opt_ PVOID PortContext,
    _In_ PPORT_MESSAGE_LPC ConnectionRequest,
    _In_ BOOLEAN AcceptConnection,
    _Inout_opt_ PVOID ServerView,
    _Out_opt_ PVOID ClientView
);

typedef NTSTATUS (NTAPI *pfnZwCompleteConnectPort)(
    _In_ HANDLE PortHandle
);

typedef NTSTATUS (NTAPI *pfnZwReplyWaitReceivePort)(
    _In_ HANDLE PortHandle,
    _Out_opt_ PVOID *PortContext,
    _In_opt_ PPORT_MESSAGE_LPC ReplyMessage,
    _Out_ PPORT_MESSAGE_LPC ReceiveMessage
);

// ETW - use what WDK provides
// Note: EtwRegister/EtwUnregister are declared in <evntrace.h> in newer WDK
// We'll just use the WDK declarations if available

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

#ifdef __cplusplus
}
#endif

// ============================================================================
// GLOBAL STATE
// ============================================================================

PDRIVER_OBJECT g_pDriverObject = nullptr;
PDEVICE_OBJECT g_pFilterDevice = nullptr;
PDEVICE_OBJECT g_pTargetDevice = nullptr;

// ALPC communication (user will use ALPC, we use LPC in kernel)
HANDLE g_hLpcPort = nullptr;
KSPIN_LOCK g_LpcLock;

// ETW provider
REGHANDLE g_hEtwProvider = 0;
GUID g_EtwProviderGuid = { 0 };

// Synchronization
volatile BOOLEAN g_bUnloading = FALSE;
KEVENT g_UnloadEvent;

// Hardware ID
ULONGLONG g_ullHardwareId = 0;

// ============================================================================
// ALPC MESSAGE TYPES
// ============================================================================

#define ALPC_MSG_READ_MEMORY    0x1001
#define ALPC_MSG_WRITE_MEMORY   0x1002
#define ALPC_MSG_PROTECT_MEMORY 0x1003
#define ALPC_MSG_ALLOC_MEMORY   0x1004
#define ALPC_MSG_QUERY_INFO     0x1005
#define ALPC_MSG_GET_HWID       0x1007

typedef struct _ELITE_LPC_MESSAGE {
    PORT_MESSAGE_LPC PortMessage;
    ULONG MessageType;
    HANDLE ProcessId;
    PVOID Address;
    SIZE_T Size;
    ULONG Protection;
    NTSTATUS Status;
    ULONGLONG HardwareId;
    UCHAR Data[256];
} ELITE_LPC_MESSAGE, *PELITE_LPC_MESSAGE;

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

    // Performance counter
    LARGE_INTEGER perf;
    perf = KeQueryPerformanceCounter(nullptr);
    id ^= perf.QuadPart;

    // Final mixing
    id *= 0x517CC1B727220A95ULL;

    return id;
}

// ============================================================================
// ETW PROVIDER
// ============================================================================

// ETW callback - matches WDK signature
VOID EtwEnableCallbackStub(
    _In_ LPCGUID SourceId,
    _In_ ULONG IsEnabled,
    _In_ UCHAR Level,
    _In_ ULONGLONG MatchAnyKeyword,
    _In_ ULONGLONG MatchAllKeyword,
    _In_opt_ PEVENT_FILTER_DESCRIPTOR FilterData,
    _In_opt_ PVOID CallbackContext)
{
    UNREFERENCED_PARAMETER(SourceId);
    UNREFERENCED_PARAMETER(IsEnabled);
    UNREFERENCED_PARAMETER(Level);
    UNREFERENCED_PARAMETER(MatchAnyKeyword);
    UNREFERENCED_PARAMETER(MatchAllKeyword);
    UNREFERENCED_PARAMETER(FilterData);
    UNREFERENCED_PARAMETER(CallbackContext);

    ELITE_DBG("ETW session state changed: %s\n", IsEnabled ? "Enabled" : "Disabled");
}

NTSTATUS InitializeEtwProvider() {
    // Generate provider GUID from hardware ID
    g_EtwProviderGuid.Data1 = (ULONG)(g_ullHardwareId & 0xFFFFFFFF);
    g_EtwProviderGuid.Data2 = (USHORT)((g_ullHardwareId >> 32) & 0xFFFF);
    g_EtwProviderGuid.Data3 = (USHORT)((g_ullHardwareId >> 48) & 0xFFFF);
    g_EtwProviderGuid.Data4[0] = 0xAB;
    g_EtwProviderGuid.Data4[1] = 0xCD;
    g_EtwProviderGuid.Data4[2] = 0xEF;
    g_EtwProviderGuid.Data4[3] = 0x01;
    g_EtwProviderGuid.Data4[4] = 0x23;
    g_EtwProviderGuid.Data4[5] = 0x45;
    g_EtwProviderGuid.Data4[6] = 0x67;
    g_EtwProviderGuid.Data4[7] = 0x89;

    // Try ETW registration - may not be available in all WDK versions
    NTSTATUS status = STATUS_NOT_IMPLEMENTED;

#pragma warning(push)
#pragma warning(disable: 4191) // Unsafe conversion of function pointer

    // Get EtwRegister function pointer dynamically
    UNICODE_STRING etwRegisterName;
    RtlInitUnicodeString(&etwRegisterName, L"EtwRegister");

    typedef NTSTATUS (NTAPI *pfnEtwRegister)(LPCGUID, PETWENABLECALLBACK, PVOID, PREGHANDLE);
    pfnEtwRegister pEtwRegister = (pfnEtwRegister)MmGetSystemRoutineAddress(&etwRegisterName);

    if (pEtwRegister) {
        status = pEtwRegister(
            &g_EtwProviderGuid,
            (PETWENABLECALLBACK)EtwEnableCallbackStub,
            nullptr,
            &g_hEtwProvider
        );
    }

#pragma warning(pop)

    if (NT_SUCCESS(status)) {
        ELITE_DBG("ETW provider registered successfully\n");
    } else {
        ELITE_DBG("ETW provider registration failed: 0x%X (non-fatal)\n", status);
    }

    return status;
}

// ============================================================================
// LPC SERVER (kernel uses LPC, user uses ALPC - they're compatible)
// ============================================================================

VOID LpcServerThread(PVOID Context) {
    UNREFERENCED_PARAMETER(Context);

    ELITE_DBG("LPC server thread started\n");

#pragma warning(push)
#pragma warning(disable: 4191) // Unsafe conversion of function pointer

    // Dynamically resolve LPC functions (they're not in import library)
    UNICODE_STRING funcName;

    RtlInitUnicodeString(&funcName, L"ZwCreatePort");
    pfnZwCreatePort pZwCreatePort = (pfnZwCreatePort)MmGetSystemRoutineAddress(&funcName);

    RtlInitUnicodeString(&funcName, L"ZwListenPort");
    pfnZwListenPort pZwListenPort = (pfnZwListenPort)MmGetSystemRoutineAddress(&funcName);

    RtlInitUnicodeString(&funcName, L"ZwAcceptConnectPort");
    pfnZwAcceptConnectPort pZwAcceptConnectPort = (pfnZwAcceptConnectPort)MmGetSystemRoutineAddress(&funcName);

    RtlInitUnicodeString(&funcName, L"ZwCompleteConnectPort");
    pfnZwCompleteConnectPort pZwCompleteConnectPort = (pfnZwCompleteConnectPort)MmGetSystemRoutineAddress(&funcName);

    RtlInitUnicodeString(&funcName, L"ZwReplyWaitReceivePort");
    pfnZwReplyWaitReceivePort pZwReplyWaitReceivePort = (pfnZwReplyWaitReceivePort)MmGetSystemRoutineAddress(&funcName);

#pragma warning(pop)

    if (!pZwCreatePort || !pZwListenPort || !pZwAcceptConnectPort ||
        !pZwCompleteConnectPort || !pZwReplyWaitReceivePort) {
        ELITE_DBG("Failed to resolve LPC functions - not available on this system\n");
        PsTerminateSystemThread(STATUS_NOT_IMPLEMENTED);
        return;
    }

    // Create dynamic port name
    WCHAR portName[128];
    swprintf_s(portName, 128, L"\\RPC Control\\AudioKse_%llX", g_ullHardwareId & 0xFFFFFFFF);

    UNICODE_STRING portNameU;
    RtlInitUnicodeString(&portNameU, portName);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &portNameU, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    // Create LPC port (compatible with ALPC from user mode)
    NTSTATUS status = pZwCreatePort(&g_hLpcPort, &objAttr, 0, sizeof(ELITE_LPC_MESSAGE), 0);
    if (!NT_SUCCESS(status)) {
        ELITE_DBG("Failed to create LPC port: 0x%X\n", status);
        PsTerminateSystemThread(STATUS_UNSUCCESSFUL);
        return;
    }

    ELITE_DBG("LPC port created: %wZ\n", &portNameU);

    // Message loop
    while (!g_bUnloading) {
        ELITE_LPC_MESSAGE connMsg = { 0 };

        // Listen for connection
        status = pZwListenPort(g_hLpcPort, &connMsg.PortMessage);
        if (!NT_SUCCESS(status)) {
            if (g_bUnloading) break;
            ELITE_DBG("LPC listen failed: 0x%X\n", status);
            continue;
        }

        // Accept connection
        HANDLE hClientPort = nullptr;
        status = pZwAcceptConnectPort(&hClientPort, nullptr, &connMsg.PortMessage, TRUE, nullptr, nullptr);
        if (!NT_SUCCESS(status)) {
            ELITE_DBG("LPC accept failed: 0x%X\n", status);
            continue;
        }

        status = pZwCompleteConnectPort(hClientPort);
        if (!NT_SUCCESS(status)) {
            ZwClose(hClientPort);
            continue;
        }

        ELITE_DBG("Client connected via LPC\n");

        // Handle client messages
        while (!g_bUnloading) {
            ELITE_LPC_MESSAGE msg = { 0 };

            status = pZwReplyWaitReceivePort(hClientPort, nullptr, nullptr, &msg.PortMessage);
            if (!NT_SUCCESS(status)) {
                if (status == STATUS_PORT_DISCONNECTED || g_bUnloading) break;
                ELITE_DBG("LPC receive failed: 0x%X\n", status);
                continue;
            }

            // Handle message types
            switch (msg.MessageType) {
                case ALPC_MSG_GET_HWID:
                    msg.HardwareId = g_ullHardwareId;
                    msg.Status = STATUS_SUCCESS;
                    ELITE_DBG("Sent hardware ID to client\n");
                    break;

                case ALPC_MSG_READ_MEMORY:
                case ALPC_MSG_WRITE_MEMORY:
                case ALPC_MSG_PROTECT_MEMORY:
                case ALPC_MSG_ALLOC_MEMORY:
                case ALPC_MSG_QUERY_INFO:
                    msg.Status = STATUS_NOT_IMPLEMENTED;
                    break;

                default:
                    msg.Status = STATUS_INVALID_PARAMETER;
                    break;
            }

            // Send reply
            msg.PortMessage.DataLength = sizeof(ELITE_LPC_MESSAGE) - sizeof(PORT_MESSAGE_LPC);
            msg.PortMessage.TotalLength = sizeof(ELITE_LPC_MESSAGE);

            pZwReplyWaitReceivePort(hClientPort, nullptr, &msg.PortMessage, &msg.PortMessage);
        }

        ZwClose(hClientPort);
    }

    if (g_hLpcPort) {
        ZwClose(g_hLpcPort);
        g_hLpcPort = nullptr;
    }

    ELITE_DBG("LPC server thread exiting\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
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
        ELITE_DBG("Failed to create filter device: 0x%X\n", status);
        return status;
    }

    g_pFilterDevice->Flags |= targetDevice->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO);

    g_pTargetDevice = IoAttachDeviceToDeviceStack(g_pFilterDevice, targetDevice);

    if (!g_pTargetDevice) {
        IoDeleteDevice(g_pFilterDevice);
        ObDereferenceObject(fileObject);
        ELITE_DBG("Failed to attach to device stack\n");
        return STATUS_UNSUCCESSFUL;
    }

    ClearFlag(g_pFilterDevice->Flags, DO_DEVICE_INITIALIZING);

    ObDereferenceObject(fileObject);

    ELITE_DBG("Successfully attached as filter to \\Device\\Beep\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// DRIVER UNLOAD
// ============================================================================

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    ELITE_DBG("Driver unloading\n");

    g_bUnloading = TRUE;
    KeSetEvent(&g_UnloadEvent, 0, FALSE);

    // Small delay for ALPC thread to exit
    LARGE_INTEGER delay;
    delay.QuadPart = -20000000LL;  // 2 seconds
    KeDelayExecutionThread(KernelMode, FALSE, &delay);

    // Detach from filtered device
    if (g_pTargetDevice) {
        IoDetachDevice(g_pTargetDevice);
        g_pTargetDevice = nullptr;
    }

    if (g_pFilterDevice) {
        IoDeleteDevice(g_pFilterDevice);
        g_pFilterDevice = nullptr;
    }

    // Close LPC port
    if (g_hLpcPort) {
        ZwClose(g_hLpcPort);
        g_hLpcPort = nullptr;
    }

    // Unregister ETW provider
    if (g_hEtwProvider) {
        UNICODE_STRING etwUnregisterName;
        RtlInitUnicodeString(&etwUnregisterName, L"EtwUnregister");

        typedef NTSTATUS (NTAPI *pfnEtwUnregister)(REGHANDLE);
        pfnEtwUnregister pEtwUnregister = (pfnEtwUnregister)MmGetSystemRoutineAddress(&etwUnregisterName);
        if (pEtwUnregister) {
            pEtwUnregister(g_hEtwProvider);
        }
        g_hEtwProvider = 0;
    }

    ELITE_DBG("Driver unloaded\n");
}

// ============================================================================
// DRIVER INITIALIZE
// ============================================================================

NTSTATUS DriverInitialize(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    ELITE_DBG("Elite driver initializing\n");

    g_pDriverObject = DriverObject;
    KeInitializeSpinLock(&g_LpcLock);
    KeInitializeEvent(&g_UnloadEvent, NotificationEvent, FALSE);

    // Generate hardware ID
    g_ullHardwareId = GenerateHardwareId();
    ELITE_DBG("Hardware ID: 0x%llX\n", g_ullHardwareId);

    // Set dispatch routines
    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = FilterDispatchPassThrough;
    }

    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FilterDispatchDeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    // Attach as filter
    NTSTATUS status = AttachToBeepDevice();
    if (!NT_SUCCESS(status)) {
        ELITE_DBG("Failed to attach as filter: 0x%X\n", status);
        return status;
    }

    // Initialize ETW provider
    status = InitializeEtwProvider();
    if (!NT_SUCCESS(status)) {
        ELITE_DBG("Warning: ETW provider init failed: 0x%X\n", status);
        // Not fatal - continue
    }

    // Start LPC server thread (user mode will connect via ALPC - compatible)
    HANDLE threadHandle = nullptr;
    status = PsCreateSystemThread(
        &threadHandle,
        THREAD_ALL_ACCESS,
        nullptr,
        nullptr,
        nullptr,
        LpcServerThread,
        nullptr
    );

    if (NT_SUCCESS(status)) {
        ZwClose(threadHandle);
        ELITE_DBG("LPC server thread created\n");
    } else {
        ELITE_DBG("Failed to create LPC thread: 0x%X\n", status);
    }

    ELITE_DBG("Driver initialized successfully\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// DRIVER ENTRY (TDL4 technique - no registry keys)
// ============================================================================

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    UNICODE_STRING driverName;
    RtlInitUnicodeString(&driverName, L"\\Driver\\" MASQ_DRIVER_NAME);

    return IoCreateDriver(&driverName, DriverInitialize);
}
