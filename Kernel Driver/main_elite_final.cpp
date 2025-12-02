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

// ALPC structures - fully declared
typedef struct _PORT_MESSAGE_KERNEL {
    union {
        struct {
            USHORT DataLength;
            USHORT TotalLength;
        } s1;
        ULONG Length;
    } u1;
    union {
        struct {
            USHORT Type;
            USHORT DataInfoOffset;
        } s2;
        ULONG ZeroInit;
    } u2;
    union {
        CLIENT_ID ClientId;
        double DoNotUseThisField;
    };
    ULONG MessageId;
    union {
        SIZE_T ClientViewSize;
        ULONG CallbackId;
    };
} PORT_MESSAGE_KERNEL, *PPORT_MESSAGE_KERNEL;

typedef struct _ALPC_PORT_ATTRIBUTES_KERNEL {
    ULONG Flags;
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    SIZE_T MaxMessageLength;
    SIZE_T MemoryBandwidth;
    SIZE_T MaxPoolUsage;
    SIZE_T MaxSectionSize;
    SIZE_T MaxViewSize;
    SIZE_T MaxTotalSectionSize;
    ULONG DupObjectTypes;
} ALPC_PORT_ATTRIBUTES_KERNEL, *PALPC_PORT_ATTRIBUTES_KERNEL;

typedef struct _ALPC_MESSAGE_ATTRIBUTES_KERNEL {
    ULONG AllocatedAttributes;
    ULONG ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES_KERNEL, *PALPC_MESSAGE_ATTRIBUTES_KERNEL;

// ALPC Functions
NTSYSAPI NTSTATUS NTAPI NtAlpcCreatePort(
    _Out_ PHANDLE PortHandle,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PALPC_PORT_ATTRIBUTES_KERNEL PortAttributes
);

NTSYSAPI NTSTATUS NTAPI NtAlpcSendWaitReceivePort(
    _In_ HANDLE PortHandle,
    _In_ ULONG Flags,
    _In_opt_ PPORT_MESSAGE_KERNEL SendMessage,
    _In_opt_ PALPC_MESSAGE_ATTRIBUTES_KERNEL SendMessageAttributes,
    _Out_opt_ PPORT_MESSAGE_KERNEL ReceiveMessage,
    _Inout_opt_ PSIZE_T BufferLength,
    _Out_opt_ PALPC_MESSAGE_ATTRIBUTES_KERNEL ReceiveMessageAttributes,
    _In_opt_ PLARGE_INTEGER Timeout
);

NTSYSAPI NTSTATUS NTAPI NtAlpcAcceptConnectPort(
    _Out_ PHANDLE PortHandle,
    _In_ HANDLE ConnectionPortHandle,
    _In_ ULONG Flags,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PALPC_PORT_ATTRIBUTES_KERNEL PortAttributes,
    _In_opt_ PVOID PortContext,
    _In_ PPORT_MESSAGE_KERNEL ConnectionRequest,
    _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES_KERNEL ConnectionMessageAttributes,
    _In_ BOOLEAN AcceptConnection
);

// ETW - use kernel mode callback signature
typedef VOID (NTAPI *PETWENABLECALLBACK_KERNEL)(
    _In_ LPCGUID SourceId,
    _In_ ULONG IsEnabled,
    _In_ UCHAR Level,
    _In_ ULONGLONG MatchAnyKeyword,
    _In_ ULONGLONG MatchAllKeyword,
    _In_opt_ PVOID FilterData,
    _In_opt_ PVOID CallbackContext
);

NTSYSAPI NTSTATUS NTAPI EtwRegister(
    _In_ LPCGUID ProviderId,
    _In_opt_ PETWENABLECALLBACK_KERNEL EnableCallback,
    _In_opt_ PVOID CallbackContext,
    _Out_ PREGHANDLE RegHandle
);

NTSYSAPI NTSTATUS NTAPI EtwUnregister(
    _In_ REGHANDLE RegHandle
);

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

// Boot time
extern "C" NTSYSAPI LARGE_INTEGER KeBootTime;

#ifdef __cplusplus
}
#endif

// ============================================================================
// GLOBAL STATE
// ============================================================================

PDRIVER_OBJECT g_pDriverObject = nullptr;
PDEVICE_OBJECT g_pFilterDevice = nullptr;
PDEVICE_OBJECT g_pTargetDevice = nullptr;

// ALPC communication
HANDLE g_hAlpcPort = nullptr;
KSPIN_LOCK g_AlpcLock;

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

typedef struct _ELITE_ALPC_MESSAGE {
    PORT_MESSAGE_KERNEL PortMessage;
    ULONG MessageType;
    HANDLE ProcessId;
    PVOID Address;
    SIZE_T Size;
    ULONG Protection;
    NTSTATUS Status;
    ULONGLONG HardwareId;
    UCHAR Data[256];
} ELITE_ALPC_MESSAGE, *PELITE_ALPC_MESSAGE;

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

    // System boot time
    id ^= KeBootTime.QuadPart;

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

VOID NTAPI EtwEnableCallback(
    _In_ LPCGUID SourceId,
    _In_ ULONG IsEnabled,
    _In_ UCHAR Level,
    _In_ ULONGLONG MatchAnyKeyword,
    _In_ ULONGLONG MatchAllKeyword,
    _In_opt_ PVOID FilterData,
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

    NTSTATUS status = EtwRegister(
        &g_EtwProviderGuid,
        EtwEnableCallback,
        nullptr,
        &g_hEtwProvider
    );

    if (NT_SUCCESS(status)) {
        ELITE_DBG("ETW provider registered successfully\n");
    } else {
        ELITE_DBG("ETW provider registration failed: 0x%X (non-fatal)\n", status);
    }

    return status;
}

// ============================================================================
// ALPC SERVER
// ============================================================================

VOID AlpcServerThread(PVOID Context) {
    UNREFERENCED_PARAMETER(Context);

    ELITE_DBG("ALPC server thread started\n");

    // Create dynamic port name
    WCHAR portName[128];
    swprintf_s(portName, 128, L"\\RPC Control\\AudioKse_%llX", g_ullHardwareId & 0xFFFFFFFF);

    UNICODE_STRING portNameU;
    RtlInitUnicodeString(&portNameU, portName);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &portNameU, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    ALPC_PORT_ATTRIBUTES_KERNEL portAttribs = { 0 };
    portAttribs.MaxMessageLength = sizeof(ELITE_ALPC_MESSAGE);

    NTSTATUS status = NtAlpcCreatePort(&g_hAlpcPort, &objAttr, &portAttribs);
    if (!NT_SUCCESS(status)) {
        ELITE_DBG("Failed to create ALPC port: 0x%X\n", status);
        PsTerminateSystemThread(STATUS_UNSUCCESSFUL);
        return;
    }

    ELITE_DBG("ALPC port created: %wZ\n", &portNameU);

    // Message loop
    while (!g_bUnloading) {
        ELITE_ALPC_MESSAGE msg = { 0 };
        SIZE_T msgLength = sizeof(msg);

        LARGE_INTEGER timeout;
        timeout.QuadPart = -10000000LL;  // 1 second

        status = NtAlpcSendWaitReceivePort(
            g_hAlpcPort,
            0,
            nullptr,
            nullptr,
            &msg.PortMessage,
            &msgLength,
            nullptr,
            &timeout
        );

        if (status == STATUS_TIMEOUT) {
            continue;
        }

        if (!NT_SUCCESS(status)) {
            if (g_bUnloading) break;
            ELITE_DBG("ALPC receive failed: 0x%X\n", status);
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
                // TODO: Implement handlers
                msg.Status = STATUS_NOT_IMPLEMENTED;
                break;

            default:
                msg.Status = STATUS_INVALID_PARAMETER;
                break;
        }

        // Send reply
        msg.PortMessage.u1.s1.DataLength = sizeof(ELITE_ALPC_MESSAGE) - sizeof(PORT_MESSAGE_KERNEL);
        msg.PortMessage.u1.s1.TotalLength = sizeof(ELITE_ALPC_MESSAGE);

        NtAlpcSendWaitReceivePort(
            g_hAlpcPort,
            0,
            &msg.PortMessage,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr
        );
    }

    if (g_hAlpcPort) {
        ZwClose(g_hAlpcPort);
        g_hAlpcPort = nullptr;
    }

    ELITE_DBG("ALPC server thread exiting\n");
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

    // Close ALPC port
    if (g_hAlpcPort) {
        ZwClose(g_hAlpcPort);
        g_hAlpcPort = nullptr;
    }

    // Unregister ETW provider
    if (g_hEtwProvider) {
        EtwUnregister(g_hEtwProvider);
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
    KeInitializeSpinLock(&g_AlpcLock);
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

    // Start ALPC server thread
    HANDLE threadHandle = nullptr;
    status = PsCreateSystemThread(
        &threadHandle,
        THREAD_ALL_ACCESS,
        nullptr,
        nullptr,
        nullptr,
        AlpcServerThread,
        nullptr
    );

    if (NT_SUCCESS(status)) {
        ZwClose(threadHandle);
        ELITE_DBG("ALPC server thread created\n");
    } else {
        ELITE_DBG("Failed to create ALPC thread: 0x%X\n", status);
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
