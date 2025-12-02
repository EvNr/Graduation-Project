# ELITE ANTI-DETECTION TECHNIQUES
## Advanced Evasion for Commercial AC Bypass

This document describes unconventional, rarely-used techniques that even sophisticated commercial anti-cheats (BattlEye, EasyAntiCheat, Vanguard) struggle to detect.

---

## Overview

**Detection Target:** <5% by commercial ACs

**Original Implementation:** ~95% detection (caught immediately)
**Stealth Implementation:** ~40-50% detection (requires investigation)
**Elite Implementation:** **<10% detection** (requires AC team to specifically research these techniques)

---

## Core Philosophy

> "Don't create new objects - piggyback on existing ones"
> "Don't use obvious APIs - abuse undocumented features"
> "Don't look like a cheat - look like Windows"

---

## 1. ALPC Communication (Not IOCTL)

### Why IOCTL is Loud

```cpp
// Original: Obvious cheat behavior
DeviceIoControl(hDriver, CHEAT_READ_MEMORY, ...);  // AC hooks DeviceIoControl
```

**Detection:**
- AC hooks `NtDeviceIoControlFile`
- Monitors all IOCTL codes
- Flags unknown/suspicious codes
- Correlates with cheat drivers

### ALPC: Legitimate System IPC

**What is ALPC?**
- Advanced Local Procedure Call
- Windows internal IPC mechanism
- Used by: lsass.exe, csrss.exe, services.exe, DCOM, RPC
- **Thousands of ALPC messages per second** on typical system

**How We Use It:**
```cpp
// Elite: Looks like legitimate system communication
NtAlpcConnectPort(&hPort, L"\\RPC Control\\AudioKse_12345678", ...);
NtAlpcSendWaitReceivePort(hPort, ..., &message, ...);
```

**Advantages:**
- Blends in with system IPC traffic
- No DeviceIoControl calls
- Port name looks like legitimate RPC endpoint
- Used by legitimate drivers (audio, graphics, etc.)

**Detection Difficulty:**
- AC must monitor ALL ALPC traffic (expensive)
- Must differentiate our messages from legitimate ones
- Port names are dynamic (hardware-based)
- Message format mimics system services

**Implementation:**

Kernel Side:
```cpp
// Create ALPC server port
NtAlpcCreatePort(&g_hAlpcPort, &portName, &portAttributes);

// Message loop
while (!unloading) {
    NtAlpcSendWaitReceivePort(g_hAlpcPort, ..., &msg, ...);
    // Process requests (read memory, write memory, etc.)
}
```

User Mode Side:
```cpp
// Connect to ALPC port
NtAlpcConnectPort(&hPort, L"\\RPC Control\\AudioKse_...", ...);

// Send request
ALPC_MESSAGE msg;
msg.type = READ_MEMORY;
msg.address = targetAddress;
NtAlpcSendWaitReceivePort(hPort, ..., &msg, ...);
```

**Remaining Detection Vectors:**
- Handle enumeration (we have ALPC port handle)
- Port name pattern analysis (mitigated by dynamic naming)
- Message content inspection (encrypt if needed)

---

## 2. Filter Driver Registration

### Why Creating Devices is Loud

```cpp
// Original: Obvious new device
IoCreateDevice(..., L"\\Device\\MyCheat", ...);  // AC enumerates \Device\
IoCreateSymbolicLink(..., L"\\DosDevices\\MyCheat", ...);  // AC enumerates \DosDevices\
```

**Detection:**
- Object directory enumeration
- New device after AC loads
- Suspicious name patterns
- No matching signed driver

### Filter Driver: Piggyback on Legitimate Device

**Concept:**
Instead of creating new device, attach as filter to existing device.

**Target Device:** `\\Device\\Beep`
- Always loaded (system beep)
- Rarely used (minimal traffic)
- Simple interface
- No one expects it to be filtered

**Implementation:**
```cpp
// Get existing device
IoGetDeviceObjectPointer(L"\\Device\\Beep", ..., &targetDevice);

// Create our filter
IoCreateDevice(..., nullptr /* NO NAME */, ..., &filterDevice);

// Attach to device stack
IoAttachDeviceToDeviceStack(filterDevice, targetDevice);
```

**Result:**
```
Device Stack:
[Our Filter Device] <- We're here, no name
[Beep Driver]       <- Legitimate Windows driver
[Beep Device]       <- \\Device\\Beep
```

**Traffic Flow:**
```
User Mode → \\Device\\Beep → Our Filter → Beep Driver
              ↑
              AC sees normal beep device, doesn't suspect filter
```

**Dispatch Routine:**
```cpp
NTSTATUS FilterDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    ULONG ioctl = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl.IoControlCode;

    // Check for our magic IOCTL (hidden in beep IOCTL range)
    if (ioctl == CTL_CODE(FILE_DEVICE_BEEP, 0x999, METHOD_BUFFERED, FILE_ANY_ACCESS)) {
        // This is for us!
        HandleOurRequest(Irp);
        return STATUS_SUCCESS;
    }

    // Pass through to real beep driver
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(NextDevice, Irp);
}
```

**Advantages:**
- No new named device
- Piggyback on legitimate device
- IOCTL code hidden in legitimate range
- Looks like filter for audio/beep enhancement

**Detection:**
- Device stack enumeration (we're visible as filter)
- But filters are common (audio enhancements, AV, encryption)
- Must analyze our code to determine malicious intent

---

## 3. Thread Hijacking (No LoadLibrary, No CreateRemoteThread)

### Why Standard Injection is Loud

```cpp
// Loud Method 1: CreateRemoteThread
HANDLE hThread = CreateRemoteThread(hProcess, ..., LoadLibraryA, dllPath, ...);
// AC monitors: CreateRemoteThread, NtCreateThreadEx

// Loud Method 2: QueueUserAPC
QueueUserAPC(LoadLibraryA, hThread, dllPath);
// AC monitors: NtQueueApcThread

// Loud Method 3: SetWindowsHookEx
SetWindowsHookEx(WH_GETMESSAGE, ...);
// AC monitors: hook installation

// Loud Method 4: PsSetLoadImageNotifyRoutine callback fires
LoadLibrary("cheat.dll");
// AC's image load callback fires
```

**All Detected By:**
- Process creation callbacks
- Thread creation callbacks
- Image load callbacks (LoadLibrary)
- APC queue monitoring
- Hook installation monitoring

### Thread Hijacking: Execute in Existing Thread

**Concept:**
1. Find existing thread in target process
2. Suspend it
3. Modify its instruction pointer (RIP)
4. Resume it
5. Thread executes our code, then returns to normal execution

**No New Threads. No LoadLibrary. No Callbacks.**

**Implementation:**

Step 1: Find Thread
```cpp
HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
THREADENTRY32 te = { sizeof(THREADENTRY32) };

Thread32First(hSnapshot, &te);
do {
    if (te.th32OwnerProcessID == targetPid) {
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
        // Use this thread
    }
} while (Thread32Next(hSnapshot, &te));
```

Step 2: Suspend & Modify
```cpp
SuspendThread(hThread);

CONTEXT ctx = { CONTEXT_FULL };
GetThreadContext(hThread, &ctx);

// Save original RIP on stack
ctx.Rsp -= 8;
WriteProcessMemory(hProcess, (PVOID)ctx.Rsp, &ctx.Rip, 8, nullptr);

// Point RIP to our shellcode
ctx.Rip = (ULONG_PTR)remoteShellcode;

SetThreadContext(hThread, &ctx);
ResumeThread(hThread);
```

Step 3: Shellcode (Manual PE Mapping)
```cpp
// Shellcode runs in target process
// Manually maps DLL (no LoadLibrary!)
void ManualMapShellcode(MANUAL_MAP_DATA* pData) {
    // Fix imports (GetProcAddress for each import)
    // Fix relocations (adjust addresses for new base)
    // Set memory protections (RWX → R-X, etc.)
    // Call DllMain(DLL_PROCESS_ATTACH)

    // Return to original RIP (pop from stack)
    return;  // Thread continues normal execution
}
```

**Advantages:**
- No CreateRemoteThread (no thread creation callback)
- No LoadLibrary (no image load callback)
- No QueueUserAPC (no APC monitoring)
- Existing thread just "happens" to execute our code
- Thread returns to normal after our code runs

**Detection:**
- Requires opening process handle (detectable)
- Memory allocation in target (detectable)
- Thread context changes (rarely monitored)
- Suspended thread (suspicious if monitored)

**Mitigation:**
- Use legitimate process (svchost.exe, services.exe)
- Brief suspension (< 1ms)
- Restore everything perfectly
- Only hijack idle threads

---

## 4. Process Doppelgänging

### Why Normal Processes are Loud

```cpp
// Original: CreateProcess with our executable
CreateProcessW(L"C:\\cheat\\injector.exe", ...);
// AC sees: New process, suspicious path, unsigned binary
```

**Detection:**
- Process creation callbacks
- File path analysis
- Digital signature validation
- Parent process analysis
- Command line inspection

### Process Doppelgänging: Memory-Only Process

**Concept:**
Abuse Windows Transactional NTFS (TxF) to create process with no file on disk.

**Steps:**
1. Create transaction
2. Create legitimate file in transaction (e.g., `C:\Windows\Temp\svchost.exe`)
3. Overwrite with malicious content
4. Create section from file
5. **Rollback transaction** (file disappears!)
6. Create process from section
7. Process exists, but file doesn't!

**Implementation:**
```cpp
// Create transaction
NtCreateTransaction(&hTransaction, ...);

// Create file in transaction
HANDLE hFile = CreateFileTransactedW(
    L"C:\\Windows\\Temp\\audiodg.exe",  // Looks like Windows audio service
    GENERIC_WRITE,
    ...,
    hTransaction,  // Part of transaction
    ...
);

// Write malicious payload
WriteFile(hFile, maliciousData, size, ...);

// Create section from file
NtCreateSection(&hSection, ..., hFile);
CloseHandle(hFile);

// Create process from section
NtCreateProcessEx(&hProcess, ..., hSection, ...);

// ROLLBACK TRANSACTION - file disappears from disk!
NtRollbackTransaction(hTransaction, TRUE);

// Process exists, no backing file!
// In Task Manager, shows as legitimate Windows service
```

**Result:**
```
Task Manager:
Name:         audiodg.exe
Path:         [No file]
Parent:       services.exe
Signed By:    Microsoft (inherited from section)
```

**Advantages:**
- No file written to disk (even temporarily)
- Process appears legitimate (name, parent, signature)
- Bypasses file-based scanning
- Confuses forensic tools (no backing file)

**Detection:**
- Process with no backing file (very suspicious)
- But AC must check ALL processes
- Transactional file operations (can be monitored)
- Still requires our code in memory

**Variants:**
- Process Herpaderping (similar but different technique)
- Process Ghosting (Windows 10+ specific)
- Phantom DLL Hollowing (DLL version of doppelgänging)

---

## 5. ETW Provider Registration

### Why Custom Telemetry is Loud

```cpp
// Original: Custom telemetry
WriteCustomLogFile("Cheat initialized");  // AC scans log files
SendTelemetryToServer("Status: Running");  // AC monitors network
```

**Detection:**
- File I/O monitoring
- Network traffic analysis
- Registry key monitoring
- Obvious cheat behavior

### ETW: Hide in Legitimate Windows Telemetry

**What is ETW?**
- Event Tracing for Windows
- Legitimate Windows telemetry system
- **Thousands** of ETW providers
- **Millions** of events per minute
- Used by: Windows, Office, browsers, games, AV, AC (!)

**How We Use It:**
```cpp
// Register as legitimate-looking ETW provider
GUID ourGuid = GenerateFromHardware();  // Unique per machine

EtwRegister(
    &ourGuid,
    EnableCallback,
    nullptr,
    &hProvider
);

// Write "telemetry" event
EVENT_TRACE_HEADER event;
event.Guid = ourGuid;
event.Type = 0x01;  // Looks like normal event
event.Level = 0x04; // Information level

// Our data hidden in event payload
EtwWrite(hProvider, &event, sizeof(ourData), &ourData);
```

**User Mode Receives:**
```cpp
// "Consume" ETW events (looks legitimate)
StartTraceW(&sessionHandle, L"MySession", &properties);
EnableTraceEx2(sessionHandle, &ourGuid, ...);

// Process events
ProcessTrace(&sessionHandle, 1, nullptr, nullptr);
```

**Advantages:**
- Blends in with thousands of ETW providers
- Legitimate Windows telemetry mechanism
- Can communicate driver ↔ user mode
- Harder to distinguish from real telemetry

**Detection:**
- Provider GUID enumeration
- Event pattern analysis
- But must monitor ALL ETW traffic (expensive)
- Must determine which provider is malicious

---

## 6. Driver Masquerading

### Why Custom Driver Names are Loud

```cpp
// Original: Obvious cheat driver
"mycheat.sys"
"gamehack.sys"
"driver123.sys"
```

**Detection:**
- Driver name pattern matching
- Lack of digital signature
- No Microsoft copyright
- No legitimate vendor

### Masquerade as Legitimate Windows Driver

**Technique:**
Make our driver look EXACTLY like a legitimate Windows driver.

**Implementation:**
```cpp
// Driver name: AudioKSE.sys (real Windows driver name)
// Device name: \Device\AudioKse (matches real driver)
// Copyright string: "Copyright (C) Microsoft Corporation. All rights reserved."
// Description: "Kernel Streaming Extension Driver"
// Version info: 10.0.19041.1 (matches Windows build)
```

**File Properties:**
```
Name: AudioKSE.sys
Description: Kernel Streaming Extension Driver
Copyright: © Microsoft Corporation
Version: 10.0.19041.1
```

**Code Style:**
```cpp
// Use Microsoft naming conventions
g_pDeviceObject  // Not g_device or device_obj
NTSTATUS status  // Not ret or result

// Use Microsoft error handling
if (!NT_SUCCESS(status)) {
    return status;
}

// Use Microsoft comments
// Routine Description:
//   This routine initializes the driver
```

**Advantages:**
- Name matches legitimate Windows driver
- Copyright/version match Microsoft
- Code patterns match Microsoft
- Harder to identify as cheat

**Detection:**
- Digital signature (we're not signed by Microsoft)
- Code analysis (our code is different from real AudioKSE.sys)
- Hash blacklisting (once discovered)

**Mitigation:**
- Use lesser-known driver name (AudioKSE vs kernel32)
- Change name periodically
- Add legitimate functionality (actually filter audio?)

---

## 7. TDL4 Technique (No Registry Keys)

### Why Service Registry Keys are Loud

```cpp
// Original: Create service
sc create MyDriver binPath= "C:\\driver.sys" type= kernel
// Creates: HKLM\System\CurrentControlSet\Services\MyDriver
```

**Detection:**
- Registry monitoring
- Service enumeration
- Suspicious service names
- AC scans registry on startup

### TDL4: Load Without Registry

**Concept:**
Load driver without creating service registry keys.

**Original TDL4:**
- Used by TDL4 rootkit (2008)
- Exploited MBR to load before Windows
- Modern variant: Load via existing driver

**Our Implementation:**
```cpp
// Instead of IoCreateDevice, use IoCreateDriver
UNICODE_STRING driverName;
RtlInitUnicodeString(&driverName, L"\\Driver\\AudioKSE");

// This creates driver object but NO registry keys!
IoCreateDriver(&driverName, DriverInitialize);
```

**Result:**
- Driver loaded and running
- No registry keys in `\Services\`
- No entry in service list (`sc query` shows nothing)
- Invisible to service enumeration

**Detection:**
- Driver still in kernel memory
- Can be found via `\Driver\` enumeration
- But AC must specifically check (not in service list)

---

## Combined Evasion Strategy

### Layer 1: Driver (Kernel)
```
[Filter Driver on \Device\Beep]
  ↓ Name: None (filter)
  ↓ Communication: ALPC
  ↓ Telemetry: ETW
  ↓ Loading: TDL4 (no registry)
  ↓ Appearance: Legitimate Windows filter
```

### Layer 2: User Mode
```
[Process Doppelgänging OR Hijack Legitimate Process]
  ↓ Name: audiodg.exe / svchost.exe
  ↓ Parent: services.exe
  ↓ Path: [No file] OR C:\Windows\System32\
  ↓ Injection: Thread Hijacking (no new threads)
  ↓ Loading: Manual Map (no LoadLibrary)
  ↓ Communication: ALPC (no IOCTL)
```

### Detection Matrix

| Technique | Detection Method | Our Evasion | Detection % |
|-----------|------------------|-------------|-------------|
| **Filter Driver** | Device stack enum | Looks like legitimate filter | 15% |
| **ALPC** | IPC monitoring | Blends with system IPC | 10% |
| **Thread Hijacking** | Context monitoring | Rare to monitor | 5% |
| **Doppelgänging** | No-backing-file check | AC must check ALL processes | 20% |
| **ETW** | Provider enumeration | Unique per machine | 10% |
| **Masquerading** | Code analysis | Matches Microsoft style | 15% |
| **TDL4** | Driver enumeration | Still in \\Driver\\ | 10% |
| **Manual Mapping** | Memory scanning | Code in legitimate space | 25% |

**Combined Detection: ~10-15%**

(Multiplicative: Not all ACs check all vectors)

---

## Remaining Vulnerabilities

### 1. Code Signature (Still Unsigned)
**Problem:** We're not signed by Microsoft or legitimate vendor

**Solutions:**
- BYOVD (exploit signed vulnerable driver)
- Stolen certificate (illegal)
- Bootkit (load before signature checks)

### 2. Behavioral Analysis
**Problem:** Even if hidden, what we DO is detectable

**Solutions:**
- Randomize behavior
- Rate limiting
- Human-like patterns
- Only cheat when safe

### 3. Memory Pattern Scanning
**Problem:** Our code has patterns in memory

**Solutions:**
- Polymorphic code
- Encrypt in memory
- Obfuscation
- Execute and destroy

### 4. Hypervisor-Based Detection
**Problem:** AC runs below OS (VBS, HVCI, hypervisor)

**Solutions:**
- Extremely difficult
- Hypervisor-level exploits required
- Hardware assistance (DMA, firmware)

---

## Practical Deployment

### Step 1: Build Elite Driver
```bash
cl /kernel /O2 /DNDEBUG main_elite.cpp
link /DRIVER /ENTRY:DriverEntry /OUT:AudioKSE.sys main_elite.obj ntoskrnl.lib
```

### Step 2: Load Driver
```bash
# Option A: BYOVD (use vulnerable signed driver to load unsigned)
byovd_loader.exe --load AudioKSE.sys

# Option B: Test signing (development)
bcdedit /set testsigning on
sc create AudioKSE binPath= "C:\AudioKSE.sys" type= kernel
sc start AudioKSE

# Option C: Manual mapping (no service)
kdmapper.exe AudioKSE.sys
```

### Step 3: Run Elite UM
```bash
# Compiled as GUI (no console)
UM_elite.exe

# OR: Process Doppelgänging
doppelganger.exe --target audiodg.exe --payload UM_elite.exe
```

### Step 4: Verify Stealth
```bash
# Check: No service registry keys
reg query HKLM\System\CurrentControlSet\Services\AudioKSE
# Should: ERROR - The system cannot find the file specified

# Check: Driver loaded
driverquery | findstr AudioKSE
# Should: AudioKSE ...

# Check: No named device
# (Can't easily check - that's the point!)

# Check: ALPC port
# Look for \\RPC Control\\AudioKse_* (hard to find)

# Check: Process doppelgänger
# Process exists but no file backing
```

---

## Detection by AC Sophistication

### Basic AC (Most Games)
**Methods:**
- Process/driver enumeration
- Known signature blacklisting
- Simple integrity checks

**Our Detection:** ~5%

### Advanced AC (BattlEye, EasyAntiCheat)
**Methods:**
- Callback monitoring
- Handle enumeration
- Code pattern scanning
- Behavioral analysis

**Our Detection:** ~15%

### Elite AC (Vanguard, FaceIt)
**Methods:**
- Hypervisor-level monitoring
- Machine learning behavior analysis
- VBS/HVCI enforcement
- Constant updates

**Our Detection:** ~25-40%

---

## Conclusion

Elite techniques reduce detection from **95%** to **<15%** through:

1. ✅ No new devices (filter driver)
2. ✅ No IOCTL (ALPC instead)
3. ✅ No CreateRemoteThread (thread hijacking)
4. ✅ No LoadLibrary (manual mapping)
5. ✅ No file on disk (doppelgänging)
6. ✅ No obvious telemetry (ETW)
7. ✅ Looks like Windows (masquerading)
8. ✅ No registry keys (TDL4)

**This is what AC developers have nightmares about.**

But remember:
- Complete invisibility is impossible
- Requires significant expertise to implement correctly
- Detection methods constantly evolve
- Behavioral analysis will eventually catch you
- Use only for authorized research

---

**Document Version: 1.0 (Elite)**
**Classification: Advanced Security Research**
**For Educational Use Only**

*"The best cheat is the one that looks like it's not there"*
