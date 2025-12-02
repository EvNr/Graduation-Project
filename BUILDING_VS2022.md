# Building Elite Stealth in Visual Studio 2022

## Prerequisites

### Required Software
1. **Visual Studio 2022** (Community, Professional, or Enterprise)
   - Download: https://visualstudio.microsoft.com/vs/

2. **Windows Driver Kit (WDK) 10**
   - Download: https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
   - **Must match your Windows SDK version**

3. **Windows SDK 10.0.19041.0 or later**
   - Usually installed with Visual Studio
   - Verify in Visual Studio Installer

### Visual Studio Workloads Required
- Desktop development with C++
- Windows Driver Kit (install WDK separately first)

---

## Step-by-Step Setup

### 1. Install Windows Driver Kit

```bash
# Run WDK installer
# Select: "Install Windows Driver Kit to this computer"
# SDK version: 10.0.19041 or later
# Verify installation: C:\Program Files (x86)\Windows Kits\10\
```

### 2. Configure Visual Studio

Open Visual Studio 2022, go to:
```
Tools → Options → Projects and Solutions → Build and Run
→ Set "MSBuild project build output verbosity" to "Detailed" (for debugging)
```

### 3. Open Solution

```
File → Open → Project/Solution
→ Navigate to: Graduation-Project\EliteStealth.sln
→ Click Open
```

You should see two projects:
- **EliteKernelDriver** (kernel driver)
- **EliteUserMode** (user-mode application)

---

## Building the Kernel Driver

### Configuration

Right-click **EliteKernelDriver** → Properties:

**General:**
- Configuration: All Configurations
- Platform: x64
- Target OS Version: Windows 10
- Target Platform: Desktop

**C/C++ → General:**
- Warning Level: Level 4 (/W4)
- Treat Warnings As Errors: No

**C/C++ → Preprocessor:**
- Debug: `_DEBUG;DBG=1`
- Release: `NDEBUG`

**Linker → General:**
- Entry Point: `DriverEntry`

### Build Steps

1. Select configuration:
   - **Debug** (for testing with DbgPrint)
   - **Release** (for production, no debug output)

2. Select platform: **x64**

3. Build:
   ```
   Right-click EliteKernelDriver → Build
   OR
   Build → Build EliteKernelDriver
   OR
   Ctrl+Shift+B (build solution)
   ```

### Output

```
bin\x64\Debug\AudioKSE.sys      (Debug build)
bin\x64\Release\AudioKSE.sys    (Release build)
```

### Common Errors & Fixes

**Error: "Cannot open include file: 'ntddk.h'"**
```
Solution: Install WDK 10
Verify: C:\Program Files (x86)\Windows Kits\10\Include\<version>\km\ntddk.h exists
```

**Error: "LNK1561: entry point must be defined"**
```
Solution: Set entry point to DriverEntry
Project Properties → Linker → Advanced → Entry Point: DriverEntry
```

**Error: "MSB8040: Spectre-mitigated libraries are required"**
```
Solution: Install Spectre libraries via Visual Studio Installer
OR disable: C/C++ → Code Generation → Spectre Mitigation: Disabled
```

---

## Building the User Mode Application

### Configuration

Right-click **EliteUserMode** → Properties:

**General:**
- Configuration Type: Application (.exe)
- Platform Toolset: Visual Studio 2022 (v143)
- Character Set: Unicode

**C/C++ → General:**
- Warning Level: Level 3 (/W3)

**C/C++ → Preprocessor:**
- Debug: `_DEBUG;_CONSOLE`
- Release: `NDEBUG;_WINDOWS`

**C/C++ → Code Generation:**
- Runtime Library: Multi-threaded (/MT) for Release

**Linker → System:**
- SubSystem: Console (Debug), Windows (Release)

**Linker → Input:**
- Additional Dependencies: `ntdll.lib;kernel32.lib;user32.lib;advapi32.lib;ole32.lib`

### Build Steps

1. Select configuration:
   - **Debug** (console window, debug output)
   - **Release** (no console, GUI only)

2. Select platform: **x64**

3. Build:
   ```
   Right-click EliteUserMode → Build
   ```

### Output

```
bin\x64\Debug\AudioDiagnostic.exe      (Debug with console)
bin\x64\Release\AudioDiagnostic.exe    (Release, no console)
```

### Common Errors & Fixes

**Error: "Cannot open include file: 'winternl.h'"**
```
Solution: Should be in Windows SDK
Verify SDK installation in Visual Studio Installer
```

**Error: "Unresolved external symbol NtAlpcConnectPort"**
```
Solution: Link ntdll.lib
Project Properties → Linker → Input → Additional Dependencies: ntdll.lib
```

**Error: "warning C4996: 'freopen': This function or variable may be unsafe"**
```
Solution: Ignore (it's for debug console redirection)
OR add preprocessor: _CRT_SECURE_NO_WARNINGS
```

---

## Building Both Projects

### Quick Build

```
Build → Build Solution (Ctrl+Shift+B)
```

This builds both projects in sequence.

### Batch Build

```
Build → Batch Build
→ Check both Debug and Release for both projects
→ Click "Build"
```

Builds all configurations at once.

---

## Testing the Build

### 1. Verify Outputs

Check that files exist:
```
bin\x64\Release\AudioKSE.sys           (Kernel driver)
bin\x64\Release\AudioDiagnostic.exe    (User mode)
```

### 2. Check Driver Properties

Right-click `AudioKSE.sys` → Properties:
- Type: Driver (.sys)
- Size: ~50-150 KB
- Should have **no** digital signature (expected)

### 3. Load Driver (Test Signing)

```batch
# Enable test signing (requires restart)
bcdedit /set testsigning on
# Restart computer

# Load driver
sc create AudioKSE binPath= "C:\full\path\to\AudioKSE.sys" type= kernel
sc start AudioKSE

# Verify loaded
driverquery | findstr AudioKSE
```

### 4. Run User Mode

```batch
# Debug build (has console)
bin\x64\Debug\AudioDiagnostic.exe

# Release build (no console)
bin\x64\Release\AudioDiagnostic.exe
```

---

## Debugging

### Kernel Driver Debugging

**Option 1: DebugView (Easy)**
```
1. Download DebugView from Sysinternals
2. Run as Administrator
3. Enable "Capture Kernel"
4. Load debug build of driver
5. See DbgPrint output in real-time
```

**Option 2: WinDbg (Advanced)**
```
1. Set up kernel debugging (host + target machines)
2. Configure debug connection (network, serial, USB)
3. Attach WinDbg to target
4. Set breakpoints in driver code
5. Step through kernel code
```

### User Mode Debugging

**In Visual Studio:**
```
1. Set EliteUserMode as startup project
2. Set breakpoints in code (F9)
3. Press F5 (Start Debugging)
4. Step through code (F10 = step over, F11 = step into)
```

**Attach to Running Process:**
```
Debug → Attach to Process
→ Find AudioDiagnostic.exe
→ Attach
```

---

## Clean Build

If you encounter weird errors:

```
Build → Clean Solution
→ Manually delete bin\ and obj\ folders
→ Build → Rebuild Solution
```

---

## Release Build Checklist

Before final release build:

### Kernel Driver
- [ ] `#define ELITE_DBG` disabled (check main_elite_final.cpp)
- [ ] Configuration: Release
- [ ] Platform: x64
- [ ] Code optimization: MaxSpeed
- [ ] All debug code removed

### User Mode
- [ ] `#ifdef _DEBUG` blocks won't compile (check UM_elite_final.cpp)
- [ ] Configuration: Release
- [ ] Platform: x64
- [ ] SubSystem: Windows (not Console)
- [ ] Runtime Library: Multi-threaded (/MT)

### Both
- [ ] Builds without errors
- [ ] Builds without warnings
- [ ] Test on clean Windows 10/11 VM
- [ ] Verify detection evasion

---

## Troubleshooting

### "Cannot find ntoskrnl.lib"

**Solution:**
```
Project Properties → Linker → General → Additional Library Directories
Add: $(DDK_LIB_PATH)
OR: C:\Program Files (x86)\Windows Kits\10\Lib\<version>\km\x64
```

### "DriverEntry" not recognized

**Solution:**
```
extern "C" NTSTATUS DriverEntry(...) must be present
Check that it's not inside namespace or class
```

### "Windows SDK version not found"

**Solution:**
```
Right-click project → Retarget Projects
→ Select installed SDK version
→ Click OK
```

### IntelliSense shows errors but builds fine

**Solution:**
```
This is normal for kernel drivers
IntelliSense doesn't understand kernel headers fully
If it builds, ignore red squiggles
```

---

## Performance Tips

### Faster Builds

1. **Use SSD** for source code location
2. **Disable antivirus** for project folder (temporarily)
3. **Close unnecessary programs** while building
4. **Use parallel builds**: Tools → Options → Projects and Solutions → Build and Run → "maximum number of parallel project builds" = CPU cores

### Reduce Build Time

```
Project Properties → C/C++ → General
→ Multi-processor Compilation: Yes (/MP)
```

---

## Distribution

### For Testing
```
Distribute:
- AudioKSE.sys (driver)
- AudioDiagnostic.exe (user mode)
- Instructions for loading

Keep source code private!
```

### For Research
```
Package:
- Full source code
- Project files
- Documentation (ELITE_TECHNIQUES.md)
- Build instructions (this file)
- Research paper/report

License appropriately!
```

---

## Next Steps

After successful build:

1. **Test in VM** - Don't test on main system!
2. **Verify stealth** - Check detection vectors
3. **Test functionality** - Ensure it does what you need
4. **Document behavior** - For your graduation project
5. **Prepare defense** - Explain techniques to committee

---

## Support

### If Build Fails

Check:
1. WDK installed correctly
2. SDK version matches
3. Platform is x64 (not x86 or ARM)
4. All dependencies in project properties
5. Clean and rebuild

### If Runtime Fails

Check:
1. Driver signed (test signing mode)
2. Driver loaded successfully
3. User mode has correct permissions
4. Target process exists
5. Debug output for errors

---

**Now compile and dominate. 💀**

---

*Document Version: 1.0*
*Target: Visual Studio 2022 (v143)*
*Platform: x64 Windows 10/11*
*WDK: 10.0.19041+*
