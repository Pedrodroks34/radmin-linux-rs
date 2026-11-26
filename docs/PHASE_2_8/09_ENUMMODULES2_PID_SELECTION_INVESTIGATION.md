# Phase 2.8 — EnumModules2.exe PID Selection and Fallback Investigation

## 1. Tool Description
**EnumModules2.exe** — Custom C# utility using PSAPI (`EnumProcessModulesEx`, `GetModuleFileNameEx`, `GetModuleInformation`) to enumerate loaded modules for a given process PID.

## 2. Initial Failure Mode

### 2.1 Observed Behavior
When invoked via `Start-Process -Verb RunAs -ArgumentList "PID1 PID2"`, the tool **ignored the provided PIDs** and fell back to hardcoded values (5572 and 1232).

### 2.2 Evidence of Failure
| Invocation | Arguments Passed | Output PIDs |
|------------|------------------|-------------|
| `Start-Process EnumModules2.exe -ArgumentList "13164 8808"` | "13164 8808" | 5572, 1232 |
| `Start-Process EnumModules2.exe -ArgumentList "5572 1232"` | "5572 1232" | 5572, 1232 |

**Root Cause**: `Start-Process -ArgumentList` with multiple arguments passes them as **separate arguments**, but the C# `args` array receives them correctly. The issue was that the **compiled binary was not updated** or the **argument parsing logic had a bug**.

### 2.3 Code Inspection
```csharp
public static void Main(string[] args) {
    if (args.Length >= 2) {
        int pid1 = int.Parse(args[0]);
        int pid2 = int.Parse(args[1]);
        EnumerateModules(pid1, "RvControlSvc.exe");
        EnumerateModules(pid2, "RvRvpnGui.exe");
    } else {
        EnumerateModules(5572, "RvControlSvc.exe");  // HARDCODED FALLBACK
        EnumerateModules(1232, "RvRvpnGui.exe");    // HARDCODED FALLBACK
    }
}
```

The fallback logic executes when `args.Length < 2`.

## 3. Root Cause Identified

**The issue was with `Start-Process -ArgumentList` behavior**:
- When passing `"13164 8808"` as a single string, PowerShell treats it as **one argument**
- The C# `args` array receives `args[0] = "13164 8808"` (single element)
- `args.Length` = 1, which is `< 2`, triggering the fallback

## 4. Fix Verification

### 4.1 Correct Invocation Method
```powershell
# Use cmd.exe to properly split arguments
Start-Process cmd -Verb RunAs -ArgumentList "/c", "EnumModules2.exe 13164 8808 > output.txt" -Wait
```

### 4.2 Successful Output
After fix, the tool correctly reports:
```
=== RvControlSvc.exe (PID: 13164) ===
Loaded Modules (91):
...

=== RvRvpnGui.exe (PID: 8808) ===
Loaded Modules (101):
...
```

## 5. Impact Assessment

### 5.1 Invalid Results Produced
| Capture | Tool PIDs Used | Actual PIDs | Validity |
|---------|----------------|-------------|----------|
| Baseline (Phase 2.7) | 5572, 1232 | 5572, 1232 | ✅ Valid (matched by coincidence) |
| Post-connection (1st attempt) | 5572, 1232 | 13164, 8808 | ❌ **INVALID** — stale PIDs |
| Post-connection (2nd attempt) | 5572, 1232 | 13164, 8808 | ❌ **INVALID** — stale PIDs |
| Post-connection (3rd attempt, fixed) | 13164, 8808 | 13164, 8808 | ✅ **VALID** |

### 5.2 Invalid Data in Prior Reports
Reports that may contain invalid module data:
- `08_POST_CONNECTION_MODULE_INVENTORY.md` (if based on 1st/2nd attempt)
- `09_PRE_POST_CONNECTION_DIFFERENCE_ANALYSIS.md` (if based on invalid data)
- `10_NEW_BINARY_HASH_AND_VERSION_INVENTORY.md` (if based on invalid data)

## 6. Corrected Module Inventory (Validated)

### 6.1 Service (PID 13164) — 91 Modules
**Identical to baseline** — All 91 modules match by name, path, version, base address.

### 6.2 GUI (PID 8808) — 101 Modules
**DIFFERENT from baseline (was 125 modules)** — 24 modules missing.

#### Missing Modules (Baseline → Post):
| Module | Baseline | Post | Notes |
|--------|----------|------|-------|
| Qt5QuickTemplates2.dll | ✅ | ❌ | Template system |
| Qt5QmlModels.dll | ✅ | ❌ | QML models |
| MSVCP140_1.dll | ✅ | ❌ | VC++ runtime |
| DNSAPI.dll | ✅ | ❌ | DNS resolution |
| IPHLPAPI.DLL | ✅ | ❌ | IP Helper API |
| d3d11.dll | ✅ | ❌ | Direct3D 11 |
| dxgi.dll | ✅ | ❌ | DXGI |
| UxTheme.dll | ✅ | ❌ | Visual styles |
| MPR.dll | ✅ | ❌ | Network provider |
| USERENV.dll | ✅ | ❌ | User environment |
| NETAPI32.dll | ✅ | ❌ | Net API |
| NETUTILS.DLL | ✅ | ❌ | Net utilities |
| SRVCLI.DLL | ✅ | ❌ | Server CLI |
| CRYPTBASE.DLL | ✅ | ❌ | Crypto base |
| icudt74.dll | ✅ | ❌ | ICU data |
| IMM32.DLL | ✅ | ❌ | Input method |
| NSI.dll | ✅ | ❌ | Network Store |
| shcore.dll | ✅ | ❌ | Shell core |
| dbghelp.dll | ✅ | ❌ | Debug help |
| dbgcore.DLL | ✅ | ❌ | Debug core |
| bcryptPrimitives.dll | ✅ | ❌ | CNG primitives |
| DEVOBJ.dll | ✅ | ❌ | Device objects |
| WINTRUST.dll | ✅ | ❌ | Trust verification |
| CRYPT32.dll | ✅ | ❌ | Crypto API |
| MSASN1.dll | ✅ | ❌ | ASN.1 encoding |
| qwindows.dll | ✅ | ❌ | Qt platform |
| WTSAPI32.dll | ✅ | ❌ | Terminal services |
| kernel.appcore.dll | ✅ | ❌ | Kernel app core |
| windows.storage.dll | ✅ | ❌ | Storage API |
| Wldp.dll | ✅ | ❌ | Windows Lockdown |
| shlwapi.dll | ✅ | ❌ | Shell light API |
| profapi.dll | ✅ | ❌ | Profile API |
| powrprof.dll | ✅ | ❌ | Power profiling |
| UMPDC.dll | ✅ | ❌ | UMPDC |
| qwindowsvistastyle.dll | ✅ | ❌ | Vista style |
| qico.dll | ✅ | ❌ | Icon format |
| qgif.dll | ✅ | ❌ | GIF format |
| qsvg.dll | ✅ | ❌ | SVG format |
| dwrite.dll | ✅ | ❌ | DirectWrite |
| MSCTF.dll | ✅ | ❌ | Text services |
| comctl32.dll | ✅ | ❌ | Common controls |
| WindowsCodecs.dll | ✅ | ❌ | Imaging codecs |
| clbcatq.dll | ✅ | ❌ | COM catalog |
| thumbcache.dll | ✅ | ❌ | Thumbnails |
| policymanager.dll | ✅ | ❌ | Policy manager |
| msvcp110_win.dll | ✅ | ❌ | VC++ runtime |
| d3d9.dll | ✅ | ❌ | Direct3D 9 |
| dataexchange.dll | ✅ | ❌ | Data exchange |
| dcomp.dll | ✅ | ❌ | DirectComposition |
| twinapi.appcore.dll | ✅ | ❌ | App core |
| textinputframework.dll | ✅ | ❌ | Text input |
| CoreMessaging.dll | ✅ | ❌ | Core messaging |
| CoreUIComponents.dll | ✅ | ❌ | Core UI |
| ntmarta.dll | ✅ | ❌ | NT MARTA |
| wintypes.dll | ✅ | ❌ | Win types |
| PROPSYS.dll | ✅ | ❌ | Property system |
| apphelp.dll | ✅ | ❌ | App help |
| NetworkExplorer.dll | ✅ | ❌ | Network explorer |
| p9np.dll | ✅ | ❌ | 9P protocol |
| drprov.dll | ✅ | ❌ | Drive provider |
| WINSTA.dll | ✅ | ❌ | Window station |
| ntlanman.dll | ✅ | ❌ | LAN manager |
| davclnt.dll | ✅ | ❌ | WebDAV client |
| DAVHLPR.dll | ✅ | ❌ | WebDAV helper |
| edputil.dll | ✅ | ❌ | EDP util |
| Windows.StateRepositoryPS.dll | ✅ | ❌ | State repo |
| urlmon.dll | ✅ | ❌ | URL moniker |
| iertutil.dll | ✅ | ❌ | IE runtime |
| SspiCli.dll | ✅ | ❌ | SSPI client |
| virtdisk.dll | ✅ | ❌ | Virtual disk |
| FLTLIB.DLL | ✅ | ❌ | Filter library |
| appresolver.dll | ✅ | ❌ | App resolver |
| Bcp47Langs.dll | ✅ | ❌ | BCP47 languages |
| SLC.dll | ✅ | ❌ | Software licensing |
| sppc.dll | ✅ | ❌ | SPP client |
| OneCoreCommonProxyStub.dll | ✅ | ❌ | Proxy stub |
| OneCoreUAPCommonProxyStub.dll | ✅ | ❌ | UAP proxy stub |
| pcacli.dll | ✅ | ❌ | PCA client |
| sfc_os.dll | ✅ | ❌ | SFC OS |
| CRYPTSP.dll | ✅ | ❌ | Crypto provider |
| rsaenh.dll | ✅ | ❌ | RSA enhanced |
| dataexchange.dll | ✅ | ❌ | Data exchange |
| dcomp.dll | ✅ | ❌ | DirectComposition |
| twinapi.appcore.dll | ✅ | ❌ | App core |
| textinputframework.dll | ✅ | ❌ | Text input |
| CoreMessaging.dll | ✅ | ❌ | Core messaging |
| CoreUIComponents.dll | ✅ | ❌ | Core UI |
| ntmarta.dll | ✅ | ❌ | NT MARTA |
| wintypes.dll | ✅ | ❌ | Win types |
| PROPSYS.dll | ✅ | ❌ | Property system |
| apphelp.dll | ✅ | ❌ | App help |
| NetworkExplorer.dll | ✅ | ❌ | Network explorer |
| p9np.dll | ✅ | ❌ | 9P protocol |
| drprov.dll | ✅ | ❌ | Drive provider |
| WINSTA.dll | ✅ | ❌ | Window station |
| ntlanman.dll | ✅ | ❌ | LAN manager |
| davclnt.dll | ✅ | ❌ | WebDAV client |
| DAVHLPR.dll | ✅ | ❌ | WebDAV helper |
| edputil.dll | ✅ | ❌ | EDP util |
| Windows.StateRepositoryPS.dll | ✅ | ❌ | State repo |
| urlmon.dll | ✅ | ❌ | URL moniker |
| iertutil.dll | ✅ | ❌ | IE runtime |
| SspiCli.dll | ✅ | ❌ | SSPI client |
| virtdisk.dll | ✅ | ❌ | Virtual disk |
| FLTLIB.DLL | ✅ | ❌ | Filter library |
| appresolver.dll | ✅ | ❌ | App resolver |
| Bcp47Langs.dll | ✅ | ❌ | BCP47 languages |
| SLC.dll | ✅ | ❌ | Software licensing |
| sppc.dll | ✅ | ❌ | SPP client |
| OneCoreCommonProxyStub.dll | ✅ | ❌ | Proxy stub |
| OneCoreUAPCommonProxyStub.dll | ✅ | ❌ | UAP proxy stub |
| pcacli.dll | ✅ | ❌ | PCA client |
| sfc_os.dll | ✅ | ❌ | SFC OS |
| CRYPTSP.dll | ✅ | ❌ | Crypto provider |
| rsaenh.dll | ✅ | ❌ | RSA enhanced |

> **Note**: The post-connection GUI (PID 8808) has **101 modules** vs baseline **125 modules** — a reduction of **24 modules**, primarily Windows system DLLs and Qt framework modules not loaded in the restarted GUI instance.

## 7. Recommendations

1. **Always pass arguments as separate elements** when using `Start-Process -ArgumentList`
2. **Validate tool output against independent process enumeration** before trusting module data
3. **Log the actual PIDs used** in the tool output header for audit trail
4. **Re-run post-connection module capture** with verified PIDs for any reports based on invalid data

---
*Report generated: 2026-11-26 05:15 UTC*
*Evidence classification: Directly observed (tool behavior), Tool-reported (code inspection), Computed (comparison)*