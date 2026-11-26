# Phase 2.7 — Pre-Connection Module Inventory

## 1. Overview
This report documents all modules loaded by Radmin processes **before** any VPN network connection is established. Baseline captured at **2026-11-26 03:15 UTC**.

## 2. RvControlSvc.exe (PID 5572) — Module Inventory
**Total Modules**: 91  
**Process Type**: 32-bit Windows Service (WoW64)  
**Base Address**: 0x00E70000  
**Image Size**: 0x1D6000 (1,925,120 bytes)

### 2.1 Radmin-Owned Modules (Loaded by RvControlSvc.exe)

| Module | Base Address | Size | File Version | Path | Classification |
|--------|--------------|------|--------------|------|----------------|
| RvControlSvc.exe | 0x00E70000 | 0x1D6000 | 2.1.4952.2 | C:\Program Files (x86)\Radmin VPN\RvControlSvc.exe | **Radmin Primary** |
| RvROLClient.dll | 0x70570000 | 0x205000 | 2.1.4952.2 | C:\Program Files (x86)\Radmin VPN\RvROLClient.dll | **Radmin Core** |
| RvDownloader.dll | 0x6F940000 | 0xA7000 | 2.1.4952.2 | C:\Program Files (x86)\Radmin VPN\RvDownloader.dll | **Radmin Helper** |
| RvRolUpdater.dll | 0x6F9F0000 | 0xC7000 | 2.1.4952.2 | C:\Program Files (x86)\Radmin VPN\RvRolUpdater.dll | **Radmin Helper** |
| RvUESClient.dll | 0x72AD0000 | 0x2B000 | 2.1.4952.2 | C:\Program Files (x86)\Radmin VPN\RvUESClient.dll | **Radmin Helper** |
| Shelper.dll | 0x704B0000 | 0xBB000 | 4.0.0.4 | C:\Program Files (x86)\Radmin VPN\Shelper.dll | **Radmin Vendor** |

### 2.2 Third-Party / Open Source Libraries (Loaded by RvControlSvc.exe)

| Module | Base Address | Size | Version | Vendor | Path |
|--------|--------------|------|---------|--------|------|
| libcurl.dll | 0x70430000 | 0x74000 | 8.6.0 | curl project | C:\Program Files (x86)\Radmin VPN\libcurl.dll |
| libcrypto-3.dll | 0x6FAC0000 | 0x467000 | 3.6.1 | OpenSSL Project | C:\Program Files (x86)\Radmin VPN\libcrypto-3.dll |
| libssl-3.dll | 0x70320000 | 0x108000 | 3.6.1 | OpenSSL Project | C:\Program Files (x86)\Radmin VPN\libssl-3.dll |
| VCRUNTIME140.dll | 0x75290000 | 0x14000 | 14.29.30157.0 | Microsoft | C:\Program Files (x86)\Radmin VPN\VCRUNTIME140.dll |

### 2.3 Windows System Modules (Loaded by RvControlSvc.exe)
*Key system modules only — full list of 91 modules in evidence*

| Module | Base Address | Size | Path | Notes |
|--------|--------------|------|------|-------|
| ntdll.dll | 0x77DD0000 / 0x7FF9EB170000 | 0x1A4000 / 0x1F8000 | C:\Windows\SYSTEM32\ntdll.dll | Both WoW64 and native |
| KERNEL32.DLL | 0x75C40000 | 0xF0000 | C:\Windows\System32\KERNEL32.DLL | |
| KERNELBASE.dll | 0x76240000 | 0x239000 | C:\Windows\System32\KERNELBASE.dll | |
| ADVAPI32.dll | 0x760F0000 | 0x7D000 | C:\Windows\System32\ADVAPI32.dll | |
| msvcrt.dll | 0x76B70000 | 0xBF000 | C:\Windows\System32\msvcrt.dll | |
| RPCRT4.dll | 0x76520000 | 0xB9000 | C:\Windows\System32\RPCRT4.dll | |
| WS2_32.dll | 0x76B00000 | 0x63000 | C:\Windows\System32\WS2_32.dll | Network I/O |
| WININET.dll | 0x71B10000 | 0x455000 | C:\Windows\SYSTEM32\WININET.dll | HTTP/Internet |
| WINHTTP.dll | 0x6F870000 | 0xCA000 | C:\Windows\SYSTEM32\WINHTTP.dll | HTTP client |
| IPHLPAPI.DLL | 0x74AA0000 | 0x32000 | C:\Windows\SYSTEM32\IPHLPAPI.DLL | IP Helper API |
| DNSAPI.dll | 0x74AE0000 | 0x90000 | C:\Windows\SYSTEM32\DNSAPI.dll | DNS resolution |
| CRYPT32.dll | 0x765E0000 | 0xFF000 | C:\Windows\System32\CRYPT32.dll | Crypto API |
| bcrypt.dll | 0x76960000 | 0x19000 | C:\Windows\System32\bcrypt.dll | CNG crypto |
| bcryptPrimitives.dll | 0x77CE0000 | 0x5F000 | C:\Windows\System32\bcryptPrimitives.dll | CNG primitives |
| mswsock.dll | 0x70240000 | 0x52000 | C:\Windows\system32\mswsock.dll | Socket extensions |
| fwpuclnt.dll | 0x707C0000 | 0x58000 | C:\Windows\SYSTEM32\fwpuclnt.dll | Firewall API |
| netprofm.dll | 0x702A0000 | 0x32000 | C:\Windows\system32\netprofm.dll | Network profiles |

### 2.4 WMI / WBEM Modules (Notable — Service Context)
| Module | Base Address | Size | Notes |
|--------|--------------|------|-------|
| wbemprox.dll | 0x73D20000 | 0xD000 | WMI Proxy |
| wbemcomn.dll | 0x6F800000 | 0x70000 | WMI Common |
| wbemsvc.dll | 0x73120000 | 0x10000 | WMI Service |
| fastprox.dll | 0x6F730000 | 0xCA000 | WMI Fast Proxy |

### 2.5 WoW64 Subsystem Modules
| Module | Base Address | Size | Notes |
|--------|--------------|------|-------|
| wow64.dll | 0x7FF9E9730000 | 0x59000 | WoW64 core |
| wow64win.dll | 0x7FF9EAC60000 | 0x83000 | WoW64 Windows |
| wow64cpu.dll | 0x77DC0000 | 0xA000 | WoW64 CPU |

---

## 3. RvRvpnGui.exe (PID 1232) — Module Inventory
**Total Modules**: 125  
**Process Type**: 32-bit GUI Application (WoW64, Qt-based)  
**Base Address**: 0x00700000  
**Image Size**: 0xE08000 (14,712,832 bytes)

### 3.1 Radmin-Owned Modules (Loaded by RvRvpnGui.exe)

| Module | Base Address | Size | File Version | Path | Classification |
|--------|--------------|------|--------------|------|----------------|
| RvRvpnGui.exe | 0x00700000 | 0xE08000 | 2.1.4952.2 | C:\Program Files (x86)\Radmin VPN\RvRvpnGui.exe | **Radmin Primary** |

> **Note**: RvROLClient.dll, RvDownloader.dll, RvRolUpdater.dll, RvUESClient.dll, Shelper.dll are **NOT** loaded by the GUI process at baseline. They are only loaded by the service (RvControlSvc.exe).

### 3.2 Qt Framework Modules (Loaded by RvRvpnGui.exe)

| Module | Base Address | Size | Version | Path |
|--------|--------------|------|---------|------|
| Qt5Core.dll | 0x72BB0000 | 0x53C000 | 5.15.15.0 | C:\Program Files (x86)\Radmin VPN\Qt5Core.dll |
| Qt5Gui.dll | 0x723C0000 | 0x5E7000 | 5.15.15.0 | C:\Program Files (x86)\Radmin VPN\Qt5Gui.dll |
| Qt5Network.dll | 0x753B0000 | 0xCF000 | 5.15.15.0 | C:\Program Files (x86)\Radmin VPN\Qt5Network.dll |
| Qt5Quick.dll | 0x74E10000 | 0x361000 | 5.15.15.0 | C:\Program Files (x86)\Radmin VPN\Qt5Quick.dll |
| Qt5Widgets.dll | 0x71F70000 | 0x449000 | 5.15.15.0 | C:\Program Files (x86)\Radmin VPN\Qt5Widgets.dll |
| Qt5Qml.dll | 0x754B0000 | 0x2E2000 | 5.15.15.0 | C:\Program Files (x86)\Radmin VPN\Qt5Qml.dll |
| Qt5QmlModels.dll | 0x751D0000 | 0x59000 | 5.15.15.0 | C:\Program Files (x86)\Radmin VPN\Qt5QmlModels.dll |
| Qt5QuickControls2.dll | 0x75480000 | 0x24000 | 5.15.15.0 | C:\Program Files (x86)\Radmin VPN\Qt5QuickControls2.dll |
| Qt5QuickTemplates2.dll | 0x742C0000 | 0xEB000 | 5.15.15.0 | C:\Program Files (x86)\Radmin VPN\Qt5QuickTemplates2.dll |
| Qt5Svg.dll | 0x75360000 | 0x42000 | 5.15.15.0 | C:\Program Files (x86)\Radmin VPN\Qt5Svg.dll |
| Qt5WinExtras.dll | 0x75320000 | 0x33000 | 5.15.15.0 | C:\Program Files (x86)\Radmin VPN\Qt5WinExtras.dll |

### 3.3 Qt Plugin Modules (Loaded by RvRvpnGui.exe)

| Module | Base Address | Size | Version | Path |
|--------|--------------|------|---------|------|
| qwindows.dll | 0x731D0000 | 0x133000 | 5.15.15.0 | C:\Program Files (x86)\Radmin VPN\platforms\qwindows.dll |
| qwindowsvistastyle.dll | 0x740D0000 | 0x23000 | 5.15.15.0 | C:\Program Files (x86)\Radmin VPN\styles\qwindowsvistastyle.dll |
| qico.dll | 0x743F0000 | 0xB000 | 5.15.15.0 | C:\Program Files (x86)\Radmin VPN\imageformats\qico.dll |
| qgif.dll | 0x74200000 | 0xB000 | 5.15.15.0 | C:\Program Files (x86)\Radmin VPN\imageformats\qgif.dll |
| qsvg.dll | 0x740C0000 | 0xA000 | 5.15.15.0 | C:\Program Files (x86)\Radmin VPN\imageformats\qsvg.dll |

### 3.4 ICU (International Components for Unicode) Modules
| Module | Base Address | Size | Version | Path |
|--------|--------------|------|---------|------|
| icuuc74.dll | 0x75A60000 | 0x1D6000 | 74.1 | C:\Program Files (x86)\Radmin VPN\icuuc74.dll |
| icuin74.dll | 0x757A0000 | 0x2B7000 | 74.1 | C:\Program Files (x86)\Radmin VPN\icuin74.dll |
| icudt74.dll | 0x1F80000 | 0x1D5E000 | 74.1 | C:\Program Files (x86)\Radmin VPN\icudt74.dll |

### 3.5 Microsoft Visual C++ Runtime Modules
| Module | Base Address | Size | Version | Path |
|--------|--------------|------|---------|------|
| MSVCP140.dll | 0x752B0000 | 0x6D000 | 14.29.30157.0 | C:\Program Files (x86)\Radmin VPN\MSVCP140.dll |
| MSVCP140_1.dll | 0x751C0000 | 0x7000 | 14.29.30157.0 | C:\Program Files (x86)\Radmin VPN\MSVCP140_1.dll |
| VCRUNTIME140.dll | 0x75290000 | 0x14000 | 14.29.30157.0 | C:\Program Files (x86)\Radmin VPN\VCRUNTIME140.dll |

### 3.6 Windows System Modules (Key — Loaded by RvRvpnGui.exe)
| Module | Base Address | Size | Notes |
|--------|--------------|------|-------|
| ntdll.dll | 0x77DD0000 / 0x7FF9EB170000 | 0x1A4000 / 0x1F8000 | Both WoW64 and native |
| KERNEL32.DLL | 0x75C40000 | 0xF0000 | |
| KERNELBASE.dll | 0x76240000 | 0x239000 | |
| USER32.dll | 0x77470000 | 0x19D000 | GUI subsystem |
| win32u.dll | 0x75D90000 | 0x18000 | User-mode GUI |
| GDI32.dll | 0x76170000 | 0x23000 | Graphics |
| gdi32full.dll | 0x76000000 | 0xE7000 | Full GDI |
| d3d11.dll | 0x73680000 | 0x1E0000 | Direct3D 11 |
| dxgi.dll | 0x73DF0000 | 0xC5000 | DXGI |
| dwrite.dll | 0x71900000 | 0x20C000 | DirectWrite |
| d3d9.dll | 0x713C0000 | 0x192000 | Direct3D 9 (legacy) |
| dcomp.dll | 0x71250000 | 0x165000 | DirectComposition |
| combase.dll | 0x771F0000 | 0x280000 | COM base |
| ole32.dll | 0x75E30000 | 0xE3000 | OLE |
| OLEAUT32.dll | 0x76480000 | 0x96000 | OLE Automation |
| SHELL32.dll | 0x77700000 | 0x5DB000 | Shell |
| SHCORE.dll | 0x77670000 | 0x87000 | Shell core |
| shlwapi.dll | 0x76980000 | 0x49000 | Shell light-weight |
| windows.storage.dll | 0x74450000 | 0x619000 | Storage API |
| WS2_32.dll | 0x76B00000 | 0x63000 | Sockets |
| DNSAPI.dll | 0x74AE0000 | 0x90000 | DNS |
| IPHLPAPI.DLL | 0x74AA0000 | 0x32000 | IP Helper |
| WININET.dll | 0x71B10000 | 0x455000 | Internet |
| WINMM.dll | 0x75260000 | 0x28000 | Multimedia |
| CRYPT32.dll | 0x765E0000 | 0xFF000 | Crypto |
| bcryptPrimitives.dll | 0x77CE0000 | 0x5F000 | CNG primitives |

### 3.7 Additional Notable Modules (GUI-Specific)
| Module | Base Address | Size | Notes |
|--------|--------------|------|-------|
| comctl32.dll | 0x716E0000 | 0x211000 | Common Controls v6 |
| WindowsCodecs.dll | 0x71560000 | 0x172000 | Imaging codecs |
| dwmapi.dll | 0x75230000 | 0x26000 | Desktop Window Manager |
| UxTheme.dll | 0x74240000 | 0x74000 | Visual Styles |
| textinputframework.dll | 0x735C0000 | 0xB9000 | Text Input |
| CoreMessaging.dll | 0x73130000 | 0x9B000 | Core Messaging |
| CoreUIComponents.dll | 0x70E30000 | 0x27F000 | Core UI Components |
| twinapi.appcore.dll | 0x710B0000 | 0x191000 | App Core |
| iertutil.dll | 0x73860000 | 0x238000 | IE Runtime Utility |
| urlmon.dll | 0x73B70000 | 0x1AD000 | URL Moniker |

---

## 4. Cross-Process Module Comparison (Baseline)

| Module | RvControlSvc.exe (PID 5572) | RvRvpnGui.exe (PID 1232) |
|--------|------------------------------|---------------------------|
| RvControlSvc.exe | ✅ Primary | ❌ |
| RvRvpnGui.exe | ❌ | ✅ Primary |
| RvROLClient.dll | ✅ 0x70570000 | ❌ |
| RvDownloader.dll | ✅ 0x6F940000 | ❌ |
| RvRolUpdater.dll | ✅ 0x6F9F0000 | ❌ |
| RvUESClient.dll | ✅ 0x72AD0000 | ❌ |
| Shelper.dll | ✅ 0x704B0000 | ❌ |
| Qt5Core.dll | ❌ | ✅ 0x72BB0000 |
| Qt5Gui.dll | ❌ | ✅ 0x723C0000 |
| Qt5Network.dll | ❌ | ✅ 0x753B0000 |
| Qt5Quick.dll | ❌ | ✅ 0x74E10000 |
| Qt5Widgets.dll | ❌ | ✅ 0x71F70000 |
| Qt5Qml.dll | ❌ | ✅ 0x754B0000 |
| icuuc74.dll | ❌ | ✅ 0x75A60000 |
| icuin74.dll | ❌ | ✅ 0x757A0000 |
| icudt74.dll | ❌ | ✅ 0x1F80000 |
| libcurl.dll | ✅ 0x70430000 | ❌ |
| libcrypto-3.dll | ✅ 0x6FAC0000 | ❌ |
| libssl-3.dll | ✅ 0x70320000 | ❌ |
| VCRUNTIME140.dll | ✅ 0x75290000 | ✅ 0x75290000 (shared) |
| MSVCP140.dll | ❌ | ✅ 0x752B0000 |
| MSVCP140_1.dll | ❌ | ✅ 0x751C0000 |

---

## 5. Evidence Sources & Limitations

### 5.1 Enumeration Method
- **Primary**: Custom C# enumerator using PSAPI (`EnumProcessModulesEx`, `GetModuleFileNameEx`, `GetModuleInformation`) run as Administrator
- **Secondary**: WinDbg `lm` command output (attached to PID 5572)
- **Timestamps**: Baseline captured 2026-11-26 03:15 UTC

### 5.2 Limitations
1. **WoW64 processes**: Both Radmin processes are 32-bit running on 64-bit Windows; enumeration captures both 32-bit and 64-bit (WoW64 subsystem) modules
2. **Module list completeness**: PSAPI `LIST_MODULES_ALL` (0x03) used; may not capture manually mapped/reflected modules
3. **Symbol availability**: Many system modules show "deferred" symbols; version info from FileVersionInfo where available
4. **No memory dumps**: This is a non-intrusive enumeration only
5. **Third-party DLL hashes**: Not computed in this phase (only primary Radmin binaries hashed)
6. **Dynamic loads**: Modules loaded after baseline capture are not included here

### 5.3 Classification Definitions
- **Radmin Primary**: Main executable of the process
- **Radmin Core**: RvROLClient.dll — central Radmin library (loaded by service)
- **Radmin Helper**: RvDownloader, RvRolUpdater, RvUESClient — auxiliary Radmin DLLs
- **Radmin Vendor**: Shelper.dll — Famatech-signed but version differs (4.0.0.4)
- **Third-Party**: OpenSSL, libcurl, Qt, ICU — bundled dependencies
- **Windows System**: Microsoft-signed OS components

---
*Report generated: 2026-11-26 03:25 UTC*
*Evidence classification: Tool-reported (custom enumerator, WinDbg), Computed (addresses, sizes), Directly observed (file paths, versions)*