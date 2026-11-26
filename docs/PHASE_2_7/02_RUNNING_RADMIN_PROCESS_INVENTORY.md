# Phase 2.7 — Running Radmin Process Inventory

## 1. Identified Radmin Processes

### 1.1 RvControlSvc.exe (Service Process)
| Property | Value |
|----------|-------|
| Process Name | RvControlSvc.exe |
| Process ID (PID) | 5572 |
| Parent Process ID (PPID) | 592 (services.exe) |
| Session ID | 0 (Service session) |
| Start Time | 2026-11-26 02:44:04.939 UTC |
| Executable Path | C:\Program Files (x86)\Radmin VPN\RvControlSvc.exe |
| File Version | 2.1.4952.2 |
| Product Version | 2.1.4952.2 |
| Company | Famatech Corp. |
| SHA-256 | 0E2E6EAACBE8EBE01286CDA39A12EAAD34A20434D50F4F8BF2FDD91D4D6EF2AD |
| File Size | ~1.8 MB (1,925,120 bytes) |
| Architecture | 32-bit (WoW64) |
| Process Type | Windows Service |
| Command Line | (Not captured - service) |

### 1.2 RvRvpnGui.exe (GUI Process)
| Property | Value |
|----------|-------|
| Process Name | RvRvpnGui.exe |
| Process ID (PID) | 1232 |
| Parent Process ID (PPID) | 6912 (explorer.exe) |
| Session ID | 1 (Interactive user session) |
| Start Time | 2026-11-26 02:44:00.503 UTC |
| Executable Path | C:\Program Files (x86)\Radmin VPN\RvRvpnGui.exe |
| File Version | 2.1.4952.2 |
| Product Version | 2.1.4952.2 |
| Company | Famatech Corp. |
| SHA-256 | A9B093C68288AA8B8282FEBA37A254DDF45D8BEABFC9F575CF8B07620825739E |
| File Size | ~13.7 MB (14,398,328 bytes) |
| Architecture | 32-bit (WoW64) |
| Process Type | GUI Application (Qt-based) |
| Main Window Title | "Radmin VPN" |
| Main Window Handle | 0x525552 |
| Command Line | (Not captured - launched via Explorer) |

### 1.3 Other Radmin Binaries Present (Not Running)
| Binary | Path | SHA-256 | Version | Status |
|--------|------|---------|---------|--------|
| RvROLClient.dll | C:\Program Files (x86)\Radmin VPN\RvROLClient.dll | 018EECAB36CFD80BD307A385294702C4418B81A26ACF63484451F3D7CA8038A9 | 2.1.4952.2 | Loaded by both processes |
| RvDownloader.dll | C:\Program Files (x86)\Radmin VPN\RvDownloader.dll | 882B5ABEB4896AC42652682B1693E5AD20AFEEEF989169E96A17C086C42A31F2 | 2.1.4952.2 | Loaded by RvControlSvc |
| RvRolUpdater.dll | C:\Program Files (x86)\Radmin VPN\RvRolUpdater.dll | 0FE7F1B441A6869A2304D8EF6470D1A138AAAED69ED8DC394A888539E1842DCD | 2.1.4952.2 | Loaded by RvControlSvc |
| RvUESClient.dll | C:\Program Files (x86)\Radmin VPN\RvUESClient.dll | DF732E2A0815BC377D035B9F590C528400DC079AF4FC7F733A03884527743C5F | 2.1.4952.2 | Loaded by RvControlSvc |
| RvGuiStarter.exe | C:\Program Files (x86)\Radmin VPN\RvGuiStarter.exe | 2891A6DC87498AC85483E4C3E7FE51E0126483584D731B036E9F1C39A92703BE | 2.1.4952.2 | Not running |
| RvFwHelper.exe | C:\Program Files (x86)\Radmin VPN\RvFwHelper.exe | DBA18C5D039C2AF7031540156F6129AD61D707B434053EB36CDF499BE1065EE8 | 2.1.4952.2 | Not running |
| drvinst.exe | C:\Program Files (x86)\Radmin VPN\drvinst.exe | EADC3524E28AC20F879DFABFB901C96F5ED0BDE09DC09C202C505BC4CE0354B2 | 2.1.4952.2 | Not running |
| Radmin.exe | C:\Program Files (x86)\Radmin VPN\Radmin.exe | 5FC07F57D1D1A46BF080DD833511D5166235FFC2C00812FAF46D99F008384D21 | 3.5.2.0 | Not running (separate product) |

### 1.4 Third-Party / Supporting Binaries (Loaded)
| Binary | Path | SHA-256 | Version | Vendor |
|--------|------|---------|---------|--------|
| libcurl.dll | C:\Program Files (x86)\Radmin VPN\libcurl.dll | (not hashed) | 8.6.0 | curl project |
| libcrypto-3.dll | C:\Program Files (x86)\Radmin VPN\libcrypto-3.dll | (not hashed) | 3.6.1 | OpenSSL Project |
| libssl-3.dll | C:\Program Files (x86)\Radmin VPN\libssl-3.dll | (not hashed) | 3.6.1 | OpenSSL Project |
| Qt5Core.dll | C:\Program Files (x86)\Radmin VPN\Qt5Core.dll | (not hashed) | 5.15.15.0 | Qt Company |
| Qt5Gui.dll | C:\Program Files (x86)\Radmin VPN\Qt5Gui.dll | (not hashed) | 5.15.15.0 | Qt Company |
| Qt5Network.dll | C:\Program Files (x86)\Radmin VPN\Qt5Network.dll | (not hashed) | 5.15.15.0 | Qt Company |
| Qt5Quick.dll | C:\Program Files (x86)\Radmin VPN\Qt5Quick.dll | (not hashed) | 5.15.15.0 | Qt Company |
| Qt5Widgets.dll | C:\Program Files (x86)\Radmin VPN\Qt5Widgets.dll | (not hashed) | 5.15.15.0 | Qt Company |
| Qt5Qml.dll | C:\Program Files (x86)\Radmin VPN\Qt5Qml.dll | (not hashed) | 5.15.15.0 | Qt Company |
| icuuc74.dll | C:\Program Files (x86)\Radmin VPN\icuuc74.dll | (not hashed) | 74.1 | ICU Project |
| icuin74.dll | C:\Program Files (x86)\Radmin VPN\icuin74.dll | (not hashed) | 74.1 | ICU Project |
| icudt74.dll | C:\Program Files (x86)\Radmin VPN\icudt74.dll | (not hashed) | 74.1 | ICU Project |

## 2. Process Verification

### 2.1 RvControlSvc.exe Confirmation
- ✅ Confirmed as actual running service (PID 5572)
- ✅ Parent is services.exe (PID 592) — legitimate Windows service host
- ✅ Executable path matches installation directory
- ✅ File version matches installed binary (2.1.4952.2)
- ✅ SHA-256 matches known binary hash
- ✅ Not a stale process entry — actively running with handles, threads, memory
- ✅ No duplicate instances found

### 2.2 RvRvpnGui.exe Confirmation
- ✅ Confirmed as actual running GUI (PID 1232)
- ✅ Parent is explorer.exe (PID 6912) — launched by user
- ✅ Has visible main window ("Radmin VPN")
- ✅ Executable path matches installation directory
- ✅ File version matches installed binary (2.1.4952.2)
- ✅ SHA-256 matches known binary hash
- ✅ Not a stale process entry — actively running with UI
- ✅ No duplicate instances found

## 3. Process Relationships

```
services.exe (592)
  └── RvControlSvc.exe (5572)  [Service, Session 0]

explorer.exe (6912)
  └── RvRvpnGui.exe (1232)     [GUI, Session 1]
```

- No child processes spawned by either Radmin process at baseline
- No cross-process parent/child relationship between the two Radmin processes
- Both are top-level in their respective process trees

## 4. Limitations
- Module enumeration for 32-bit processes on 64-bit OS requires WoW64-aware tools
- Process command lines not captured for service (RvControlSvc) due to Windows service restrictions
- Some version info unavailable for system DLLs (deferred symbols in WinDbg)
- SHA-256 hashes computed only for primary Radmin binaries; third-party DLLs not hashed in this phase

---
*Report generated: 2026-11-26 03:15 UTC*
*Evidence classification: Directly observed (process enumeration), Tool-reported (WinDbg lm, custom enumerator), Computed (SHA-256)*