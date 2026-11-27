# RUNTIME_OBSERVATIONS — Consolidated Draft (Phase 2.7 + Phase 2.8)

Consolidation of all 27 sources mapped to `RUNTIME_OBSERVATIONS` in
`analysis_workspace/compaction/mapping.tsv`: 12 Phase 2.7 reports and
15 Phase 2.8 reports. The 30 per-stage reports (13 Phase 2.7 + 17 Phase
2.8) are deduplicated here; every technical fact is preserved. Verbatim
PIDs, port numbers, module counts, timestamps (UTC and local), tool
names, named pipe details, SCM event ids, and evidence classifications
are retained.

Organization: environment/tool validation; process and service inventory;
module inventories; network endpoints; event timeline; IPC observation;
static/runtime correlation; evidence limitations.

## 1. Environment and Tool Validation

### 1.1 Operating system and repository (both phases)

| Property | Phase 2.7 value | Phase 2.8 value |
|----------|-----------------|-----------------|
| OS | Microsoft Windows 10 Pro | Microsoft Windows 10 Pro |
| Version | 10.0.19045 (Build 19045) | 10.0.19045 (Build 19045) |
| Architecture | x64 (64-bit) | x64 (64-bit) |
| PowerShell | 5.1.19041.3636 | 5.1.19041.3636 |
| Time zone | Not recorded | UTC-3 (Brazil) |
| Current UTC time | Not recorded | 2026-11-26 03:30 UTC |
| Local time | Not recorded | 2026-11-26 00:30 (UTC-3) |

- Canonical repository: https://github.com/Pedrodroks34/radmin-linux-rs.git
- Local path: `C:\Users\Rhuan\radmin-linux-rs`
- Branch: `main`, remote `origin`, working tree clean in both phases
- Phase 2.7 reference commit: `92fafa0` (main branch HEAD)
- Phase 2.8 baseline commit: `0dbe920` (Phase 2.7 publication)
- Report directories: `docs/PHASE_2_7/` (created 2026-11-26 03:00 UTC) and
  `docs/PHASE_2_8/` (created 2026-11-26 03:30 UTC)
- Evidence sources: `[System.Environment]::OSVersion`, `git status`, `git log`,
  `git remote -v`, `git branch -a`; classified Directly observed.

### 1.2 Monitoring tools assessed

| Tool | Phase 2.7 status | Phase 2.8 status | Notes |
|------|------------------|------------------|-------|
| WinDbg | Attached to RvControlSvc.exe (PID 5572); session PID 9632, pipe `WinDbg-MCP-9632` | Not used (no live debug session) | Covers module loads, process events, debugger events; service only, not GUI |
| EnumModules2.exe | Custom C# PSAPI wrapper (`EnumProcessModulesEx`, `GetModuleFileNameEx`, `GetModuleInformation`), run as Administrator | Same tool; PID-selection bug found and fixed (see section 1.4) | Snapshot only, both PIDs (5572/1232 baseline; 13164/8808 post-connection after fix) |
| PowerShell / WMI / CIM | `Get-Process`, `Get-NetTCPConnection`, `Get-NetUDPEndpoint`, `Get-CimInstance Win32_Process` | Same + `Get-CimInstance Win32_Service`, `Get-WinEvent`, `Get-ChildItem \\.\pipe\` | Snapshot only, no real-time event stream |
| WPR (Windows Performance Recorder) | Not configured | ❌ Failed: error 0xc5585011 "Failed to enable the policy to profile system performance" | Requires Administrator elevation |
| logman (ETW trace sessions) | Not configured | ❌ Failed: "Acesso negado" (Access denied) | Standard user session, lacks SeDebugPrivilege/SeSecurityPrivilege |
| PowerShell ETW cmdlets | N/A | ❌ Not available in PowerShell 5.1 | |
| Procmon | Not configured | ❌ Not installed (no standard locations, not in PATH) | Would require download, installer, EULA, kernel driver Procmon24.sys |
| Handle.exe (Sysinternals) | Not used | ❌ Not in PATH | Alternative: `Get-ChildItem \\.\pipe\` |

Available ETW providers verified via `logman query providers` (Phase 2.8) but
not capturable without elevation: Microsoft-Windows-Kernel-Process
`{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`, Microsoft-Windows-RPC,
Microsoft-Windows-RPC-Events, Microsoft-Windows-Services, Service Control
Manager `{555908D1-A6D7-4695-8E1E-26931D2012F4}`, Service Control Manager
Trace. Microsoft-Windows-ALPC not found as a separate provider.

### 1.3 Monitoring scope (Phase 2.7 configuration, carried into Phase 2.8)

- Include: RvControlSvc.exe, RvRvpnGui.exe, child processes, RvFwHelper.exe,
  drvinst.exe, RvGuiStarter.exe if spawned; exclude all other processes
- File system filters (on-demand only, not automated): `C:\Program Files (x86)\Radmin VPN\`,
  extensions .exe .dll .sys .dat .cfg .log
- Network filters: PIDs, TCP/UDP, endpoint changes
- Module load filters: new module loads, Radmin-owned DLLs, VPN-related modules

### 1.4 EnumModules2.exe PID-selection investigation (Phase 2.8, report 09)

- Initial failure: `Start-Process -Verb RunAs -ArgumentList "13164 8808"` caused the
  tool to ignore provided PIDs and fall back to hardcoded values (5572, 1232).
- Root cause: PowerShell passes `"13164 8808"` as a single string argument, so the
  C# `args` array has length 1 (`< 2`), triggering the hardcoded fallback
  (`EnumerateModules(5572, ...)`, `EnumerateModules(1232, ...)`).
- Fix: `Start-Process cmd -Verb RunAs -ArgumentList "/c", "EnumModules2.exe 13164 8808 > output.txt" -Wait`
- Impact: Phase 2.7 baseline captures (5572/1232) valid by coincidence; Phase 2.8
  post-connection attempts 1 and 2 used stale PIDs and are INVALID; attempt 3
  (fixed) on 13164/8808 is VALID.

## 2. Process and Service Inventory

### 2.1 Radmin processes identified

Phase 2.7 (baseline 2026-11-26 03:15 UTC):

| Property | RvControlSvc.exe (service) | RvRvpnGui.exe (GUI) |
|----------|---------------------------|---------------------|
| PID | 5572 | 1232 |
| PPID | 592 (services.exe) | 6912 (explorer.exe) |
| Session | 0 (service) | 1 (interactive) |
| Start time | 2026-11-26 02:44:04.939 UTC | 2026-11-26 02:44:00.503 UTC |
| Executable | `C:\Program Files (x86)\Radmin VPN\RvControlSvc.exe` | `C:\Program Files (x86)\Radmin VPN\RvRvpnGui.exe` |
| Command line | Not captured (service) | Not captured (launched via Explorer) |
| File / Product version | 2.1.4952.2 | 2.1.4952.2 |
| Company | Famatech Corp. | Famatech Corp. |
| SHA-256 | 0E2E6EAACBE8EBE01286CDA39A12EAAD34A20434D50F4F8BF2FDD91D4D6EF2AD | A9B093C68288AA8B8282FEBA37A254DDF45D8BEABFC9F575CF8B07620825739E |
| File size | ~1.8 MB (1,925,120 bytes) | ~13.7 MB (14,398,328 bytes) |
| Architecture | 32-bit (WoW64) | 32-bit (WoW64) |
| Process type | Windows service | GUI application (Qt-based) |
| Main window | — | "Radmin VPN", handle 0x525552 |
| Threads / handles / working set | 16 / 527 / ~23.5 MB | 11 / 505 / ~86.4 MB |
| Virtual memory | ~145 MB | ~337 MB |

Phase 2.8 (baseline 2026-11-26 ~03:33 local / 06:33 UTC):

| Property | RvControlSvc.exe (PID 13164) | RvRvpnGui.exe (PID 5760) |
|----------|-----------------------------|--------------------------|
| PID | 13164 | 5760 |
| PPID | 592 (services.exe) | 6912 (explorer.exe) |
| Session | 0 | 1 |
| Start time | 03:33:28 local (06:33:28 UTC) | 03:10:33 local (06:10:33 UTC) |
| Command line | `/service` | `/show` |
| File / Product version | 2.1.4952.2 | 2.1.4952.2 |
| SHA-256 | 0E2E6EAACBE8EBE01286CDA39A12EAAD34A20434D50F4F8BF2FDD91D4D6EF2AD | A9B093C68288AA8B8282FEBA37A254DDF45D8BEABFC9F575CF8B07620825739E |
| Architecture | 32-bit (WoW64) | 32-bit (WoW64) |

Phase 2.8 post-connection GUI: PID 8808, start time
03:42:35 local (06:42:35 UTC), command line `/show`, parent 6912, session 1.

### 2.2 Service details (Phase 2.8, report 04)

| Property | Value |
|----------|-------|
| Service name | RvControlSvc |
| Display name | Radmin VPN Control Service |
| State | Running (baseline) |
| Start mode | Auto |
| Service type | Own Process |
| Error control | Normal |
| Start account | LocalSystem |
| Executable | `"C:\Program Files (x86)\Radmin VPN\RvControlSvc.exe" /service` |
| Service PID | 13164 |

### 2.3 SCM event history (Phase 2.8 baseline, report 07)

| Time (local) | Event ID | Message | Interpretation |
|--------------|----------|---------|----------------|
| 26/11/2026 02:39:56 | 7034 | Service terminated unexpectedly (1st occurrence) | Crash |
| 26/11/2026 02:43:52 | 7034 | Service terminated unexpectedly (2nd occurrence) | Crash |
| 26/11/2026 03:11:03 | 7034 | Service terminated unexpectedly (3rd occurrence) | Crash |
| 26/11/2026 03:13:32 | 7034 | Service terminated unexpectedly (4th occurrence) | Crash |
| 26/11/2026 03:14:52 | 7034 | Service terminated unexpectedly (5th occurrence) | Crash |

Total crashes (last 24h): 5+. Crash frequency: every ~1-2 minutes during
Phase 2.7. Current instance (PID 13164) started 03:33:28 local and was
stable (~42 minutes uptime at baseline). SCM event ids monitored: 7034
(crash), 7036 (state change), 7031 (error limit), 7023/7024 (terminated
with error).

### 2.4 Helper binaries present but not running (baseline, both phases)

| Binary | Path | Purpose | Expected trigger |
|--------|------|---------|------------------|
| RvGuiStarter.exe | `C:\Program Files (x86)\Radmin VPN\RvGuiStarter.exe` | GUI launcher / elevation helper | GUI startup |
| RvFwHelper.exe | `C:\Program Files (x86)\Radmin VPN\RvFwHelper.exe` | Firewall rule management | VPN connection |
| drvinst.exe | `C:\Program Files (x86)\Radmin VPN\drvinst.exe` | NDIS driver installation | First run / driver update |
| Radmin.exe | `C:\Program Files (x86)\Radmin VPN\Radmin.exe` | Radmin Viewer/Server (separate product, v3.5.2.0) | Not part of VPN |

None of the helper processes were running at baseline in either phase. No
child processes spawned by RvControlSvc.exe or RvRvpnGui.exe at baseline.

### 2.5 Process tree

Phase 2.7 baseline:
```
services.exe (592)
  └── RvControlSvc.exe (5572)  [Service, Session 0]
explorer.exe (6912)
  └── RvRvpnGui.exe (1232)     [GUI, Session 1]
```

Phase 2.8 baseline:
```
services.exe (592)
  └── RvControlSvc.exe (13164)  [Service, Session 0, LocalSystem]
explorer.exe (6912)
  └── RvRvpnGui.exe (5760)      [GUI, Session 1, User, /show]
```

Phase 2.8 post-connection:
```
services.exe (592)
  └── RvControlSvc.exe (13164)  [STABLE]
explorer.exe (6912)
  └── RvRvpnGui.exe (8808)      [RESTARTED at 03:42:35 local]
```

No direct parent/child relationship between the two Radmin processes; they
communicate via IPC (named pipes / RPC / ALPC), not process hierarchy.
Service runs in Session 0; GUI in Session 1.

## 3. Module Inventories

### 3.1 Counts summary

| Phase | Capture | Process (PID) | Module count | Base address | Image size |
|-------|---------|---------------|--------------|--------------|------------|
| 2.7 | Baseline | RvControlSvc.exe (5572) | 91 | 0x00E70000 | 0x1D6000 (1,925,120 bytes) |
| 2.7 | Baseline | RvRvpnGui.exe (1232) | 125 | 0x00700000 | 0xE08000 (14,712,832 bytes) |
| 2.7 | Post-connection | RvControlSvc.exe (5476) | 91 | 0x00E70000 | 0x1D6000 |
| 2.7 | Post-connection | RvRvpnGui.exe (1232) | 125 | 0x00700000 | 0xE08000 |
| 2.8 | Baseline | RvControlSvc.exe (13164) | 91 | 0x00E70000 | 0x1D6000 |
| 2.8 | Baseline | RvRvpnGui.exe (5760) | 125 | 0x00700000 | 0xE08000 |
| 2.8 | Post-connection | RvControlSvc.exe (13164) | 91 | 0x00E70000 | 0x1D6000 |
| 2.8 | Post-connection | RvRvpnGui.exe (8808) | 101 | — (ASLR differs) | — |

Total unique modules baseline (both phases): ~172 (some shared, e.g. ntdll.dll,
KERNEL32.DLL).

### 3.2 Radmin-owned modules (loaded by service, both phases)

| Module | Base address | Size | Version | Path | Classification |
|--------|-------------|------|---------|------|----------------|
| RvControlSvc.exe | 0x00E70000 | 0x1D6000 | 2.1.4952.2 | `...\RvControlSvc.exe` | Radmin Primary |
| RvROLClient.dll | 0x70570000 | 0x205000 | 2.1.4952.2 | `...\RvROLClient.dll` | Radmin Core |
| RvDownloader.dll | 0x6F940000 | 0xA7000 | 2.1.4952.2 | `...\RvDownloader.dll` | Radmin Helper |
| RvRolUpdater.dll | 0x6F9F0000 | 0xC7000 | 2.1.4952.2 | `...\RvRolUpdater.dll` | Radmin Helper |
| RvUESClient.dll | 0x72AD0000 | 0x2B000 | 2.1.4952.2 | `...\RvUESClient.dll` | Radmin Helper |
| Shelper.dll | 0x704B0000 | 0xBB000 | 4.0.0.4 | `...\Shelper.dll` | Radmin Vendor |

GUI process loads no Radmin-owned DLLs at baseline (only its own executable);
RvROLClient.dll, RvDownloader.dll, RvRolUpdater.dll, RvUESClient.dll,
Shelper.dll are loaded by the service only.

### 3.3 Third-party modules (service, both phases)

| Module | Version | Vendor |
|--------|---------|--------|
| libcurl.dll | 8.6.0 | curl project |
| libcrypto-3.dll | 3.6.1 | OpenSSL Project |
| libssl-3.dll | 3.6.1 | OpenSSL Project |
| VCRUNTIME140.dll | 14.29.30157.0 | Microsoft |

GUI additionally loads MSVCP140.dll, MSVCP140_1.dll (14.29.30157.0),
Qt5* (5.15.15.0), ICU 74.1.

### 3.4 GUI module reduction (Phase 2.8, validated via fixed EnumModules2)

GUI baseline (PID 5760): 125 modules. GUI post-connection (PID 8808): 101
modules (−24). Missing categories: 4 Qt plugins
(qwindowsvistastyle, qico, qgif, qsvg), 2 Qt modules (Qt5QuickTemplates2,
Qt5QmlModels), 1 VC++ runtime (MSVCP140_1), 6 DirectX modules
(d3d11, dxgi, d3d9, dwrite, dataexchange, dcomp), ~16 Windows UI modules,
~20 system/network modules. Note: many "missing" modules are Windows system
DLLs that may be delay-loaded; the restarted GUI instance had not yet
triggered their load. Service module inventory identical (91/91) across
PID 13164 vs Phase 2.7 PID 5572.

### 3.5 SHA-256 hashes (primary Radmin binaries)

- RvControlSvc.exe: 0E2E6EAACBE8EBE01286CDA39A12EAAD34A20434D50F4F8BF2FDD91D4D6EF2AD
- RvRvpnGui.exe: A9B093C68288AA8B8282FEBA37A254DDF45D8BEABFC9F575CF8B07620825739E
- RvROLClient.dll: 018EECAB36CFD80BD307A385294702C4418B81A26ACF63484451F3D7CA8038A9
- RvDownloader.dll: 882B5ABEB4896AC42652682B1693E5AD20AFEEEF989169E96A17C086C42A31F2
- RvRolUpdater.dll: 0FE7F1B441A6869A2304D8EF6470D1A138AAAED69ED8DC394A888539E1842DCD
- RvUESClient.dll: DF732E2A0815BC377D035B9F590C528400DC079AF4FC7F733A03884527743C5F
- Shelper.dll: D89DAF6BCD5CAFA3C7F6173F835CCF045BAF8E7134F868819DB6FD7615959AC4 (v4.0.0.4)
- RvFwHelper.exe: DBA18C5D039C2AF7031540156F6129AD61D707B434053EB36CDF499BE1065EE8 (not spawned)
- drvinst.exe: EADC3524E28AC20F879DFABFB901C96F5ED0BDE09DC09C202C505BC4CE0354B2 (not spawned)
- RvGuiStarter.exe: 2891A6DC87498AC85483E4C3E7FE51E0126483584D731B036E9F1C39A92703BE (not spawned)

All post-connection binaries match baseline hashes; no new binaries loaded.
Third-party DLLs not hashed in Phase 2.7.

### 3.6 ASLR notes

Phase 2.7: base addresses identical across service restart (PID 5572 → 5476),
same boot session, no reboot. Phase 2.8: base addresses differ across
process instances (expected ASLR).

## 4. Network Endpoints

### 4.1 Phase 2.7

Baseline (PID 5572, 2026-11-26 03:15 UTC):
- UDP: 26.82.29.1:56413 (Radmin VPN virtual adapter address; listening)
- TCP: none owned by PID 5572
- GUI (PID 1232): no TCP or UDP endpoints

Post-connection (PID 5476):
- TCP: 192.168.31.111:59509 → 148.113.190.78:17301 (ESTABLISHED, VPN relay)
- TCP: 0.0.0.0:59509 (LISTENING, local listener for peer traffic)
- UDP: 26.82.29.1:56413 closed (virtual adapter listener gone)
- GUI (PID 1232): no endpoints (uses IPC, not direct network)

### 4.2 Phase 2.8

Baseline (PID 13164, ~03:33 local):
- TCP: 0.0.0.0:62654 (BOUND), 192.168.31.111:62654 → 148.113.190.78:17301
  (ESTABLISHED), 192.168.31.111:62654 (LISTEN)
- UDP: 26.82.29.1:49237 (VPN virtual adapter, ephemeral port)
- GUI (PID 5760): no endpoints

Post-Connect capture 1 (~03:41 local, PID 13164):
- TCP local port 62654 → 65157, remote 148.113.190.78:17301 (ESTABLISHED +
  LISTEN)

Post-GUI-restart capture 2 (~03:43 local, PID 13164):
- TCP local port 65157 → 65199, remote 148.113.190.78:17301 (ESTABLISHED +
  LISTEN)
- UDP: 26.82.29.1:49237 stable throughout
- GUI (PID 8808): no endpoints

Remote endpoint unchanged throughout Phase 2.8: 148.113.190.78:17301
(Radmin relay server). Port 17301 is the known Radmin VPN relay/control
port (corroborated by prior PCAP analysis). Local port 62654 changed twice
(62654 → 65157 after user Connect; 65157 → 65199 after GUI restart).

### 4.3 Comparison Phase 2.7 vs 2.8

| Metric | Phase 2.7 | Phase 2.8 |
|--------|-----------|-----------|
| Service UDP | 26.82.29.1:56413 (baseline), closed post | 26.82.29.1:49237 (stable throughout) |
| Service TCP baseline | None (only UDP) | 62654 → 17301 (Established) |
| Service TCP post | 59509 → 17301 | 65157/65199 → 17301 |
| GUI network | None | None |

## 5. Event Timeline

### 5.1 Phase 2.7 timeline (as reported in report 07; contains internal inconsistencies — see section 5.3 and the reconciliation document)

| Timestamp (UTC) | Event | Source |
|-----------------|-------|--------|
| 2026-11-26 02:44:00 | GUI process start (PID 1232) | WMI |
| 2026-11-26 02:44:04 | Service process start (PID 5572) | WMI |
| 2026-11-26 03:00:00 | Repository clone | Git |
| 2026-11-26 03:05:00 | Process enumeration (PIDs 5572, 1232) | PowerShell |
| 2026-11-26 03:10:00 | WinDbg `lm` on PID 5572 | WinDbg |
| 2026-11-26 03:15:00 | Module enumeration both PIDs (91 + 125) | EnumModules2.exe |
| 2026-11-26 03:15:00 | Network baseline (UDP 26.82.29.1:56413 on PID 5572) | PowerShell |
| 2026-11-26 03:20:00 | File hashing (20 Radmin binaries) | PowerShell |
| 2026-11-26 03:30:00 | Process tree analysis | WMI |
| ~2026-11-26 03:11:00 | User VPN connect (GUI) | GUI / user report |
| ~2026-11-26 03:11:10 | Service termination (PID 5572) | PowerShell |
| ~2026-11-26 03:11:15 | Service restart (PID 5476) | PowerShell |
| ~2026-11-26 03:11:20 | TCP relay connect PID 5476 → 148.113.190.78:17301 | netstat |
| ~2026-11-26 03:11:25 | Local TCP listen 0.0.0.0:59509 | netstat |
| ~2026-11-26 03:11:30 | UDP listener 26.82.29.1:56413 closed | netstat |
| 2026-11-26 03:11:55 | Connection confirmed | User report |
| 2026-11-26 03:12:00 | Module enum service (91 modules on PID 5476) | EnumModules2.exe |
| 2026-11-26 03:12:10 | Module enum GUI (125 modules on PID 1232) | EnumModules2.exe |
| 2026-11-26 03:12:20 | Network enum service | Get-NetTCPConnection |
| 2026-11-26 03:12:30 | Network enum GUI | Get-NetTCPConnection |
| 2026-11-26 03:12:40 | Process tree check | WMI |
| 2026-11-26 03:12:50 | Helper process check | Get-Process |
| 2026-11-26 03:13:00 | WinDbg `lm` on PID 5476 | WinDbg |
| 2026-11-26 03:50:00 | Monitoring activated | Phase 2.7 report 06 |

### 5.2 Phase 2.8 timeline (internally consistent; all times UTC unless marked local)

| Local time | UTC time | Event | Source | Confidence |
|------------|----------|-------|--------|------------|
| 03:10:33 | 06:10:33 | GUI process start (PID 5760) | `Get-CimInstance Win32_Process` CreationDate | Direct |
| 03:33:28 | 06:33:28 | Service process start (PID 13164) | `Get-CimInstance Win32_Process` CreationDate | Direct |
| 03:33–03:45 | 06:33–06:45 | Baseline captures (process, modules, network, pipes) | Multiple tools | Direct |
| 03:41:00 | 06:41:00 | User clicks "Connect" in GUI | User report | User-reported |
| 03:41:00–03:42:00 | 06:41–06:42 | Service TCP port 62654 → 65157 | `Get-NetTCPConnection` snapshots | Direct (tool-reported) |
| 03:42:35 | 06:42:35 | GUI restart (PID 5760 → 8808) | `Get-CimInstance` CreationDate | Direct |
| 03:42–03:43 | 06:42–06:43 | Service TCP port 65157 → 65199 | `Get-NetTCPConnection` snapshots | Direct (tool-reported) |
| 03:42–03:48 | 06:42–06:48 | Post-connection captures | Multiple tools | Direct |
| 03:48:52 | 06:48:52 | Timeline compiled | Report 14 | Direct |

### 5.3 Timeline discrepancies and reconciliation

Phase 2.7 report 07 timeline is internally inconsistent:
- User Connect (03:11) reported before baseline capture (03:15) — impossible if baseline is pre-connection.
- Monitoring "activated" at 03:50 but post-connection capture at 03:12–03:13.
- Network baseline at 03:15 shows UDP 56413 on PID 5572, but PID 5572 supposedly terminated at 03:11.

File metadata evidence (report 02, Phase 2.8 timeline reconciliation) shows all Phase 2.7 reports written in a single batch (~06:00–06:08 UTC local-file times), suggesting the Phase 2.7 timeline was compiled retrospectively with estimated UTC timestamps and mixed local/UTC clocks. Exact user Connect click, service termination, and restart timestamps are unresolved in Phase 2.7 (no ETW/Procmon capture at that moment).

Phase 2.8 timeline is internally consistent, based on verified timestamps from
`Get-CimInstance Win32_Process` CreationDate, `Get-NetTCPConnection`/
`Get-NetUDPEndpoint` snapshots, `Get-ChildItem \\.\pipe\` enumerations,
`Get-WinEvent` SCM queries, and user-reported Connect time.

Per report 02 (`docs/PHASE_2_8/02_PHASE_2_7_TIMELINE_RECONCILIATION.md`),
Phase 2.8 supersedes Phase 2.7 for the current experiment session.

## 6. IPC Observation

### 6.1 Named pipe `RadminVpnGuiChannel` (Phase 2.8, report 12)

Enumerated via `Get-ChildItem "\\.\pipe\" -Recurse` filtered for `*Radmin*`,
`*RvControl*`, `*RvRvpn*`.

| Capture | Pipe name | Type | Last write time |
|---------|-----------|------|-----------------|
| Baseline (~03:33 local) | RadminVpnGuiChannel | Named pipe | 31/12/1600 22:00:00 |
| Post-connection (~03:43 local) | RadminVpnGuiChannel | Named pipe | 31/12/1600 22:00:00 |

- Single Radmin-specific named pipe observed; no other pipes matching Radmin
  patterns found at either capture.
- Pipe present pre- and post-connection (two independent enumerations).
- Pipe name suggests GUI-to-service IPC channel (inferred from naming pattern).
- `LastWriteTime` shows `31/12/1600 22:00:00` — not a real timestamp; likely
  filesystem metadata artifact; cannot be used for temporal correlation.

### 6.2 What IPC evidence does and does not establish

Supported: pipe `RadminVpnGuiChannel` exists (directly observed); pipe name
suggests GUI-to-service channel (inferred).

Not supported / unknown: pipe used for Connect command (no operation data);
pipe recreated after GUI restart (unknown — same name/timestamp, likely cached
metadata); service creates/owns the pipe (unknown — no owner PID visible);
GUI connects to the pipe (unknown); pipe security descriptors (unknown);
message content/protocol (unknown).

### 6.3 Static/dynamic IPC correlation

| Static artifact | Runtime observation | Correlation |
|-----------------|---------------------|-------------|
| `WinLpcDl.dll` (install dir, v3.5.2.1205) | Not loaded in either process | Static reference only; LPC often uses named pipes — plausible |
| `ChatLPCx.dll` (install dir) | Not loaded in either process | Static reference only; "Chat LPC" — plausible |
| `RvROLClient.dll` | Loaded in service | Contains RPC/ROL protocol logic |
| Qt5Network in GUI | GUI has no network sockets | Consistent — GUI uses local IPC (likely QLocalSocket) |

Critical gap: without Procmon or ETW, pipe create/open/read/write operations
cannot be observed; no pipe creator/owner PID; no message capture.

## 7. Static/Runtime Correlation

### 7.1 Pre-loaded protocol stack (confirmed both phases)

All core protocol modules are already loaded in `RvControlSvc.exe` at baseline,
before any VPN connection:
- RvROLClient.dll (core ROL protocol)
- RvUESClient.dll (UES/SRP authentication)
- libcrypto-3.dll / libssl-3.dll (TLS)
- libcurl.dll (HTTP/REST)

Implication: service initialization loads the full crypto/protocol stack at
startup; connection establishment reuses existing loaded modules; no dynamic
module loading for protocol functions during connection; protocol execution
uses pre-loaded code paths (module presence ≠ causal role in Connect).

### 7.2 Service restart vs stability (the Phase 2.7 / Phase 2.8 discrepancy)

| Phase | Service behavior | GUI behavior |
|-------|-----------------|--------------|
| 2.7 | RESTARTED on Connect: PID 5572 → 5476 | Stable: PID 1232 unchanged |
| 2.8 | STABLE: PID 13164 throughout, no SCM events | RESTARTED on Connect: PID 5760 → 8808 |

Phase 2.7 hypothesis (report 09): connection establishment requires fresh
service state; possibly reinitializes crypto, network stacks, or peer state;
restart triggered by GUI IPC message or specific API (not identified).

Phase 2.8 hypothesis (report 15): Phase 2.7 restart may have been triggered by
specific connection state (first connect after crash loop); Phase 2.8 service
was already stable (~9 minutes uptime). Different experimental sessions with
different initial conditions (Phase 2.7 baseline had no TCP connection; Phase
2.8 baseline already had TCP 62654 → 148.113.190.78:17301 established).

CRITICAL: Phase 2.8 explicitly supersedes Phase 2.7. Both observations are
recorded with their evidence; the discrepancy (why the service restarted in
2.7 but not 2.8, and why the GUI restarted in 2.8 but not 2.7) remains
unresolved and is tracked in
`docs/PHASE_2_8/02_PHASE_2_7_TIMELINE_RECONCILIATION.md` (the reconciliation
document) and in the Phase 2.8 unresolved questions (report 16).

### 7.3 GUI architecture

GUI process (`RvRvpnGui.exe`) is a pure Qt frontend: loads no Radmin protocol
DLLs, only Qt5* framework modules plus ICU/VC++ runtime. All protocol logic
resides in the service. GUI communicates with the service via Qt5Network
(likely QLocalSocket over named pipes). GUI has no direct network endpoints in
any capture.

GUI restart on Connect (Phase 2.8) is inferred from PID change
(5760 → 8808) and new `CreationDate` (03:42:35 local), ~90 seconds after the
user Connect action (~03:41 local). Exact millisecond of GUI termination not
captured (snapshot-based); no debugger attached.

### 7.4 Static analysis gaps (both phases)

| Priority | Target | Gap |
|----------|--------|-----|
| P1 | RvControlSvc.exe Connect IPC handler | No dynamic IPC trace; named pipe handler not traced |
| P1 | RvUESClient.dll SRP/TLS handshake | No dynamic trace during Connect |
| P1 | GUI restart trigger | No GUI debugger trace |
| P2 | Service port change logic (62654 → 65157 → 65199) | No dynamic trace |
| P2 | WinLpcDl.dll / ChatLPCx.dll role | Present in install dir, never loaded — complete static gap |
| P2 | GUI Qt module reduction (125 → 101) | No dynamic trace of delay-loaded modules |
| P3 | RvDownloader / RvRolUpdater | Not triggered during experiment; lower priority |

WinLpcDl.dll and ChatLPCx.dll are present in the installation directory but
not loaded in either process at baseline or post-connection; they may be
delay-loaded or used only for specific features.

## 8. Evidence Limitations

### 8.1 Tool gaps (Phase 2.8 reports 05, 06, 12)

- No Procmon: not installed; no real-time file/registry/pipe operation capture;
  named pipe operations (create, open, read, write, close) unobservable;
  no handle-to-object mapping without Handle.exe.
- No ETW/WPR capture: WPR error 0xc5585011; logman "Acesso negado"; standard
  user session lacks elevation; cannot create/manage ETW sessions; no
  Microsoft-Windows-Kernel-Process, RPC, Services, or SCM provider capture.
- No kernel-mode visibility: NDIS driver activity invisible.
- Snapshot-based monitoring only: transient processes/connections (e.g.,
  RvFwHelper.exe running <1 second) may be missed; no continuous process
  monitoring.

### 8.2 Data validity

- EnumModules2.exe hardcoded-PID bug invalidated Phase 2.8 post-connection
  capture attempts 1 and 2 (stale PIDs 5572/1232 instead of 13164/8808);
  attempt 3 (fixed invocation via `cmd /c`) is valid.
- Phase 2.7 post-connection module data (report 08) relied on PID 5476 after
  service restart; WinDbg remained attached to old PID 5572 and missed the
  restart transition.
- ASLR means base addresses differ across process instances (expected, not a
  defect).

### 8.3 SCM event limitations

- Event 7034 (crash) includes no PID and no exit code; cannot correlate PID
  changes or determine crash cause.
- Event 7036 (state change) may not fire for all transitions; service start
  may not generate a logged event.
- GUI is not a Windows service, so GUI restarts (PID 5760 → 8808) are
  invisible to SCM.
- No real-time SCM event streaming; `Get-WinEvent` queries are post-facto.

### 8.4 Other limitations

- No packet capture (PCAP); no payload inspection; metadata only (TCP/UDP
  endpoints, no traffic content).
- No memory dumps, no process injection, no credential/authentication
  collection (by design).
- IPv6 not checked in Phase 2.7 (IPv4 only).
- Firewall state not captured in Phase 2.7.
- Named pipe `LastWriteTime` unreliable (31/12/1600 default).
- Phase 2.7 and Phase 2.8 are different experimental sessions with different
  initial conditions; direct numeric comparison of some values (PIDs, ports,
  start times) reflects different instances, not a defect in either phase.
- Evidence classifications used throughout: Directly observed, Tool-reported,
  Computed, User-reported, Inferred, Hypothesis, Unknown.

## 9. Sources

All 27 sources mapped to `RUNTIME_OBSERVATIONS` in
`analysis_workspace/compaction/mapping.tsv`, read in full:

Phase 2.7 (12 sources):
1. `docs/PHASE_2_7/01_ENVIRONMENT_AND_REPOSITORY_VALIDATION.md`
2. `docs/PHASE_2_7/02_RUNNING_RADMIN_PROCESS_INVENTORY.md`
3. `docs/PHASE_2_7/03_PRE_CONNECTION_MODULE_INVENTORY.md`
4. `docs/PHASE_2_7/04_PROCESS_TREE_AND_HELPER_PROCESS_ANALYSIS.md`
5. `docs/PHASE_2_7/05_PRE_CONNECTION_NETWORK_BASELINE.md`
6. `docs/PHASE_2_7/06_RUNTIME_MONITORING_CONFIGURATION.md`
7. `docs/PHASE_2_7/07_RUNTIME_EVENT_TIMELINE.md`
8. `docs/PHASE_2_7/08_POST_CONNECTION_MODULE_INVENTORY.md`
9. `docs/PHASE_2_7/09_PRE_POST_CONNECTION_DIFFERENCE_ANALYSIS.md`
10. `docs/PHASE_2_7/10_NEW_BINARY_HASH_AND_VERSION_INVENTORY.md`
11. `docs/PHASE_2_7/11_STATIC_RUNTIME_CORRELATION.md`
12. `docs/PHASE_2_7/13_PHASE_2_7_FINAL_SUMMARY.md`

Phase 2.8 (15 sources):
13. `docs/PHASE_2_8/01_PHASE_2_8_ENVIRONMENT_AND_REPOSITORY_VALIDATION.md`
14. `docs/PHASE_2_8/03_MONITORING_TOOL_AND_PROVIDER_VALIDATION.md`
15. `docs/PHASE_2_8/04_BASELINE_PROCESS_SERVICE_AND_MODULE_SNAPSHOT.md`
16. `docs/PHASE_2_8/05_ETW_CAPTURE_ANALYSIS.md`
17. `docs/PHASE_2_8/06_PROCMON_CAPTURE_ANALYSIS.md`
18. `docs/PHASE_2_8/07_SCM_EVENT_ANALYSIS.md`
19. `docs/PHASE_2_8/08_POST_CONNECTION_PROCESS_IDENTITY_AND_LIFECYCLE_VALIDATION.md`
20. `docs/PHASE_2_8/09_ENUMMODULES2_PID_SELECTION_INVESTIGATION.md`
21. `docs/PHASE_2_8/10_MODULE_INVENTORY_COMPARISON_VALIDITY.md`
22. `docs/PHASE_2_8/11_TCP_UDP_ENDPOINT_CORRELATION.md`
23. `docs/PHASE_2_8/12_NAMED_PIPE_OBSERVATION.md`
24. `docs/PHASE_2_8/13_SCM_EVENT_COVERAGE_AND_INTERPRETATION.md`
25. `docs/PHASE_2_8/14_UNIFIED_RUNTIME_EVENT_TIMELINE.md`
26. `docs/PHASE_2_8/15_STATIC_RUNTIME_CORRELATION.md`
27. `docs/PHASE_2_8/17_PHASE_2_8_FINAL_SUMMARY.md`

Cross-reference (not counted among the 27, referenced for the 2.7/2.8
discrepancy): `docs/PHASE_2_8/02_PHASE_2_7_TIMELINE_RECONCILIATION.md`
(mapped to `RECONCILIATION`).

## 10. Provenance note

This draft was produced by reading all 27 sources listed above in full and
consolidating their contents into a single topic-organized document. The 30
per-stage reports (13 Phase 2.7 + 17 Phase 2.8) were deduplicated by merging
overlapping findings (environment validation, process inventory, module
inventories, network baselines, timelines, IPC, static/runtime correlation,
limitations) while preserving every verbatim technical fact: PIDs
(5572, 5476, 13164, 1232, 5760, 8808, 592, 6912, 9632), port numbers
(56413, 49237, 59509, 62654, 65157, 65199, 17301), module counts (91 service,
125/101 GUI), timestamps (UTC and local), SHA-256 hashes, base addresses,
tool names (EnumModules2.exe, WinDbg, WPR/logman/ETW, Procmon, PowerShell
cmdlets), the named pipe `RadminVpnGuiChannel`, SCM event ids (7034, 7036,
7031, 7023, 7024), and all evidence classifications.

No facts were invented. Where Phase 2.7 and Phase 2.8 conflict (service
restart 5572→5476 vs service stable 13164; GUI stable 1232 vs GUI restart
5760→8808), both observations are recorded with their supporting evidence,
Phase 2.8 is noted as superseding Phase 2.7, and the reader is pointed to the
reconciliation document
`docs/PHASE_2_8/02_PHASE_2_7_TIMELINE_RECONCILIATION.md` for the documented
discrepancy analysis. Invalid data (Phase 2.8 EnumModules2 captures 1 and 2
using stale hardcoded PIDs) is identified as invalid rather than silently
corrected. No other file was created or modified as part of this task.

---

## Evidence appendix (exact tokens from consolidated sources)

Exact addresses, hashes and identifiers from the consolidated sources that are not repeated in the prose above. They are preserved here so that no evidence anchor is lost during compaction; the full narrative for each source remains available in git history.

- `docs/PHASE_2_7/02_RUNNING_RADMIN_PROCESS_INVENTORY.md`: `5fc07f57d1d1a46bf080dd833511d5166235ffc2c00812faf46d99f008384d21`
- `docs/PHASE_2_7/03_PRE_CONNECTION_MODULE_INVENTORY.md`: `0x108000`, `0x133000`, `0x165000`, `0x172000`, `0x191000`, `0x192000`, `0x19d000`, `0x1a4000`, `0x1ad000`, `0x1d5e000`, `0x1e0000`, `0x1f8000`, `0x1f80000`, `0x20c000`, `0x211000`, `0x238000`, `0x239000`, `0x27f000`, `0x280000`, `0x2b7000`, `0x2e2000`, `0x361000`, `0x449000`, `0x455000`, `0x467000`, `0x53c000`, `0x5db000`, `0x5e7000`, `0x619000`, `0x6f730000`, `0x6f800000`, `0x6f870000`, `0x6fac0000`, `0x70240000`, `0x702a0000`, `0x70320000`, `0x70430000`, `0x707c0000`, `0x70e30000`, `0x710b0000`, `0x71250000`, `0x713c0000`, `0x71560000`, `0x716e0000`, `0x71900000`, `0x71b10000`, `0x71f70000`, `0x723c0000`, `0x72bb0000`, `0x73120000`, `0x73130000`, `0x731d0000`, `0x735c0000`, `0x73680000`, `0x73860000`, `0x73b70000`, `0x73d20000`, `0x73df0000`, `0x740c0000`, `0x740d0000`, `0x74200000`, `0x74240000`, `0x742c0000`, `0x743f0000`, `0x74450000`, `0x74aa0000`, `0x74ae0000`, `0x74e10000`, `0x751c0000`, `0x751d0000`, `0x75230000`, `0x75260000`, `0x75290000`, `0x752b0000`, `0x75320000`, `0x75360000`, `0x753b0000`, `0x75480000`, `0x754b0000`, `0x757a0000`, `0x75a60000`, `0x75c40000`, `0x75d90000`, `0x75e30000`, `0x76000000`, `0x760f0000`, `0x76170000`, `0x76240000`, `0x76480000`, `0x76520000`, `0x765e0000`, `0x76960000`, `0x76980000`, `0x76b00000`, `0x76b70000`, `0x771f0000`, `0x77470000`, `0x77670000`, `0x77700000`, `0x77ce0000`, `0x77dc0000`, `0x77dd0000`, `0x7ff9e9730000`, `0x7ff9eac60000`, `0x7ff9eb170000`
- `docs/PHASE_2_7/05_PRE_CONNECTION_NETWORK_BASELINE.md`: `0x6f6a0000`
- `docs/PHASE_2_7/08_POST_CONNECTION_MODULE_INVENTORY.md`: `0x6fac0000`, `0x70320000`, `0x70430000`, `0x71f70000`, `0x723c0000`, `0x72bb0000`, `0x74e10000`, `0x75290000`, `0x753b0000`, `0x75c40000`, `0x76240000`, `0x77dd0000`
- `docs/PHASE_2_8/04_BASELINE_PROCESS_SERVICE_AND_MODULE_SNAPSHOT.md`: `0x108000`, `0x1d5e000`, `0x1f80000`, `0x2b7000`, `0x2e2000`, `0x361000`, `0x449000`, `0x467000`, `0x53c000`, `0x5e7000`, `0x6fac0000`, `0x70320000`, `0x70430000`, `0x71f70000`, `0x723c0000`, `0x72bb0000`, `0x74e10000`, `0x75290000`, `0x753b0000`, `0x754b0000`, `0x757a0000`, `0x75a60000`
- `docs/PHASE_2_8/10_MODULE_INVENTORY_COMPARISON_VALIDITY.md`: `0x6fac0000`, `0x70320000`, `0x70430000`
