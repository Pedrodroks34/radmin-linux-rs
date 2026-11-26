# Phase 2.7 — Process Tree and Helper Process Analysis

## 1. Radmin Process Tree (Baseline)

### 1.1 Complete Process Hierarchy
```
System (PID 4)
  └── smss.exe (PID 384)
        └── csrss.exe (PID 572)
        └── wininit.exe (PID 592)
              └── services.exe (PID 592)
                    └── RvControlSvc.exe (PID 5572)  ← Radmin Service
        └── winlogon.exe (PID 680)
              └── explorer.exe (PID 6912)
                    └── RvRvpnGui.exe (PID 1232)  ← Radmin GUI
```

### 1.2 Process Details

#### RvControlSvc.exe (PID 5572)
- **Parent**: services.exe (PID 592) — Windows Service Control Manager
- **Session**: 0 (Non-interactive service session)
- **Start Type**: Auto-start service (Radmin VPN Control Service)
- **Children**: None at baseline
- **Threads**: 16 threads (observed via Process.GetProcessById)
- **Handles**: 527 handles
- **Working Set**: ~23.5 MB
- **Virtual Memory**: ~145 MB

#### RvRvpnGui.exe (PID 1232)
- **Parent**: explorer.exe (PID 6912) — Windows Shell
- **Session**: 1 (Interactive user session)
- **Start Type**: User-initiated (GUI launch)
- **Children**: None at baseline
- **Threads**: 11 threads
- **Handles**: 505 handles
- **Working Set**: ~86.4 MB
- **Virtual Memory**: ~337 MB
- **Main Window**: "Radmin VPN" (Handle: 0x525552)

### 1.3 No Direct Relationship
- RvControlSvc.exe and RvRvpnGui.exe have **no parent-child relationship**
- They communicate via IPC (likely named pipes, LPC, or RPC) — not process hierarchy
- Service runs in Session 0; GUI runs in Session 1

## 2. Helper Process Analysis

### 2.1 Radmin Binaries Present But Not Running at Baseline

| Binary | Path | Purpose | Expected Trigger |
|--------|------|---------|------------------|
| RvGuiStarter.exe | C:\Program Files (x86)\Radmin VPN\RvGuiStarter.exe | GUI launcher / elevation helper | GUI startup (may have already run) |
| RvFwHelper.exe | C:\Program Files (x86)\Radmin VPN\RvFwHelper.exe | Firewall rule management | VPN connection (adds firewall rules) |
| drvinst.exe | C:\Program Files (x86)\Radmin VPN\drvinst.exe | NDIS driver installation | First run / driver update |
| Radmin.exe | C:\Program Files (x86)\Radmin VPN\Radmin.exe | Radmin Viewer/Server (separate product) | Not part of VPN |

### 2.2 Expected Helper Process Behavior
Based on binary names and typical Radmin architecture:

| Helper | Expected Behavior | When Spawned |
|--------|-------------------|--------------|
| RvFwHelper.exe | Adds Windows Firewall rules for VPN adapter | On VPN network join |
| drvinst.exe | Installs/updates Radmin VPN NDIS driver | First connection or driver update |
| RvGuiStarter.exe | Launches GUI with appropriate privileges | GUI startup (may be one-shot) |

### 2.3 Current Status at Baseline
- **None of the helper processes are running**
- No child processes spawned by either RvControlSvc.exe or RvRvpnGui.exe
- This is expected: no VPN connection active yet

## 3. Process Classification

### 3.1 Directly Radmin-Related Processes
| PID | Name | Type | Confidence |
|-----|------|------|------------|
| 5572 | RvControlSvc.exe | Core Service | ✅ Confirmed |
| 1232 | RvRvpnGui.exe | GUI Client | ✅ Confirmed |

### 3.2 Windows System Processes (Context Only)
| PID | Name | Role |
|-----|------|------|
| 592 | services.exe | Service Control Manager (parent of RvControlSvc) |
| 6912 | explorer.exe | Shell (parent of RvRvpnGui) |
| 4 | System | Kernel process |
| 384 | smss.exe | Session Manager |
| 572 | csrss.exe | Client/Server Runtime |
| 680 | winlogon.exe | Logon Process |

### 3.3 Unrelated Background Processes (Excluded)
The following processes were found in the initial WMI query but are **not Radmin-related**:
- Ext2Srv.exe (Paragon ExtFS driver)
- OneApp.IGCC.WinService.exe (Intel graphics)
- jhi_service.exe (Intel DAL)
- RtkAudUService64.exe (Realtek Audio)
- RstMwService.exe (Intel RST)
- wslservice.exe (WSL)
- WMIRegistrationService.exe
- MpDefenderCoreService.exe (Windows Defender)
- SecurityHealthService.exe
- NisSrv.exe (Network Inspection)
- codex-windows-sandbox-service.exe (VS Code sandbox)

## 4. IPC Mechanisms (Inferred from Architecture)

### 4.1 Service ↔ GUI Communication
Since there is no process hierarchy linking them, communication must use:
- **Named Pipes** (most likely — Windows standard for service-GUI)
- **RPC / ALPC** (Advanced Local Procedure Call)
- **Window Messages** (via hidden window or broadcast)
- **Shared Memory** (file mapping)
- **LPC / WinLpcDl.dll** (Radmin-specific — WinLpcDl.dll is present in install dir)

### 4.2 Evidence from Module Inventory
- **WinLpcDl.dll** present in install directory (v3.5.2.1205) — suggests LPC-based IPC
- **ChatLPCx.dll** present — "Chat LPC" suggests LPC usage for chat/control
- **RvROLClient.dll** loaded in service — likely the server side of RPC/ROL protocol
- **Qt5Network** in GUI — could use local sockets (QLocalSocket)

## 5. Baseline Verification Checklist

| Check | Status | Evidence |
|-------|--------|----------|
| RvControlSvc.exe identified | ✅ | PID 5572, correct path, version, hash |
| RvRvpnGui.exe identified | ✅ | PID 1232, correct path, version, hash, window title |
| Service parent = services.exe | ✅ | PPID 592 |
| GUI parent = explorer.exe | ✅ | PPID 6912 |
| No child processes | ✅ | WMI query for children returned none |
| No duplicate instances | ✅ | Single PID per process name |
| Helper processes not running | ✅ | RvFwHelper, drvinst, RvGuiStarter not in process list |
| Module inventory complete | ✅ | 91 (service) + 125 (GUI) modules enumerated |

## 6. Limitations
- **IPC channels not directly observed** — inferred from binary presence and architecture
- **Command lines not captured** for service (Windows restriction)
- **Thread-level details** not analyzed (would require debugger attachment)
- **Handle tables not inspected** — would reveal open pipes, events, mutexes
- **RvGuiStarter.exe** may have already run and exited before baseline

---
*Report generated: 2026-11-26 03:35 UTC*
*Evidence classification: Directly observed (process tree), Tool-reported (WMI, PSAPI), Inferred (IPC mechanisms from binary presence)*