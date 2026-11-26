# Phase 2.7 — Runtime Monitoring Configuration

## 1. Monitoring Activation
- **Monitoring Start Time**: 2026-11-26 03:50 UTC
- **Baseline Capture Complete**: 2026-11-26 03:45 UTC
- **Monitoring Status**: **ACTIVE** — Awaiting user VPN connection action

## 2. Monitoring Sources Configured

### 2.1 Primary: WinDbg (Attached to RvControlSvc.exe)
| Parameter | Value |
|-----------|-------|
| Target PID | 5572 (RvControlSvc.exe) |
| WinDbg Session PID | 9632 |
| Pipe Name | WinDbg-MCP-9632 |
| Commands Available | `lm` (modules), `dx` (data model), breakpoints, scripts |
| Coverage | Module loads, process events, debugger events |
| Limitations | Only attached to service (PID 5572), not GUI (PID 1232) |

### 2.2 Secondary: Custom Module Enumerator (On-Demand)
| Parameter | Value |
|-----------|-------|
| Tool | EnumModules2.exe (C# PSAPI wrapper) |
| Targets | PID 5572 and PID 1232 |
| Trigger | Manual execution (pre/post connection) |
| Coverage | Full module inventory with paths, base addresses, sizes, versions |
| Limitations | Requires Admin; snapshot only; no real-time events |

### 2.3 Tertiary: PowerShell / WMI (On-Demand)
| Parameter | Value |
|-----------|-------|
| Commands | `Get-Process`, `Get-NetTCPConnection`, `Get-NetUDPEndpoint`, `Get-CimInstance Win32_Process` |
| Targets | PID 5572, 1232, and child processes |
| Trigger | Manual execution |
| Coverage | Process tree, network endpoints, basic process info |
| Limitations | No real-time event stream; no file access monitoring |

## 3. Monitoring Scope (Filters Applied)

### 3.1 Process Filters
- **Include**: RvControlSvc.exe (PID 5572), RvRvpnGui.exe (PID 1232)
- **Include**: Any child processes spawned by above
- **Include**: RvFwHelper.exe, drvinst.exe, RvGuiStarter.exe if spawned
- **Exclude**: All other system/user processes

### 3.2 File System Filters (Not Automated — On-Demand Only)
- **Directory**: C:\Program Files (x86)\Radmin VPN\
- **Extensions**: .exe, .dll, .sys, .dat, .cfg, .log
- **Note**: Real-time file monitoring (Procmon) not configured due to:
  - Requires separate Procmon setup
  - High volume without filtering
  - Will use on-demand comparison instead

### 3.3 Network Filters
- **Processes**: PID 5572, 1232
- **Protocols**: TCP, UDP
- **Capture**: Endpoint changes (new listeners, connections)

### 3.4 Module Load Filters
- **Processes**: PID 5572, 1232
- **Event**: New module loads (DLLs, EXEs)
- **Particular Interest**: Radmin-owned DLLs, VPN-related modules

## 4. Monitoring Limitations

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| WinDbg only on PID 5572 | GUI process (PID 1232) module loads not captured in real-time | On-demand enumeration for both processes pre/post |
| No Procmon / ETW session | File/registry access not captured in real-time | Pre/post filesystem hash comparison; on-demand network check |
| No kernel driver monitoring | NDIS driver activity not visible | Post-connection module check for driver-related DLLs |
| Single snapshot baseline | Transient modules/processes may be missed | User to wait for GUI confirmation before post-capture |
| Manual trigger required | Human delay between connection and capture | Clear handoff instructions; timestamp recording |

## 5. What Will Be Captured Post-Connection

### 5.1 Automated (WinDbg — Service Only)
- New module loads in RvControlSvc.exe
- Any process creation/termination (if debugger catches it)
- Exception/debug events

### 5.2 On-Demand (Both Processes)
- Full module inventory (EnumModules2.exe)
- Process tree (any new children)
- Network endpoints (TCP/UDP)
- File hashes of any new binaries

### 5.3 Manual (User Report)
- GUI connection confirmation timestamp
- Network name connected to
- Any error messages or UI state changes

## 6. Handoff Instructions for User

### 6.1 Current State
✅ Baseline complete  
✅ Monitoring active (WinDbg on service)  
✅ On-demand tools ready  

### 6.2 User Action Required
**When ready, perform ONE normal VPN connection:**
1. In the Radmin VPN GUI (already open), click to join/connect to your authorized test network
2. Wait for GUI to show **"Connected"** or **"Online"** status for that network
3. **Do not disconnect** — leave the connection active
4. Report back: "Connected to [network name] at [approximate time]"

### 6.3 What NOT To Do
- ❌ Do not restart Radmin service or GUI
- ❌ Do not connect to multiple networks
- ❌ Do not modify any Radmin settings
- ❌ Do not run other VPN software simultaneously

## 7. Post-Connection Capture Plan
Upon user confirmation:
1. Record connection timestamp
2. Run EnumModules2.exe (both PIDs)
3. Query network endpoints (both PIDs)
4. Query process tree (check for helpers)
5. Run WinDbg `lm` on service
6. Compare with baseline
7. Generate differential reports

## 8. Evidence Preservation
- All raw enumerator output saved to `C:\Users\Rhuan\enum_output.txt`
- WinDbg session logs available via `get_logs`
- Reports written to `docs/PHASE_2_7/`
- No sensitive data captured

---
*Report generated: 2026-11-26 03:50 UTC*
*Monitoring start: 2026-11-26 03:50 UTC*
*Evidence classification: Directly observed (tool configuration), Planned (post-connection actions)*