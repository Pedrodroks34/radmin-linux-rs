# Phase 2.8 — ETW Capture Analysis

## 1. ETW Capture Attempt Summary

### 1.1 Tools Tested
| Tool | Status | Issue |
|------|--------|-------|
| WPR (Windows Performance Recorder) | ❌ Failed | Error 0xc5585011 - "Failed to enable the policy to profile system performance" |
| logman (ETW trace sessions) | ❌ Failed | "Acesso negado" (Access denied) - requires elevated session |
| PowerShell ETW cmdlets | ❌ Not available | No native ETW cmdlets in PowerShell 5.1 |

### 1.2 Root Cause
- Current PowerShell session runs with **standard user privileges** (no SeDebugPrivilege, SeSecurityPrivilege)
- ETW trace sessions require **Administrator privileges** (Elevation)
- `Start-Process -Verb RunAs` launches a NEW elevated window but cannot interact with the current session's ETW state
- Cannot create/manage ETW sessions from non-elevated session

### 1.3 Available Providers (Verified but Not Capturable)
| Provider | GUID | Intended Use |
|----------|------|--------------|
| Microsoft-Windows-Kernel-Process | {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716} | Process create/terminate |
| Microsoft-Windows-RPC | {6AD52B32-D609-4BE9-AE07-CE8DAE937E39} | RPC activity |
| Microsoft-Windows-RPC-Events | {F4AED7C7-A898-4627-B053-44A7CAA12FCD} | RPC events |
| Microsoft-Windows-Services | {0063715B-EEDA-4007-9429-AD526F62696E} | Service lifecycle |
| Service Control Manager | {555908D1-A6D7-4695-8E1E-26931D2012F4} | SCM events |

## 2. Alternative Evidence Sources Used

Since ETW capture was not possible, the following alternatives were used:

| Source | Capability | Limitation |
|--------|------------|------------|
| PowerShell snapshots (`Get-Process`, `Get-CimInstance`) | Process/service state at points in time | No continuous capture; misses transient events |
| `Get-NetTCPConnection` / `Get-NetUDPEndpoint` | Network endpoints at points in time | No continuous capture |
| `Get-ChildItem \\.\pipe\` | Named pipe enumeration | No operation tracking (open/read/write) |
| `Get-WinEvent` (SCM logs) | Service state changes | Post-facto only; no real-time |
| Custom EnumModules2.exe | Module inventory | Snapshot only |

## 3. Impact on Phase 2.8 Objectives

| Objective | ETW Required? | Alternative Approach |
|-----------|---------------|---------------------|
| Process create/terminate | Yes | Snapshots before/after + SCM logs |
| Service lifecycle events | Yes | SCM Event Log (7034, 7036) |
| RPC/ALPC activity | Yes | Not capturable without ETW/Procmon |
| Named pipe operations | Partial | Enumeration only; no open/read/write |
| Module loads | Partial | Snapshots only |

## 4. Limitations Documented

1. **No continuous process monitoring** - Cannot detect brief process spawns (e.g., RvFwHelper.exe if it runs for <1 second)
2. **No RPC/ALPC capture** - Cannot directly observe GUI-to-service IPC mechanism
3. **No file/registry/pipe operation tracking** - Without Procmon or ETW
4. **No kernel-mode visibility** - NDIS driver activity invisible
5. **Transient events may be missed** - Snapshots are point-in-time

## 5. Mitigation Strategy for Phase 2.8

- Use **frequent PowerShell snapshots** (every 2-3 seconds) during connection experiment
- Capture **SCM events before and after** for service state correlation
- **Enumerate named pipes repeatedly** during experiment
- **Record exact timestamps** for each snapshot
- Document all gaps explicitly in reports

## 6. Recommendation for Future Phases

To enable ETW capture:
1. Run entire Phase 2.8+ in an **elevated PowerShell session** (Run as Administrator)
2. Or use **WPR UI** (wprui.exe) manually before starting experiment
3. Or install **Procmon** (requires driver install, admin)
4. Consider **Windows Performance Analyzer (WPA)** for post-capture analysis

---
*Report generated: 2026-11-26 04:45 UTC*
*Evidence classification: Directly observed (tool failures), Tool-reported (error messages), Inferred (impact assessment)*