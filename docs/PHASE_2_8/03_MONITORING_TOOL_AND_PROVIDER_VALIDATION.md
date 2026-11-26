# Phase 2.8 — Monitoring Tool and Provider Validation

## 1. Tool Availability Assessment

### 1.1 Windows Performance Recorder (WPR)
| Property | Value |
|----------|-------|
| Version | 10.0.19041 (CoreSystem) |
| Available Profiles | GeneralProfile, CPU, DiskIO, FileIO, Registry, Network, Heap, Pool, VirtualAllocation, Audio, Video, Power, Minifilter, GPU, Handle, XAMLActivity, HTMLActivity, DesktopComposition, ReferenceSet, ResidentSet, DotNET, WdfTraceLoggingProvider, HeapSnapshot, and more |
| Status | ✅ Available |

### 1.2 ETW Providers (Verified via `logman query providers`)

| Provider | GUID | Relevance | Status |
|----------|------|-----------|--------|
| Microsoft-Windows-Kernel-Process | {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716} | Process creation/termination | ✅ Available |
| Microsoft-Windows-RPC | {6AD52B32-D609-4BE9-AE07-CE8DAE937E39} | RPC activity | ✅ Available |
| Microsoft-Windows-RPC-Events | {F4AED7C7-A898-4627-B053-44A7CAA12FCD} | RPC events | ✅ Available |
| Microsoft-Windows-RPC-Audit | {3C578D57-F85A-5FC9-DEA0-8C663CCFF942} | RPC audit | ✅ Available |
| Microsoft-Windows-Services | {0063715B-EEDA-4007-9429-AD526F62696E} | Service lifecycle | ✅ Available |
| Microsoft-Windows-ServiceTriggerPerfEventProvider | {6545939F-3398-411A-88B7-6A8914B8CEC7} | Service triggers | ✅ Available |
| Service Control Manager | {555908D1-A6D7-4695-8E1E-26931D2012F4} | SCM events | ✅ Available |
| Service Control Manager Trace | {EBCCA1C2-AB46-4A1D-8C2A-906C2FF25F39} | SCM trace | ✅ Available |
| Microsoft-Windows-Kernel-Network | (not listed separately) | Network | ⚠️ Check via WPR Network profile |
| Microsoft-Windows-ALPC | N/A | ALPC/LPC | ❌ Not found as separate provider |

### 1.3 Process Monitor (Procmon)
| Property | Value |
|----------|-------|
| Installed | ❌ Not found in standard locations |
| PATH | Not available |
| Alternative | Use `Get-ChildItem \\.\pipe\` for named pipes; PowerShell for file/registry |

### 1.4 Handle / Handle64 (Sysinternals)
| Property | Value |
|----------|-------|
| Installed | ❌ Not in PATH |
| Alternative | `Get-ChildItem \\.\pipe\` for named pipes |

### 1.5 PowerShell / WMI / CIM
| Capability | Status |
|------------|--------|
| Get-Process | ✅ Available |
| Get-CimInstance Win32_Process | ✅ Available |
| Get-CimInstance Win32_Service | ✅ Available |
| Get-NetTCPConnection | ✅ Available |
| Get-NetUDPEndpoint | ✅ Available |
| Get-WinEvent | ✅ Available |
| Get-ChildItem \\.\pipe\ | ✅ Available |

## 2. Recommended WPR Profile for Phase 2.8

Based on available providers and Phase 2.8 objectives:

**Primary Profile**: `GeneralProfile` (First level triage)
- Captures: Process, Thread, Image Load, Disk I/O, File I/O, Network, Registry, CPU sampling
- Includes: Microsoft-Windows-Kernel-Process provider

**Supplementary Profiles** (if needed):
- `Network` - for network I/O correlation
- `Handle` - for handle/pipe tracking
- `CPU` - for CPU usage context

## 3. SCM Event Collection Strategy

Event IDs to monitor:
- 7034: Service terminated unexpectedly
- 7036: Service state change (running/stopped)
- 7031: Service exceeded error limit
- 7023: Service terminated with error
- 7024: Service terminated with error code

## 4. Named Pipe Discovery Approach

Since Procmon and Handle.exe are not available:
1. **Baseline**: `Get-ChildItem \\.\pipe\ -Recurse` before Connect
2. **During/After**: Repeat at intervals
3. **Correlation**: Check for new pipes with "Radmin", "RvControl", "RvRvpn", or similar patterns

## 5. Limitations

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| No Procmon | No real-time file/registry/pipe operation capture | Use ETW + periodic snapshots |
| No Handle.exe | No handle-to-object mapping | Use named pipe enumeration |
| No ALPC provider | No ALPC/LPC message capture | Rely on RPC provider + static analysis |
| Service crashes on start | May need multiple attempts | Capture crash events via SCM |
| WPR requires Admin | Need elevation for recording | Request when starting capture |

## 6. Recording Plan

### 6.1 ETW Recording (WPR)
```powershell
# Start recording with GeneralProfile
wpr -start GeneralProfile -filemode

# ... perform connection experiment ...

# Stop recording
wpr -stop C:\Users\Rhuan\phase28_capture.etl
```

### 6.2 SCM Event Collection
```powershell
# Before experiment
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'; Id=7034,7036,7031,7023} -MaxEvents 50 > baseline_scm.txt

# After experiment
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'; Id=7034,7036,7031,7023} -MaxEvents 50 > post_scm.txt
```

### 6.3 Periodic Snapshots
- Process state: every 5 seconds during experiment
- Network endpoints: every 5 seconds
- Named pipes: every 10 seconds
- Module inventory: baseline + post-connection only

---
*Report generated: 2026-11-26 04:00 UTC*
*Evidence classification: Directly observed (tool checks), Tool-reported (logman, wpr)*