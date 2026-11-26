# Phase 2.8 — Procmon Capture Analysis

## 1. Procmon Availability Assessment

### 1.1 Installation Check
| Location | Status |
|----------|--------|
| C:\Program Files\Process Monitor | ❌ Not found |
| C:\Program Files (x86)\Process Monitor | ❌ Not found |
| C:\Sysinternals | ❌ Not found |
| C:\Tools | ❌ Not found |
| PATH (procmon, procmon64) | ❌ Not found |

### 1.2 Procmon Capabilities (If Available)
| Capability | Relevance to Phase 2.8 |
|------------|------------------------|
| Process/Thread create/exit | Service restart, helper process spawn |
| File system operations | Config reads, log writes, certificate access |
| Registry operations | Service config, crypto keys, network settings |
| Network operations | TCP/UDP connect/listen/close |
| Named pipe operations | **GUI-to-service IPC discovery** |
| Process profiling | CPU/memory during connection |

### 1.3 Current Status
**Procmon is not available** for Phase 2.8. Installation would require:
1. Download from Sysinternals (internet access)
2. Run installer (requires Admin)
3. Accept EULA (interactive)
4. Load kernel driver (Procmon24.sys)

## 2. Alternative Monitoring Used

| Monitoring Need | Primary Tool | Fallback Tool |
|-----------------|--------------|---------------|
| Process create/exit | PowerShell snapshots (2-3 sec interval) | SCM Event Log (7034, 7036) |
| Service state changes | SCM Event Log (Get-WinEvent) | PowerShell snapshots |
| Network endpoints | Get-NetTCPConnection / Get-NetUDPEndpoint | netstat -ano |
| Named pipe enumeration | Get-ChildItem \\.\pipe\ | N/A |
| Module inventory | EnumModules2.exe (PSAPI) | N/A |
| File/registry access | **NOT AVAILABLE** | N/A |

## 3. Impact on IPC Discovery

**Critical Gap**: Without Procmon, **named pipe operations cannot be observed in real-time**.

### What We CAN Do:
- Enumerate named pipes before/during/after connection
- Correlate pipe appearance/disappearance with connection events
- Identify pipe names (e.g., `RadminVpnGuiChannel`)

### What We CANNOT Do:
- See which process opens/creates the pipe
- Observe pipe read/write operations
- Capture pipe message content/metadata
- See pipe security descriptors
- Observe RPC/ALPC activity

## 4. Mitigation for Phase 2.8

### 4.1 Named Pipe Monitoring Loop
```powershell
# Run every 2 seconds during experiment
$pipes = Get-ChildItem "\\.\pipe\" -Recurse -ErrorAction SilentlyContinue |
         Where-Object { $_.Name -like "*Radmin*" -or $_.Name -like "*RvControl*" -or $_.Name -like "*RvRvpn*" }
```

### 4.2 Process Monitoring Loop
```powershell
# Run every 2 seconds
Get-Process -Name "RvControlSvc", "RvRvpnGui", "RvFwHelper", "drvinst", "RvGuiStarter" -ErrorAction SilentlyContinue
```

### 4.3 Network Monitoring Loop
```powershell
# Run every 2 seconds
Get-NetTCPConnection -OwningProcess 13164,5760 -ErrorAction SilentlyContinue
Get-NetUDPEndpoint -OwningProcess 13164,5760 -ErrorAction SilentlyContinue
```

### 4.4 SCM Event Capture
```powershell
# Before and after experiment
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'; Id=7034,7036,7031,7023} -MaxEvents 20
```

## 5. Limitations Summary

| Limitation | Severity | Impact |
|------------|----------|--------|
| No real-time process monitoring | High | May miss short-lived helper processes |
| No pipe operation visibility | **Critical** | Cannot directly observe IPC mechanism |
| No file/registry monitoring | Medium | Config/cert access patterns unknown |
| No RPC/ALPC capture | High | Cannot confirm RPC vs named pipe |
| No driver/NDIS visibility | Medium | Tunnel creation invisible |

## 6. Recommendation

**For Phase 2.9+**: Install Procmon in an elevated session before starting the experiment:
1. Download Procmon from Sysinternals
2. Run as Administrator
3. Accept EULA
4. Configure filters for Radmin processes
5. Start capture before user clicks Connect
6. Save PML locally (do not commit)

---
*Report generated: 2026-11-26 04:50 UTC*
*Evidence classification: Directly observed (tool absence), Tool-reported (Sysinternals capabilities), Inferred (impact assessment)*