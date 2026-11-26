# Phase 2.8 — Baseline Process, Service, and Module Snapshot

## 1. Capture Metadata
- **Capture Timestamp**: 2026-11-26 04:15 UTC (local: 2026-11-26 01:15 UTC-3)
- **Phase**: 2.8 Pre-Connection Baseline
- **Previous Phase Reference**: Phase 2.7 (commit 0dbe920)

## 2. Process Information

### 2.1 RvControlSvc.exe (Service)
| Property | Value |
|----------|-------|
| Process Name | RvControlSvc.exe |
| Process ID (PID) | 13164 |
| Parent Process ID (PPID) | 592 (services.exe) |
| Session ID | 0 (Service session) |
| Start Time | 2026-11-26 03:33:28 local (06:33:28 UTC) |
| Executable Path | C:\Program Files (x86)\Radmin VPN\RvControlSvc.exe |
| Command Line | `"C:\Program Files (x86)\Radmin VPN\RvControlSvc.exe" /service` |
| File Version | 2.1.4952.2 |
| Product Version | 2.1.4952.2 |
| Company | Famatech Corp. |
| SHA-256 | 0E2E6EAACBE8EBE01286CDA39A12EAAD34A20434D50F4F8BF2FDD91D4D6EF2AD |
| Architecture | 32-bit (WoW64) |

### 2.2 RvRvpnGui.exe (GUI)
| Property | Value |
|----------|-------|
| Process Name | RvRvpnGui.exe |
| Process ID (PID) | 5760 |
| Parent Process ID (PPID) | 6912 (explorer.exe) |
| Session ID | 1 (Interactive user session) |
| Start Time | 2026-11-26 03:10:33 local (06:10:33 UTC) |
| Executable Path | C:\Program Files (x86)\Radmin VPN\RvRvpnGui.exe |
| Command Line | `"C:\Program Files (x86)\Radmin VPN\RvRvpnGui.exe" /show` |
| File Version | 2.1.4952.2 |
| Product Version | 2.1.4952.2 |
| Company | Famatech Corp. |
| SHA-256 | A9B093C68288AA8B8282FEBA37A254DDF45D8BEABFC9F575CF8B07620825739E |
| Architecture | 32-bit (WoW64) |

## 3. Service Information

### 3.1 RvControlSvc Service Details
| Property | Value |
|----------|-------|
| Service Name | RvControlSvc |
| Display Name | Radmin VPN Control Service |
| State | Running |
| Start Mode | Auto |
| Service Type | Own Process |
| Error Control | Normal |
| Start Account | LocalSystem |
| Service PID | 13164 |
| Executable Path | `"C:\Program Files (x86)\Radmin VPN\RvControlSvc.exe" /service` |

### 3.2 Service History (Recent SCM Events)
| Time (Local) | Event ID | Message |
|--------------|----------|---------|
| 26/11/2026 03:14:52 | 7034 | Service terminated unexpectedly (5th occurrence) |
| 26/11/2026 03:13:32 | 7034 | Service terminated unexpectedly (4th occurrence) |
| 26/11/2026 03:11:03 | 7034 | Service terminated unexpectedly (3rd occurrence) |
| 26/11/2026 02:43:52 | 7034 | Service terminated unexpectedly (2nd occurrence) |
| 26/11/2026 02:39:56 | 7034 | Service terminated unexpectedly (1st occurrence) |

> **Note**: The service has been crashing repeatedly. Current instance (PID 13164) started at 03:33:28 local and is currently stable.

## 4. Module Inventory

### 4.1 RvControlSvc.exe (PID 13164) — 91 Modules
**Key Radmin Modules:**
| Module | Base Address | Size | Version | Path |
|--------|--------------|------|---------|------|
| RvControlSvc.exe | 0x00E70000 | 0x1D6000 | 2.1.4952.2 | C:\Program Files (x86)\Radmin VPN\RvControlSvc.exe |
| RvROLClient.dll | 0x70570000 | 0x205000 | 2.1.4952.2 | C:\Program Files (x86)\Radmin VPN\RvROLClient.dll |
| RvDownloader.dll | 0x6F940000 | 0xA7000 | 2.1.4952.2 | C:\Program Files (x86)\Radmin VPN\RvDownloader.dll |
| RvRolUpdater.dll | 0x6F9F0000 | 0xC7000 | 2.1.4952.2 | C:\Program Files (x86)\Radmin VPN\RvRolUpdater.dll |
| RvUESClient.dll | 0x72AD0000 | 0x2B000 | 2.1.4952.2 | C:\Program Files (x86)\Radmin VPN\RvUESClient.dll |
| Shelper.dll | 0x704B0000 | 0xBB000 | 4.0.0.4 | C:\Program Files (x86)\Radmin VPN\Shelper.dll |

**Key Third-Party Modules:**
| Module | Base Address | Size | Version | Vendor |
|--------|--------------|------|---------|--------|
| libcurl.dll | 0x70430000 | 0x74000 | 8.6.0 | curl project |
| libcrypto-3.dll | 0x6FAC0000 | 0x467000 | 3.6.1 | OpenSSL Project |
| libssl-3.dll | 0x70320000 | 0x108000 | 3.6.1 | OpenSSL Project |
| VCRUNTIME140.dll | 0x75290000 | 0x14000 | 14.29.30157.0 | Microsoft |

### 4.2 RvRvpnGui.exe (PID 5760) — 125 Modules
**Key Radmin Module:**
| Module | Base Address | Size | Version | Path |
|--------|--------------|------|---------|------|
| RvRvpnGui.exe | 0x00700000 | 0xE08000 | 2.1.4952.2 | C:\Program Files (x86)\Radmin VPN\RvRvpnGui.exe |

**Key Qt Framework Modules:**
| Module | Base Address | Size | Version |
|--------|--------------|------|---------|
| Qt5Core.dll | 0x72BB0000 | 0x53C000 | 5.15.15.0 |
| Qt5Gui.dll | 0x723C0000 | 0x5E7000 | 5.15.15.0 |
| Qt5Network.dll | 0x753B0000 | 0xCF000 | 5.15.15.0 |
| Qt5Quick.dll | 0x74E10000 | 0x361000 | 5.15.15.0 |
| Qt5Widgets.dll | 0x71F70000 | 0x449000 | 5.15.15.0 |
| Qt5Qml.dll | 0x754B0000 | 0x2E2000 | 5.15.15.0 |

**Key ICU Modules:**
| Module | Base Address | Size | Version |
|--------|--------------|------|---------|
| icuuc74.dll | 0x75A60000 | 0x1D6000 | 74.1 |
| icuin74.dll | 0x757A0000 | 0x2B7000 | 74.1 |
| icudt74.dll | 0x1F80000 | 0x1D5E000 | 74.1 |

## 5. Network Baseline

### 5.1 TCP Endpoints
| Local Address | Local Port | Remote Address | Remote Port | State | Owning PID |
|---------------|------------|----------------|-------------|-------|------------|
| 0.0.0.0 | 62654 | 0.0.0.0 | 0 | Bound | 13164 |
| 192.168.31.111 | 62654 | 148.113.190.78 | 17301 | Established | 13164 |
| 192.168.31.111 | 62654 | 0.0.0.0 | 0 | Listen | 13164 |

> **Observation**: Service already has an **ESTABLISHED** TCP connection to Radmin relay server 148.113.190.78:17301 on local port 62654. Also listening on 0.0.0.0:62654.

### 5.2 UDP Endpoints
| Local Address | Local Port | Protocol | Owning PID |
|---------------|------------|----------|------------|
| 26.82.29.1 | 49237 | UDP | 13164 |

> **Observation**: Service bound to VPN virtual adapter (26.82.29.1) on ephemeral port 49237.

### 5.3 GUI Network Endpoints
| Process | TCP Endpoints | UDP Endpoints |
|---------|---------------|---------------|
| RvRvpnGui.exe (PID 5760) | None | None |

## 6. IPC Objects

### 6.1 Named Pipes (Radmin-Related)
| Pipe Name | Type | Last Write |
|-----------|------|------------|
| RadminVpnGuiChannel | Named Pipe | 31/12/1600 22:00:00 |

> **Observation**: Single Radmin-specific named pipe `RadminVpnGuiChannel` present. Likely the GUI-to-service IPC channel.

## 7. Process Tree

```
services.exe (592)
  └── RvControlSvc.exe (13164)  [Service, Session 0, LocalSystem]

explorer.exe (6912)
  └── RvRvpnGui.exe (5760)  [GUI, Session 1, User, /show]
```

No child processes spawned by either Radmin process.

## 8. Comparison with Phase 2.7 Baseline

| Aspect | Phase 2.7 (PID 5572/1232) | Phase 2.8 (PID 13164/5760) | Change |
|--------|---------------------------|----------------------------|--------|
| Service PID | 5572 | 13164 | Different instance |
| Service Start Time | 02:44 UTC | 06:33 UTC | New instance |
| Service TCP Connection | None (baseline) | **Established to 148.113.190.78:17301** | **NEW** |
| Service UDP Port | 56413 | 49237 | Different ephemeral port |
| GUI PID | 1232 | 5760 | Different instance |
| GUI Start Time | 02:44 UTC | 06:10 UTC | New instance |
| GUI Command Line | (not captured) | `/show` | Captured |
| Module Count (Service) | 91 | 91 | Same |
| Module Count (GUI) | 125 | 125 | Same |
| Radmin Named Pipe | Not checked | **RadminVpnGuiChannel** | **NEW** |

## 9. Evidence Sources
- Process enumeration: `Get-Process`, `Get-CimInstance Win32_Process`
- Service info: `Get-CimInstance Win32_Service`, `sc queryex`
- Module inventory: Custom EnumModules2.exe (PSAPI, run as Admin)
- Network: `Get-NetTCPConnection`, `Get-NetUDPEndpoint`
- Named pipes: `Get-ChildItem \\.\pipe\ -Recurse`
- SCM events: `Get-WinEvent` (System log, Service Control Manager)
- File hashes: `Get-FileHash -Algorithm SHA256`

## 10. Limitations
- Module enumeration uses PSAPI snapshot; transient modules not captured
- Network snapshot is point-in-time; brief connections may be missed
- Named pipe enumeration shows existence only; no access/operation tracking without Procmon
- SCM events show service crashes but not root cause
- No Procmon/Handle.exe for real-time file/pipe/handle monitoring

---
*Report generated: 2026-11-26 04:30 UTC*
*Evidence classification: Directly observed (process, service, network), Tool-reported (EnumModules2, PowerShell cmdlets), Computed (comparison)*