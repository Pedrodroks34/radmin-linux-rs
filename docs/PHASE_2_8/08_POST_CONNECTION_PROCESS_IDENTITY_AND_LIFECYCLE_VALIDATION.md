# Phase 2.8 — Post-Connection Process Identity and Lifecycle Validation

## 1. Verification Method
All findings below are based on independent verification using `Get-CimInstance Win32_Process` and `Get-Process` at the time of capture, not on tool output alone.

## 2. Service Process (RvControlSvc.exe) — STABLE

| Property | Baseline | Post-Connection | Verification |
|----------|----------|-----------------|--------------|
| PID | 13164 | 13164 | ✅ **SAME** — Verified via `Get-CimInstance Win32_Process` |
| Process Name | RvControlSvc.exe | RvControlSvc.exe | ✅ |
| Executable Path | `C:\Program Files (x86)\Radmin VPN\RvControlSvc.exe` | Same | ✅ |
| Parent PID | 592 (services.exe) | 592 (services.exe) | ✅ |
| Session ID | 0 | 0 | ✅ |
| Start Time (Local) | 2026-11-26 03:33:28 | 2026-11-26 03:33:28 | ✅ **UNCHANGED** |
| Command Line | `/service` | `/service` | ✅ |
| Service State | Running | Running | ✅ |

**Finding**: **Service process remained stable** — no restart, no PID change, same start time.

## 3. GUI Process (RvRvpnGui.exe) — RESTARTED

| Property | Baseline | Post-Connection | Verification |
|----------|----------|-----------------|--------------|
| PID | 5760 | **8808** | ✅ **CHANGED** — Verified via `Get-CimInstance Win32_Process` |
| Process Name | RvRvpnGui.exe | RvRvpnGui.exe | ✅ |
| Executable Path | `C:\Program Files (x86)\Radmin VPN\RvRvpnGui.exe` | Same | ✅ |
| Parent PID | 6912 (explorer.exe) | 6912 (explorer.exe) | ✅ |
| Session ID | 1 | 1 | ✅ |
| Start Time (Local) | 2026-11-26 03:10:33 | **2026-11-26 03:42:35** | ✅ **NEW START TIME** |
| Command Line | `/show` | `/show` | ✅ |

**Finding**: **GUI process RESTARTED** — New PID (8808), new start time (03:42:35 local ≈ 06:42:35 UTC), same parent.

## 4. Timeline Correlation

| Event | Local Time | UTC Time | Source |
|-------|------------|----------|--------|
| Baseline capture | 03:33–03:45 | 06:33–06:45 | Snapshot |
| User clicked Connect | ~03:41 (user reported) | ~06:41 | User report |
| GUI restart observed | 03:42:35 (new PID 8808 start) | 06:42:35 | `Get-CimInstance` |
| Post-connection capture | 03:42–03:48 | 06:42–06:48 | Snapshot |

> **Note**: The GUI restart (new PID 8808 starting at 03:42:35) occurred **after** the user's reported Connect action (~03:41), consistent with the connection triggering a GUI restart.

## 5. Process Tree (Post-Connection)

```
services.exe (592)
  └── RvControlSvc.exe (13164)  [STABLE, Session 0, LocalSystem]

explorer.exe (6912)
  └── RvRvpnGui.exe (8808)  [RESTARTED at 03:42:35, Session 1, User]
```

No child processes spawned by either process.

## 6. Evidence Classification

| Finding | Classification | Source |
|---------|----------------|--------|
| Service PID stable (13164) | **Directly observed** | `Get-CimInstance Win32_Process` |
| Service start time unchanged | **Directly observed** | `CreationDate` property |
| GUI PID changed (5760 → 8808) | **Directly observed** | `Get-CimInstance Win32_Process` |
| GUI new start time (03:42:35) | **Directly observed** | `CreationDate` property |
| No service restart | **Corroborated** | Process + SCM events |
| GUI restart triggered by Connect | **Inferred** | Temporal correlation |

## 7. Limitations

- GUI restart inferred from PID change + new start time; no direct observation of termination/start sequence
- Exact millisecond of GUI termination not captured (snapshot-based)
- No debugger attached to observe internal state transitions

---
*Report generated: 2026-11-26 04:55 UTC*
*Evidence classification: Directly observed (process enumeration), Corroborated (multiple tools), Inferred (temporal correlation)*