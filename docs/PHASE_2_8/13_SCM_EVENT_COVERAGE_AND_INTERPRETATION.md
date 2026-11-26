# Phase 2.8 — SCM Event Coverage and Interpretation

## 1. SCM Event Collection Method
Events queried via `Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'; Id=7034,7036,7031,7023} -MaxEvents 20` at baseline and post-connection.

## 2. Baseline SCM Events (Pre-Connection)

### 2.1 Radmin VPN Control Service Events (Recent History)
| Time (Local) | Event ID | Message |
|--------------|----------|---------|
| 26/11/2026 03:14:52 | 7034 | Service terminated unexpectedly (5th occurrence) |
| 26/11/2026 03:13:32 | 7034 | Service terminated unexpectedly (4th occurrence) |
| 26/11/2026 03:11:03 | 7034 | Service terminated unexpectedly (3rd occurrence) |
| 26/11/2026 02:43:52 | 7034 | Service terminated unexpectedly (2nd occurrence) |
| 26/11/2026 02:39:56 | 7034 | Service terminated unexpectedly (1st occurrence) |

### 2.2 Current Service Instance
- **Service**: RvControlSvc (Radmin VPN Control Service)
- **PID**: 13164
- **State**: Running
- **Start Time**: 2026-11-26 03:33:28 local
- **No SCM Event 7036 (start) captured in last 20 events** — may not log for auto-restart

## 3. Post-Connection SCM Events (Post-Connection)

### 3.1 Query Results (Same as Baseline)
| Time (Local) | Event ID | Message |
|--------------|----------|---------|
| 26/11/2026 03:14:52 | 7034 | Service terminated unexpectedly (5th occurrence) |
| ... | ... | ... |

**No new SCM events** for RvControlSvc between baseline and post-connection captures.

## 4. Interpretation

### 4.1 Service Stability During Experiment
| Metric | Value |
|--------|-------|
| Service PID at baseline | 13164 |
| Service PID at post-connection | 13164 |
| SCM Event 7034 (crash) during experiment | **None** |
| SCM Event 7036 (state change) during experiment | **None** |
| Service uptime at baseline | ~0 min (just started 03:33) |
| Service uptime at post-connection | ~9 min |

**Finding**: **Service remained stable** throughout the connection experiment. No crash, no restart, no state change logged by SCM.

### 4.2 SCM Event Coverage Assessment

| Event Type | Captured? | Notes |
|------------|-----------|-------|
| Service crash (7034) | ❌ None during experiment | Service stable |
| Service start (7036) | ❌ Not in last 20 | May not log for running service |
| Service stop (7036) | ❌ None | Service didn't stop |
| Service error limit (7031) | ❌ None | Not triggered |
| Service error termination (7023) | ❌ None | Not applicable |

### 4.3 GUI Restart — Not Visible in SCM
- GUI (RvRvpnGui.exe) is **not a Windows service** — runs as user process
- Process restart (PID 5760 → 8808) **not logged in SCM**
- Only visible via process enumeration (`Get-CimInstance Win32_Process`)

## 5. Correlation with Phase 2.7

| Aspect | Phase 2.7 | Phase 2.8 |
|--------|-----------|-----------|
| Service PID at baseline | 5572 | 13164 |
| Service PID post-connection | 5476 (RESTART) | 13164 (STABLE) |
| SCM Event 7034 during experiment | Yes (multiple) | **No** |
| Service restart during Connect | **YES** | **NO** |

> **Critical Difference**: Phase 2.7 observed service restart (PID 5572→5476); Phase 2.8 observed **service stability** (PID 13164 throughout).

## 6. SCM Event Limitations

| Limitation | Impact |
|------------|--------|
| No real-time event streaming | Must poll `Get-WinEvent`; may miss brief events |
| Event 7036 (state change) may not fire for auto-restart | Service restarts may be invisible |
| No process ID in SCM events | Cannot correlate PID change with event |
| No exit code in Event 7034 | Cannot determine crash cause |
| GUI process not a service | GUI restarts invisible to SCM |

## 5. Evidence Classification

| Finding | Classification | Source |
|---------|----------------|--------|
| Service PID 13164 stable | **Directly observed** | `Get-CimInstance Win32_Process` + SCM query |
| No Event 7034 during experiment | **Directly observed** | `Get-WinEvent` query |
| No Event 7036 during experiment | **Directly observed** | `Get-WinEvent` query |
| GUI restart invisible to SCM | **Directly observed** | GUI not a service |
| Phase 2.7 vs 2.8 service behavior differs | **Corroborated** | Independent SCM queries |

## 7. Unresolved Questions

| Question | Priority |
|----------|----------|
| Why did service restart in Phase 2.7 but not Phase 2.8? | HIGH |
| Does SCM Event 7036 fire for service auto-restart? | MEDIUM |
| What caused the 5 crashes before baseline? | MEDIUM |
| Is service stability dependent on prior crash state? | HIGH |

## 8. Conclusion

**SCM events confirm service stability during Phase 2.8 experiment.** The service (PID 13164) did not crash, restart, or change state during the connection experiment. The GUI process restart (PID 5760→8808) is not visible in SCM because GUI is not a Windows service.

The discrepancy with Phase 2.7 (where service restarted) remains unexplained and warrants investigation.

---
*Report generated: 2026-11-26 06:05 UTC*
*Evidence classification: Directly observed (SCM queries, process enumeration), Corroborated (Phase 2.7 comparison), Inferred (GUI restart not in SCM)*