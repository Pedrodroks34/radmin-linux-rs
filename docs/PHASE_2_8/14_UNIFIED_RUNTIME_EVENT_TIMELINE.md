# Phase 2.8 — Unified Runtime Event Timeline

## 1. Timeline Construction Method
Events normalized to UTC for correlation. Original timestamps preserved with time zones. Sources identified for each event.

## 2. Phase 2.8 Experiment Timeline (Local Time = UTC-3)

| Local Time | UTC Time | Event | Source | Process | Confidence |
|------------|----------|-------|--------|---------|------------|
| 2026-11-26 03:10:33 | 06:10:33 | GUI process starts (PID 5760) | `Get-CimInstance Win32_Process` CreationDate | RvRvpnGui.exe (5760) | **Direct** |
| 2026-11-26 03:33:28 | 06:33:28 | Service starts (PID 13164) | `Get-CimInstance Win32_Process` CreationDate | RvControlSvc.exe (13164) | **Direct** |
| 2026-11-26 03:33–03:45 | 06:33–06:45 | **Baseline captures** (process, modules, network, pipes) | Multiple tools | Both | **Direct** |
| 2026-11-26 03:41:00 | 06:41:00 | User clicks "Connect" in GUI | User report | RvRvpnGui.exe (5760) | **User-reported** |
| 2026-11-26 03:41:00–03:42:00 | 06:41–06:42 | Service TCP port changes: 62654 → 65157 | `Get-NetTCPConnection` snapshots | RvControlSvc.exe (13164) | **Direct** (tool-reported) |
| 2026-11-26 03:42:35 | 06:42:35 | **GUI restarts** (PID 5760 exits, PID 8808 starts) | `Get-CimInstance` CreationDate | RvRvpnGui.exe (8808) | **Direct** |
| 2026-11-26 03:42–03:43 | 06:42–06:43 | Service TCP port changes: 65157 → 65199 | `Get-NetTCPConnection` snapshots | RvControlSvc.exe (13164) | **Direct** (tool-reported) |
| 2026-11-26 03:42–03:48 | 06:42–06:48 | **Post-connection captures** (modules, network, pipes) | Multiple tools | Both | **Direct** |
| 2026-11-26 03:48:52 | 06:48:52 | Timeline compiled | This report | — | **Direct** |

## 3. Cross-Referenced Event Correlation

| Event | Precedes | Follows | Evidence |
|-------|----------|---------|----------|
| User Connect | Service port change (62654→65157) | GUI restart | Temporal |
| Service port change (62654→65157) | GUI restart | Service port change (65157→65199) | Temporal |
| GUI restart | Service port change (65157→65199) | Post-captures | Temporal |

## 4. Process State Timeline

### 4.1 Service (RvControlSvc.exe)
| Time (Local) | PID | State | Network |
|--------------|-----|-------|---------|
| 03:33:28 | 13164 | Started | — |
| 03:33 | 13164 | Running | TCP 62654→17301 (Established), UDP 49237 |
| 03:41 | 13164 | Running | TCP 65157→17301 (Established), UDP 49237 |
| 03:42:35 | 13164 | Running | TCP 65157→17301 |
| 03:43 | 13164 | Running | TCP 65199→17301 (Established), UDP 49237 |

**Service stable throughout** — same PID, no SCM events.

### 4.2 GUI (RvRvpnGui.exe)
| Time (Local) | PID | State | Notes |
|--------------|-----|-------|-------|
| 03:10:33 | 5760 | Started | Baseline |
| 03:41 | 5760 | User clicks Connect | User action |
| 03:42:35 | **8808** | **Restarted** | New PID, new start time |
| 03:43 | 8808 | Running | Post-connection |

**GUI restarted once** at 03:42:35 (after user Connect).

## 5. Network State Timeline

| Time (Local) | Service TCP | Service UDP | GUI Network |
|--------------|-------------|-------------|-------------|
| 03:33 | 62654→17301 (Est) + Listen | 49237 | None |
| 03:41 | 65157→17301 (Est) + Listen | 49237 | None |
| 03:42:35 | 65157→17301 | 49237 | None (old PID gone) |
| 03:43 | 65199→17301 (Est) + Listen | 49237 | None |

## 6. Named Pipe Timeline

| Time (Local) | Pipe | Status |
|--------------|------|--------|
| 03:33 | RadminVpnGuiChannel | Present |
| 03:43 | RadminVpnGuiChannel | Present |

**Pipe stable throughout** — but no operation data captured.

## 7. Phase 2.7 vs 2.8 Discrepancy Summary

| Aspect | Phase 2.7 | Phase 2.8 |
|--------|-----------|-----------|
| Service PID baseline | 5572 | 13164 |
| Service PID post-connection | 5476 (restart) | 13164 (stable) |
| Service restart during Connect | **YES** | **NO** |
| GUI PID baseline | 1232 | 5760 |
| GUI PID post-connection | 1232 (stable) | 8808 (restart) |
| GUI restart during Connect | **NO** | **YES** |
| Service TCP port baseline | None (only UDP) | 62654→17301 (Established) |

> **Note**: Phase 2.7 and 2.8 appear to be **different experimental sessions** with different initial conditions. Phase 2.7 started with no TCP connection; Phase 2.8 started with TCP already established.

## 8. Timeline Gaps and Uncertainties

| Gap | Duration | Impact |
|-----|----------|--------|
| Exact millisecond of user Connect click | Unknown | User-reported only |
| Exact millisecond of GUI termination | Unknown | Snapshots only |
| Exact millisecond of service port change 62654→65157 | ~1 min window | Snapshot interval |
| Exact millisecond of service port change 65157→65199 | ~1 min window | Snapshot interval |
| Pipe operations during Connect | Not captured | Tool limitation |

## 9. Evidence Classification Summary

| Event | Classification |
|-------|----------------|
| Process start times (CreationDate) | **Directly observed** |
| Service PID stability | **Directly observed** |
| GUI PID change (5760→8808) | **Directly observed** |
| Service TCP port changes | **Tool-reported** (Get-NetTCPConnection) |
| Service UDP stability | **Tool-reported** (Get-NetUDPEndpoint) |
| User Connect action | **User-reported** |
| Pipe presence | **Directly observed** |
| Temporal correlations | **Inferred** |
| Causal relationships | **Hypothesis** |

## 10. Reconciliation with Phase 2.7 Timeline

Per Report 02 (`02_PHASE_2_7_TIMELINE_RECONCILIATION.md`), Phase 2.7 timeline contained internal inconsistencies. Phase 2.8 timeline is **internally consistent** and based on verified timestamps from:
- `Get-CimInstance Win32_Process` CreationDate (process start times)
- `Get-NetTCPConnection`/`Get-NetUDPEndpoint` snapshots
- `Get-ChildItem \\.\pipe\` enumerations
- `Get-WinEvent` SCM queries
- User-reported Connect time

**Phase 2.8 timeline supersedes Phase 2.7 for the current experiment session.**

---
*Report generated: 2026-11-26 06:15 UTC*
*Evidence classification: Directly observed, Tool-reported, User-reported, Inferred, Hypothesis*