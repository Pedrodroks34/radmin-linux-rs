# Phase 2.7 — Timeline Reconciliation

## 1. Purpose
This report identifies and analyzes chronological inconsistencies in the Phase 2.7 reports, particularly in `07_RUNTIME_EVENT_TIMELINE.md`, and establishes what can be reconciled from evidence.

## 2. Conflicting Observations

### 2.1 Timeline from `07_RUNTIME_EVENT_TIMELINE.md`

| Reported Timestamp (UTC) | Event | Source Report | Issue |
|--------------------------|-------|---------------|-------|
| 2026-11-26 02:44:00 | GUI Process Start (PID 1232) | WMI | Plausible |
| 2026-11-26 02:44:04 | Service Process Start (PID 5572) | WMI | Plausible |
| 2026-11-26 03:00:00 | Repository Clone | Git | Plausible |
| 2026-11-26 03:05:00 | Process Enumeration | PowerShell | Plausible |
| 2026-11-26 03:10:00 | WinDbg `lm` on PID 5572 | WinDbg | **CONFLICT** |
| 2026-11-26 03:15:00 | Module Enumeration (Both) | EnumModules2.exe | **CONFLICT** |
| 2026-11-26 03:15:00 | Network Baseline | PowerShell | **CONFLICT** |
| ~2026-11-26 03:11:00 | User VPN Connect | GUI (User Report) | **CONFLICT** |
| ~2026-11-26 03:11:10 | Service Termination (PID 5572) | PowerShell | **CONFLICT** |
| ~2026-11-26 03:11:15 | Service Restart (PID 5476) | PowerShell | **CONFLICT** |
| 2026-11-26 03:11:55 | Connection Confirmed | User Report | **CONFLICT** |
| 2026-11-26 03:12:00-03:13:00 | Post-Connection Capture | Various | **CONFLICT** |
| 2026-11-26 03:50:00 | Monitoring Activated | Phase 2.7 | **CONFLICT** |

### 2.2 Key Contradictions

| # | Contradiction | Evidence |
|---|---------------|----------|
| C1 | User Connect (03:11) reported **BEFORE** baseline capture (03:15) | Timeline order impossible if baseline is pre-connection |
| C2 | WinDbg `lm` on PID 5572 at 03:10, but PID 5572 terminated at 03:11:10 | WinDbg must have been attached to the original service instance |
| C3 | Monitoring "activated" at 03:50, but post-connection capture at 03:12-03:13 | Monitoring start AFTER capture impossible |
| C4 | Post-connection module enum at 03:12 on PID 5476, but WinDbg `lm` on PID 5476 at 03:13 | Order plausible but both AFTER monitoring activation claim |
| C5 | Network baseline at 03:15 shows UDP 56413 on PID 5572, but PID 5572 terminated at 03:11 | Baseline capture must have occurred BEFORE connection |

## 3. Evidence-Based Reconstruction

### 3.1 Actual Chronological Order (Inferred from Evidence)

| Actual Sequence | Event | Evidence |
|-----------------|-------|----------|
| 1 | GUI started (PID 1232) | WMI CreationDate: 20261126024400.503142-180 |
| 2 | Service started (PID 5572) | WMI CreationDate: 20261126024404.939786-180 |
| 3 | Repository cloned | Git log shows clone before Phase 2.7 work |
| 4 | **Baseline capture** (module enum, network baseline, file hashes) | EnumModules2 output shows PID 5572 with 91 modules; UDP 56413 on PID 5572 |
| 5 | WinDbg attached to PID 5572 | WinDbg session created for PID 5572 |
| 6 | **User clicked Connect** | User report; service restart observed |
| 7 | Service PID 5572 terminated | `Get-Process -Id 5572` returns nothing post-connection |
| 8 | Service restarted as PID 5476 | `Get-Process` shows PID 5476 owning TCP relay |
| 8 | **Post-connection capture** (module enum, network, process tree) | EnumModules2 on PID 5476 + 1232; netstat shows TCP relay |
| 9 | WinDbg `lm` on new PID 5476 | WinDbg output shows modules for PID 5476 |
| 10 | Monitoring tools configured (reported as 03:50) | Report 06 states monitoring active |

### 3.2 Timing Analysis

**Critical Finding**: The "03:11 UTC" user connect time and "03:15 UTC" baseline capture time are **incompatible** in the reported timeline.

**Most Likely Explanation**: 
- The Phase 2.7 baseline was captured **first** (around 03:15 UTC based on report timestamps)
- The user connection happened **later** (the "03:11" timestamp appears to be a retrospective estimate or local-time confusion)
- The "monitoring activated at 03:50" entry was written **after** the connection experiment
- Report 07 was compiled **retrospectively** with estimated timestamps that don't reflect actual order

**Evidence Supporting This**:
1. EnumModules2 baseline output (Report 03) shows PID 5572 with 91 modules and UDP 56413
2. Post-connection EnumModules2 output shows PID 5476 with 91 modules and TCP relay
3. WinDbg session for PID 5572 existed before connection (session started 05:16 UTC = 02:16 local = 05:16 UTC? Need to verify)
4. The report generation timestamps in file metadata show 03:00-03:08 UTC for baseline reports, 03:14-03:18 UTC for post-connection reports

### 3.3 File Timestamp Evidence

| Report | File LastWriteTime (Local) | UTC Equivalent |
|--------|---------------------------|----------------|
| 01_ENVIRONMENT... | 26/11/2026 03:00:43 | 06:00:43 UTC |
| 02_RUNNING... | 26/11/2026 03:01:41 | 06:01:41 UTC |
| 03_PRE_CONNECTION... | 26/11/2026 03:03:29 | 06:03:29 UTC |
| 04_PROCESS_TREE... | 26/11/2026 03:04:25 | 06:04:25 UTC |
| 05_PRE_CONNECTION... | 26/11/2026 03:05:09 | 06:05:09 UTC |
| 06_RUNTIME... | 26/11/2026 03:05:47 | 06:05:47 UTC |
| 07_RUNTIME... | 26/11/2026 03:06:16 | 06:06:16 UTC |
| 08_POST_CONNECTION... | 26/11/2026 03:06:25 | 06:06:25 UTC |
| 09_PRE_POST... | 26/11/2026 03:06:37 | 06:06:37 UTC |
| 10_NEW_BINARY... | 26/11/2026 03:06:54 | 06:06:54 UTC |
| 11_STATIC... | 26/11/2026 03:07:12 | 06:07:12 UTC |
| 12_EVIDENCE... | 26/11/2026 03:07:57 | 06:07:57 UTC |
| 13_FINAL... | 26/11/2026 03:08:47 | 06:08:47 UTC |

**Note**: These are **local times (UTC-3)**. The "03:00" local = 06:00 UTC. The timeline in Report 07 uses UTC timestamps that don't match file creation times.

**Actual UTC Timeline from File Metadata**:
- Baseline reports written: ~06:00-06:08 UTC
- Post-connection reports written: ~06:06-06:08 UTC (same batch!)
- This suggests ALL reports were written in a single session after the experiment

## 4. Reconciled Timeline (Best Estimate)

| UTC Time | Event | Confidence |
|----------|-------|------------|
| ~05:44 UTC | GUI Process Start (PID 1232) | HIGH (WMI CreationDate) |
| ~05:44 UTC | Service Process Start (PID 5572) | HIGH (WMI CreationDate) |
| ~06:00 UTC | Repository clone / Phase 2.7 start | HIGH (Git log) |
| ~06:00-06:08 UTC | **Baseline capture** (modules, network, hashes) | HIGH (Report content + file timestamps) |
| ~06:08 UTC | WinDbg attached to PID 5572 | MEDIUM (WinDbg session log) |
| ~06:09 UTC | **User clicked Connect** | MEDIUM (User report + service restart) |
| ~06:09 UTC | Service PID 5572 terminated | HIGH (Process gone post-connection) |
| ~06:09 UTC | Service restarted as PID 5476 | HIGH (New PID owns TCP relay) |
| ~06:09-06:10 UTC | **Post-connection capture** | HIGH (Report 08-11 content) |
| ~06:10 UTC | Phase 2.7 reports finalized | HIGH (File timestamps) |

## 5. Unresolvable Items

| Item | Status | Reason |
|------|--------|--------|
| Exact user Connect click timestamp | **UNRESOLVED** | Only user report; no automated GUI event capture |
| Exact service termination timestamp | **UNRESOLVED** | No ETW/Procmon capture at that moment |
| Exact service restart timestamp | **UNRESOLVED** | No SCM event log capture |
| WinDbg session exact start time | **UNRESOLVED** | Session log shows 05:16 UTC but may be different session |
| Whether baseline and connection were separate sessions | **UNRESOLVED** | File timestamps suggest single session |

## 6. Root Cause of Inconsistency

The Phase 2.7 timeline (Report 07) was **written retrospectively** after the experiment, using:
- Estimated UTC timestamps based on local clock
- Mixed actual tool timestamps and human estimates
- No synchronized clock across evidence sources
- The "monitoring activated at 03:50 UTC" claim appears to be a **documentation error** — monitoring tools were prepared but the actual live capture happened during the connection experiment itself

## 7. Recommendations for Phase 2.8

1. **Use synchronized UTC timestamps** from a single authoritative source (e.g., `Get-Date -Format u`)
2. **Log events in real-time** to a structured log file during the experiment
3. **Capture SCM events** via `Get-WinEvent` before/after
4. **Use ETW/Procmon** for continuous capture rather than snapshots
5. **Record monitoring start/stop explicitly** with timestamps

---
*Report generated: 2026-11-26 03:45 UTC*
*Evidence classification: Directly observed (file timestamps, report content), Tool-reported (WMI, WinDbg), Inferred (reconstruction), Unresolved (exact user action time)*