# Phase 2.8 — SCM Event Analysis

## 1. Baseline SCM Events (Pre-Experiment)

### 1.1 Recent Radmin VPN Control Service Events
| Time (Local) | Event ID | Message | Interpretation |
|--------------|----------|---------|----------------|
| 26/11/2026 03:14:52 | 7034 | Service terminated unexpectedly (5th occurrence) | Crash |
| 26/11/2026 03:13:32 | 7034 | Service terminated unexpectedly (4th occurrence) | Crash |
| 26/11/2026 03:11:03 | 7034 | Service terminated unexpectedly (3rd occurrence) | Crash |
| 26/11/2026 02:43:52 | 7034 | Service terminated unexpectedly (2nd occurrence) | Crash |
| 26/11/2026 02:39:56 | 7034 | Service terminated unexpectedly (1st occurrence) | Crash |

### 1.2 Current Service State
- **Service**: RvControlSvc (Radmin VPN Control Service)
- **State**: Running (as of baseline capture)
- **PID**: 13164
- **Start Time**: 26/11/2026 03:33:28 local
- **Start Type**: Auto
- **Account**: LocalSystem

### 1.3 Pattern Analysis
| Metric | Value |
|--------|-------|
| Total crashes (last 24h) | 5+ |
| Crash frequency | Every ~1-2 minutes (during Phase 2.7) |
| Current uptime | ~42 minutes (since 03:33:28) |
| Crash interval (recent) | ~1-2 minutes |

> **Observation**: The service has been crashing repeatedly. The current instance (PID 13164) has been stable for ~42 minutes, which is longer than the previous crash interval.

## 2. SCM Event Types Monitored

| Event ID | Name | Description | Relevance |
|----------|------|-------------|-----------|
| 7034 | Service Crash | Service terminated unexpectedly | **Primary** - indicates crash |
| 7036 | State Change | Service entered running/stopped state | **Primary** - tracks lifecycle |
| 7031 | Error Limit | Service exceeded error limit | Secondary - recovery limit |
| 7023 | Terminated with Error | Service terminated with error code | Secondary - error detail |
| 7024 | Terminated with Error | Service terminated with error code | Secondary - error detail |

## 3. Baseline Event Log Position

### 3.1 Pre-Experiment Event Count
- **Total SCM events (RvControlSvc, last 20)**: 15 events
- **Last event before experiment**: 26/11/2026 03:14:52 (Event 7034)
- **Current service start**: 26/11/2026 03:33:28 (no SCM event logged for start, or Event 7036 not captured in last 20)

### 3.2 Event Record ID Baseline
*Not captured - need to query specific record IDs for correlation*

## 4. Post-Experiment Collection Plan

After the connection experiment, collect:
1. New SCM events for RvControlSvc
2. Event 7036 (state change) timestamps
3. Event 7034 (crash) if service restarts
3. Event 7031/7023/7024 if error codes present
4. Correlate with connection timeline

## 5. Limitations

| Limitation | Impact |
|------------|--------|
| No real-time SCM event streaming | Events only visible via `Get-WinEvent` queries |
| Event 7036 (state change) may not log for all transitions | Service start may not generate event |
| No crash dump / error code capture | Event 7034 doesn't include exit code |
| No correlation with process ID in event | Event 7034 doesn't include PID |

## 6. Correlation Strategy

| Experiment Event | Expected SCM Event | Correlation Method |
|------------------|-------------------|-------------------|
| User clicks Connect | None directly | Timestamp correlation |
| Service restarts (PID change) | 7034 (crash) + 7036 (start) | Timestamp + service name |
| Service crashes | 7034 | Count increment |
| Service stops cleanly | 7036 (stopped) | State transition |

---
*Report generated: 2026-11-26 04:55 UTC*
*Evidence classification: Tool-reported (Get-WinEvent), Directly observed (service state), Inferred (correlation strategy)*