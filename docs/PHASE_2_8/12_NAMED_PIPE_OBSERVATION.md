# Phase 2.8 — Named Pipe Observation and Limitations

## 1. Observation Method
Named pipes enumerated via `Get-ChildItem "\\.\pipe\" -Recurse -ErrorAction SilentlyContinue` with filtering for Radmin-related patterns (`*Radmin*`, `*RvControl*`, `*RvRvpn*`).

## 2. Observations

### 2.1 Baseline (Pre-Connection) — ~03:33 local
| Pipe Name | Type | Last Write Time |
|-----------|------|-----------------|
| RadminVpnGuiChannel | Named Pipe | 31/12/1600 22:00:00 |

### 2.2 Post-Connection (After GUI Restart) — ~03:43 local
| Pipe Name | Type | Last Write Time |
|-----------|------|-----------------|
| RadminVpnGuiChannel | Named Pipe | 31/12/1600 22:00:00 |

### 2.3 Additional Checks
No other pipes matching `*Radmin*`, `*RvControl*`, `*RvRvpn*` found at either time.

## 3. What This Evidence Establishes

| Claim | Supported? | Evidence |
|-------|------------|----------|
| Pipe `RadminVpnGuiChannel` exists | ✅ **YES** | Enumerated at both captures |
| Pipe name suggests GUI-to-service channel | ✅ **YES** | Name pattern |
| Pipe is used for Connect command | ❌ **NO** | No operation data captured |
| Pipe was recreated after GUI restart | ❌ **UNKNOWN** | Same name, same timestamp (likely cached FS metadata) |
| Service creates/owns the pipe | ❌ **UNKNOWN** | No owner PID visible via this method |
| GUI connects to the pipe | ❌ **UNKNOWN** | No connection data |

## 4. What This Evidence Does NOT Establish

| Limitation | Impact |
|------------|--------|
| No pipe open/read/write operations captured | Cannot confirm actual IPC usage |
| No pipe security descriptor visible | Cannot verify ACLs |
| No pipe creator/owner PID | Cannot confirm which process created it |
| No message content or protocol | Cannot analyze IPC protocol |
| Timestamp is filesystem metadata (likely cached) | Cannot determine creation time |
| Single snapshot per phase | No continuous monitoring |

## 5. Correlation with Static Analysis

### 5.1 Static Evidence (Prior Phases)
- `WinLpcDl.dll` — LPC/IPC mechanism DLL present in install directory
- `ChatLPCx.dll` — "Chat LPC" DLL present
- `RvROLClient.dll` — Contains RPC/ROL protocol logic
- Qt5Network in GUI — Could use `QLocalSocket` for named pipe communication

### 5.2 Static/Dynamic Correlation
| Static Indicator | Dynamic Observation | Correlation |
|------------------|---------------------|-------------|
| `WinLpcDl.dll` exists | Named pipe `RadminVpnGuiChannel` exists | **Plausible** — LPC often uses named pipes |
| `ChatLPCx.dll` exists | Pipe name contains "Channel" | **Plausible** — Chat/IPC channel |
| Qt5Network in GUI | GUI has no network sockets | **Consistent** — GUI uses local IPC |

## 6. Phase 2.7 Comparison

| Aspect | Phase 2.7 | Phase 2.8 |
|--------|-----------|-----------|
| Pipe `RadminVpnGuiChannel` | Not checked | ✅ Observed both phases |
| Other Radmin pipes | Not checked | None found |
| Pipe operation capture | None | None (tool limitation) |

## 7. Evidence Classification

| Finding | Classification | Source |
|---------|----------------|--------|
| Pipe `RadminVpnGuiChannel` exists | **Directly observed** | `Get-ChildItem \\.\pipe\` |
| Pipe present pre and post | **Directly observed** | Two independent enumerations |
| Pipe name suggests GUI-service IPC | **Inferred** | Naming pattern |
| Pipe used for Connect command | **Hypothesis** | Temporal correlation only |
| Pipe recreated on GUI restart | **Unknown** | No operation data |

## 8. Critical Limitations

### 8.1 Without Procmon/ETW
- Cannot observe pipe **creation** (which process, when)
- Cannot observe pipe **connections** (which process opens)
- Cannot observe **read/write operations** (message flow)
- Cannot capture **message content** (protocol analysis)

### 8.2 Without Handle.exe
- Cannot map pipe handle to owning process
- Cannot see pipe security descriptor

### 8.3 Timestamp Reliability
- `LastWriteTime` shows `31/12/1600 22:00:00` — clearly not a real timestamp
- Likely filesystem metadata artifact or default value
- **Cannot use for temporal correlation**

## 9. Recommendations for Future Phases

1. **Install Procmon** — Capture pipe create/open/read/write/close operations
2. **Use ETW Microsoft-Windows-Kernel-File** — Track file/pipe operations
3. **Implement named pipe client** — Connect to `\\.\pipe\RadminVpnGuiChannel` and observe protocol
4. **Static analysis of WinLpcDl.dll/ChatLPCx.dll** — Reverse engineer IPC protocol

## 10. Conclusion

**The named pipe `RadminVpnGuiChannel` is the only Radmin-related pipe observed.** Its existence is confirmed, but **its actual usage for GUI-to-service IPC during the Connect action cannot be confirmed** with the current evidence. The pipe's presence is consistent with the static analysis findings (WinLpcDl.dll, ChatLPCx.dll), but no dynamic IPC activity was captured.

---
*Report generated: 2026-11-26 05:55 UTC*
*Evidence classification: Directly observed (pipe enumeration), Inferred (naming correlation), Hypothesis (IPC role), Unknown (operation details)*