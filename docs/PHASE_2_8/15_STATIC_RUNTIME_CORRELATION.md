# Phase 2.8 — Static/Runtime Correlation

## 1. Correlation Framework
Maps runtime observations (Phase 2.8) to static analysis evidence (Phase 2.3, 2.4, 2.5, Round-02 REA).

## 2. Module Coverage Matrix

| Runtime Module | Static Coverage | Phase 2.8 Observation | Gap |
|----------------|-----------------|----------------------|-----|
| **RvROLClient.dll** | ✅ Extensive (Phase 2.3, 2.4, 2.5, Round-02) | Loaded in service (PID 13164) pre/post | Low |
| **RvControlSvc.exe** | ✅ Moderate (Phase 2.3, 2.5) | Stable service, no restart | Medium (IPC/restart trigger) |
| **RvRvpnGui.exe** | ✅ Moderate (Phase 2.3, 2.5) | Restarted on Connect (5760→8808) | Medium (GUI IPC) |
| **RvUESClient.dll** | ⚠️ Partial (Round-02 UES) | Loaded in service pre/post | High (SRP/TLS) |
| **RvDownloader.dll** | ⚠️ Partial (Phase 2.5) | Loaded in service pre/post | High (Update) |
| **RvRolUpdater.dll** | ⚠️ Partial (Phase 2.5) | Loaded in service pre/post | High (ROL Update) |
| **Shelper.dll** | ❌ None (v4.0.0.4) | Loaded in service pre/post | Complete |
| **WinLpcDl.dll** | ❌ None (referenced) | Not loaded in either process | Complete (static only) |
| **ChatLPCx.dll** | ❌ None (referenced) | Not loaded in either process | Complete (static only) |
| **libcrypto-3.dll** | N/A (OpenSSL 3.6.1) | Loaded in service | N/A |
| **libssl-3.dll** | N/A (OpenSSL 3.6.1) | Loaded in service | N/A |
| **libcurl.dll** | N/A (cURL 8.6.0) | Loaded in service | N/A |
| **Qt5*.dll** | N/A (Qt 5.15.15) | Loaded in GUI (reduced set post-restart) | N/A |

## 3. Key Correlation Findings

### 3.1 Pre-Loaded Protocol Stack Confirmed
All core protocol modules **already loaded in service at baseline**:
- RvROLClient.dll (core ROL protocol)
- RvUESClient.dll (UES/SRP authentication)
- libcrypto-3.dll / libssl-3.dll (TLS)
- libcurl.dll (HTTP/REST)

**Static correlation**: Phase 2.3/2.5 shows these are core service components. Runtime confirms they load at service startup, not on-demand during Connect.

### 3.2 Service Stability vs Phase 2.7 Restart
| Phase | Service Behavior | Static Insight |
|-------|------------------|----------------|
| 2.7 | Restarted on Connect (5572→5476) | Service entry point in Phase 2.3 shows initialization logic |
| 2.8 | **Stable** (13164 throughout) | Same binary, different initial state |

**Hypothesis**: Service restart in Phase 2.7 may have been triggered by specific connection state (first connect after crash loop). Phase 2.8 service was already stable (9 min uptime).

### 3.3 GUI Restart Correlation
| Static Evidence | Runtime Observation |
|-----------------|---------------------|
| Phase 2.3: GUI uses Qt5Network (QLocalSocket likely) | GUI has no network endpoints; uses IPC |
| Phase 2.3: GUI imports RvROLClient? | **No** — GUI loads NO Radmin protocol DLLs |
| Phase 2.5: Qt5Network in GUI | GUI module reduction post-restart (125→101) |

**Finding**: GUI is a **pure Qt frontend** — all protocol logic in service. GUI restart on Connect suggests GUI reinitializes its IPC connection to service.

### 3.4 Named Pipe / IPC Correlation
| Static Artifact | Runtime Observation | Correlation |
|-----------------|---------------------|-------------|
| `WinLpcDl.dll` (install dir) | Not loaded in either process | Static reference only |
| `ChatLPCx.dll` (install dir) | Not loaded in either process | Static reference only |
| `RadminVpnGuiChannel` (pipe) | Observed pre/post | **Plausible IPC channel** |
| Qt5Network in GUI | GUI has no TCP/UDP endpoints | Consistent — uses local IPC |

**Gap**: WinLpcDl.dll and ChatLPCx.dll are present in install directory but **not loaded** in either process at baseline or post-connection. They may be delay-loaded or used only for specific features.

### 3.5 Network Stack Correlation
| Static Evidence | Runtime Observation |
|-----------------|---------------------|
| PCAP: Relay at 148.113.190.78:17301 | Service connects to 148.113.190.78:17301 ✅ |
| PCAP: Port 17301 for control | Service TCP→17301 ✅ |
| libcurl in service | HTTP/REST for auth/discovery ✅ |
| libcrypto/libssl in service | TLS for relay/peer ✅ |
| UDP on VPN adapter (26.82.29.1) | Service UDP 49237 on 26.82.29.1 ✅ |

## 4. Static Analysis Gaps Identified

| Priority | Target | Runtime Trigger | Static Gap |
|----------|--------|-----------------|------------|
| **P1** | RvControlSvc.exe IPC handler | Connect command from GUI | No dynamic IPC trace |
| **P1** | RvUESClient.dll SRP/TLS | Auth during Connect | No dynamic trace |
| **P1** | GUI restart trigger | Connect command | No GUI debugger trace |
| **P2** | Service port change logic (62654→65157→65199) | Connect + GUI restart | No dynamic trace |
| **P2** | WinLpcDl.dll / ChatLPCx.dll role | Not loaded observed | Complete gap |
| **P2** | GUI Qt module reduction (125→101) | GUI restart | No dynamic trace |
| **P3** | RvDownloader/RvRolUpdater | Not triggered | Low priority |

## 5. Temporal Correlation Caveats

⚠️ **Module presence ≠ causal role in Connect**
- RvROLClient.dll loaded at service startup (03:33), not at Connect (03:41)
- libcrypto/libssl loaded at startup, not at Connect
- **Protocol execution uses pre-loaded code paths**

⚠️ **GUI restart ≠ Connect handler**
- GUI restarted at 03:42:35, ~1.5 min after Connect (03:41)
- Could be GUI reinitializing IPC after service state change

## 6. Recommendations for Static Analysis

1. **Trace RvControlSvc.exe Connect IPC handler** — Find named pipe/RPC entry point
2. **Analyze RvUESClient.dll SRP/TLS** — Key exchange during Connect
3. **Reverse WinLpcDl.dll/ChatLpcx** — IPC transport layer
4. **Trace GUI Qt5Network usage** — QLocalSocket to `RadminVpnGuiChannel`
5. **Service port change logic** — Why two port changes?

---
*Report generated: 2026-11-26 06:25 UTC*
*Evidence classification: Directly observed (runtime), Tool-reported (static repo index), Inferred (correlation), Hypothesis (gaps)*