# Phase 2.7 — Static/Runtime Correlation

## 1. Correlation Overview
This report correlates the **runtime module inventory** (baseline + post-connection) with **existing static analysis evidence** in the repository (Ghidra projects, REA reports, Phase 2.x reports).

## 2. Module Coverage Matrix

| Runtime Module | Static Coverage | Repository Evidence | Gap Assessment | Priority |
|----------------|-----------------|---------------------|----------------|----------|
| **RvROLClient.dll** | ✅ **Extensive** | Ghidra project, Round-02 REA, Phase 2.3/2.4/2.5 reports | Low — Core protocol logic documented | HIGH |
| **RvControlSvc.exe** | ✅ **Moderate** | Ghidra project, Phase 2.3 (service entry, IPC), Phase 2.5 | Medium — Service lifecycle, restart trigger | HIGH |
| **RvRvpnGui.exe** | ✅ **Moderate** | Ghidra project, Qt integration analysis | Medium — GUI→Service IPC, connection UI flow | HIGH |
| **RvDownloader.dll** | ⚠️ **Partial** | Referenced in Phase 2.5, limited REA | High — Update mechanism, not connection | MEDIUM |
| **RvRolUpdater.dll** | ⚠️ **Partial** | Referenced in Phase 2.5, limited REA | High — ROL update logic | MEDIUM |
| **RvUESClient.dll** | ⚠️ **Partial** | Referenced in Round-02 (UES protocol) | High — UES client logic, key exchange | HIGH |
| **Shelper.dll** | ❌ **None** | Not analyzed (v4.0.0.4, different version) | Complete — Shared helper, unknown functions | MEDIUM |
| **WinLpcDl.dll** | ❌ **None** | Referenced in Round-02 (IPC mechanism) | Complete — LPC transport layer | HIGH |
| **ChatLPCx.dll** | ❌ **None** | Referenced in Round-02 (Chat over LPC) | Complete — Chat IPC | MEDIUM |
| **libcrypto-3.dll** | N/A | OpenSSL 3.6.1 — public source | None — Standard library | N/A |
| **libssl-3.dll** | N/A | OpenSSL 3.6.1 — public source | None — Standard library | N/A |
| **libcurl.dll** | N/A | cURL 8.6.0 — public source | None — Standard library | N/A |
| **Qt5*.dll** | N/A | Qt 5.15.15 — public source | None — Framework | N/A |
| **icu*.dll** | N/A | ICU 74.1 — public source | None — Framework | N/A |

## 3. Key Correlation Findings

### 3.1 Pre-Loaded Protocol Stack
**Critical**: All core protocol modules (RvROLClient.dll, RvUESClient.dll, libcrypto-3.dll, libssl-3.dll, libcurl.dll) are **loaded in RvControlSvc.exe BEFORE any VPN connection**. This means:
- Service initialization loads full crypto/protocol stack at startup
- Connection establishment reuses existing loaded modules
- No dynamic module loading for protocol functions during connection

### 3.2 Service Restart Correlation
- **Static evidence**: Phase 2.3/2.5 show service entry point, initialization routines
- **Runtime evidence**: Service restarts (PID 5572→5476) on connection
- **Hypothesis**: Restart reinitializes protocol state machines, crypto contexts, peer tables
- **Gap**: Exact restart trigger (IPC message? API call?) not identified in static analysis

### 3.3 GUI-Service IPC
- **Static**: Phase 2.3 shows RvControlSvc.exe exports, possible named pipe/RPC interfaces
- **Runtime**: GUI (PID 1232) has **no Radmin protocol DLLs loaded** — only Qt5Network
- **Inference**: GUI communicates via Qt5Network (QLocalSocket/named pipes) to service
- **Gap**: Exact IPC protocol (message format, commands) not fully documented

### 3.4 Network Stack Correlation
| Runtime Observation | Static Evidence | Correlation |
|---------------------|-----------------|-------------|
| TCP relay to 148.113.190.78:17301 | PCAP shows port 17301 for relay | ✅ Confirmed |
| UDP 26.82.29.1:56413 baseline | Not in PCAPs (pre-connection) | New observation |
| libcurl in service | HTTP/REST for auth/discovery | ✅ Likely |
| libcrypto/libssl in service | TLS for relay/peer links | ✅ Confirmed |

### 3.5 Missing Static Coverage (Post-Connection)
No new modules loaded → **no new static analysis targets** from this phase.

However, the **service restart behavior** is a runtime phenomenon requiring:
1. Dynamic analysis of restart trigger (IPC tracing)
2. Memory state comparison pre/post restart
3. Crypto key lifecycle across restart

## 4. Prioritized Static Analysis Gaps

| Priority | Target | Reason | Suggested Approach |
|----------|--------|--------|-------------------|
| **P1** | RvControlSvc.exe restart trigger | Connection requires restart | Trace GUI→Service IPC; find restart API |
| **P1** | RvUESClient.dll key exchange | UES protocol, likely SRP/TLS | REA dynamic + Ghidra static |
| **P1** | WinLpcDl.dll / ChatLPCx.dll | IPC transport layer | REA on DLL exports |
| **P2** | RvROLClient.dll peer handshake | Core ROL protocol | Extend existing Ghidra |
| **P2** | Service crypto state reinit | Restart clears/recreates keys | Dynamic trace + static |
| **P3** | Shelper.dll (v4.0.0.4) | Shared helper, unknown role | REA from scratch |
| **P3** | RvDownloader/RvRolUpdater | Update mechanism | Lower priority for VPN core |

## 5. Temporal Correlation Caveats
⚠️ **Important**: Module presence at connection time ≠ causation
- RvROLClient.dll loaded at service startup (02:44 UTC), not at connection (03:11 UTC)
- libcrypto/libssl loaded at startup, not at connection
- **No module loads observed during connection establishment** (service restart replaces process)
- Protocol execution uses **already-loaded code paths**

## 6. Repository Evidence Index
*Key documents for correlation:*
- `docs/reverse-engineering/round-02/` — 10 protocol analysis reports
- `docs/PHASE_2_3/` — 23 static analysis reports (object lifecycle, vtables)
- `docs/PHASE_2_5/` — 19 static correction reports (vtables, dispatch)
- `docs/CRYPTO_*.md` — 30+ crypto analysis reports
- `docs/PCAP_*.md` — 7 PCAP forensics reports (port 17301, relay)

---
*Report generated: 2026-11-26 03:40 UTC*
*Evidence classification: Directly observed (runtime), Tool-reported (static repo index), Inferred (correlation)*