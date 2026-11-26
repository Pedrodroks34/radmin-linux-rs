# Phase 2.7 — Evidence Limitations and Unresolved Questions

## 1. Baseline Capture Limitations

### 1.1 Module Enumeration
| Limitation | Impact | Severity |
|------------|--------|----------|
| PSAPI `EnumProcessModulesEx` with `LIST_MODULES_ALL` may miss manually mapped modules | Potential false negatives for reflective/injected DLLs | Medium |
| WoW64 processes: 32-bit enumerator sees 32-bit modules; 64-bit modules (WoW64 subsystem) also visible but paths may be redirected | Both 32-bit and 64-bit module lists captured | Low (documented) |
| No kernel-mode module enumeration | Driver (NDIS) modules not visible | High |
| Single snapshot — transient modules missed | Modules loaded/unloaded between snapshots invisible | Medium |
| Base addresses change per-boot (ASLR) — not comparable across reboots | Address comparison only valid within same session | Low |

### 1.2 Process Monitoring
| Limitation | Impact | Severity |
|------------|--------|----------|
| No real-time process creation monitoring (no Procmon/ETW) | Short-lived helper processes may be missed | Medium |
| WinDbg only attached to PID 5572 (service) | GUI process events not captured in real-time | Medium |
| Command lines not available for service process | Cannot verify service arguments | Low |
| Thread-level activity not captured | Cannot correlate module loads with specific threads | Medium |

### 1.3 Network Monitoring
| Limitation | Impact | Severity |
|------------|--------|----------|
| Snapshot only (`Get-Net*Endpoint`) | Transient connections missed | Medium |
| No packet capture (PCAP) | Cannot analyze protocol, encryption, payloads | High |
| IPv6 not checked | Potential IPv6 endpoints missed | Low |
| Firewall rule state not captured | Cannot correlate with RvFwHelper.exe activity | Medium |
| No DNS query capture | Cannot see resolution of Radmin servers | Medium |

### 1.4 File System Monitoring
| Limitation | Impact | Severity |
|------------|--------|----------|
| No real-time file access monitoring (Procmon) | Config/log/data file accesses invisible | Medium |
| No file hash comparison (only baseline hashes) | Modified files not detected until post-capture | Medium |
| Registry access not monitored | Configuration changes invisible | Medium |

### 1.5 General
| Limitation | Impact | Severity |
|------------|--------|----------|
| No memory dumps / code injection | Cannot analyze runtime state, keys, buffers | High (by design — non-intrusive) |
| Single baseline — no historical comparison | Cannot detect gradual changes | Low |
| User-reported GUI timing | ~seconds latency in event correlation | Low |
| Admin required for full enumeration | Some environments may restrict | Medium |

## 2. Unresolved Questions (Pre-Connection)

### 2.1 Architecture Questions
| # | Question | Evidence Needed | Priority |
|---|----------|-----------------|----------|
| Q1 | What IPC mechanism does GUI use to talk to service? | Named pipe / RPC / LPC handle enumeration | High |
| Q2 | Is RvROLClient.dll the sole protocol implementation in service? | Static analysis + runtime call tracing | High |
| Q3 | What triggers RvFwHelper.exe spawn? | Post-connection process tree | High |
| Q4 | Does drvinst.exe run on every connection or only first? | Multiple connection tests | Medium |
| Q5 | What is the purpose of WinLpcDl.dll / ChatLPCx.dll? | Static analysis + runtime loading | High |

### 2.2 Network Questions
| # | Question | Evidence Needed | Priority |
|---|----------|-----------------|----------|
| Q6 | What protocol runs on UDP 56413? | PCAP + payload analysis | High |
| Q7 | Does service establish TCP to relay servers pre-connection? | Continuous netstat / PCAP | Medium |
| Q8 | How are peer addresses discovered? | Post-connection network diff | High |
| Q9 | Is there a persistent control channel to Famatech servers? | Long-term network monitoring | Medium |

### 2.3 Crypto/Key Questions
| # | Question | Evidence Needed | Priority |
|---|----------|-----------------|----------|
| Q10 | Where are session keys generated/stored? | Memory analysis (not in scope) | High |
| Q11 | Does libcrypto-3/libssl-3 handle all TLS? | Call tracing + static analysis | High |
| Q12 | What is RvUESClient.dll's role in key exchange? | Static analysis + runtime | High |

### 2.4 Module/Code Questions
| # | Question | Evidence Needed | Priority |
|---|----------|-----------------|----------|
| Q13 | Why does GUI not load RvROLClient.dll at baseline? | Static analysis of GUI imports | Medium |
| Q14 | What Qt plugins are loaded dynamically post-connection? | Module diff | Low |
| Q15 | Are there any delay-loaded DLLs in Radmin binaries? | Static analysis (delay import table) | Medium |

## 3. Post-Connection Questions (Anticipated)
*To be refined after connection*

| # | Question | Status |
|---|----------|--------|
| PQ1 | Which new modules load in service during connection? | Pending |
| PQ2 | Which new modules load in GUI during connection? | Pending |
| PQ3 | Does RvFwHelper.exe spawn? With what args? | Pending |
| PQ4 | What new TCP/UDP endpoints appear? | Pending |
| PQ5 | Are any temporary files created in Radmin dir? | Pending |

## 4. Evidence Classification Reference
Used throughout Phase 2.7 reports:

| Label | Definition |
|-------|------------|
| **Directly observed** | Seen by human operator (e.g., GUI window, process list) |
| **Tool-reported** | Output from automated tool (WinDbg, EnumModules2, PowerShell) |
| **Computed** | Derived values (SHA-256, base address math, timestamps) |
| **Inferred** | Logical deduction from evidence (e.g., "virtual adapter" from IP range) |
| **Hypothesis** | Testable prediction not yet verified |
| **Unknown / Not captured** | Explicitly not measured or unavailable |

## 5. Scope Boundaries
### In Scope
- Radmin VPN processes (RvControlSvc, RvRvpnGui)
- Modules loaded by these processes
- Network endpoints owned by these processes
- Helper processes spawned by these processes
- Files in C:\Program Files (x86)\Radmin VPN\

### Out of Scope
- Kernel drivers (NDIS, filter drivers)
- Other user processes
- Full packet captures
- Memory contents / key material
- Credential handling
- Famatech server infrastructure
- Other VPN software

---
*Report generated: 2026-11-26 04:00 UTC*
*Evidence classification: Directly observed (limitations), Hypothesis (questions)*