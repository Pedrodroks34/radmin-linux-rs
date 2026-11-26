# Phase 2.8 — Evidence Limitations and Unresolved Questions

## 1. Tool and Coverage Limitations

### 1.1 Missing Monitoring Capabilities
| Capability | Tool Required | Status | Impact |
|------------|---------------|--------|--------|
| Real-time process monitoring | Procmon / ETW | ❌ Unavailable | Miss transient helper processes |
| Named pipe operations | Procmon / ETW | ❌ Unavailable | Cannot observe IPC message flow |
| File/registry access | Procmon | ❌ Unavailable | Config/cert access unknown |
| RPC/ALPC message capture | ETW RPC/ALPC providers | ❌ Failed (no admin) | IPC mechanism unknown |
| Kernel/NDIS driver activity | Kernel ETW / WPP | ❌ Unavailable | Tunnel creation invisible |
| Packet capture | Wireshark / pktmon | ❌ Not done | Protocol content unknown |
| Memory/key extraction | Debugger | ❌ Prohibited | Crypto keys unknown |

### 1.2 Snapshot-Based Limitations
| Limitation | Effect |
|------------|--------|
| Process/network snapshots every ~1-2 min | Transient events (sub-second) missed |
| No continuous pipe monitoring | Pipe create/connect/read/write invisible |
| No SCM event streaming | Must poll; may miss brief state changes |
| Module enumeration is point-in-time | Delay-loaded modules may be missed |
| No GUI debugger attach | GUI internal state during Connect unknown |

### 1.3 Tool-Specific Issues
| Tool | Issue | Mitigation |
|------|-------|------------|
| EnumModules2.exe | Initially used hardcoded PIDs due to Start-Process arg parsing | Fixed by using `cmd /c` invocation |
| Start-Process -ArgumentList | Single string treated as one argument | Use `cmd /c` or separate args |
| Get-WinEvent | No real-time; must poll | Accept polling gap |
| Get-NetTCPConnection | Snapshot only | Accept polling gap |

## 2. Evidence Classification Reference

| Label | Definition | Example |
|-------|------------|---------|
| **Directly observed** | Human-visible in raw tool output | PID 13164 in `Get-Process` output |
| **Tool-reported** | Tool output, not independently verified | `Get-NetTCPConnection` port 65157 |
| **Corroborated** | Multiple independent sources | PID 13164 stable (Process + SCM) |
| **Computed** | Derived from recorded values | Port delta 62654→65157 |
| **Inferred** | Logical deduction from evidence | GUI restart caused by Connect |
| **Hypothesis** | Testable prediction | Service port change = relay reconnect |
| **Unknown** | Not established | Pipe message protocol |

## 3. Unresolved Questions

### 3.1 Service Behavior
| # | Question | Priority | Evidence Needed |
|---|----------|----------|-----------------|
| Q1 | Why did service restart in Phase 2.7 but not Phase 2.8? | **HIGH** | Compare initial conditions (crash loop vs stable) |
| Q2 | Why does service change local TCP port on Connect (62654→65157)? | **HIGH** | Service code trace / relay protocol |
| Q3 | Why does service change local TCP port again after GUI restart (65157→65199)? | **HIGH** | Service code trace / GUI IPC |
| Q4 | Is UDP port 49237 fixed or ephemeral? | MEDIUM | Multiple connections |
| Q5 | What causes the 5 pre-baseline crashes? | MEDIUM | Crash dumps / Event Viewer |

### 3.2 GUI Behavior
| # | Question | Priority | Evidence Needed |
|---|----------|----------|-----------------|
| Q6 | What triggers GUI restart on Connect? | **HIGH** | GUI debugger trace / IPC trace |
| Q7 | Why does GUI module count drop 125→101 on restart? | **HIGH** | Delay-load analysis / Qt plugin load logic |
| Q8 | Does GUI restart reinitialize IPC channel? | **HIGH** | Pipe operation trace |
| Q9 | Does GUI use QLocalSocket to `RadminVpnGuiChannel`? | **HIGH** | Qt5Network code trace |

### 3.3 IPC Mechanism
| # | Question | Priority | Evidence Needed |
|---|----------|----------|-----------------|
| Q10 | What is the exact IPC protocol on `RadminVpnGuiChannel`? | **HIGH** | Pipe message capture (Procmon) |
| Q11 | Does service create the pipe or GUI? | MEDIUM | Pipe create trace |
| Q12 | Are WinLpcDl.dll / ChatLPCx.dll ever loaded? | MEDIUM | Delay-load trace / feature trigger |
| Q13 | Is RPC/ALPC used in addition to named pipes? | MEDIUM | ETW RPC/ALPC capture |

### 3.4 Network/Protocol
| # | Question | Priority | Evidence Needed |
|---|----------|----------|-----------------|
| Q14 | What protocol runs on TCP 17301 to relay? | **HIGH** | PCAP / service trace |
| Q15 | What causes service port change 62654→65157? | **HIGH** | Service trace |
| Q16 | What causes service port change 65157→65199? | **HIGH** | Service trace |
| Q17 | Is UDP 49237 used for peer traffic or keepalive? | MEDIUM | PCAP / traffic analysis |
| Q18 | How are peer addresses discovered? | MEDIUM | PCAP / service trace |

### 3.5 Crypto/Key Management
| # | Question | Priority | Evidence Needed |
|---|----------|----------|-----------------|
| Q19 | Where are session keys generated/stored? | **HIGH** | Memory analysis (prohibited) |
| Q20 | How does libcrypto/libssl integrate with RvROLClient? | **HIGH** | Static trace + dynamic |
| Q21 | Does GUI restart affect session keys? | **HIGH** | Key comparison pre/post |

## 4. Scope Boundaries

### In Scope
- Radmin VPN processes (RvControlSvc, RvRvpnGui)
- Modules loaded by these processes
- Network endpoints owned by these processes
- Named pipe `RadminVpnGuiChannel`
- Service Control Manager events for RvControlSvc
- Files in `C:\Program Files (x86)\Radmin VPN\`

### Out of Scope
- Kernel drivers (NDIS, filter drivers)
- Other user processes
- Full packet captures (PCAP)
- Memory contents / key material
- Credential handling
- Famatech server infrastructure
- Other VPN software

## 5. Evidence Gaps by Category

| Category | Coverage | Gap Severity |
|----------|----------|--------------|
| Process lifecycle | Good (snapshots) | Medium (no continuous) |
| Module inventory | Good (validated snapshots) | Low |
| Network endpoints | Good (snapshots) | Medium (no continuous) |
| IPC mechanisms | Poor (pipe existence only) | **Critical** |
| File/registry access | None | High |
| Crypto/keys | None (prohibited) | **Critical** |
| Protocol content | None | **Critical** |
| GUI internal state | None (no debugger) | High |

## 6. Recommendations for Next Phase

1. **Install Procmon** in elevated session before experiment
2. **Run ETW capture** from elevated PowerShell (`logman` with Kernel-Process, RPC, ALPC)
3. **Capture PCAP** with Wireshark/pktmon (authorized)
4. **Static analysis**: Trace RvControlSvc.exe Connect IPC handler
5. **Static analysis**: Reverse WinLpcDl.dll / ChatLPCx.dll
6. **Compare Phase 2.7 vs 2.8 initial conditions** to explain service restart difference

---
*Report generated: 2026-11-26 06:35 UTC*
*Evidence classification: Directly observed (limitations), Hypothesis (questions)*