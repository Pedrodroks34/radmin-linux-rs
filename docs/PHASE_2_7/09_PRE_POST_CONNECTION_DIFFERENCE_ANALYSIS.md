# Phase 2.7 — Pre/Post Connection Difference Analysis

## 1. Executive Summary
**Primary Finding**: VPN connection triggers **RvControlSvc.exe service restart** (PID 5572 → 5476). No new modules loaded in either process. Network state changes from idle UDP listener to active TCP relay connection.

## 2. Difference Matrix

| Category | Baseline (Pre) | Post-Connection | Change Type | Significance |
|----------|----------------|-----------------|-------------|--------------|
| **Service PID** | 5572 | **5476** | **Process restart** | **HIGH** |
| **Service Modules** | 91 | 91 | None | Low |
| **GUI Modules** | 125 | 125 | None | Low |
| **Service Network** | UDP 26.82.29.1:56413 | TCP 192.168.31.111:59509→148.113.190.78:17301 (ESTABLISHED) + TCP 0.0.0.0:59509 (LISTEN) | **Protocol/endpoint shift** | **HIGH** |
| **GUI Network** | None | None | None | Low |
| **Helper Processes** | None | None | None | Low |
| **Child Processes** | None | None | None | Low |

## 3. Detailed Analysis

### 3.1 Process Restart (HIGH SIGNIFICANCE)
- **Observation**: Original RvControlSvc.exe (PID 5572, started 02:44 UTC) terminated; new instance (PID 5476) started ~03:11 UTC
- **Trigger**: User VPN connection action in GUI
- **Evidence**: 
  - `Get-Process -Id 5572` returns nothing post-connection
  - New PID 5476 owns the VPN relay TCP connection
  - Parent remains services.exe (592) — normal service restart
- **Implication**: Connection establishment requires fresh service state; possibly reinitializes crypto, network stacks, or peer state

### 3.2 Module Inventory (NO CHANGE)
- **Service (91 modules)**: Identical filenames, paths, versions, base addresses
- **GUI (125 modules)**: Identical filenames, paths, versions, base addresses
- **No new DLLs loaded**: No RvFwHelper.dll, no additional crypto, no NDIS driver interface DLLs
- **No modules unloaded**: All baseline modules present post-restart
- **ASLR layout preserved**: Base addresses identical — same boot session, no reboot

### 3.3 Network Endpoint Changes (HIGH SIGNIFICANCE)

| Endpoint | Baseline | Post-Connection | Notes |
|----------|----------|-----------------|-------|
| Service UDP | 26.82.29.1:56413 | **GONE** | Virtual adapter listener closed |
| Service TCP | None | 192.168.31.111:59509 → 148.113.190.78:17301 (ESTABLISHED) | **VPN relay connection** |
| Service TCP Listen | None | 0.0.0.0:59509 (LISTENING) | Local listener for peer traffic? |
| GUI TCP | None | None | GUI uses IPC, not direct network |
| GUI UDP | None | None | — |

**Remote Endpoint Analysis**:
- **148.113.190.78:17301** — Likely Radmin VPN relay/server infrastructure
- **Port 17301** — Known Radmin VPN relay port (from PCAP analysis in prior phases)
- **Local port 59509** — Ephemeral port selected for this session

### 3.4 Helper Process Analysis (NO CHANGE)
| Helper Binary | Baseline | Post-Connection | Expected Trigger |
|---------------|----------|-----------------|------------------|
| RvFwHelper.exe | Not running | Not running | Firewall rule add |
| drvinst.exe | Not running | Not running | Driver install |
| RvGuiStarter.exe | Not running | Not running | GUI launch |

**Finding**: No helper processes spawned. Firewall rules and driver already configured from prior runs.

### 3.5 Process Tree (MINOR CHANGE)
```
Baseline:          Post-Connection:
services(592)      services(592)
  └─ RvCtrl(5572)    └─ RvCtrl(5476)  [RESTARTED]
explorer(6912)     explorer(6912)
  └─ RvGui(1232)     └─ RvGui(1232)   [UNCHANGED]
```

## 4. Hypothesis Testing Results

| Hypothesis | Test | Result |
|------------|------|--------|
| H1: RvROLClient.dll already loaded — no new load | Module diff | ✅ **Confirmed** — Already loaded pre-connection |
| H2: RvFwHelper.exe spawns on connection | Process tree diff | ❌ **Refuted** — Not spawned |
| H3: New TLS/crypto modules for peer encryption | Module diff | ❌ **Refuted** — libcrypto/libssl already loaded |
| H4: NDIS driver interaction via new DLL | Module diff | ❌ **Refuted** — No new driver DLLs |
| H5: GUI loads additional Qt plugins | Module diff | ❌ **Refuted** — No new Qt modules |
| H6: Service restart required for connection | Process diff | ✅ **Confirmed** — PID changed |

## 5. Unresolved Questions from Diff

| Question | Priority | Notes |
|----------|----------|-------|
| Why does service restart? Reinit crypto state? Peer auth? | HIGH | Critical for protocol reconstruction |
| What triggers restart — GUI IPC message? Specific API? | HIGH | Need IPC analysis |
| Is 148.113.190.78:17301 a fixed relay or dynamic? | MEDIUM | Check multiple connections |
| Does local TCP 59509 accept peer connections? | MEDIUM | Test with second peer |
| Why UDP 56413 closed? Replaced by TCP relay? | MEDIUM | Protocol shift observation |
| Are firewall rules added silently (no RvFwHelper)? | LOW | Check Windows Firewall API calls |

## 6. Evidence Classification

| Finding | Classification | Source |
|---------|----------------|--------|
| Service restart (PID change) | **Directly observed** | PowerShell `Get-Process` |
| No new modules | **Tool-reported** | EnumModules2.exe (both snapshots) |
| TCP relay connection | **Tool-reported** | `Get-NetTCPConnection`, `netstat` |
| UDP listener gone | **Tool-reported** | `Get-NetUDPEndpoint`, `netstat` |
| No helper processes | **Directly observed** | Process enumeration |
| GUI unchanged | **Tool-reported** | EnumModules2.exe, network cmds |
| Relay IP 148.113.190.78 | **Inferred** | Known Radmin infrastructure from PCAPs |

---
*Report generated: 2026-11-26 03:30 UTC*
*Evidence classification: Directly observed, Tool-reported, Inferred*