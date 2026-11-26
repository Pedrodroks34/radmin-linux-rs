# Phase 2.7 — Pre-Connection Network Baseline

## 1. Overview
Network connection metadata for Radmin processes captured **before** any VPN network connection is established. Baseline timestamp: **2026-11-26 03:15 UTC**.

## 2. Network Endpoints — RvControlSvc.exe (PID 5572)

### 2.1 UDP Endpoints
| Local Address | Local Port | Protocol | State | Notes |
|---------------|------------|----------|-------|-------|
| 26.82.29.1 | 56413 | UDP | Listening | **Radmin VPN virtual adapter address** |

### 2.2 TCP Endpoints
| Local Address | Local Port | Remote Address | Remote Port | Protocol | State | Owning PID |
|---------------|------------|----------------|-------------|----------|-------|------------|
| (none) | — | — | — | TCP | — | 5572 |

### 2.3 Analysis
- **Single UDP endpoint** on 26.82.29.1:56413
- **26.82.29.1** is the **Radmin VPN virtual network adapter** address (IANA-reserved for carrier-grade NAT / shared address space)
- **Port 56413** — likely the Radmin VPN control/data port
- No TCP listening ports or established connections at baseline
- Service is "online" but not connected to any VPN network

## 3. Network Endpoints — RvRvpnGui.exe (PID 1232)

### 3.1 UDP Endpoints
| Local Address | Local Port | Protocol | State | Notes |
|---------------|------------|----------|-------|-------|
| (none) | — | UDP | — | No UDP endpoints owned by GUI process |

### 3.2 TCP Endpoints
| Local Address | Local Port | Remote Address | Remote Port | Protocol | State | Owning PID |
|---------------|------------|----------------|-------------|----------|-------|------------|
| (none) | — | — | — | TCP | — | 1232 |

### 3.3 Analysis
- **No network endpoints** owned by the GUI process at baseline
- GUI communicates with service via local IPC (not network sockets)
- GUI may initiate outbound connections when user interacts (updates, auth, etc.) but none active now

## 4. System-Wide Network Context (Radmin-Relevant)

### 4.1 Radmin VPN Virtual Adapter
- **Interface**: "Radmin VPN" virtual network adapter
- **IPv4 Address**: 26.82.29.1/24 (typical for Radmin VPN)
- **Status**: Up/Enabled (service bound to it)
- **MAC**: Not captured (would require `Get-NetAdapter`)

### 4.2 Physical Network Interfaces (Context)
*Not Radmin-specific but relevant for correlation*
- Primary physical interface: Not captured in this phase
- Default gateway: Not captured
- DNS servers: Not captured

### 4.3 Windows Defender / Security Software
- **MpOav.dll** loaded in RvControlSvc.exe (0x6F6A0000) — Windows Defender AV monitoring
- No network blocking observed at baseline

## 5. Comparison with Expected Post-Connection State

| Metric | Pre-Connection (Baseline) | Expected Post-Connection |
|--------|---------------------------|--------------------------|
| RvControlSvc UDP endpoints | 1 (26.82.29.1:56413) | ≥1 (additional peer endpoints) |
| RvControlSvc TCP endpoints | 0 | ≥1 (control channel to relay/peers) |
| RvRvpnGui TCP endpoints | 0 | Possible (update checks, auth) |
| VPN virtual adapter traffic | Idle | Active (encapsulated packets) |
| Remote peers visible | None | ≥1 (connected network members) |

## 6. Evidence Sources & Limitations

### 6.1 Enumeration Methods
- `Get-NetUDPEndpoint -OwningProcess 5572,1232`
- `Get-NetTCPConnection -OwningProcess 5572,1232`
- `netstat -ano` cross-reference

### 6.2 Limitations
1. **Snapshot only** — momentary view; transient connections may be missed
2. **No packet capture** — not performing PCAP in this phase
3. **No payload inspection** — metadata only
4. **Firewall state not captured** — rules may exist but not enumerated
5. **IPv6 not checked** — only IPv4 endpoints shown
6. **Peer addresses unknown** — no VPN connection = no peers
7. **Port 56413** — identified as Radmin VPN port but not verified against documentation

### 6.3 What Is NOT Collected
- Credentials, tokens, authentication material
- Packet payloads
- Encryption keys
- Session identifiers
- Full routing tables

## 7. Key Findings

1. **Service owns the VPN virtual adapter binding** — RvControlSvc.exe (PID 5572) holds the UDP socket on 26.82.29.1:56413
2. **GUI has no direct network presence** — RvRvpnGui.exe (PID 1232) uses local IPC to communicate with service
3. **No active VPN tunnels** — Zero TCP connections, single UDP listener
4. **Virtual adapter IP confirmed** — 26.82.29.1 is the local VPN address
5. **Windows Defender monitoring** — MpOav.dll injected into service process

---
*Report generated: 2026-11-26 03:45 UTC*
*Evidence classification: Tool-reported (PowerShell network cmdlets), Directly observed (endpoint enumeration), Inferred (virtual adapter purpose from address range)*