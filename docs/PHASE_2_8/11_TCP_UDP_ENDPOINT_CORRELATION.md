# Phase 2.8 — TCP/UDP Endpoint Correlation

## 1. Endpoint Verification Method
All endpoints verified via `Get-NetTCPConnection` and `Get-NetUDPEndpoint` with `-OwningProcess` filter at specific capture times.

## 2. Baseline Endpoints (Pre-Connection)

### 2.1 Service (PID 13164) — Captured 2026-11-26 ~03:33 local
| Protocol | Local Address | Local Port | Remote Address | Remote Port | State | Owning PID |
|----------|---------------|------------|----------------|-------------|-------|------------|
| TCP | 0.0.0.0 | 62654 | 0.0.0.0 | 0 | Bound | 13164 |
| TCP | 192.168.31.111 | 62654 | 148.113.190.78 | 17301 | Established | 13164 |
| TCP | 192.168.31.111 | 62654 | 0.0.0.0 | 0 | Listen | 13164 |
| UDP | 26.82.29.1 | 49237 | — | — | — | 13164 |

### 2.2 GUI (PID 5760) — Captured 2026-11-26 ~03:33 local
| Protocol | Local Address | Local Port | Remote Address | Remote Port | State | Owning PID |
|----------|---------------|------------|----------------|-------------|-------|------------|
| (none) | — | — | — | — | — | 5760 |

## 3. Post-Connection Endpoints (Post-Connection)

### 3.1 Service (PID 13164) — Captured 2026-11-26 ~03:42 local
| Protocol | Local Address | Local Port | Remote Address | Remote Port | State | Owning PID |
|----------|---------------|------------|----------------|-------------|-------|------------|
| TCP | 0.0.0.0 | 65157 | 0.0.0.0 | 0 | Bound | 13164 |
| TCP | 192.168.31.111 | 65157 | 148.113.190.78 | 17301 | Established | 13164 |
| TCP | 192.168.31.111 | 65157 | 0.0.0.0 | 0 | Listen | 13164 |
| UDP | 26.82.29.1 | 49237 | — | — | — | 13164 |

### 3.2 Service (PID 13164) — Captured 2026-11-26 ~03:43 local (after GUI restart)
| Protocol | Local Address | Local Port | Remote Address | Remote Port | State | Owning PID |
|----------|---------------|------------|----------------|-------------|-------|------------|
| TCP | 0.0.0.0 | 65199 | 0.0.0.0 | 0 | Bound | 13164 |
| TCP | 192.168.31.111 | 65199 | 148.113.190.78 | 17301 | Established | 13164 |
| TCP | 192.168.31.111 | 65199 | 0.0.0.0 | 0 | Listen | 13164 |
| UDP | 26.82.29.1 | 49237 | — | — | — | 13164 |

### 3.3 GUI (PID 8808) — Captured 2026-11-26 ~03:43 local
| Protocol | Local Address | Local Port | Remote Address | Remote Port | State | Owning PID |
|----------|---------------|------------|----------------|-------------|-------|------------|
| (none) | — | — | — | — | — | 8808 |

## 4. Correlation Analysis

### 4.1 Service TCP Port Changes
| Capture | Local Port | Remote Port | State Change |
|---------|------------|-------------|--------------|
| Baseline | 62654 | 17301 | Established + Listen |
| Post-Connect (1) | 65157 | 17301 | Established + Listen (NEW PORT) |
| Post-Connect (2) | 65199 | 17301 | Established + Listen (NEW PORT) |

**Finding**: Service **changed local TCP port twice** after connection:
1. 62654 → 65157 (after user Connect)
2. 65157 → 65199 (after GUI restart)

Remote endpoint **unchanged**: 148.113.190.78:17301 (Radmin relay)

### 4.2 Service UDP Endpoint
| Capture | Local Address | Local Port | Change |
|---------|---------------|------------|--------|
| Baseline | 26.82.29.1 | 49237 | — |
| Post-Connect (1) | 26.82.29.1 | 49237 | **Stable** |
| Post-Connect (2) | 26.82.29.1 | 49237 | **Stable** |

**Finding**: UDP endpoint on VPN virtual adapter (26.82.29.1) **remained stable** throughout.

### 4.3 GUI Network Endpoints
| Process | Baseline (PID 5760) | Post-Connection (PID 8808) |
|---------|---------------------|---------------------------|
| GUI | No endpoints | No endpoints |

**Finding**: GUI process has **no direct network endpoints** in either state. All network communication handled by service.

## 5. Correlation with Process Events

| Time (Local) | Process Event | Network Change |
|--------------|---------------|----------------|
| ~03:33 | Baseline capture | Service: TCP 62654, UDP 49237 |
| ~03:41 | User clicks Connect | Service: Port 62654 → 65157 |
| 03:42:35 | GUI restarts (PID 8808 starts) | — |
| ~03:43 | Post-GUI-restart capture | Service: Port 65157 → 65199 |

### 5.1 Key Observations
1. **Service port change (62654→65157)** occurred **after user Connect**, **before GUI restart**
2. **Service port change (65157→65199)** occurred **after GUI restart**
3. **UDP endpoint never changed** — stable on VPN virtual adapter
4. **Remote relay unchanged** — 148.113.190.78:17301 throughout

## 6. Phase 2.7 Comparison

| Metric | Phase 2.7 (PID 5572/5476) | Phase 2.8 (PID 13164) |
|--------|---------------------------|----------------------|
| Service UDP | 26.82.29.1:56413 | 26.82.29.1:49237 |
| Service TCP (Baseline) | None | 62654→17301 (Established) |
| Service TCP (Post) | 59509→17301 | 65157/65199→17301 |
| GUI Network | None | None |

> **Note**: Phase 2.7 showed service restart (PID 5572→5476); Phase 2.8 shows **service stable** (PID 13164 throughout).

## 7. Evidence Classification

| Finding | Classification | Source |
|---------|----------------|--------|
| Service TCP port 62654→65157 | **Directly observed** | `Get-NetTCPConnection -OwningProcess 13164` |
| Service TCP port 65157→65199 | **Directly observed** | `Get-NetTCPConnection -OwningProcess 13164` |
| Service UDP stable at 49237 | **Directly observed** | `Get-NetUDPEndpoint -OwningProcess 13164` |
| GUI no network endpoints | **Directly observed** | `Get-NetTCPConnection -OwningProcess 5760/8808` |
| Remote relay 148.113.190.78:17301 | **Directly observed** | `Get-NetTCPConnection` |
| Port changes correlate with events | **Inferred** | Temporal correlation |

## 8. Limitations

- Snapshots only; transient connections may be missed
- No packet capture (PCAP) to verify traffic content
- Port change mechanism not observed (service internal logic)
- Cannot determine if port change is service-driven or relay-driven

## 9. Unresolved Questions

| Question | Priority |
|----------|----------|
| Why does service change local TCP port on Connect? | HIGH |
| Why does service change local TCP port again after GUI restart? | HIGH |
| Is 65199 the final stable port or will it change again? | MEDIUM |
| What triggers UDP port selection (56413 vs 49237)? | MEDIUM |
| Does service recreate TCP connection to relay on port change? | HIGH |

---
*Report generated: 2026-11-26 05:45 UTC*
*Evidence classification: Directly observed (Get-NetTCPConnection, Get-NetUDPEndpoint), Inferred (temporal correlation)*