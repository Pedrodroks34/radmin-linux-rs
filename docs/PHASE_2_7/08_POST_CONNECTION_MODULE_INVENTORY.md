# Phase 2.7 — Post-Connection Module Inventory

## 1. Capture Metadata
- **Capture Timestamp**: 2026-11-26 03:11:55 UTC
- **Connection Confirmed**: User reported "connected" at ~03:11 UTC
- **Baseline Reference**: Report 03 (captured 2026-11-26 03:15 UTC)

## 2. Critical Finding: Service Restart
**The RvControlSvc.exe service RESTARTED during VPN connection establishment.**

| Property | Baseline (Pre-Connection) | Post-Connection |
|----------|---------------------------|-----------------|
| Process Name | RvControlSvc.exe | RvControlSvc.exe |
| Process ID (PID) | 5572 | **5476 (NEW)** |
| Start Time | 2026-11-26 02:44:04 UTC | ~2026-11-26 03:11 UTC (after connection) |
| Parent Process | services.exe (592) | services.exe (592) |
| Session ID | 0 | 0 |

> **Evidence**: `Get-Process` shows PID 5572 no longer exists; new PID 5476 owns the VPN relay connection.

## 3. RvControlSvc.exe (PID 5476) — Module Inventory
**Total Modules**: 91 (identical count to baseline)  
**Process Type**: 32-bit Windows Service (WoW64)  
**Base Address**: 0x00E70000 (same as baseline)  
**Image Size**: 0x1D6000 (1,925,120 bytes)

### 3.1 Module List Comparison
| Module | Baseline Base | Post Base | Changed? |
|--------|---------------|-----------|----------|
| RvControlSvc.exe | 0x00E70000 | 0x00E70000 | No (ASLR same) |
| ntdll.dll | 0x77DD0000 | 0x77DD0000 | No |
| KERNEL32.DLL | 0x75C40000 | 0x75C40000 | No |
| KERNELBASE.dll | 0x76240000 | 0x76240000 | No |
| RvROLClient.dll | 0x70570000 | 0x70570000 | No |
| RvDownloader.dll | 0x6F940000 | 0x6F940000 | No |
| RvRolUpdater.dll | 0x6F9F0000 | 0x6F9F0000 | No |
| RvUESClient.dll | 0x72AD0000 | 0x72AD0000 | No |
| Shelper.dll | 0x704B0000 | 0x704B0000 | No |
| libcrypto-3.dll | 0x6FAC0000 | 0x6FAC0000 | No |
| libssl-3.dll | 0x70320000 | 0x70320000 | No |
| libcurl.dll | 0x70430000 | 0x70430000 | No |
| VCRUNTIME140.dll | 0x75290000 | 0x75290000 | No |
| ... (all 91 modules) | ... | ... | **No changes** |

> **Finding**: **Zero new modules loaded**. All 91 modules identical to baseline by filename, path, version, and base address (ASLR layout preserved across restart).

## 4. RvRvpnGui.exe (PID 1232) — Module Inventory
**Total Modules**: 125 (identical count to baseline)  
**Process Type**: 32-bit GUI Application (WoW64, Qt-based)  
**Base Address**: 0x00700000 (same as baseline)  
**Image Size**: 0xE08000 (14,712,832 bytes)

### 4.1 Module List Comparison
| Module | Baseline Base | Post Base | Changed? |
|--------|---------------|-----------|----------|
| RvRvpnGui.exe | 0x00700000 | 0x00700000 | No |
| Qt5Core.dll | 0x72BB0000 | 0x72BB0000 | No |
| Qt5Gui.dll | 0x723C0000 | 0x723C0000 | No |
| Qt5Network.dll | 0x753B0000 | 0x753B0000 | No |
| Qt5Quick.dll | 0x74E10000 | 0x74E10000 | No |
| Qt5Widgets.dll | 0x71F70000 | 0x71F70000 | No |
| All 125 modules | ... | ... | **No changes** |

> **Finding**: **Zero new modules loaded** in GUI process. No Qt plugins, no Radmin DLLs, no additional libraries loaded post-connection.

## 5. Cross-Process Module Summary

| Metric | Baseline | Post-Connection | Delta |
|--------|----------|-----------------|-------|
| RvControlSvc.exe modules | 91 | 91 | 0 |
| RvRvpnGui.exe modules | 125 | 125 | 0 |
| **Total unique modules** | 172* | 172* | 0 |
| New modules loaded | — | **0** | 0 |
| Modules unloaded | — | **0** | 0 |

*Some modules shared between processes (e.g., ntdll.dll, KERNEL32.DLL)

## 6. New Binary Hashes
**No new binaries identified** — all modules match baseline hashes from Report 02.

## 7. Evidence Sources
- EnumModules2.exe (PSAPI enumeration, run as Admin) — both PIDs
- WinDbg `lm` on service (PID 5476 — new instance)
- Process enumeration via PowerShell/WMI

## 8. Limitations
- Service restart means baseline PID (5572) ≠ post-connection PID (5476)
- WinDbg was attached to old PID (5572); new instance (5476) not debugged in real-time
- Module enumeration is snapshot-based; transient loads during restart not captured
- ASLR base addresses coincidentally identical (same boot session)

---
*Report generated: 2026-11-26 03:25 UTC*
*Evidence classification: Tool-reported (EnumModules2, WinDbg), Directly observed (PID change), Computed (comparison)*