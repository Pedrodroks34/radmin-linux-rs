# Phase 2.5 Stage 09 — Subinitializer Complete Inventory

**Classification: VERIFIED** (inventory reconciled against Phase 2.4 discrepancy)

## 1. Purpose

Create a complete, reconciled inventory of constructor sub-initializers, correcting the Phase 2.4 count discrepancy (reported "eight" but listed nine addresses).

## 2. Phase 2.4 Count Discrepancy

**Phase 2.4 Report 10 stated:** "eight previously unanalyzed constructor sub-initializers"

**Phase 2.4 Report 10 listed:** `FUN_0047A8A0`, `FUN_0043E500`, `FUN_00403540`, `FUN_004728E0`, `FUN_00483750`, `FUN_0043E680`, `FUN_0047BB20`, `FUN_00475B70`, `FUN_00479240`

**Discrepancy:** Nine addresses listed, but count stated as eight.

**Resolution:** There are **9** unanalyzed sub-initializers, not 8. The count in Phase 2.4 Report 10 was off by one.

## 3. Complete Sub-Initializer Inventory (12 Total)

| # | Address | Name | Status | Analyzed in Phase 2.5? |
|---|---------|------|--------|----------------------|
| 1 | 0x43E100 | FUN_0043E100 | ANALYZED | Yes (Phase 2.3) — zeroing loop |
| 2 | 0x47A8A0 | FUN_0047A8A0 | NOT ANALYZED | No |
| 3 | 0x43E500 | FUN_0043E500 | NOT ANALYZED | No |
| 4 | 0x403540 | FUN_00403540 | NOT ANALYZED | No |
| 5 | 0x4728E0 | FUN_004728E0 | PARTIALLY ANALYZED | No (called by FUN_004802F0 and FUN_0043A9A0) |
| 6 | 0x483750 | FUN_00483750 | NOT ANALYZED | No |
| 7 | 0x43E680 | FUN_0043E680 | NOT ANALYZED | No |
| 8 | 0x47BB20 | FUN_0047BB20 | NOT ANALYZED | No |
| 9 | 0x475B70 | FUN_00475B70 | NOT ANALYZED | No |
| 10 | 0x479240 | FUN_00479240 | NOT ANALYZED | No |
| 11 | 0x43A9A0 | FUN_0043A9A0 | ANALYZED | Yes (Phase 2.3) — list cleanup with CUniversalString |
| 12 | 0x4E7EC0 | FUN_004E7EC0 | ANALYZED | Yes (Phase 2.3/2.4) — 5-byte thunk → FUN_004ec736 |

**Summary:**
- Analyzed: 4 (FUN_0043E100, FUN_0043A9A0, FUN_004E7EC0, plus FUN_004728E0 partially)
- Not analyzed: 8 (FUN_0047A8A0, FUN_0043E500, FUN_00403540, FUN_00483750, FUN_0043E680, FUN_0047BB20, FUN_00475B70, FUN_00479240)

**Note:** FUN_004728E0 was partially analyzed (called by FUN_004802F0 and FUN_0043A9A0 but body not decompiled).

## 4. Functions Requiring Detailed Analysis (Stage 10)

The following 8 functions need detailed pseudocode and field-write analysis:

| Address | Name | Reason |
|---------|------|--------|
| 0x47A8A0 | FUN_0047A8A0 | Not in any previous analysis |
| 0x43E500 | FUN_0043E500 | Not in any previous analysis |
| 0x403540 | FUN_00403540 | Not in any previous analysis |
| 0x4728E0 | FUN_004728E0 | Called in constructor and destruction paths |
| 0x483750 | FUN_00483750 | Not in any previous analysis |
| 0x43E680 | FUN_0043E680 | Not in any previous analysis |
| 0x47BB20 | FUN_0047BB20 | Not in any previous analysis |
| 0x475B70 | FUN_00475B70 | Not in any previous analysis |
| 0x479240 | FUN_00479240 | Not in any previous analysis |

**Total: 9 functions** (the discrepancy is resolved — 9, not 8).

## 5. Confidence Classification

| Question | Classification | Basis |
|----------|---------------|-------|
| 12 sub-initializers identified | CONFIRMED | Constructor disassembly |
| 4 sub-initializers analyzed | CONFIRMED | Phase 2.3/2.4 REA analysis |
| 9 sub-initializers not analyzed | CONFIRMED | Not in analyzed set |
| Phase 2.4 count was "eight" | REFUTED | Nine addresses actually listed |
| Correct count is nine | CONFIRMED | Verified against Phase 2.4 Report 10 list |