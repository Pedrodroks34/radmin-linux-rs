# Phase 2.5 Stage 03 — Vtable Address-Point Correction

**Classification: PROVEN** — every address, byte, and pointer value re-read from the actual executable `RvControlSvc_Installed.exe` (SHA-256 `0E2E6EAACBE8EBE01286CDA39A12EAAD34A20434D50F4F8BF2FDD91D4D6EF2AD`) and mapped through the verified PE section table (ImageBase `0x00400000`).

Cross-reference: `02_PHASE_2_4_EVIDENCE_RECONCILIATION.md`, `04_VTABLE_SLOT_TARGET_RESOLUTION.md`, `05_VTABLE_TRANSITION_AND_CONSTRUCTOR_ANALYSIS.md`.

---

## 1. The Core Error: Nominal Base vs. Actual Vptr

Phase 2.4 treated Table A's **nominal base** `0x0051FFAC` as the object vptr and computed slots from it. The constructor, however, writes the object vptr as `0x0051FFB4` — which is Table A **slot 2**, one slot above the nominal base.

Constructor vptr writes (verified raw bytes):

| VA | Instruction | Raw bytes | Immediate value written | Meaning |
|----|-------------|-----------|-------------------------|---------|
| `0x0043E1B1` | `MOV [EDI], imm32` | `C7 07 B4 FF 51 00` | `0x0051FFB4` | Initial object vptr = Table A slot 2 |
| `0x0043E4C8` | `MOV [EDI], imm32` | `C7 07 70 E5 51 00` | `0x0051E570` | Intermediate vptr = Table B |
| `0x0043E4E8` | `MOV [EDI], imm32` | `C7 07 F0 E4 51 00` | `0x0051E4F0` | Final vptr = Table C |

All three are `C7 07 <imm32 LE>` = `MOV [EDI], imm32`. Confirmed at file offsets `0x0003D5B3`, `0x0003D8CA`, `0x0003D8EA`.

**Conclusion:** The actual object vptr (address point) is `0x0051FFB4`, **not** `0x0051FFAC`. `0x0051FFAC` is Table A slot 0 and is never the object's vptr.

---

## 2. PE Mapping for Vtable Addresses

All vtable addresses lie in `.rdata` (RVA range `0x00119000`–`0x001495C8`, raw pointer `0x00117A00`).

| VA | RVA (VA − 0x400000) | File offset | Section |
|----|---------------------|-------------|---------|
| `0x0051FFAC` | `0x0011FFAC` | `0x0011E9AC` | `.rdata` |
| `0x0051FFB4` | `0x0011FFB4` | `0x0011E9B4` | `.rdata` |
| `0x0051E570` | `0x0011E570` | `0x0011CF70` | `.rdata` |
| `0x0051E4F0` | `0x0011E4F0` | `0x0011CEF0` | `.rdata` |

File-offset formula: `fileOffset = 0x00117A00 + (RVA − 0x00119000)`.

---

## 3. Recalculated Slot Addresses (using ACTUAL vptr address points)

For an indirect dispatch `CALL [EAX+0x34]`, the effective slot address is `EAX + 0x34`. For `CALL [EAX+0x58]`, it is `EAX + 0x58`. EAX = object vptr.

### Table A — actual vptr `0x0051FFB4`

| Slot | Offset from vptr | Slot address (correct) | Value at slot (verified bytes → U32LE) | Phase 2.4 used (wrong) |
|------|------------------|------------------------|----------------------------------------|------------------------|
| 0 | +0x00 | `0x0051FFB4` | `0x0043ECF0` (`F0 EC 43 00`) | `0x0051FFAC`→slot0=`0x0043E8E0` |
| 1 | +0x04 | `0x0051FFB8` | `0x0044F3E0` (`E0 F3 44 00`) | — |
| 2 | +0x08 | `0x0051FFBC` | `0x0044F3F0` (`F0 F3 44 00`) | report called this "slot 4" |
| 12 | +0x30 | `0x0051FFE4` | `0x00450FF0` (`F0 0F 45 00`) | — |
| **13** | **+0x34** | **`0x0051FFE8`** | **`0x004510A0` (`A0 10 45 00`)** | report: `0x0051FFE0`=`0x00451010` (slot 12!) |
| 14 | +0x38 | `0x0051FFEC` | `0x00451080` (`80 10 45 00`) | — |
| 20 | +0x50 | `0x00520004` | `0x00451070` (`70 10 45 00`) | report called this "slot 22" |
| 21 | +0x54 | `0x00520008` | `0x00451090` (`90 10 45 00`) | — |
| **22** | **+0x58** | **`0x0052000C`** | **`0x00450FA0` (`A0 0F 45 00`)** | report: `0x00520004`=`0x00451070` (slot 20!) |

**Key correction:** Report `05` reported "slot 13 = `0x0051FFE0` → `0x00451010`" and "slot 22 = `0x00520004` → `0x00451070`". Those are actually **slot 12** and **slot 20** relative to vptr `0x0051FFB4` (or slot 13/22 relative to the *nominal* base `0x0051FFAC`). The nominal base is not the object vptr.

### Table B — vptr `0x0051E570`

| Slot | Offset | Slot address | Value (verified) |
|------|--------|--------------|------------------|
| 0 | +0x00 | `0x0051E570` | `0x0043EED0` (`D0 EE 43 00`) |
| 1 | +0x04 | `0x0051E574` | `0x0044F3E0` (`E0 F3 44 00`) |
| 13 | +0x34 | `0x0051E5A4` | `0x004510B0` (`B0 10 45 00`) |
| 20 | +0x50 | `0x0051E5C0` | — |
| 21 | +0x54 | `0x0051E5C4` | `0x00451090` (`90 10 45 00`) |
| **22** | **+0x58** | **`0x0051E5C8`** | **`0x00450FC0` (`C0 0F 45 00`)** |

Report `05` listed Table B slot 22 at `0x0051E5C4` = `0x00451090`. That is slot 21, not slot 22. Correct slot 22 = `0x0051E5C8` → `0x00450FC0`.

### Table C — vptr `0x0051E4F0`

| Slot | Offset | Slot address | Value (verified) |
|------|--------|--------------|------------------|
| 0 | +0x00 | `0x0051E4F0` | `0x0043F110` (`10 F1 43 00`) |
| 1 | +0x04 | `0x0051E4F4` | `0x0044F3E0` (`E0 F3 44 00`) |
| 13 | +0x34 | `0x0051E524` | `0x004510B0` (`B0 10 45 00`) |
| 21 | +0x54 | `0x0051E544` | `0x00451090` (`90 10 45 00`) |
| **22** | **+0x58** | **`0x0051E548`** | **`0x00450FC0` (`C0 0F 45 00`)** |

Report `05` listed Table C slot 22 at `0x0051E544` = `0x00451090`. That is slot 21. Correct slot 22 = `0x0051E548` → `0x00450FC0`.

---

## 4. Decoded Slot Targets

| Table | Slot | Address | Pointer value | Resolved function | Disassembly (verified) |
|-------|------|---------|---------------|-------------------|------------------------|
| A | 13 | `0x0051FFE8` | `0x004510A0` | `FUN_004510A0` | **not yet disassembled** (report claimed `0x00451010`) |
| A | 22 | `0x0052000C` | `0x00450FA0` | `FUN_00450FA0` | **not yet disassembled** (report claimed `0x00451070`) |
| B | 13 | `0x0051E5A4` | `0x004510B0` | `FUN_004510B0` | `B8 10 00 00 00 C3` = `MOV EAX,0x10; RET` (returns 16) |
| B | 22 | `0x0051E5C8` | `0x00450FC0` | `FUN_00450FC0` | **not yet disassembled** (report claimed `0x00451090`) |
| C | 13 | `0x0051E524` | `0x004510B0` | `FUN_004510B0` | `MOV EAX,0x10; RET` (returns 16) |
| C | 22 | `0x0051E548` | `0x00450FC0` | `FUN_00450FC0` | **not yet disassembled** (report claimed `0x00451090`) |

Slot 0 of each table (the destructor):
- Table A slot 0 (`0x0051FFB4`) = `0x0043ECF0` — this is the **constructor wrapper**, not a destructor! (Unusual — slot 0 normally = destructor.)
- Table B slot 0 (`0x0051E570`) = `0x0043EED0`
- Table C slot 0 (`0x0051E4F0`) = `0x0043F110`

Note: `0x0043ECF0` as Table A slot 0 is inconsistent with a conventional vtable (slot 0 should be the destructor). This supports the hypothesis that Table A is **not** a conventional C++ vtable, or the object's slot-0 semantics differ. See Report 05.

---

## 5. Address-Point Summary Table

| Table | Nominal base (Phase 2.4) | Actual object vptr | Differs? | Address-point location |
|-------|--------------------------|--------------------|----------|------------------------|
| A | `0x0051FFAC` | `0x0051FFB4` | **YES (+4)** | Table A slot 2 — written by constructor as initial vptr |
| B | `0x0051E570` | `0x0051E570` | No | Intermediate constructor write |
| C | `0x0051E4F0` | `0x0051E4F0` | No | Final constructor write |

Only Table A has a nominal-base ≠ vptr discrepancy, because Phase 2.4 mistakenly used slot 0 as the base instead of the constructor-written vptr `0x0051FFB4`.

---

## 6. Confidence

- Constructor vptr write values: **PROVEN** (raw bytes `C7 07 <imm32>` at 3 addresses).
- Slot byte values: **PROVEN** (read 4 bytes at each slot VA, mapped to file offset).
- Function-target disassembly for `0x004510B0`, `0x00451090`, `0x00451070`, `0x00451010`: **PROVEN** for `0x004510B0` (`MOV EAX,0x10; RET`); the corrected targets `0x004510A0` and `0x00450FC0` are **not yet disassembled** (marked for Report 04 follow-up).
- The claim that "slot 13 = `0x00451010` / slot 22 = `0x00451070`" for Table A: **CONTRADICTED** (those are slots 12/20 relative to the real vptr).
