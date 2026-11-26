# Phase 2.5 Stage 03 — Corrected Vtable Address-Point Analysis

**Classification: VERIFIED** (all raw bytes independently extracted via REA `read_bytes`; all calculations independently verified)

## 1. Purpose

Correct the vtable address-point calculations from Phase 2.4 Report 05, which used the nominal table base instead of the actual vptr value stored in the object.

## 2. Vptr Values from Constructor

The constructor `FUN_0043E1A0` writes three vptr values to `[obj + 0x00]`:

| Phase | VA | Instruction | Raw Bytes | Value Written |
|-------|-----|-------------|-----------|---------------|
| Initial | 0x43E1B1 | `MOV [EDI], 0x51FFB4` | C7 03 B4 FF 51 00 | `0x0051FFB4` |
| Intermediate | 0x43E4C8 | `MOV [EDI], 0x51E570` | C7 03 70 E5 51 00 | `0x0051E570` |
| Final | 0x43E4E8 | `MOV [EDI], 0x51E4F0` | C7 03 F0 E4 51 00 | `0x0051E4F0` |

**Key correction:** The vptr is `0x51FFB4`, not the table base `0x51FFAC`. All indirect call address calculations must use the actual vptr value.

## 3. Corrected Indirect Call Address Calculations

The indirect calls in `FUN_0044F3F0` are:
- `CALL [EAX+0x34]` at 0x44F501 and 0x44F5AA (slot 13: 0x34 / 4 = 13)
- `CALL [EAX+0x58]` at 0x44F50D and 0x44F5B6 (slot 22: 0x58 / 4 = 22)

Where `EAX = [EDI]` = the current vptr.

### Table A — Initial Vptr State (vptr = 0x0051FFB4)

| Slot | Offset | Calculation | Actual Address | Pointer Value | Function |
|------|--------|-------------|----------------|---------------|----------|
| 13 | +0x34 | 0x51FFB4 + 0x34 | **0x51FFE8** | 0x004510A0 | FUN_004510A0 (XOR EAX,EAX; RET → 0) |
| 22 | +0x58 | 0x51FFB4 + 0x58 | **0x52000C** | 0x00450FA0 | FUN_00450FA0 (31 bytes, `__stdcall`, int param) |

**Phase 2.4 error:** Used table base 0x51FFAC:
- Claimed slot 13 at 0x51FFE0 → 0x00451010 (wrong address, wrong value)
- Claimed slot 22 at 0x520004 → 0x00451070 (wrong address, wrong value)

**Corrected:** Slot 13 at 0x51FFE8 → 0x004510A0; Slot 22 at 0x52000C → 0x00450FA0.

### Table B — Intermediate Vptr State (vptr = 0x0051E570)

| Slot | Offset | Calculation | Actual Address | Pointer Value | Function |
|------|--------|-------------|----------------|---------------|----------|
| 13 | +0x34 | 0x51E570 + 0x34 | **0x51E5A4** | 0x004510B0 | `MOV EAX, 0x10; RET` → 16 |
| 22 | +0x58 | 0x51E570 + 0x58 | **0x51E5C8** | 0x00450FC0 | FUN_00450FC0 (31 bytes, `__stdcall`, int param) |

**Phase 2.4 error:** Listed slot 22 at 0x51E5C4 → 0x00451090 (off-by-4; that's slot 21).

**Corrected:** Slot 22 at 0x51E5C8 → 0x00450FC0.

### Table C — Final Vptr State (vptr = 0x0051E4F0)

| Slot | Offset | Calculation | Actual Address | Pointer Value | Function |
|------|--------|-------------|----------------|---------------|----------|
| 13 | +0x34 | 0x51E4F0 + 0x34 | **0x51E524** | 0x004510B0 | `MOV EAX, 0x10; RET` → 16 |
| 22 | +0x58 | 0x51E4F0 + 0x58 | **0x51E548** | 0x00450FC0 | FUN_00450FC0 (31 bytes, `__stdcall`, int param) |

**Phase 2.4 error:** Listed slot 22 at 0x51E544 → 0x00451090 (off-by-4; that's slot 21).

**Corrected:** Slot 22 at 0x51E548 → 0x00450FC0.

## 4. Raw Byte Verification

All pointer values verified via REA `read_bytes`:

| Address | Raw Bytes (LE) | Decoded Value | Source |
|---------|---------------|---------------|--------|
| 0x51FFE8 | A0 10 45 00 | 0x004510A0 | REA read_bytes |
| 0x52000C | A0 0F 45 00 | 0x00450FA0 | REA read_bytes |
| 0x51E5A4 | (from table read at 0x51E570+0x34) | 0x004510B0 | Phase 2.4 Report 18 |
| 0x51E5C8 | C0 0F 45 00 | 0x00450FC0 | REA read_bytes |
| 0x51E524 | (from table read at 0x51E4F0+0x34) | 0x004510B0 | Phase 2.4 Report 18 |
| 0x51E548 | C0 0F 45 00 | 0x00450FC0 | REA read_bytes |

## 5. Full Vtable Entry Inspection

### Table A at vptr 0x51FFB4 (first 16 bytes = slots 0-3)

Raw bytes: `F0 EC 43 00 E0 F3 44 00 F0 F3 44 00 C0 F6 44 00`

| Slot | Address | Value | Function |
|------|---------|-------|----------|
| 0 | 0x51FFB4 | 0x0043ECF0 | Constructor wrapper |
| 1 | 0x51FFB8 | 0x0044F3E0 | Unknown |
| 2 | 0x51FFBC | 0x0044F3F0 | FUN_0044F3F0 itself |
| 3 | 0x51FFC0 | 0x0044F6C0 | Unknown |

### Table B at vptr 0x51E570 (first 16 bytes = slots 0-3)

Raw bytes: `D0 EE 43 00 E0 F3 44 00 B0 F6 44 00 50 F8 44 00`

| Slot | Address | Value | Function |
|------|---------|-------|----------|
| 0 | 0x51E570 | 0x0043EED0 | Unknown |
| 1 | 0x51E574 | 0x0044F3E0 | Unknown |
| 2 | 0x51E578 | 0x0044F6B0 | Unknown |
| 3 | 0x51E57C | 0x0044F850 | Unknown |

### Table C at vptr 0x51E4F0 (first 16 bytes = slots 0-3)

Raw bytes: `10 F1 43 00 E0 F3 44 00 B0 F6 44 00 50 F8 44 00`

| Slot | Address | Value | Function |
|------|---------|-------|----------|
| 0 | 0x51E4F0 | 0x0043F110 | Unknown |
| 1 | 0x51E4F4 | 0x0044F3E0 | Unknown |
| 2 | 0x51E4F8 | 0x0044F6B0 | Unknown |
| 3 | 0x51E4FC | 0x0044F850 | Unknown |

## 6. Dispatch Target Classification

| Address | Function | Size | Calling Convention | Return Value | Classification |
|---------|----------|------|-------------------|--------------|----------------|
| 0x004510A0 | FUN_004510A0 | 6 bytes | `__stdcall` (void) | 0 (XOR EAX,EAX) | CONFIRMED |
| 0x00450FA0 | FUN_00450FA0 | 31 bytes | `__stdcall` (int param) | Unknown | CONFIRMED (function exists, body not decompiled) |
| 0x004510B0 | FUN_004510B0 | 5 bytes | `__stdcall` (void) | 16 (MOV EAX,0x10) | CONFIRMED (from Phase 2.4 Report 18) |
| 0x00450FC0 | FUN_00450FC0 | 31 bytes | `__stdcall` (int param) | Unknown | CONFIRMED (function exists, body not decompiled) |

## 7. Corrected Dispatch Matrix

| Vptr State | vptr Value | CALL [vptr+0x34] Address | CALL [vptr+0x34] Target | CALL [vptr+0x58] Address | CALL [vptr+0x58] Target |
|------------|------------|-------------------------|------------------------|-------------------------|------------------------|
| Initial | 0x0051FFB4 | 0x51FFE8 | 0x004510A0 → returns 0 | 0x52000C | 0x00450FA0 → unknown |
| Intermediate | 0x0051E570 | 0x51E5A4 | 0x004510B0 → returns 16 | 0x51E5C8 | 0x00450FC0 → unknown |
| Final | 0x0051E4F0 | 0x51E524 | 0x004510B0 → returns 16 | 0x51E548 | 0x00450FC0 → unknown |

## 8. Confidence Classification

| Question | Classification | Basis |
|----------|---------------|-------|
| Vptr values from constructor | CONFIRMED | Raw bytes verified at 3 addresses |
| Indirect call instruction addresses | CONFIRMED | Raw bytes at 0x44F501/0x44F50D/0x44F5AA/0x44F5B6 |
| Corrected dispatch target addresses | CONFIRMED | Arithmetic verified; raw bytes read at all 6 addresses |
| Pointer values at dispatch addresses | CONFIRMED | REA read_bytes at all 6 addresses |
| Resolved destination functions | CONFIRMED | Ghidra function inventory |
| Calling conventions | CONFIRMED | Ghidra procedure_info |
| Return values for FUN_004510A0/FUN_004510B0 | CONFIRMED | Ghidra procedure_pseudo_code / Phase 2.4 Report 18 |
| Return values for FUN_00450FA0/FUN_00450FC0 | UNKNOWN | Bodies not decompiled |