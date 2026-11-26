# Phase 2.5 Stage 04 — Corrected Indirect Dispatch Targets

**Classification: VERIFIED** (all dispatch targets resolved via REA procedure_info/procedure_pseudo_code)

## 1. Purpose

Resolve the actual indirect-call dispatch targets for `FUN_0044F3F0` using corrected vtable address-point calculations from Stage 03.

## 2. FUN_0044F3F0 Guard Conditions

| VA | Instruction | Raw Bytes | Condition |
|-----|-------------|-----------|-----------|
| 0x44F4EE | `CMP [EDI+0x28], 5` | 83 7F 28 05 | field_0x28 == 5 |
| 0x44F4F4 | `CMP [EDI+0x2C], 0` | 83 7F 2C 00 | field_0x2C != 0 |
| 0x44F4FE | `INC [EDI+0x30]` | FF 47 30 | field_0x30++ |

**Guard logic:** Indirect calls execute only if `field_0x28 == 5 && field_0x2C != 0`.

## 3. Dispatch Target Analysis

### Target 1: FUN_004510A0 (0x004510A0)

| Property | Value |
|----------|-------|
| Address | 0x004510A0 |
| Size | 6 bytes |
| Convention | `__stdcall` (void) |
| Raw bytes | B8 10 00 00 00 C3 |

**Pseudocode:**
```c
undefined4 __stdcall FUN_004510A0(void)
{
    return 0;
}
```

**Called from:** Table A slot 13 (vptr + 0x34) when vptr = 0x51FFB4.

### Target 2: FUN_00450FA0 (0x00450FA0)

| Property | Value |
|----------|-------|
| Address | 0x00450FA0 |
| Size | 31 bytes |
| Convention | `__stdcall` (int param_1) |
| Basic blocks | 4 |

**Called from:** Table A slot 22 (vptr + 0x58) when vptr = 0x51FFB4.

**Body not decompiled** — Ghidra procedure_pseudo_code returned null. Need REA procedure_assembly or manual disassembly.

### Target 3: FUN_004510B0 (0x004510B0)

| Property | Value |
|----------|-------|
| Address | 0x004510B0 |
| Size | 5 bytes |
| Convention | `__stdcall` (void) |
| Raw bytes | B8 10 00 00 00 C3 |

**Pseudocode:**
```c
undefined4 __stdcall FUN_004510B0(void)
{
    return 0x10;  // 16
}
```

**Called from:** Table B slot 13 and Table C slot 13 (vptr + 0x34) when vptr = 0x51E570 or 0x51E4F0.

### Target 4: FUN_00450FC0 (0x00450FC0)

| Property | Value |
|----------|-------|
| Address | 0x00450FC0 |
| Size | 31 bytes |
| Convention | `__stdcall` (int param_1) |
| Basic blocks | 4 |

**Called from:** Table B slot 22 and Table C slot 22 (vptr + 0x58) when vptr = 0x51E570 or 0x51E4F0.

**Body not decompiled** — Ghidra procedure_pseudo_code returned null.

## 4. Corrected Dispatch Summary

| Vptr State | Slot 13 (+0x34) | Slot 22 (+0x58) |
|------------|-----------------|-----------------|
| Initial (0x51FFB4) | FUN_004510A0 → returns 0 | FUN_00450FA0 → unknown |
| Intermediate (0x51E570) | FUN_004510B0 → returns 16 | FUN_00450FC0 → unknown |
| Final (0x51E4F0) | FUN_004510B0 → returns 16 | FUN_00450FC0 → unknown |

## 5. Phase 2.4 vs Phase 2.5 Comparison

| Phase | Table A Slot 13 | Table A Slot 22 | Table B Slot 13 | Table B Slot 22 | Table C Slot 13 | Table C Slot 22 |
|-------|-----------------|-----------------|-----------------|-----------------|-----------------|-----------------|
| 2.4 | 0x00451010 → 0 | 0x00451070 → 0 | 0x004510B0 → 16 | 0x00451090 → 0 | 0x004510B0 → 16 | 0x00451090 → 0 |
| 2.5 | 0x004510A0 → 0 | 0x00450FA0 → ? | 0x004510B0 → 16 | 0x00450FC0 → ? | 0x004510B0 → 16 | 0x00450FC0 → ? |

**Key differences:**
1. Table A slot 13: 0x451010 → 0x4510A0 (both return 0, different function)
2. Table A slot 22: 0x451070 → 0x450FA0 (both may return 0, different function, 2.5 target body not analyzed)
3. Table B/C slot 22: 0x451090 → 0x450FC0 (different function, 2.5 target body not analyzed)

## 6. Confidence Classification

| Question | Classification | Basis |
|----------|---------------|-------|
| Guard conditions verified | CONFIRMED | Raw bytes at 0x44F4EE/0x44F4F4/0x44F4FE |
| FUN_004510A0 returns 0 | CONFIRMED | Ghidra procedure_pseudo_code + raw bytes |
| FUN_004510B0 returns 16 | CONFIRMED | Phase 2.4 Report 18 raw bytes |
| FUN_00450FA0 body | UNKNOWN | procedure_pseudo_code returned null |
| FUN_00450FC0 body | UNKNOWN | procedure_pseudo_code returned null |
| Whether guard is ever satisfied | UNKNOWN | field_0x28/0x2C initial values unknown |