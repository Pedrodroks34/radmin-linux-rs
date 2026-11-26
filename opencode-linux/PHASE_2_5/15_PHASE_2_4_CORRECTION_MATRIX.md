# Phase 2.5 Stage 15 — Phase 2.4 Correction Matrix

**Classification: VERIFIED** (all corrections traceable to Phase 2.5 static re-analysis)

## 1. Purpose

Document all corrections to Phase 2.4 findings, preserving historical evidence while establishing the corrected technical foundation.

## 2. Correction Matrix

| # | Phase 2.4 Claim | Phase 2.5 Correction | Report(s) Affected | Correction Evidence | Confidence |
|---|----------------|---------------------|-------------------|---------------------|------------|
| C1 | Table A base = 0x51FFAC is the vptr | vptr = 0x51FFB4; table base is nominal only | 03, 04, 05 | Raw bytes at 0x43E1B1: C7 03 B4 FF 51 00 | CONFIRMED |
| C2 | Table B slot 22 at 0x51E5C4 | Slot 22 at 0x51E5C8 (0x51E570 + 0x58) | 05 | Arithmetic verified; raw bytes at 0x51E5C8: C0 0F 45 00 | CONFIRMED |
| C3 | Table C slot 22 at 0x51E544 | Slot 22 at 0x51E548 (0x51E4F0 + 0x58) | 05 | Arithmetic verified; raw bytes at 0x51E548: C0 0F 45 00 | CONFIRMED |
| C4 | Table A slot 13 at 0x51FFE0 → 0x451010 | Slot 13 at 0x51FFE8 → 0x4510A0 | 05 | REA read_bytes at 0x51FFE8: A0 10 45 00 | CONFIRMED |
| C5 | Table A slot 22 at 0x520004 → 0x451070 | Slot 22 at 0x52000C → 0x450FA0 | 05 | REA read_bytes at 0x52000C: A0 0F 45 00 | CONFIRMED |
| C6 | Table B slot 22 at 0x51E5C4 → 0x451090 | Slot 22 at 0x51E5C8 → 0x450FC0 | 05 | REA read_bytes at 0x51E5C8: C0 0F 45 00 | CONFIRMED |
| C7 | Table C slot 22 at 0x51E544 → 0x451090 | Slot 22 at 0x51E548 → 0x450FC0 | 05 | REA read_bytes at 0x51E548: C0 0F 45 00 | CONFIRMED |
| C8 | 0x500CA6 in .data or gap | 0x500CA6 in .text (VA 0x401000–0x519000) | 05, 08 | REA binary_overview section table | CONFIRMED |
| C9 | 0x500CA6 is IAT slot / pointer | 0x500CA6 is `free` function entry; contains code | 08 | REA read_bytes: function prologue; Ghidra: FID_conflict:_free | CONFIRMED |
| C10 | CALL [0x500CA6] reads valid pointer | DWORD at 0x500CA6 = 0x8B55FF8B (not valid) | 08 | REA read_bytes: 8B FF 55 8B | CONFIRMED |
| C11 | FUN_00473210 = decrement-and-destroy-if-zero | FUN_00473210 = destroy/reset: sets obj+0x20 to 0, exchanges obj+0x24, deletes critical section | 06, 07, 11 | REA procedure_pseudo_code at 0x473210 | CONFIRMED |
| C12 | Standard COM AddRef/Release lifecycle | Destroy-on-read-nonzero pattern; no AddRef found | 06, 07, 11 | FUN_004731E0 + FUN_00473210 analyzed | CONFIRMED |
| C13 | 8 sub-initializers not analyzed | 9 sub-initializers not analyzed | 09, 10 | Phase 2.4 Report 10 listed 9 addresses | CONFIRMED |
| C14 | obj+0x20/0x28/0x2C initialized by constructor | Not initialized by constructor | 06, 08 | Full constructor disassembly reviewed | CONFIRMED |

## 3. Corrected Dispatch Matrix

| Vptr State | vptr | CALL [vptr+0x34] | Target | CALL [vptr+0x58] | Target |
|------------|------|------------------|--------|------------------|--------|
| Initial | 0x51FFB4 | 0x51FFE8 | 0x4510A0 (→0) | 0x52000C | 0x450FA0 (? ) |
| Intermediate | 0x51E570 | 0x51E5A4 | 0x4510B0 (→16) | 0x51E5C8 | 0x450FC0 (? ) |
| Final | 0x51E4F0 | 0x51E524 | 0x4510B0 (→16) | 0x51E548 | 0x450FC0 (? ) |

## 4. Corrected Object Lifecycle

```
ALLOCATION (UNKNOWN)
    ↓
CONSTRUCTION (FUN_0043ECF0 → FUN_0043E1A0)
    - Vptr: 0x51FFB4 → 0x51E570 → 0x51E4F0
    - Subobject vptrs at 0x38, 0x40, 0x50, 0x98, 0x9C
    - obj+0x20, 0x28, 0x2C NOT initialized
    - obj+0x30 NOT initialized by constructor
    ↓
REFERENCE COUNTING (FUN_004731E0)
    - Atomic read of obj+0x20
    - If != 0: call FUN_00473210
    ↓
DESTRUCTION (FUN_00473210)
    - DeleteCriticalSection(obj+8)
    - Set obj+0x20 to 0
    - Atomic exchange obj+0x24 (get old, set 1)
    ↓
LIST CLEANUP (5 functions → FUN_004e6cd7 per node)
    ↓
DEALLOCATION (CALL [0x500CA6] → target UNKNOWN)
```

## 5. Reports That Remain Valid (No Correction Needed)

| Report | Reason |
|--------|--------|
| 00 | Environment facts unchanged |
| 02 | Phase 2.3 reconciliation unchanged |
| 03 | Binary identity unchanged |
| 12 | Runtime evidence plan unchanged |
| 13 | Rust compatibility assessment unchanged (already conservative) |
| 15 | Phase 2.3 contradiction resolution unchanged |
| 16 | Unresolved questions updated but not invalidated |
| 19 | Completion and preservation unchanged |

## 6. Reports Requiring Updated Content

| Report | Sections Requiring Update |
|--------|--------------------------|
| 04 | FUN_00473210 section; allocation section |
| 05 | Entire dispatch matrix (corrected addresses and targets) |
| 06 | Field initialization (obj+0x20/0x28/0x2C not initialized) |
| 07 | FUN_00473210 is destroy/reset, not Release |
| 08 | 0x500CA6 is in .text, contains `free` function |
| 09 | Allocation site still unknown; deallocation target unresolved |
| 10 | Subinitializer count corrected to 9 |
| 11 | Object lifecycle is not standard refcounting |
| 14 | Multiple findings updated (see registry) |
| 17 | Corrected technical summary |
| 18 | Corrected raw bytes and address calculations |

## 7. Confidence Summary

| Classification | Count |
|---------------|-------|
| CONFIRMED corrections | 14 |
| Partially corrected | 0 |
| Still unresolved | 9 (from Stage 16) |