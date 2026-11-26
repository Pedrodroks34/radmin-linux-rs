# Phase 2.5 Stage 16 — Indirect Call and Thunk Inventory

**Classification: PROVEN / PARTIALLY UNRESOLVED** — every indirect call and thunk related to the target object is catalogued; the `0x00500CA6` entry is corrected from indirect-slot to direct-call-to-function.

Cross-reference: `03_VTABLE_ADDRESS_POINT_CORRECTION.md`, `04_VTABLE_SLOT_TARGET_RESOLUTION.md`, `06_PE_LAYOUT_AND_00500CA6_CORRECTION.md`, `07_INDIRECT_DEALLOCATION_CALL_CHAIN.md`, `16` ← self.

---

## 1. Indirect Call Inventory

| # | Call site VA | Instruction | Pointer source | Slot calculation | Candidate target | Resolution status | Evidence |
|---|-------------|-------------|----------------|------------------|------------------|-------------------|----------|
| I1 | `0x0044F501` | `CALL [EAX+0x34]` | EAX = `[EDI]` (object vptr), EDI=this | vptr + 0x34 (slot 13) | Depends on active vptr: Table A → `0x004510A0`; Table B/C → `0x004510B0` | PARTIALLY (target depends on unknown active vptr) | Bytes `FF 50 34` verified; vptr load `8B 07` at `0x44F4FA` verified |
| I2 | `0x0044F50D` | `CALL [EAX+0x58]` | EAX = `[EDI]` (object vptr) | vptr + 0x58 (slot 22) | Table A → `0x00450FA0`; Table B/C → `0x00450FC0` | PARTIALLY | Bytes `FF 50 58` verified |
| I3 | `0x0044F5AA` | `CALL [EAX+0x34]` | EAX = `[EDI]` (object vptr) | vptr + 0x34 (slot 13, 2nd call) | Same as I1 | PARTIALLY | Bytes `FF 50 34` verified |
| I4 | `0x0044F5B6` | `CALL [EAX+0x58]` | EAX = `[EDI]` (object vptr) | vptr + 0x58 (slot 22, 2nd call) | Same as I2 | PARTIALLY | Bytes `FF 50 58` verified |
| I5 | `0x004EC749` | `CALL 0x00500CA6` | **Direct relative `E8`** (not memory-indirect) | N/A (direct call) | Function `0x00500CA6` | RESOLVED | Bytes `E8 58 45 01 00` → target `0x4EC74E + 0x14558 = 0x500CA6`; `0x500CA6` is code (function prologue) |

**Correction:** Phase 2.4 described I5 as `CALL [0x00500CA6]` (indirect through a memory slot). Verified: it is `CALL 0x00500CA6` (direct relative call) to function `0x00500CA6`. There is **no indirect memory slot at `0x00500CA6`** — it is code in `.text`.

---

## 2. Slot-Address Resolution (using ACTUAL vptr address points)

For each indirect call I1–I4, EAX = object vptr. The active vptr is UNKNOWN (constructor unreachable, no runtime trace).

| Active vptr | Table | Slot 13 (`+0x34`) | Slot 22 (`+0x58`) |
|-------------|-------|-------------------|-------------------|
| `0x0051FFB4` | Table A | `0x0051FFE8` → `0x004510A0` (unresolved body) | `0x0052000C` → `0x00450FA0` (unresolved body) |
| `0x0051E570` | Table B | `0x0051E5A4` → `0x004510B0` (returns 16) | `0x0051E5C8` → `0x00450FC0` (unresolved body) |
| `0x0051E4F0` | Table C | `0x0051E524` → `0x004510B0` (returns 16, shared w/ Table B) | `0x0051E548` → `0x00450FC0` (unresolved body, shared w/ Table B) |

**Guarded execution:** I1–I4 execute only if `[EDI+0x28]==5 && [EDI+0x2C]!=0` (verified at `0x44F4EE`/`0x44F4F4`).

---

## 3. Thunk Inventory

| # | Thunk VA | Size | Disassembly | Target | Type | Verified? |
|---|----------|------|-------------|--------|------|-----------|
| T1 | `0x0043E85E` | 8 | `SUB ECX, 0x38; JMP 0x0043ECF0` | `FUN_0043ECF0` | this-adjust (−0x38) | PROVEN |
| T2 | `0x0043E866` | 8 | `SUB ECX, 0x40; JMP 0x0043ECF0` | `FUN_0043ECF0` | this-adjust (−0x40) | PROVEN |
| T3 | `0x0043E86E` | 8 | `SUB ECX, 0x50; JMP 0x0043ECF0` | `FUN_0043ECF0` | this-adjust (−0x50) | PROVEN |
| T4 | `0x0043E876` | 8 | `SUB ECX, 0x98; JMP 0x0043ECF0` | `FUN_0043ECF0` | this-adjust (−0x98) | PROVEN |
| T5 | `0x0043E881` | 8 | `SUB ECX, 0x9C; JMP 0x0043ECF0` | `FUN_0043ECF0` | this-adjust (−0x9C) | PROVEN |
| T6 | `0x004E7EC0` | 5 | `JMP 0x4EC736` | `FUN_004ec736` | tail/destruction thunk | PROVEN |

All 5 constructor adjustment thunks (T1–T5) have **no callers** — unreachable from any known entry point. T6 is called by `FUN_004e6cd7` (verified).

---

## 4. Import Thunks / IAT Calls (in analyzed functions)

| VA | Function | Indirect IAT call | IAT address | Likely import | Verified? |
|----|----------|-------------------|-------------|---------------|-----------|
| `0x004731E5` | `FUN_004731E0` | `CALL [0x00519280]` | `0x00519280` | `GetLastError` | PROVEN (bytes `FF 15 80 92 51 00`) |
| `0x00473201` | `FUN_004731E0` | `CALL [0x00519260]` | `0x00519260` | `SetLastError` | PROVEN (bytes `FF 15 60 92 51 00`) |
| `0x00500CA6+...` | `0x00500CA6` | `CALL [0x005192EC]` | `0x005192EC` | unknown import | PROVEN (inside function `0x500CA6`) |
| `0x00500CA6+...` | `0x00500CA6` | `CALL [0x00519280]` | `0x00519280` | `GetLastError` | PROVEN (inside function `0x500CA6`) |
| `0x00500CA6+...` | `0x00500CA6` | `PUSH [0x005581E8]` | `0x005581E8` | data pointer global | PROVEN (inside function `0x500CA6`) |

No `CALL [0x00500CA6]` indirect slot exists. All real IAT calls go through `0x00519280`, `0x00519260`, `0x005192EC`; data read from `0x005581E8`.

---

## 5. Unresolved Indirect Targets

| # | Target | Why unresolved | Static evidence possible? | Runtime info required |
|---|--------|---------------|--------------------------|----------------------|
| I1–I4 slot 13/22 under Table A | `0x004510A0`, `0x00450FA0` | Bodies not disassembled | YES — disassemble `0x004510A0`/`0x00450FA0` | None (after disassembly) |
| I1–I4 slot 22 under Table B/C | `0x00450FC0` | Body not disassembled | YES — disassemble `0x00450FC0` | None (after disassembly) |
| I1–I4 actual target at runtime | depends on active vptr | Active vptr unknown (no caller of `FUN_0044F3F0`) | NO — runtime state | Breakpoint at `0x44F501`, inspect `[EDI]` |

---

## 6. Confidence Summary

| Item | Classification |
|------|----------------|
| Indirect calls I1–I4 (`[EAX+0x34]`, `[EAX+0x58]`) | PROVEN (bytes verified) |
| Slot arithmetic (corrected vptr base) | PROVEN |
| I5 `CALL [0x500CA6]` = indirect slot | CONTRADICTED (it's direct `CALL 0x500CA6`) |
| `0x500CA6` is function/code (not IAT) | PROVEN |
| 5 constructor adjustment thunks | PROVEN |
| Destruction thunk `0x4E7EC0` | PROVEN |
| Actual runtime targets of I1–I4 | UNKNOWN (depends on unknown active vptr) |
