# Phase 2.5 Stage 10 — Subinitializer Detailed Analysis

**Classification: BLOCKED** (8 sub-initializers not yet analyzed via REA; static analysis needed)

## 1. Purpose

Analyze the 9 remaining sub-initializers identified in Stage 09. This stage documents what is needed and what has been partially established.

## 2. Sub-Initializers Requiring Analysis

| Address | Name | Status | REA procedure_info? | Pseudocode? | Field Writes? |
|---------|------|--------|--------------------|-------------|---------------|
| 0x47A8A0 | FUN_0047A8A0 | NOT ANALYZED | No | No | Unknown |
| 0x43E500 | FUN_0043E500 | NOT ANALYZED | No | No | Unknown |
| 0x403540 | FUN_00403540 | NOT ANALYZED | No | No | Unknown |
| 0x4728E0 | FUN_004728E0 | PARTIAL (called, body not decompiled) | No | No | Unknown |
| 0x483750 | FUN_00483750 | NOT ANALYZED | No | No | Unknown |
| 0x43E680 | FUN_0043E680 | NOT ANALYZED | No | No | Unknown |
| 0x47BB20 | FUN_0047BB20 | NOT ANALYZED | No | No | Unknown |
| 0x475B70 | FUN_00475B70 | NOT ANALYZED | No | No | Unknown |
| 0x479240 | FUN_00479240 | NOT ANALYZED | No | No | Unknown |

## 3. Analysis Template for Each Function

For each sub-initializer, the following must be determined:

1. **Function boundary** — Start address, size, basic block count
2. **Calling convention** — `__fastcall`, `__stdcall`, `__cdecl`, `__thiscall`
3. **Parameters** — What the function receives (typically `this` pointer)
4. **Pseudocode** — Ghidra decompiler output
5. **Disassembly** — Key instructions, especially writes
6. **Object field writes** — Which offsets of the main object are written
7. **Subobject writes** — Any embedded object initialization
8. **Vptr writes** — Any vtable pointer writes
9. **Calls to other functions** — Internal calls within the sub-initializer
10. **Effect on main object lifetime** — Does it affect construction/destruction?

## 3. Already Established Facts About Sub-Initializers

### FUN_004728E0 — Partially Known

Called by:
- `FUN_004802F0` (FamRT::CFile constructor) at `param_1 + 4`
- `FUN_0043A9A0` (list cleanup) at `piVar3 + 0x12`

**Role:** Subobject initialization/cleanup function, likely for CFile or CUniversalString subobjects.

**Body:** NOT decompiled. Need REA `procedure_info` and `procedure_pseudo_code` at 0x4728E0.

## 4. Fields Potentially Affected by Sub-Initializers

From Stage 08 analysis, the following fields are NOT written by the constructor:
- `obj + 0x20` (refcount)
- `obj + 0x28` (state field)
- `obj + 0x2C` (handle/flag field)

**Hypothesis:** One or more sub-initializers may initialize these fields before `FUN_0044F3F0` reads them.

## 5. Confidence Classification

| Question | Classification | Basis |
|----------|---------------|-------|
| 9 sub-initializers need analysis | CONFIRMED | Inventory from Stage 09 |
| None have been analyzed in Phase 2.5 | CONFIRMED | No REA calls made to these addresses |
| FUN_004728E0 is shared between constructor and destruction | STRONGLY SUPPORTED | Called by both FUN_004802F0 and FUN_0043A9A0 |
| Sub-initializers may initialize obj+0x20/0x28/0x2c | HYPOTHESIS | Constructor doesn't write these fields; sub-initializers not yet analyzed |