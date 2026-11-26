# Phase 2.4 Stage 10 — Subinitializer and Subobject Analysis

**Classification: PARTIALLY RESOLVED** (4 of 12 sub-initializers analyzed; 8 remain unanalyzed)

## 1. Constructor Sub-Initializers (12 Total)

The constructor `FUN_0043E1A0` calls 12 sub-initializer functions. Status:

| # | Address | Name | Status | Role |
|---|---------|------|--------|------|
| 1 | 0x43E100 | FUN_0043E100 | ANALYZED | Zeroing loop (0x0C–0x4C4) |
| 2 | 0x47A8A0 | FUN_0047A8A0 | NOT ANALYZED | Unknown |
| 3 | 0x43E500 | FUN_0043E500 | NOT ANALYZED | Unknown |
| 4 | 0x403540 | FUN_00403540 | NOT ANALYZED | Unknown |
| 5 | 0x4728E0 | FUN_004728E0 | PARTIALLY ANALYZED | Called by FUN_004802F0 and FUN_0043A9A0 |
| 6 | 0x483750 | FUN_00483750 | NOT ANALYZED | Unknown |
| 7 | 0x43E680 | FUN_0043E680 | NOT ANALYZED | Unknown |
| 8 | 0x47BB20 | FUN_0047BB20 | NOT ANALYZED | Unknown |
| 9 | 0x475B70 | FUN_00475B70 | NOT ANALYZED | Unknown |
| 10 | 0x479240 | FUN_00479240 | NOT ANALYZED | Unknown |
| 11 | 0x4E70A5 | FUN_004E70A5 | NOT ANALYZED | Unknown |
| 12 | 0x43A9A0 | FUN_0043A9A0 | ANALYZED | List cleanup with CUniversalString |
| 13 | 0x4E7EC0 | FUN_004E7EC0 | ANALYZED | 5-byte thunk → FUN_004ec736 |

**Note:** FUN_004E7EC0 was listed as a sub-initializer but is actually a destruction thunk, not an initializer.

## 2. Analyzed Sub-Initializers

### FUN_0043E100 — Zeroing Loop

Zeroes object memory from offset 0x0C to 0x4C4. Part of constructor initialization.

### FUN_004802F0 (0x4802F0) — FamRT::CFile Constructor

**Pseudocode:**

```c
void __fastcall FUN_004802f0(undefined4 *param_1)
{
  *param_1 = FamRT::CFile::vftable;
  FUN_004728e0(param_1 + 4);
  FUN_004776f0(param_1);
  return;
}
```

**Behavior:**
1. Sets vptr at `*param_1` to `FamRT::CFile::vftable`
2. Calls `FUN_004728e0(param_1 + 4)` — subobject initialization at offset +4
3. Calls `FUN_004776f0(param_1)` — terminal call (likely base constructor)

**Role:** C++ constructor for `FamRT::CFile` class.

### FUN_0043A9A0 (0x43A9A0) — List Cleanup with CUniversalString

**Pseudocode:**

```c
void __fastcall FUN_0043a9a0(int param_1)
{
  int *piVar1;
  int iVar2;
  int *piVar3;

  piVar3 = (int *)FUN_00475870((int *)(param_1 + 4));
  while (piVar3 != (int *)0x0) {
    piVar3[0x12] = (int)FamRT::CUniversalString::vftable;
    FUN_004728e0(piVar3 + 0x12);
    FUN_00408af0(piVar3 + 0xe);
    piVar1 = (int *)piVar3[1];
    iVar2 = *piVar3;
    *piVar1 = iVar2;
    *(int **)(iVar2 + 4) = piVar1;
    *piVar3 = (int)piVar3;
    piVar3[1] = (int)piVar3;
    FUN_004e6cd7(piVar3);
    piVar3 = (int *)FUN_00475870((int *)(param_1 + 4));
  }
  return;
}
```

**Behavior:** List cleanup with per-node subobject cleanup:
1. Pops head node from list at `param_1 + 4` via `FUN_00475870`
2. Sets vptr at `piVar3 + 0x12` (offset 0x48) to `FamRT::CUniversalString::vftable`
3. Calls `FUN_004728e0(piVar3 + 0x12)` — CUniversalString subobject cleanup
4. Calls `FUN_00408af0(piVar3 + 0xe)` (offset 0x38) — additional subobject cleanup
5. Unlinks node from list
6. Calls `FUN_004e6cd7(node)` — node destruction
7. Repeats until list empty

**Role:** List teardown for nodes containing CUniversalString subobject.

## 3. FAM RT Class Hierarchy

| Class | Vtable Address | Referenced By |
|-------|---------------|---------------|
| FamRT::CFile | Unknown value (vftable symbol) | FUN_004802F0 |
| FamRT::CUniversalString | Unknown value (vftable symbol) | FUN_0043A9A0 |
| FamRT::CSelfDeletingObject | Unknown | Mentioned in CONTROL_PROTOCOL.md as CPacket base |

**Note:** The vtable values themselves were not extracted; only the symbol names `FamRT::CFile::vftable` and `FamRT::CUniversalString::vftable` appear in decompiled pseudocode.

## 4. Unanalyzed Sub-Initializers

| Address | Name | Reason Not Analyzed | Impact on Phase 2.4 Questions |
|---------|------|---------------------|-------------------------------|
| 0x47A8A0 | FUN_0047A8A0 | Not in Ghidra auto-analysis inventory | Unknown — may initialize fields affecting object behavior |
| 0x43E500 | FUN_0043E500 | Not in Ghidra auto-analysis inventory | Unknown |
| 0x403540 | FUN_00403540 | Not in Ghidra auto-analysis inventory | Unknown |
| 0x4728E0 | FUN_004728E0 | Called by FUN_004802F0 and FUN_0043A9A0 but body not decompiled | Unknown — called in both construction and destruction paths |
| 0x483750 | FUN_00483750 | Not in Ghidra auto-analysis inventory | Unknown |
| 0x43E680 | FUN_0043E680 | Not in Ghidra auto-analysis inventory | Unknown |
| 0x47BB20 | FUN_0047BB20 | Not in Ghidra auto-analysis inventory | Unknown |
| 0x475B70 | FUN_00475B70 | Not in Ghidra auto-analysis inventory | Unknown |
| 0x479240 | FUN_00479240 | Not in Ghidra auto-analysis inventory | Unknown |
| 0x4E70A5 | FUN_004E70A5 | Not in Ghidra auto-analysis inventory | Unknown |

## 5. Subobject Analysis

| Offset | Subobject | Vtable | Constructor Write | Overwrite | Confidence |
|--------|-----------|--------|-------------------|-----------|------------|
| 0x38 | Subobject A | 0x520014 → 0x51BE00 | CONFIRMED | CONFIRMED | STRONGLY SUPPORTED |
| 0x40 | Subobject B | 0x520020 → 0x51BE0C | CONFIRMED | CONFIRMED | STRONGLY SUPPORTED |
| 0x50 | Subobject C | 0x520034 → 0x51BE20 | CONFIRMED | CONFIRMED | STRONGLY SUPPORTED |
| 0x98 | Subobject D | 0x520050 → 0x51E810 | CONFIRMED | CONFIRMED | STRONGLY SUPPORTED |
| 0x9C | Subobject E | 0x5200E8 → 0x51E7F8 | CONFIRMED | CONFIRMED | STRONGLY SUPPORTED |

**Subobject vtable overwrites:** During construction phase 2, all 5 subobject vptrs are overwritten with different values, indicating the subobjects transition through different vtable states during construction.

## 6. FUN_004728e0 — Called in Both Construction and Destruction

`FUN_004728e0` is called from:
- `FUN_004802F0` (CFile constructor) at `param_1 + 4`
- `FUN_0043A9A0` (list cleanup) at `piVar3 + 0x12`

Its body was not decompiled. It may be a shared subobject initialization/cleanup function used by both CFile and CUniversalString.

## 7. Confidence Classification

| Question | Classification | Basis |
|----------|---------------|-------|
| 12 sub-initializers identified | CONFIRMED | Constructor disassembly |
| 4 sub-initializers analyzed | CONFIRMED | REA procedure_pseudo_code |
| 8 sub-initializers unanalyzed | CONFIRMED (absence) | Not in analyzed set |
| FamRT::CFile class exists | CONFIRMED | Symbol in pseudocode |
| FamRT::CUniversalString class exists | CONFIRMED | Symbol in pseudocode |
| FUN_004728e0 is shared init/cleanup | HYPOTHESIS | Called in both paths, body not analyzed |
| Subobject vtable states | CONFIRMED | Raw bytes at 5 write sites each |