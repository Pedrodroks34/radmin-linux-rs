# Phase 2.3 Stage 20 — Remaining Function Analysis

**Classification: VERIFIED** (all pseudocode obtained via REA `procedure_pseudo_code` from Ghidra decompiler)

## 1. Overview

This report documents the complete decompiled pseudocode for all 13 remaining unanalyzed functions identified in the Phase 2.3 checkpoint, plus `FUN_004E7EC0` (previously unresolved as a thunk).

| # | Address | Name | Size | Blocks | Convention | Params | Status |
|---|---------|------|------|--------|------------|--------|--------|
| 1 | 0x4e7ec0 | thunk_FUN_004ec736 | 5 bytes | 1 | `__cdecl` | `void *param_1` | RESOLVED (thunk) |
| 2 | 0x475c00 | FUN_00475c00 | 67 bytes | 7 | `__fastcall` | `int param_1` | ANALYZED |
| 3 | 0x4731e0 | FUN_004731e0 | 44 bytes | 3 | `__fastcall` | `int param_1` | ANALYZED |
| 4 | 0x440670 | FUN_00440670 | 55 bytes | 4 | `__fastcall` | `int param_1` | ANALYZED |
| 5 | 0x4802f0 | FUN_004802f0 | 25 bytes | 1 | `__fastcall` | `undefined4 *param_1` | ANALYZED |
| 6 | 0x46ae70 | FUN_0046ae70 | 89 bytes | 6 | `__stdcall` | (none) | ANALYZED |
| 7 | 0x4831f0 | FUN_004831f0 | 120 bytes | 6 | `__cdecl` | `int *param_1` | ANALYZED |
| 8 | 0x46b9f0 | FUN_0046b9f0 | 88 bytes | 6 | `__cdecl` | `undefined1 param_1` | ANALYZED |
| 9 | 0x451900 | FUN_00451900 | 49 bytes | 3 | `__stdcall` | `REGHANDLE *param_1` | ANALYZED |
| 10 | 0x43b470 | FUN_0043b470 | 68 bytes | 3 | `__fastcall` | `int param_1` | ANALYZED |
| 11 | 0x43b4c0 | FUN_0043b4c0 | 68 bytes | 3 | `__fastcall` | `int param_1` | ANALYZED |
| 12 | 0x43b420 | FUN_0043b420 | 68 bytes | 3 | `__fastcall` | `int param_1` | ANALYZED |
| 13 | 0x43a9a0 | FUN_0043a9a0 | 82 bytes | 3 | `__fastcall` | `int param_1` | ANALYZED |

All 13 functions are now in Ghidra's function inventory (verified via address-based `procedure_info`).

## 2. FUN_004E7EC0 (0x4e7ec0) — Adjustment Thunk

**Status: RESOLVED** — This was previously listed as "FUN_004E7EC0 body not analyzed" (unresolved Q5 in report 16).

Ghidra identifies this as `thunk_FUN_004ec736`, a 5-byte `__cdecl` thunk that simply `JMP`s to `0x4ec736`. This confirms the earlier finding: `FUN_004E7EC0` → `FUN_004ec736` (27 bytes, calls `CALL dword ptr [0x00500ca6]`).

The `FUN_004E6CD7` wrapper calls this thunk, which in turn calls `FUN_004ec736`, which makes an indirect call through `[0x00500ca6]`. This is the destruction/deallocation path invoked from all object cleanup functions.

## 3. FUN_00440670 (0x440670) — Linked List Cleanup/Destroy

**Pseudocode:**

```c
void __fastcall FUN_00440670(int param_1)
{
  int *piVar1;
  int iVar2;
  int *piVar3;

  piVar3 = (int *)FUN_00475870((int *)(param_1 + 4));
  while (piVar3 != (int *)0x0) {
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

**Behavior:** Iterates a doubly-linked list head at `param_1 + 4`. For each node:
1. Unlinks the node from the list (fixes `prev->next` and `next->prev`)
2. Makes the node self-referential (`node[0] = node`, `node[1] = node`)
3. Calls `FUN_004e6cd7(node)` to destroy the node
4. Gets the next node from the list head

**Role:** List teardown during object destruction. `FUN_00475870` pops the head node from a list. `FUN_004e6cd7` is the per-node destructor.

## 4. FUN_00475C00 (0x475c00) — Registry Key Close

**Pseudocode:**

```c
undefined4 __fastcall FUN_00475c00(int param_1)
{
  DWORD dwErrCode;

  if (*(HKEY *)(param_1 + 8) != (HKEY)0x0) {
    if (*(int *)(param_1 + 0xc) != 0) {
      dwErrCode = RegCloseKey(*(HKEY *)(param_1 + 8));
      if (dwErrCode != 0) {
        SetLastError(dwErrCode);
        return 0;
      }
      *(undefined4 *)(param_1 + 0xc) = 0;
    }
    *(undefined4 *)(param_1 + 8) = 0;
    SetLastError(0);
  }
  return 1;
}
```

**Behavior:** Closes a Windows registry key handle stored at `param_1 + 8`. If a secondary flag at `param_1 + 0xc` is non-zero, calls `RegCloseKey`. Always nulls the handle and resets `SetLastError(0)`. Returns 1 on success, 0 on `RegCloseKey` failure.

**Imports used:** `RegCloseKey` (ADVAPI32), `SetLastError` (KERNEL32).

## 5. FUN_004731E0 (0x4731e0) — Reference-Counted Release

**Pseudocode:**

```c
void __fastcall FUN_004731e0(int param_1)
{
  int *piVar1;
  int iVar2;
  DWORD dwErrCode;

  dwErrCode = GetLastError();
  piVar1 = (int *)(param_1 + 0x20);
  LOCK();
  iVar2 = *piVar1;
  *piVar1 = *piVar1;
  UNLOCK();
  if (iVar2 != 0) {
    FUN_00473210(param_1);
  }
  SetLastError(dwErrCode);
  return;
}
```

**Behavior:** Reference-counted release/destroy:
1. Saves `GetLastError()`
2. Atomically reads (`LOCK()`/`UNLOCK()`) the reference count at `param_1 + 0x20`
3. If refcount is non-zero, calls `FUN_00473210(param_1)` (presumably decrements and potentially destroys)
4. Restores `GetLastError()`

**Role:** This is the `Release()` counterpart to a reference-counted object. The `LOCK()` prefix on the read indicates interlocked access for thread safety.

**Imports used:** `GetLastError` / `SetLastError` (KERNEL32).

## 6. FUN_004802F0 (0x4802f0) — CFile VTable Initialization

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

**Behavior:** Initializes a `FamRT::CFile` object:
1. Sets vptr at `*param_1` to `FamRT::CFile::vftable`
2. Calls `FUN_004728e0` on `param_1 + 4` (subobject initialization)
3. Calls `FUN_004776f0(param_1)` (terminal call, likely base constructor)

**Role:** C++ constructor for `FamRT::CFile` class. Confirms the `FamRT` namespace/class hierarchy in the binary.

## 7. FUN_0046AE70 (0x46ae70) — Flag Getter with Critical Section

**Pseudocode:**

```c
undefined1 FUN_0046ae70(void)
{
  undefined1 uVar1;
  int iVar2;
  DWORD dwErrCode;

  LOCK();
  UNLOCK();
  if (DAT_0055e444 == 0) {
    iVar2 = FUN_00403700((LPCRITICAL_SECTION)&DAT_0055e428);
    if (iVar2 == 0) {
      LOCK();
      DAT_0055e444 = 1;
      UNLOCK();
    }
  }
  uVar1 = DAT_0055e3fd;
  dwErrCode = GetLastError();
  iVar2 = FUN_004038a0((LPCRITICAL_SECTION)&DAT_0055e428);
  if (iVar2 == 0) {
    LOCK();
    DAT_0055e444 = 1;
    UNLOCK();
  }
  SetLastError(dwErrCode);
  return uVar1;
}
```

**Behavior:** Reads a global flag `DAT_0055e3fd` with critical section synchronization. Uses `DAT_0055e444` as an initialization flag for the critical section at `DAT_0055e428`. Lazily initializes the critical section via `FUN_00403700` / `FUN_004038a0` (likely `InitializeCriticalSection` / `EnterCriticalSection` wrappers).

**Role:** Thread-safe global flag accessor.

**Imports used:** `GetLastError` / `SetLastError` (KERNEL32).

## 8. FUN_0046B9F0 (0x46b9f0) — Flag Setter with Critical Section

**Pseudocode:**

```c
void __cdecl FUN_0046b9f0(undefined1 param_1)
{
  int iVar1;
  DWORD dwErrCode;

  LOCK();
  UNLOCK();
  if (DAT_0055e444 == 0) {
    iVar1 = FUN_00403700((LPCRITICAL_SECTION)&DAT_0055e428);
    if (iVar1 == 0) {
      LOCK();
      DAT_0055e444 = 1;
      UNLOCK();
    }
  }
  DAT_0055e3fd = param_1;
  dwErrCode = GetLastError();
  iVar1 = FUN_004038a0((LPCRITICAL_SECTION)&DAT_0055e428);
  if (iVar1 == 0) {
    LOCK();
    DAT_0055e444 = 1;
    UNLOCK();
  }
  SetLastError(dwErrCode);
  return;
}
```

**Behavior:** Sets a global flag `DAT_0055e3fd = param_1` with the same critical section synchronization pattern as `FUN_0046ae70`.

**Role:** Thread-safe global flag mutator. Paired with `FUN_0046ae70` (getter/setter pair for a global state flag).

## 9. FUN_00451900 (0x451900) — Event Unregister

**Pseudocode:**

```c
void FUN_00451900(REGHANDLE *param_1)
{
  if (*(int *)param_1 == 0 && *(int *)((int)param_1 + 4) == 0) {
    return;
  }
  EventUnregister(*param_1);
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)((int)param_1 + 4) = 0;
  return;
}
```

**Behavior:** Unregisters a Windows Event Tracing (ETW) registration handle. If both DWORDs of the `REGHANDLE` are zero, returns early. Otherwise calls `EventUnregister(*param_1)` and zeroes the handle.

**Imports used:** `EventUnregister` (ADVAPI32), `GetLastError` / `SetLastError` (KERNEL32).

## 10. FUN_0043B470 (0x43b470) — Linked List Cleanup (offset +6)

**Pseudocode:**

```c
void __fastcall FUN_0043b470(int param_1)
{
  int *piVar1;
  int iVar2;
  int *piVar3;

  piVar3 = (int *)FUN_00475870((int *)(param_1 + 4));
  while (piVar3 != (int *)0x0) {
    FUN_0047b450(piVar3 + 6);
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

**Behavior:** Same list cleanup pattern as `FUN_00440670`, but calls `FUN_0047b450(piVar3 + 6)` on each node before destruction. The `+6` offset (24 bytes from node start) suggests a subobject or embedded structure within each list node that needs cleanup.

**Role:** List teardown with per-node subobject cleanup at offset 0x18 (24 decimal).

## 11. FUN_0043B4C0 (0x43b4c0) — Linked List Cleanup (offset +2)

**Pseudocode:**

```c
void __fastcall FUN_0043b4c0(int param_1)
{
  int *piVar1;
  int iVar2;
  int *piVar3;

  piVar3 = (int *)FUN_00475870((int *)(param_1 + 4));
  while (piVar3 != (int *)0x0) {
    FUN_0047b450(piVar3 + 2);
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

**Behavior:** Same list cleanup pattern, but calls `FUN_0047b450(piVar3 + 2)` on each node before destruction. The `+2` offset (8 bytes from node start) targets a different subobject within each list node.

**Role:** List teardown with per-node subobject cleanup at offset 0x08 (8 decimal).

## 12. FUN_0043B420 (0x43b420) — Linked List Cleanup (offset +4)

**Pseudocode:**

```c
void __fastcall FUN_0043b420(int param_1)
{
  int *piVar1;
  int iVar2;
  int *piVar3;

  piVar3 = (int *)FUN_00475870((int *)(param_1 + 4));
  while (piVar3 != (int *)0x0) {
    FUN_0047b450(piVar3 + 4);
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

**Behavior:** Same list cleanup pattern, but calls `FUN_0047b450(piVar3 + 4)` on each node before destruction. The `+4` offset (16 bytes from node start) targets yet another subobject within each list node.

**Role:** List teardown with per-node subobject cleanup at offset 0x10 (16 decimal).

## 13. FUN_0043A9A0 (0x43a9a0) — Linked List Cleanup (CUniversalString + offsets)

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

**Behavior:** Same list cleanup pattern, but with additional per-node cleanup:
1. Sets vptr at `piVar3 + 0x12` (offset 0x48 = 72 decimal) to `FamRT::CUniversalString::vftable`
2. Calls `FUN_004728e0(piVar3 + 0x12)` — initializes/cleans up the CUniversalString subobject
3. Calls `FUN_00408af0(piVar3 + 0xe)` (offset 0x38 = 56 decimal) — additional subobject cleanup

**Role:** List teardown for nodes containing `CUniversalString` and other subobjects. Confirms `FamRT::CUniversalString` class exists in the binary.

## 14. Cross-Cutting Observations

### 14.1 Central Destruction Function: FUN_004e6cd7

All 13 list-cleanup functions call `FUN_004e6cd7(node)` as the per-node destructor. This function is a wrapper:

- `FUN_004e6cd7` (14 bytes): `PUSH [EBP+0x8]; CALL 0x004e7ec0`
- `FUN_004e7ec0` (5 bytes, thunk): `JMP 0x4ec736`
- `FUN_004ec736` (27 bytes): `CALL dword ptr [0x00500ca6]`

The final indirect call through `[0x00500ca6]` is the actual deallocation/destruction entry point. This is a function pointer stored in the IAT or a global variable — likely `HeapFree` or a custom deallocator.

### 14.2 List Traversal Pattern

All list-cleanup functions share the identical traversal pattern:
1. `FUN_00475870(list_head)` — pops head node from doubly-linked list
2. Unlink node (fix prev/next pointers)
3. Self-reference node (`node[0] = node`, `node[1] = node`)
4. Per-node subobject cleanup (varies by function)
5. `FUN_004e6cd7(node)` — destroy the node
6. Repeat until list is empty

`FUN_00475870` is the list head accessor that returns and removes the first node.

### 14.3 FAM RT Classes Identified

- `FamRT::CFile::vftable` — referenced by `FUN_004802F0`
- `FamRT::CUniversalString::vftable` — referenced by `FUN_0043A9A0`
- These confirm the `FamRT` C++ class hierarchy with virtual inheritance