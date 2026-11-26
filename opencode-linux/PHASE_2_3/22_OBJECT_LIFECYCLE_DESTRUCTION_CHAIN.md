# Phase 2.3 Stage 22 — Object Lifecycle and Destruction Chain

**Classification: VERIFIED** (all pseudocode obtained via REA `procedure_pseudo_code`; all call relationships verified via static analysis)

## 1. Complete Destruction Chain

The object destruction path is now fully traced from reference-count release to final deallocation. Every analyzed cleanup function converges on `FUN_004e6cd7`.

### Chain Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  OBJECT LIFECYCLE                                               │
│                                                                 │
│  1. Construction: FUN_0043ECF0 → FUN_0043E1A0                  │
│     (called only by 5 adjustment thunks; thunks have no callers)│
│                                                                 │
│  2. Reference counting: refcount at obj + 0x20                 │
│     - FUN_004731E0: atomic LOCK/UNLOCK read of refcount         │
│     - If refcount != 0: calls FUN_00473210                      │
│                                                                 │
│  3. Destruction: FUN_00473210 → list cleanup functions          │
│     - FUN_00440670, FUN_0043B470, FUN_0043B4C0,                │
│       FUN_0043B420, FUN_0043A9A0                                │
│                                                                 │
│  4. Per-node destroy: FUN_004e6cd7(node)                        │
│     → thunk_FUN_004ec736 (JMP 0x4ec736)                         │
│     → FUN_004ec736                                              │
│     → CALL dword ptr [0x00500ca6]  ← FINAL DEALLOCATION        │
└─────────────────────────────────────────────────────────────────┘
```

### 4a. FUN_004e6cd7 (0x4e6cd7) — Destruction Wrapper

**Disassembly (14 bytes):**
```
PUSH [EBP+0x8]     ; push this pointer
CALL 0x004e7ec0    ; call thunk
```

**Behavior:** Calls `FUN_004e7ec0` with the `this` pointer (ECX in `__fastcall`, pushed on stack in `__cdecl`).

### 4b. FUN_004e7ec0 (0x4e7ec0) — Adjustment Thunk

**Size:** 5 bytes
**Classification:** Thunk (Ghidra: `thunk_FUN_004ec736`)
**Disassembly:** `JMP 0x004ec736`

**Behavior:** Tail-call jump to `FUN_004ec736`. No adjustment (unlike the 5 constructor adjustment thunks which do `SUB ECX, offset`).

### 4c. FUN_004ec736 (0x4ec736) — Final Destroy

**Size:** 27 bytes
**Disassembly (known):** `CALL dword ptr [0x00500ca6]`

**Behavior:** Makes an indirect call through the function pointer at `[0x00500ca6]`. This is the final deallocation entry point. The IAT slot at 0x500ca6 likely contains `HeapFree` or `ROLClient_FreeMemory`.

## 2. List Cleanup Functions — All Call FUN_004e6cd7

Five functions share the identical list traversal pattern, each calling `FUN_004e6cd7` on every node:

| Function | Address | Subobject cleanup offset | Additional subobject cleanup |
|----------|---------|-------------------------|------------------------------|
| FUN_00440670 | 0x440670 | (none) | (none) |
| FUN_0043B470 | 0x43b470 | `piVar3 + 6` (0x18) | `FUN_0047b450` |
| FUN_0043B4C0 | 0x43b4c0 | `piVar3 + 2` (0x08) | `FUN_0047b450` |
| FUN_0043B420 | 0x43b420 | `piVar3 + 4` (0x10) | `FUN_0047b450` |
| FUN_0043A9A0 | 0x43a9a0 | `piVar3 + 0x12` (0x48) | `FUN_004728e0`, `FUN_00408af0` |

**Common pattern for each node:**
1. `FUN_00475870(list_head)` — pop head node
2. Unlink from doubly-linked list
3. Self-reference node (`node[0] = node`, `node[1] = node`)
4. Function-specific subobject cleanup (varies)
5. `FUN_004e6cd7(node)` — destroy node
6. Repeat until empty

## 3. Other Destruction Functions

### FUN_00475C00 — Registry Key Close (0x475c00)
Closes an `HKEY` handle at `obj + 8` via `RegCloseKey`. Called during cleanup of registry-associated subobjects.

### FUN_00451900 — Event Unregister (0x451900)
Calls `EventUnregister(*param_1)` on an ETW registration handle, then zeroes the handle. Called during cleanup of event-traced subobjects.

### FUN_004802F0 — CFile Constructor (0x4802f0)
Initializes `FamRT::CFile` vptr and subobjects. This is a **constructor**, not destruction — called during object creation.

### FUN_0046AE70 / FUN_0046B9F0 — Global Flag Accessors
Thread-safe getter/setter for global flag `DAT_0055e3fd` with critical section synchronization. Not object lifecycle, but global state management.

### FUN_004831F0 — PerfStopProvider Call (0x4831f0)
Calls `PerfStopProvider` from `advapi32.dll` for ETW provider shutdown. Part of cleanup/shutdown sequence.

## 4. Reference Counting Pattern

**FUN_004731E0** implements `Release()` semantics:

```c
void __fastcall FUN_004731e0(int param_1)  // this = param_1
{
  dwErrCode = GetLastError();
  piVar1 = (int *)(param_1 + 0x20);  // refcount at obj + 0x20
  LOCK();
  iVar2 = *piVar1;                   // atomic read
  *piVar1 = *piVar1;                 // no-op write (compiler barrier)
  UNLOCK();
  if (iVar2 != 0) {
    FUN_00473210(param_1);           // decrement and destroy if zero
  }
  SetLastError(dwErrCode);
}
```

**Key observations:**
- Refcount stored at `obj + 0x20` (32 decimal)
- `LOCK()` prefix on read — interlocked access for thread safety
- `*piVar1 = *piVar1` — read-then-write same value (compiler memory barrier pattern)
- `FUN_00473210` is the decrement-and-destroy-if-zero function (not yet analyzed)
- `GetLastError`/`SetLastError` preserves error code across the operation

This is the COM-style `Release()` pattern. The corresponding `AddRef()` function has not been identified yet.

## 5. Object Lifecycle Summary

| Phase | Function(s) | Key Actions | Confidence |
|-------|-------------|-------------|------------|
| Allocation | Unknown (HeapAlloc / RolClientAllocMemory not found in constructor) | Allocate object memory | UNRESOLVED |
| Construction | FUN_0043ECF0 → FUN_0043E1A0 | Vptr writes (3×), subobject vptrs, field initialization | VERIFIED |
| AddRef | Unknown (not found) | Increment refcount at obj + 0x20 | UNRESOLVED |
| Release | FUN_004731E0 | Atomic read refcount at obj + 0x20, call FUN_00473210 | VERIFIED |
| Destroy | FUN_00473210 → list cleanup | Decrement refcount, destroy list nodes | PARTIAL (FUN_00473210 not analyzed) |
| Node destroy | FUN_004e6cd7 → thunk → [0x500ca6] | Per-node deallocation | VERIFIED (chain), UNRESOLVED (final target) |

## 6. Unresolved Questions in Lifecycle

| Question | Evidence Needed | Blocks Rust? |
|----------|-----------------|--------------|
| Who calls FUN_0043ECF0 / adjustment thunks? | Search for CALL to thunk addresses (0x43e85e–0x43e881) | No |
| What is FUN_00473210? | REA procedure_info at FUN_00473210 | No |
| What does `[0x00500ca6]` point to? | Read IAT slot at 0x500ca6; search for references | No |
| Object allocation size? | Find HeapAlloc/RolClientAllocMemory call with size argument | No |
| AddRef function? | Search for increment at obj + 0x20 | No |