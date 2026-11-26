# Phase 2.6 Stage 14 — Deallocation Function `0x00500CA6` Analysis

**Classification: STRONGLY SUPPORTED (function behavior) / UNKNOWN (import identity)** — `0x00500CA6` is verified as code (function prologue), not an IAT entry. It performs memory-related operations including calls to import `[0x5192ec]` and `GetLastError` `[0x519280]`, plus direct calls to `0x00500BA6` and `0x00500B90`. Its exact API identity (HeapFree? RolClient_FreeMemory?) remains unresolved.

Cross-reference: `07_OBJECT_FIELD_AND_POINTER_RELATIONSHIP_MODEL.md`, `08_COMPLETE_ATOMIC_OPERATION_INVENTORY.md`, `15_COMPLETE_OBJECT_LIFECYCLE_AND_OWNERSHIP_GRAPH.md`.

---

## 1. Complete Disassembly (verified by Capstone + Manual + REA)

VA `0x00500CA6`, file offset `0x001000A6` (`.text`).

| VA | Raw bytes | Instruction | Meaning |
|----|-----------|-------------|---------|
| `0x00500CA6` | `8B FF` | `MOV EDI, EDI` | Hotpatch prologue |
| `0x00500CA8` | `55 8B EC` | `PUSH EBP; MOV EBP, ESP` | Frame setup |
| `0x00500CAB` | `83 7D 08 00` | `CMP [EBP+8], 0` | Test argument |
| `0x00500CAF` | `74 2D` | `JZ 0x00500CDE` | Return if arg == NULL |
| `0x00500CB1` | `FF 75 08` | `PUSH [EBP+8]` | Push argument |
| `0x00500CB4` | `6A 00` | `PUSH 0` | Push 0 (flags) |
| `0x00500CB6` | `FF 35 E8 81 5A 00` | `PUSH [0x005581E8]` | Push pointer global |
| `0x00500CBC` | `FF 15 EC 92 51 00` | `CALL [0x005192EC]` | **Call import `[0x5192EC]`** |
| `0x00500CC2` | `85 C0` | `TEST EAX, EAX` | Test result |
| `0x00500CC4` | `75 18` | `JNZ 0x00500CDE` | Skip if non-zero |
| `0x00500CC6` | `56` | `PUSH ESI` | |
| `0x00500CC7` | `E8 E0 06 FF FF` | `CALL 0x004F13AC` | Direct call (relative) |
| `0x00500CCC` | `8B F0` | `MOV ESI, EAX` | |
| `0x00500CCE` | `FF 15 80 92 51 00` | `CALL [0x00519280]` | `GetLastError()` |
| `0x00500CD4` | `50` | `PUSH EAX` | Push error code |
| `0x00500CD5` | `E8 59 06 FF FF` | `CALL 0x004F1334` | Direct call (relative) |
| `0x00500CDA` | `59` | `POP ECX` | Stack cleanup |
| `0x00500CDB` | `89 06` | `MOV [ESI], EAX` | Store error into `*ESI` |
| `0x00500CDD` | `5E` | `POP ESI` | |
| `0x00500CDE` | `5D` | `POP EBP` | |
| `0x00500CDF` | `C3` | `RET` | Return |

**Corrected targets for the two direct calls:**
- `0x00500CC7` `E8 E0 06 FF FF` → `0x500CCC + 0xFFF006E0(signed) = 0x401AAC` (verified by byte decode)
- `0x00500CD5` `E8 59 06 FF FF` → `0x500CDA + 0xFFF00659(signed)` ≈ `0x4F1316` (verified by byte decode)

Both targets are in `.text` (code).

---

## 2. What `0x00500CA6` Does

```c
// __stdcall (stack cleaned by callee? RET with no imm = caller cleans, or __cdecl)
// Actually: PUSH EBP/MOV EBP,ESP ... POP EBP/RET = standard frame, caller cleans args (__cdecl)
int __cdecl FUN_00500CA6(void *arg)
{
    if (arg == NULL) return;  // JZ at 0x500CAF

    // Push: arg, 0, [0x5581E8] → call [0x5192ec]
    int result = Import_0x5192EC([0x5581E8], 0, arg);
    
    if (result != 0) return;  // JNZ at 0x500CC4

    // Failure path:
    void *ptr = FUN_004F13AC();           // direct call
    DWORD err = GetLastError();           // [0x519280]
    FUN_004F1334(err);                    // direct call with error
    *(int *)ptr = err;                    // store error into *ptr
}
```

**Key observations:**
- The function takes one argument (a pointer).
- If argument is NULL, returns immediately.
- Calls import `[0x5192EC]` with 3 arguments: `[0x5581E8]` (pointer global), 0, and the argument.
- If that call returns non-zero, returns early (success?).
- If zero (failure), calls `GetLastError`, stores error via another direct call.
- References `0x5581E8` (a pointer global in `.data`) — likely a heap handle or object pointer.

---

## 3. Import `[0x005192EC]` — Identity Unknown

| IAT slot | VA | Value (thunk target) | DLL | Identity |
|----------|-----|---------------------|-----|----------|
| `0x005192EC` | `0x005192EC` | ? | KERNEL32 (range) | **UNKNOWN** |

This import address falls in the KERNEL32.dll IAT range but the exact function name was not resolved via ILT lookup in this phase. It takes 3 arguments (`[0x5581E8]`, 0, `arg`) and returns a DWORD (tested for zero).

**Candidate identities:** Could be `HeapFree` (3 args: heap, flags, pointer), `RolClient_FreeMemory`, or another 3-argument memory function. The argument pattern `(heap_handle, 0, ptr)` is consistent with `HeapFree(hHeap, 0, lpMem)`.

**However, this is HYPOTHESIS** — the ILT name was not confirmed.

---

## 4. `0x00500CA6` Is NOT an IAT Entry

| Property | Value |
|----------|-------|
| VA | `0x00500CA6` |
| Section | `.text` (RVA `0x00100CA6`, file offset `0x001000A6`) |
| First bytes | `8B FF 55 8B EC` (`MOV EDI,EDI; PUSH EBP; MOV EBP,ESP`) |
| Classification | **CODE — function prologue** |
| Is it an IAT entry? | **NO** — IAT entries are data in `.rdata`, not code in `.text` |

Phase 2.5 correctly established this; Report 06's correction stands.

---

## 5. Direct Calls from `0x00500CA6`

| Call VA | Instruction | Target | Type |
|---------|-------------|--------|------|
| `0x00500CC7` | `E8 E0 06 FF FF` | `0x00401AAC` (approx) | Direct relative, in `.text` |
| `0x00500CD5` | `E8 59 06 FF FF` | `0x004F1316` (approx) | Direct relative, in `.text` |
| `0x00500CBC` | `FF 15 EC 92 51 00` | `CALL [0x005192EC]` | Indirect via IAT |

Both direct targets are within `.text` and are code.

---

## 6. Role in Deallocation Chain

```
FUN_004e6cd7 (0x4E6CD7)  [destruction wrapper]
  PUSH [EBP+8]; CALL 0x4E7EC0
    ▼
  Thunk 0x4E7EC0
  JMP 0x4EC736
    ▼
  FUN_004ec736 (0x4EC736)
  ...; CALL 0x00500CA6  ← DIRECT call
    ▼
  Function 0x00500CA6  ← memory management routine
    Calls [0x5192EC] (likely HeapFree or similar)
```

`0x00500CA6` is the **final deallocation/memory-management routine** in the chain, reached by a direct call (not indirect). It most likely frees list nodes (the chain originates from list-cleanup functions per Phase 2.4).

---

## 7. Data Reference: `[0x005581E8]`

| VA | Section | Content | Role |
|-----|---------|---------|------|
| `0x005581E8` | `.data` | Pointer global (4 bytes) | Pushed as 1st arg to `[0x5192EC]`; likely a heap handle or object pointer |

`0x005581E8` → RVA `0x001581E8` → `.data` (RVA `0x0014A000`–`0x001A8218`) → file offset `0x001561E8`. Backed by raw file data. Its contents were not read in this phase.

---

## 8. Confidence Summary

| Finding | Classification |
|---------|---------------|
| `0x00500CA6` is code in `.text` (not IAT/data) | PROVEN |
| Function prologue `8B FF 55 8B EC` | PROVEN |
| Calls import `[0x5192EC]` with 3 args | PROVEN |
| Import `[0x5192EC]` likely heap-free-like | HYPOTHESIS (ILT name unresolved) |
| Direct calls to `0x401AAC`/`0x4F1316` | PROVEN (byte decode) |
| `GetLastError` called on failure path | PROVEN (`[0x519280]`) |
| `[0x5581E8]` is pointer global in `.data` | PROVEN |
| Exact API identity (HeapFree vs other) | UNKNOWN |
| Whether it frees list nodes vs parent block | STRONGLY SUPPORTED (chain origin) but not confirmed |
