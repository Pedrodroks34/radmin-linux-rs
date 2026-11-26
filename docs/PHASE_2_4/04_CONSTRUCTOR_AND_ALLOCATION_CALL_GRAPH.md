# Phase 2.4 Stage 04 — Constructor and Allocation Call Graph

**Classification: PARTIALLY RESOLVED** (static evidence only; runtime allocation site not observable without Windows debugger)

## 1. Constructor Functions

### FUN_0043E1A0 (0x43E1A0) — Primary Constructor

| Property | Value |
|----------|-------|
| Address | 0x0043E1A0 |
| Size | 853 bytes |
| Basic blocks | 36 |
| Convention | `__thiscall` (ECX = `this`) |

**Vptr transitions (3 writes to [EDI+0x00]):**

| VA | Instruction | Raw Bytes | Value | Meaning |
|----|-------------|-----------|-------|---------|
| 0x43E1B1 | `MOV [EDI], 0x51FFB4` | C7 03 B4 FF 51 00 | 0x0051FFB4 | Initial vptr = Table A slot 2 |
| 0x43E4C8 | `MOV [EDI], 0x51E570` | C7 03 70 E5 51 00 | 0x0051E570 | Intermediate vptr = Table B |
| 0x43E4E8 | `MOV [EDI], 0x51E4F0` | C7 03 F0 E4 51 00 | 0x0051E4F0 | Final vptr = Table C |

**Subobject vtable writes:**

| VA | Offset | Value | Subobject |
|----|--------|-------|-----------|
| 0x43E1B7 | +0x38 | 0x520014 | Subobject A |
| 0x43E1BE | +0x40 | 0x520020 | Subobject B |
| 0x43E1C5 | +0x50 | 0x520034 | Subobject C |
| 0x43E1CC | +0x98 | 0x520050 | Subobject D |
| 0x43E1D6 | +0x9C | 0x5200E8 | Subobject E |

**Subobject vtable overwrites (during construction phase 2):**

| VA | Offset | Value |
|----|--------|-------|
| 0x43E49A | +0x9C | 0x51E7F8 |
| 0x43E4A4 | +0x98 | 0x51E810 |
| 0x43E4AE | +0x38 | 0x51BE00 |
| 0x43E4B5 | +0x40 | 0x51BE0C |
| 0x43E4BC | +0x50 | 0x51BE20 |

**Initialization extent:** Fields initialized up to offset 0x5C40. Zeroing loop covers 0x0C–0x4C4.

### FUN_0043ECF0 (0x43ECF0) — Constructor Wrapper

| Property | Value |
|----------|-------|
| Address | 0x0043ECF0 |
| Size | 36 bytes |
| Convention | `__thiscall` (ECX = `this`), returns EAX = `this` |

**Disassembly:**

| VA | Instruction | Raw Bytes |
|----|-------------|-----------|
| 0x43ECF0 | `PUSH EBP; MOV EBP, ESP; PUSH ESI; MOV ESI, ECX` | 55 8B EC 56 8B F1 |
| 0x43ECF6 | `CALL 0x0043E1A0` | E8 0B F2 FC 00 |
| 0x43ECFB | `TEST byte ptr [EBP+0x8], 0x1` | F6 45 08 01 |
| 0x43ECFF | `JZ 0x0043EF0D` | 74 14 |
| 0x43ED01 | `PUSH 0x6108` | 68 08 61 00 00 |
| 0x43ED06 | `PUSH ESI` | 56 |
| 0x43ED07 | `CALL 0x004E6CD7` | E8 28 9E 00 00 |
| 0x43ED0C | `ADD ESP, 0x8` | 83 C4 08 |
| 0x43ED0F | `MOV EAX, ESI` | 8B C6 |
| 0x43ED11 | `POP ESI` | 5E |
| 0x43ED12 | `POP EBP` | 5D |
| 0x43ED13 | `RET 0x4` | C2 04 00 |

**Behavior:** Calls FUN_0043E1A0, then if the low bit of the first stack argument is set, calls FUN_004E6CD7(this) (destruction wrapper — unusual for a constructor; suggests conditional cleanup path).

## 2. Adjustment Thunks (5)

| VA | Disassembly | Raw Bytes | Adjusts ECX by | Target |
|----|-------------|-----------|----------------|--------|
| 0x43E85E | `SUB ECX, 0x38; JMP 0x0043ECF0` | 83 E9 38 E9 8A 04 00 00 | -0x38 | FUN_0043ECF0 |
| 0x43E866 | `SUB ECX, 0x40; JMP 0x0043ECF0` | 83 E9 40 E9 80 04 00 00 | -0x40 | FUN_0043ECF0 |
| 0x43E86E | `SUB ECX, 0x50; JMP 0x0043ECF0` | 83 E9 50 E9 7A 04 00 00 | -0x50 | FUN_0043ECF0 |
| 0x43E876 | `SUB ECX, 0x98; JMP 0x0043ECF0` | 83 E9 98 E9 70 04 00 00 | -0x98 | FUN_0043ECF0 |
| 0x43E881 | `SUB ECX, 0x9C; JMP 0x0043ECF0` | 83 E9 9C E9 6A 04 00 00 | -0x9C | FUN_0043ECF0 |

**Purpose:** Multiple inheritance adjustment thunks. When a subobject pointer (at offsets 0x38, 0x40, 0x50, 0x98, 0x9C) is used as `this`, the thunk subtracts the subobject offset to recover the main object pointer, then calls FUN_0043ECF0.

## 3. Caller Analysis

| Function | Callers Found | Caller Type |
|----------|---------------|-------------|
| FUN_0043E1A0 | FUN_0043ECF0 only | Direct call |
| FUN_0043ECF0 | 5 adjustment thunks (0x43E85E–0x43E881) | Direct calls |
| Thunk 0x43E85E | None | No callers |
| Thunk 0x43E866 | None | No callers |
| Thunk 0x43E86E | None | No callers |
| Thunk 0x43E876 | None | No callers |
| Thunk 0x43E881 | None | No callers |

**Conclusion:** The entire construction chain (FUN_0043ECF0 → FUN_0043E1A0, called only by 5 thunks) has **no identified external callers**. The adjustment thunks are unreachable from any known caller.

## 4. Sub-Initializers Called by Constructor (12)

| Address | Name | Status |
|---------|------|--------|
| 0x43E100 | FUN_0043E100 | Zeroing loop (analyzed) |
| 0x47A8A0 | FUN_0047A8A0 | Not analyzed |
| 0x43E500 | FUN_0043E500 | Not analyzed |
| 0x403540 | FUN_00403540 | Not analyzed |
| 0x4728E0 | FUN_004728E0 | Not analyzed |
| 0x483750 | FUN_00483750 | Not analyzed |
| 0x43E680 | FUN_0043E680 | Not analyzed |
| 0x47BB20 | FUN_0047BB20 | Not analyzed |
| 0x475B70 | FUN_00475B70 | Not analyzed |
| 0x479240 | FUN_00479240 | Not analyzed |
| 0x4E70A5 | FUN_004E70A5 | Not analyzed |
| 0x43A9A0 | FUN_0043A9A0 | ANALYZED (list cleanup with CUniversalString) |
| 0x4E7EC0 | FUN_004E7EC0 | ANALYZED (5-byte thunk → FUN_004ec736) |

## 5. Allocator Imports

| DLL | Function | IAT RVA | Role |
|-----|----------|---------|------|
| KERNEL32.dll | HeapAlloc | 0x11941e | Heap allocation |
| KERNEL32.dll | HeapFree | 0x11942a | Heap deallocation |
| KERNEL32.dll | HeapReAlloc | 0x119436 | Heap reallocation |
| KERNEL32.dll | HeapSize | 0x11959c | Query heap block size |
| KERNEL32.dll | GetProcessHeap | 0x11957a | Get process heap handle |
| RvROLClient.dll | RolClient_AllocMemory | 0x1199c0 | Custom ROL allocation |
| RvROLClient.dll | RolClient_FreeMemory | 0x11998c | Custom ROL deallocation |
| ole32.dll | CoTaskMemFree | 0x119942 | COM task memory free |
| KERNEL32.dll | LocalFree | 0x117cd4 | Local memory free |

**No `malloc`, `operator new`, `CoTaskMemAlloc`, or `VirtualAlloc` found** in the import directory.

## 6. Allocation Site — UNRESOLVED

Despite finding allocator APIs, **no direct call to `HeapAlloc` or `RolClient_AllocMemory` was found in**:
- FUN_0043E1A0 (constructor)
- FUN_0043ECF0 (constructor wrapper)
- Any of the 5 adjustment thunks
- Any of the 12 sub-initializers

**Possible explanations (all unverified):**

1. **Object is stack-allocated or embedded in a parent object** — The caller allocates space and passes `this` via ECX. No heap allocation in the constructor itself.

2. **Object is allocated by a factory function** not yet identified — A separate function calls `HeapAlloc` then calls the constructor. This factory function has not been found in the call graph.

3. **Object is allocated via `RolClient_AllocMemory`** from RvROLClient.dll — Custom allocator in the ROL client library. The constructor does not call it directly.

4. **Object is globally allocated** — A global/static object instance exists in `.data` or `.bss`, and the constructor initializes it in place.

## 7. Object Size — UNKNOWN

No `HeapAlloc` call with a size argument was found in the constructor or any analyzed function. The constructor initializes fields up to offset 0x5C40 (23,744 bytes).

**Minimum initialized extent:** 0x5C40 bytes (~23 KB)
**Actual allocation size:** UNKNOWN
**Confirmed object size:** UNKNOWN

## 8. Confidence Classification

| Question | Classification | Basis |
|----------|---------------|-------|
| Constructor vptr transitions | CONFIRMED | Raw bytes verified at 3 addresses |
| Adjustment thunks exist | CONFIRMED | Raw bytes verified at 5 addresses |
| Constructor call chain | CONFIRMED | Ghidra call graph |
| External callers of thunks | NONE FOUND | Ghidra procedure_callers |
| Allocator APIs imported | CONFIRMED | PE import table |
| Object allocation call site | UNKNOWN | No HeapAlloc/RolClientAllocMemory call found |
| Object actual size | UNKNOWN | No allocation size argument observed |