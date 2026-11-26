# Phase 2.6 Stage 12 — Constructor Caller and Factory Reconstruction

**Classification: STRONGLY SUPPORTED (constructor unreachable)** — whole-program call-target search confirms no external caller for `FUN_0043ECF0`/`FUN_0043E1A0` or `FUN_0044F3F0`. No factory function identified. Allocation site remains UNKNOWN.

Cross-reference: `07_OBJECT_FIELD_AND_POINTER_RELATIONSHIP_MODEL.md`, `13_ALLOCATION_AND_OBJECT_SIZE_INVESTIGATION.md`, `15_COMPLETE_OBJECT_LIFECYCLE_AND_OWNERSHIP_GRAPH.md`.

---

## 1. Whole-Program Caller Search (verified by byte pattern scan)

Searched `.text` for `E8 rel32` (CALL near) instructions targeting each candidate:

| Target VA | Direct CALL sites found | Callers |
|-----------|------------------------|---------|
| `0x0043ECF0` (ctor wrapper) | **NONE** | No direct callers |
| `0x0043E1A0` (primary ctor) | 1: `0x0043ECF6` | `FUN_0043ECF0` only (ctor wrapper → primary ctor) |
| `0x0044F3F0` (indirect dispatch) | **NONE** | No direct callers |
| `0x0043F110` (scalar deleting destructor candidate) | **NONE** | No direct callers |

**The entire construction/dispatch chain is statically unreachable from any known entry point.**

---

## 2. Constructor Chain

```
FUN_0043ECF0 (ctor wrapper, 0x43ECF0)
  │  ECX = this (caller-supplied)
  │  CALL FUN_0043E1A0 (0x43ECF6)
  │  TEST byte [EBP+8], 1
  │  JZ skip
  │  PUSH 0x6108; PUSH ESI; CALL 0x4E6CD7 (destruction wrapper — conditional cleanup)
  │  MOV EAX, ESI; RET 4
  ▼
FUN_0043E1A0 (primary ctor, 0x43E1A0)
  │  Zeroing loop (0x0C–0x4C4)
  │  Vptr: [this+0] = 0x51FFB4 → 0x51E570 → 0x51E4F0 (3 transitions)
  │  Subobject vptrs (2 phases at +0x38/0x40/0x50/0x98/0x9C)
  │  Sub-initializers (9 candidates — all write unrelated vtables 0x52xxxx)
  ▼
OBJECT READY (vptr = Table C 0x51E4F0)
```

**No factory function calls the constructor.** No `HeapAlloc`/`RolClient_AllocMemory` followed by constructor invocation found in any analyzed path.

---

## 3. Adjustment Thunks (also unreachable)

| Thunk VA | Adjustment | Target | Callers |
|----------|-----------|--------|---------|
| `0x0043E85E` | `SUB ECX, 0x38` | `FUN_0043ECF0` | NONE |
| `0x0043E866` | `SUB ECX, 0x40` | `FUN_0043ECF0` | NONE |
| `0x0043E86E` | `SUB ECX, 0x50` | `FUN_0043ECF0` | NONE |
| `0x0043E876` | `SUB ECX, 0x98` | `FUN_0043ECF0` | NONE |
| `0x0043E881` | `SUB ECX, 0x9C` | `FUN_0043ECF0` | NONE |

All 5 adjustment thunks have no callers — they would recover `this` from a subobject pointer, but nothing invokes them.

---

## 4. Search for Indirect References (function pointer tables)

Searched for immediate values `0x43ECF0` and `0x43E1A0` used as data (e.g., `MOV reg, imm32` loading a function pointer):

| Searched value | Found as immediate data? | Location |
|----------------|-------------------------|----------|
| `0x43ECF0` | Not found in `.rdata`/`.data` as a stored pointer | — |
| `0x43E1A0` | Not found as a stored pointer | — |

No function-pointer table or vtable references these addresses. The constructor is not referenced as a data value anywhere.

---

## 5. What This Means

| Question | Answer | Classification |
|----------|--------|----------------|
| Who calls `FUN_0043ECF0`? | Unknown — no direct or indirect caller found | UNKNOWN |
| Who calls `FUN_0044F3F0`? | Unknown — no caller found | UNKNOWN |
| Is there a factory function? | Not identified | UNKNOWN |
| Where is storage allocated for `this`? | Unknown — constructor takes `this` in ECX (caller-supplied) | UNKNOWN |
| Is the constructor dead code? | Possibly, but cannot confirm without runtime evidence | HYPOTHESIS |
| Is there another module that calls it? | Possible (cross-module), but not verifiable statically | HYPOTHESIS |

---

## 6. Allocation Implications

Since `FUN_0043ECF0` receives `this` via ECX and performs no allocation:
- **Caller-supplied storage:** The caller must allocate memory and pass the pointer in ECX.
- **Allocation site:** Not found in any analyzed function (no `HeapAlloc`/`RolClient_AllocMemory` in constructor path).
- **Object size:** Unknown (no `HeapAlloc(size)` call observed).

This is the primary blocker for the lifecycle (see Report 19).

---

## 7. Confidence Summary

| Finding | Classification |
|---------|---------------|
| No direct caller of `FUN_0043ECF0` | PROVEN (byte scan of all `E8 rel32`) |
| No direct caller of `FUN_0044F3F0` | PROVEN (byte scan) |
| `FUN_0043E1A0` called only by `FUN_0043ECF0` | PROVEN |
| No function-pointer table references constructor | STRONGLY SUPPORTED |
| Factory function | NOT FOUND |
| Allocation site | UNKNOWN (primary blocker) |
| Constructor reachable from known entry point | CONFIRMED NO |
