# Phase 2.5 Stage 12 — Allocation and Factory Call Graph

**Classification: STRONGLY SUPPORTED (allocation side absent) / UNKNOWN (allocation site)** — all allocator APIs are imported; none are called in the constructor path; no factory function identified; allocation site remains UNKNOWN.

Cross-reference: `05_VTABLE_TRANSITION_AND_CONSTRUCTOR_ANALYSIS.md`, `11_OBJECT_FIELD_AND_SUBOBJECT_LAYOUT.md`, `14_DESTRUCTION_AND_DEALLOCATION_ANALYSIS.md`, `15_COMPLETE_OBJECT_LIFECYCLE_RECONSTRUCTION.md`.

---

## 1. Allocator Imports (verified from PE import table)

| DLL | Function | Role | IAT referenced? | Call found in object path? |
|-----|----------|------|-----------------|---------------------------|
| KERNEL32.dll | `HeapAlloc` | Heap allocation | Yes (IAT) | **No** |
| KERNEL32.dll | `HeapFree` | Heap deallocation | Yes (IAT) | Indirectly via `0x00500CA6` (unconfirmed identity) |
| KERNEL32.dll | `HeapReAlloc` | Heap reallocation | Yes (IAT) | **No** |
| KERNEL32.dll | `HeapSize` | Query block size | Yes (IAT) | **No** |
| KERNEL32.dll | `GetProcessHeap` | Process heap handle | Yes (IAT) | **No** |
| RvROLClient.dll | `RolClient_AllocMemory` | Custom ROL allocation | Yes (IAT) | **No** |
| RvROLClient.dll | `RolClient_FreeMemory` | Custom ROL deallocation | Yes (IAT) | Indirectly via `0x00500CA6` (unconfirmed identity) |
| ole32.dll | `CoTaskMemFree` | COM task memory free | Yes (IAT) | **No** |
| KERNEL32.dll | `LocalFree` | Local memory free | Yes (IAT) | **No** |

**Not imported:** `malloc`, `operator new`, `CoTaskMemAlloc`, `VirtualAlloc`, `LocalAlloc`, `HeapCreate`, `HeapDestroy`.

IAT entry addresses (from import directory parsing, `.rdata`):
- `HeapAlloc` IAT RVA `0x11941e`, `HeapFree` `0x11942a`, `HeapReAlloc` `0x119436`, `HeapSize` `0x11959c`, `GetProcessHeap` `0x11957a`, `RolClient_AllocMemory` `0x1199c0`, `RolClient_FreeMemory` `0x11998c`, `CoTaskMemFree` `0x119942`, `LocalFree` `0x117cd4` (per Phase 2.4 report `04`, VA = RVA + 0x400000).

---

## 2. Allocation Call-Site Search Results

The following functions were disassembled/inspected and contain **no** call to `HeapAlloc`, `GetProcessHeap`, `RolClient_AllocMemory`, or any wrapper:

| Function | VA | Role | Allocation call? |
|----------|-----|------|------------------|
| `FUN_0043E1A0` | `0x43E1A0` | Primary constructor | **No** |
| `FUN_0043ECF0` | `0x43ECF0` | Constructor wrapper | **No** |
| Thunk `0x43E85E` | `0x43E85E` | adjust −0x38 | **No** |
| Thunk `0x43E866` | `0x43E866` | adjust −0x40 | **No** |
| Thunk `0x43E86E` | `0x43E86E` | adjust −0x50 | **No** |
| Thunk `0x43E876` | `0x43E76` | adjust −0x98 | **No** |
| Thunk `0x43E881` | `0x43E881` | adjust −0x9C | **No** |
| Sub-initializer `FUN_0043E100` | `0x43E100` | Zeroing loop | **No** |

No function in the constructor/allocation chain calls any allocator. The constructor receives `this` via ECX (caller supplies storage).

---

## 3. Candidate Allocation Mechanisms (all unconfirmed)

| Mechanism | Plausibility | Evidence |
|-----------|--------------|----------|
| Stack allocation / caller-supplied storage | LIKELY | Constructor takes `this` in ECX and does not allocate; caller must provide storage. Caller not identified. |
| Embedded in a parent object | POSSIBLE | No parent-object relationship evidenced. |
| Factory function (HeapAlloc then ctor) | POSSIBLE | No factory found in call graph; factory may be unanalyzed/unreferenced. |
| `RolClient_AllocMemory` factory | POSSIBLE | Custom allocator imported but no call site found. |
| Global/static object (in-place init) | POSSIBLE | No global object initialization found. |
| Object pool | UNKNOWN | No pool evidenced. |

**No definitive allocation call site for the target object was found.** This remains the primary blocker (Report 02, R16).

---

## 4. Factory / Creator Functions

No factory function was identified. The construction chain (`FUN_0043ECF0` → `FUN_0043E1A0`, called only by 5 unreachable adjustment thunks) has no external caller. Therefore:

- **Constructor reachability:** The constructor is statically unreachable from any known entry point.
- **First virtual call:** `FUN_0044F3F0` (indirect dispatch) has no direct callers; reachable only if an object with the right vptr is constructed and passed to it — but nothing constructs or calls it.
- **Object publication:** None identified.

---

## 5. Object Size

| Estimate | Value | Basis | Confidence |
|----------|-------|-------|------------|
| Minimum initialized extent | `0x5C40` bytes (~23,264) | Constructor initializes through `0x5C40` | CONFIRMED |
| Zeroing loop range | `0x0C`–`0x4C4` | `FUN_0043E100` | CONFIRMED |
| Reported size ~`0x5C44` | `0x5C44` | Phase 2.4 Report 17 | UNVERIFIED |
| Actual allocation size | UNKNOWN | No `HeapAlloc(size)`/`RolClient_AllocMemory(size)` call found | UNKNOWN |

The highest initialized field offset (`0x5C40`) is **not** the allocation size. Actual size cannot be recovered without the allocation call site.

---

## 6. Deallocation Side (for symmetry comparison)

| Aspect | Finding |
|--------|---------|
| Deallocation chain | `FUN_004e6cd7` → thunk `0x4E7EC0` → `FUN_004ec736` → `CALL 0x00500CA6` (direct) |
| Final target | Function `0x00500CA6` (code in `.text`), identity unknown (likely `HeapFree` or `RolClient_FreeMemory`, HYPOTHESIS) |
| Allocator/free pairing | Cannot confirm — allocation side absent, deallocation target identity unconfirmed |
| Symmetry | UNKNOWN |

`CoTaskMemFree`/`LocalFree` are imported but their allocators (`CoTaskMemAlloc`/`LocalAlloc`) are **not** imported → those are asymmetric (not a pair). `HeapAlloc`/`HeapFree` and `RolClient_AllocMemory`/`RolClient_FreeMemory` are symmetric pairs, but neither allocation call was found in the object path.

---

## 7. Constructor Failure / Partial Initialization

No failure path or rollback/cleanup-on-failure was found in `FUN_0043E1A0` (straight-line initialization through `0x5C40`, no observed branch to cleanup). Constructor failure behavior UNKNOWN.

---

## 8. Confidence Summary

| Question | Classification |
|----------|----------------|
| Allocator APIs imported | CONFIRMED (PE import table) |
| Allocation call in constructor path | CONFIRMED ABSENCE (analyzed) |
| Factory function identified | NOT FOUND |
| Constructor reachable from known caller | CONFIRMED NO (only 5 unreachable thunks) |
| Allocation site | UNKNOWN (primary blocker) |
| Object allocation size | UNKNOWN |
| Allocation/deallocation symmetry | UNKNOWN |
| Most plausible allocation mechanism | LIKELY: caller-supplied storage (stack/embedded), since ctor takes `this` in ECX and does not allocate |
