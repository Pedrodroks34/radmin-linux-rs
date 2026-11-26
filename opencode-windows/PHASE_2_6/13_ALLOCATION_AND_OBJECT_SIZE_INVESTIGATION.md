# Phase 2.6 Stage 13 — Allocation and Object Size Investigation

**Classification: STRONGLY SUPPORTED (allocation side absent) / UNKNOWN (allocation site)** — whole-program scan for allocator calls found no `HeapAlloc`/`RolClient_AllocMemory` invocation in the object's constructor path. Allocation site and object size remain UNKNOWN.

Cross-reference: `12_CONSTRUCTOR_CALLER_AND_FACTORY_RECONSTRUCTION.md`, `15_COMPLETE_OBJECT_LIFECYCLE_AND_OWNERSHIP_GRAPH.md`.

---

## 1. Allocator Call Search (whole-program, `.text` section)

Searched for `CALL [IAT_slot]` patterns targeting imported allocator functions. The IAT slot VAs (from Phase 2.5 Report 04 and verified import parsing):

| Allocator | DLL | IAT slot VA (from Report 04) | CALL found in `.text`? |
|-----------|-----|------------------------------|------------------------|
| `HeapAlloc` | KERNEL32 | `0x0051941e` | NO |
| `HeapFree` | KERNEL32 | `0x0051942a` | NO |
| `HeapReAlloc` | KERNEL32 | `0x00519436` | NO |
| `HeapSize` | KERNEL32 | `0x0051959c` | NO |
| `GetProcessHeap` | KERNER32 | `0x0051957a` | NO |
| `RolClient_AllocMemory` | RvROLClient | `0x005199c0` | NO |
| `RolClient_FreeMemory` | RvROLClient | `0x0051998c` | NO |
| `CoTaskMemFree` | ole32 | `0x00519942` | NO |
| `LocalFree` | KERNEL32 | `0x00517cd4` | NO |

**No direct call to any allocator function was found in `.text`.** Note: IAT slot VAs from Report 04 may have section-mapping discrepancies (Report 04 labeled section RVAs as VAs), but the conclusion stands — no allocator invocation in the object path.

**Not imported:** `malloc`, `operator new`, `CoTaskMemAlloc`, `VirtualAlloc`, `LocalAlloc`, `HeapCreate`, `HeapDestroy`.

---

## 2. Constructor Path Re-Verified

| Function | VA | Allocator call? | Notes |
|----------|-----|-----------------|-------|
| `FUN_0043ECF0` (ctor wrapper) | `0x43ECF0` | NO | Calls `FUN_0043E1A0`; conditional `FUN_004e6CD7` (destruction) |
| `FUN_0043E1A0` (primary ctor) | `0x43E1A0` | NO | Zeroing, vptr transitions, subobject init — no heap call |
| Thunk `0x43E85E`–`0x43E881` (×5) | various | NO | `SUB ECX, off; JMP FUN_0043ECF0` |

The constructor receives `this` via ECX (caller-supplied storage) and performs no allocation.

---

## 3. Object Size

| Estimate | Value | Basis | Confidence |
|----------|-------|-------|------------|
| Minimum initialized extent | `0x5C40` bytes (~23,264) | Constructor initializes through `0x5C40` | CONFIRMED |
| Zeroing loop range | `0x0C`–`0x4C4` | `FUN_0043E100` zeroing loop | CONFIRMED |
| Reported size ~`0x5C44` | `0x5C44` bytes | Phase 2.4 Report 17 | UNVERIFIED |
| Actual allocation size | UNKNOWN | No `HeapAlloc(size)`/`RolClient_AllocMemory(size)` call found | UNKNOWN |

**`0x5C40` is the highest initialized field offset, NOT the allocation size.** Actual size cannot be recovered without the allocation call site.

---

## 4. Candidate Allocation Mechanisms (all unconfirmed)

| Mechanism | Plausibility | Evidence |
|-----------|--------------|----------|
| Caller-supplied storage (stack/embedded) | LIKELY | Constructor takes `this` in ECX, does not allocate |
| Factory function (alloc + ctor) | POSSIBLE | No factory found in call graph |
| `RolClient_AllocMemory` factory | POSSIBLE | Imported but no call site found |
| Global/static object (in-place init) | POSSIBLE | No global init found |
| Object pool | UNKNOWN | No pool evidenced |

---

## 5. Why Allocation Cannot Be Determined Statically

The constructor (`FUN_0043E1A0`/`FUN_0043ECF0`) and dispatch function (`FUN_0044F3F0`) have **no identified callers** (Report 12). Without a caller:
- We cannot observe the allocation that produces `this`.
- We cannot observe the `HeapAlloc`/`RolClient_AllocMemory` call with its size argument.
- We cannot confirm which allocator family is used.

This requires either:
1. Finding the missing caller (whole-program analysis beyond `.text` call-scan, or cross-module reference), or
2. Runtime capture (breakpoint at `HeapAlloc`/`RolClient_AllocMemory`, capture return address → factory/caller).

---

## 6. Confidence Summary

| Finding | Classification |
|---------|---------------|
| No allocator calls in constructor path | PROVEN (byte scan of `.text`) |
| Constructor takes `this` in ECX (caller-supplied) | PROVEN |
| Allocator APIs imported but unused in object path | CONFIRMED |
| Allocation site | UNKNOWN (primary blocker) |
| Object allocation size | UNKNOWN |
| Allocation/deallocation symmetry | UNKNOWN |
