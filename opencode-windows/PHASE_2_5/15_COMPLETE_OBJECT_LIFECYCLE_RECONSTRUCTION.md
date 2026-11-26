# Phase 2.5 Stage 15 — Complete Object Lifecycle Reconstruction

**Classification: STRONGLY SUPPORTED (partial)** — the construction/destruction/teardown mechanisms are verified, but the lifecycle is **incomplete**: the allocation site and the trigger that starts construction are unknown, and `FUN_0044F3F0` (indirect dispatch) has no identified caller. The unresolved edges are explicitly shown.

Cross-reference: `05_VTABLE_TRANSITION_AND_CONSTRUCTOR_ANALYSIS.md`, `11_OBJECT_FIELD_AND_SUBOBJECT_LAYOUT.md`, `12_ALLOCATION_AND_FACTORY_CALL_GRAPH.md`, `14_DESTRUCTION_AND_DEALLOCATION_ANALYSIS.md`.

---

## 1. Lifecycle State Model (reconstructed from evidence)

| Phase | What happens | Evidence | Confidence |
|-------|--------------|----------|------------|
| 1. Allocation | Storage obtained; `this` pointer produced | **NOT FOUND** — no `HeapAlloc`/`RolClient_AllocMemory`/factory call in any analyzed path | UNKNOWN |
| 2. Construction | `FUN_0043ECF0` → `FUN_0043E1A0` initializes object; zeroing loop `0x0C`–`0x4C4`; subobject vptrs phase 1 then phase 2 | CONFIRMED (raw bytes) | STRONGLY SUPPORTED |
| 2a. Vptr transition 1 | `MOV [this+0], 0x51FFB4` (Table A) | `0x43E1B1`, bytes verified | PROVEN |
| 2b. Vptr transition 2 | `MOV [this+0], 0x51E570` (Table B) | `0x43E4C8`, bytes verified | PROVEN |
| 2c. Vptr transition 3 | `MOV [this+0], 0x51E4F0` (Table C, final) | `0x43E4E8`, bytes verified | PROVEN |
| 2d. Subobject vptrs phase 1 | +0x38=`0x520014`, +0x40=`0x520020`, +0x50=`0x520034`, +0x98=`0x520050`, +0x9C=`0x5200E8` | 5 writes verified | PROVEN |
| 2e. Subobject vptrs phase 2 (overwrite) | +0x38=`0x51BE00`, +0x40=`0x51BE0C`, +0x50=`0x51BE20`, +0x98=`0x51E810`, +0x9C=`0x51E7F8` | 5 writes verified | PROVEN |
| 3. Ownership acquisition | Object published; refcount at `+0x20` set to initial value | **Initializer of `+0x20` not found** | UNKNOWN |
| 4. Additional references | AddRef / increment of `+0x20` | **NOT FOUND** anywhere | UNKNOWN (may be inlined/unanalyzed) |
| 5. Indirect dispatch | `FUN_0044F3F0` loads vptr, calls `[vptr+0x34]`/`[vptr+0x58]` if `+0x28==5 && +0x2C!=0`; increments `+0x30` | CONFIRMED instructions | STRONGLY SUPPORTED |
| 6. Reference release | `FUN_004731E0`: `LOCK XCHG [this+0x20],0`; if old!=0 → teardown | CONFIRMED disassembly | PROVEN |
| 7. Zero-count handling | old==0 → skip teardown (idempotent); old!=0 → `FUN_00473210` | CONFIRMED | PROVEN |
| 8. Teardown / destructor dispatch | `FUN_00473210`: helper `0x489750` on `+0x8`; XCHG `+0x20`=0; XCHG `+0x24`=1 | CONFIRMED disassembly | PROVEN |
| 9. Scalar deleting destructor | `FUN_0043F110` (Table C slot 0) suspected; body not fully analyzed | STRONGLY SUPPORTED pattern | LIKELY |
| 10. List-node deallocation | `FUN_004e6cd7` → thunk `0x4E7EC0` → `FUN_004ec736` → `CALL 0x00500CA6` (direct) | CONFIRMED | STRONGLY SUPPORTED |
| 11. Memory deallocation | Function `0x00500CA6` frees memory; identity unknown | STRONGLY SUPPORTED (as function) | STRONGLY SUPPORTED |
| 12. Parent object block free | **NOT CONFIRMED** — may be helper `0x489750` or elsewhere | — | UNKNOWN |

---

## 2. Call Graph (allocation → use → destruction)

```
[ALLOCATION SITE UNKNOWN] ─────────────►  (this pointer produced)
                                              │
                                              ▼
                           FUN_0043ECF0 (ctor wrapper, 0x43ECF0)
                                              │
                                              ▼
                           FUN_0043E1A0 (primary ctor, 0x43E1A0)
                                  ├─ zeroing loop 0x43E100
                                  ├─ sub-initializers (9 candidates, UNRELATED to ObjectCandidate)
                                  ├─ vptr: 0x51FFB4 → 0x51E570 → 0x51E4F0
                                  └─ subobject vptrs (2 phases)
                                              │
                                              ▼
                        [OBJECT READY; vptr = Table C 0x51E4F0]
                                              │
                                              │  (NO identified caller publishes/calls object)
                                              │
                                              ▼
                         FUN_0044F3F0 (indirect dispatch, 0x44F3F0)
                         [vptr load] guard(+0x28==5, +0x2C!=0)
                         CALL [vptr+0x34], CALL [vptr+0x58]; INC +0x30
                                              │
                                              ▼
                         FUN_004731E0 (Release, 0x4731E0)
                         LOCK XCHG [+0x20],0
                                              │
                     old==0 ─────────────────┴─────────────► skip teardown (idempotent)
                                              │
                     old!=0 ─────────────────┘
                                              ▼
                         FUN_00473210 (teardown, 0x473210)
                         helper 0x489750(+0x8); XCHG +0x20=0; XCHG +0x24=1
                                              │
                                              ▼
                         FUN_0043F110 (scalar deleting destructor?, Table C slot 0)
                                              │
                                              ▼
                         5 list-cleanup functions → per node:
                         FUN_004e6cd7 → thunk 0x4E7EC0 → FUN_004ec736
                                              │
                                              ▼
                         CALL 0x00500CA6 (DIRECT) → memory freed
                                              │
                                              ▼
                                        [DEALLOCATED]
```

**Unresolved edges (marked with gaps):**
1. Allocation site → `FUN_0043ECF0` (no caller of constructor found).
2. `FUN_0043ECF0` → object publication / first use (nothing calls constructor).
3. Object → `FUN_0044F3F0` (no caller of dispatch found).
4. `FUN_00473210` → parent object block free (teardown doesn't itself free the block).
5. AddRef / increment of `+0x20` (not found).

---

## 3. Ownership Model (reconstructed)

- **Reference counter** at `obj+0x20`, accessed atomically (`LOCK XCHG`).
- **Release** (`FUN_004731E0`) exchanges counter to 0 and tears down if old != 0. Idempotent (double-release is a no-op).
- **Teardown** (`FUN_00473210`) zeroes `+0x20`, sets `+0x24`=1, calls helper `0x489750` on `+0x8`.
- **No AddRef found** — the increment side of reference counting is absent from analyzed code. Object may be created with count 1 and released once (single ownership), or AddRef is inlined/in unanalyzed code.
- **Destruction** frees list nodes via `0x500CA6`; parent block free location unconfirmed.

**Ownership semantics:** Most consistent with a **single-ownership / release-latch** model rather than multi-owner strong reference counting, because the counter only goes to zero and is never incremented in analyzed code.

---

## 4. Lifecycle Reconstruction Status

| Element | Status | Blocker |
|---------|--------|---------|
| Allocation | UNKNOWN | No `HeapAlloc`/`RolClient_AllocMemory`/factory call; constructor takes `this` in ECX |
| Construction (vptr + subobjects) | PROVEN | All writes verified |
| Initial counter setup | UNKNOWN | No write to `+0x20` initializer found |
| AddRef / additional references | UNKNOWN | Not found |
| Indirect dispatch | STRONGLY SUPPORTED | Verified instructions; runtime-active vptr unknown (no caller) |
| Release | PROVEN | Verified disassembly |
| Teardown | PROVEN | Verified disassembly |
| Scalar deleting destructor | LIKELY | `FUN_0043F110` pattern; body not fully analyzed |
| List-node deallocation | STRONGLY SUPPORTED | Verified chain to `0x500CA6` |
| Parent block free | UNKNOWN | Not separately confirmed |
| Allocator/deallocator symmetry | UNKNOWN | Allocation side absent |

---

## 5. Why the Lifecycle Cannot Be Completed Statically

The constructor (`FUN_0043E1A0`/`FUN_0043ECF0`) and the dispatch function (`FUN_0044F3F0`) have **no identified callers**. Without a caller:
- We cannot observe the allocation that produces `this`.
- We cannot observe which vptr is active at dispatch time (runtime-only).
- We cannot confirm AddRef is ever called.

These are genuine runtime-only questions (or require identifying the missing caller via whole-program analysis), not resolvable by the static evidence available. Per Section 13, they are classified UNKNOWN / BLOCKED only where a specific static operation cannot be performed; here the blocker is the absence of any caller reference in the analyzed code, which is a real evidence gap, not a tool limitation.

---

## 6. Confidence Summary

| Lifecycle element | Classification |
|-------------------|----------------|
| Construction vptr transitions (3) | PROVEN |
| Subobject vptr 2-phase initialization | PROVEN |
| Release = exchange-to-zero + conditional teardown | PROVEN |
| Teardown = XCHG +0x20=0, +0x24=1 | PROVEN |
| List-node deallocation chain to `0x500CA6` | STRONGLY SUPPORTED |
| Allocation site | UNKNOWN |
| Initial counter value / setup | UNKNOWN |
| AddRef (increment) | NOT FOUND |
| Runtime-active vptr at dispatch | UNKNOWN |
| Parent object block free | UNKNOWN |
| Overall lifecycle completeness | INCOMPLETE (5 unresolved edges listed above) |
