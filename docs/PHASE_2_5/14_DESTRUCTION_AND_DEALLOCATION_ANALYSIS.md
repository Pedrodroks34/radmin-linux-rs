# Phase 2.5 Stage 14 — Destruction and Deallocation Analysis

**Classification: STRONGLY SUPPORTED / PARTIALLY CORRECTED** — the destruction chain is verified through `FUN_004ec736` → direct `CALL 0x00500CA6`; `FUN_00473210` is confirmed as atomic teardown (not decrement); the final free routine's identity remains unknown.

Cross-reference: `07_INDIRECT_DEALLOCATION_CALL_CHAIN.md`, `08_FUN_00473210_COMPLETE_ANALYSIS.md`, `09_FUN_004731E0_AND_REFERENCE_COUNT_PAIRING.md`, `15_COMPLETE_OBJECT_LIFECYCLE_RECONSTRUCTION.md`.

---

## 1. Destruction Chain (verified disassembly)

```
FUN_004731E0 (Release, VA 0x4731E0)
  LOCK XCHG [obj+0x20], 0   -> old count in ESI
  if (old != 0):
    FUN_00473210 (teardown, VA 0x473210)
      CALL 0x00489750 ([obj+0x8])
      XCHG [obj+0x20], 0    (atomic, implicit LOCK)
      XCHG [obj+0x24], 1    (atomic, implicit LOCK)
  SetLastError(restore)
```

Then, per Phase 2.4's verified list-cleanup path (Report 07 and Phase 2.4 Report 07):

```
5 list-cleanup functions
  └─ per node: FUN_004e6cd7 (VA 0x4E6CD7)
       PUSH [EBP+8]; CALL 0x4E7EC0
  └─ thunk 0x4E7EC0 (VA 0x4E7EC0)
       JMP 0x4EC736
  └─ FUN_004ec736 (VA 0x4EC736)
       ...; CALL 0x00500CA6   (DIRECT relative call, not indirect)
  └─ function 0x00500CA6 (code in .text)
       frees memory; references IAT [0x5192EC], [0x519280]; data [0x5581E8]
```

All steps verified by raw bytes (Reports 07, 08).

---

## 2. Destructor Candidates

| Candidate | VA | Role | Evidence | Confidence |
|-----------|-----|------|----------|------------|
| `FUN_0043F110` | `0x43F110` | Table C slot 0 | `55 8B EC F6 45 08` — tests stack-arg bit (scalar deleting destructor pattern: `if (arg) delete this`). Table C is the final vptr. | STRONGLY SUPPORTED (scalar deleting destructor pattern) |
| `FUN_0043EED0` | `0x43EED0` | Table B slot 0 | `55 8B EC 56 8B F1` prologue only; body not fully analyzed. | LIKELY (destructor, intermediate table) |
| Table A slot 0 | `0x51FFB4` → `0x0043ECF0` | `0x0043ECF0` is the **constructor wrapper** | Unusual — slot 0 of Table A points to constructor wrapper, not a destructor. Suggests Table A is not a conventional vtable or slot-0 semantics differ. | CONFIRMED (value is constructor wrapper) |
| `FUN_00473210` | `0x473210` | Teardown (not destructor per se) | Atomic XCHG of `+0x20`=0 and `+0x24`=1; helper `0x489750`. No branch/destroy. | PROVEN (teardown) |
| `0x00500CA6` | `0x500CA6` | Final free routine | Function prologue; called directly by `FUN_004ec736`; frees memory. | STRONGLY SUPPORTED (free routine) |

No separate "deleting destructor" distinct from `FUN_0043F110` confirmed. `FUN_0043F110`'s stack-arg-bit test is consistent with scalar deleting destructor, but body not fully disassembled (follow-up).

---

## 3. Reference-Count Zero Path

Per verified `FUN_004731E0`:
1. `LOCK XCHG [obj+0x20], 0` — atomically take counter to 0, get old value.
2. If old == 0: **skip teardown** (JZ). Object already torn down / no references — idempotent release.
3. If old != 0: call `FUN_00473210` (teardown) — zeroes `+0x20` again (idempotent), sets `+0x24`=1, calls helper `0x489750` on `+0x8`.
4. Restore last error, return.

**This is NOT "decrement-then-destroy-if-zero."** It is "exchange-to-zero, then teardown if there was anything to tear down." The object is freed once (the exchange makes subsequent releases no-ops).

**Confidence:** PROVEN for the mechanism; the actual memory-free (which function frees the object block itself vs. list nodes) is not separately confirmed beyond `0x500CA6` freeing nodes.

---

## 4. Cleanup Operations

| Operation | Function | VA | Verified? |
|-----------|----------|-----|-----------|
| Counter taken to 0 (atomic) | `FUN_004731E0` | `0x4731E0` | PROVEN |
| Teardown: XCHG `+0x20`=0 | `FUN_00473210` | `0x473210` | PROVEN |
| Teardown: XCHG `+0x24`=1 | `FUN_00473210` | `0x473210` | PROVEN |
| Helper on `+0x8` | `0x00489750` (called by `FUN_00473210`) | `0x489750` | CALLED (body not analyzed) |
| List cleanup (×5 functions) | Phase 2.4 Report 07 | — | CONFIRMED (inherited) |
| Per-node destroy | `FUN_004e6cd7` | `0x4E6CD7` | PROVEN |
| Thunk to free | `0x4E7EC0` | `0x4E7EC0` | PROVEN |
| Free routine | `0x00500CA6` | `0x500CA6` | PROVEN (as function) |
| Object block free | NOT separately confirmed | — | UNKNOWN |

---

## 5. Deallocation Mechanism and Allocator Symmetry

| Pair | Allocation | Deallocation | Symmetric? |
|------|-----------|-------------|------------|
| `HeapAlloc` / `HeapFree` | Not found in object path | `0x00500CA6` may be `HeapFree` (unconfirmed) | UNKNOWN |
| `RolClient_AllocMemory` / `RolClient_FreeMemory` | Not found | `0x00500CA6` may be `RolClient_FreeMemory` (unconfirmed) | UNKNOWN |
| `CoTaskMemAlloc` / `CoTaskMemFree` | `CoTaskMemAlloc` NOT imported | `CoTaskMemFree` imported | ASYMMETRIC |
| `LocalAlloc` / `LocalFree` | `LocalAlloc` NOT imported | `LocalFree` imported | ASYMMETRIC |

**Symmetry cannot be confirmed** because the allocation side is entirely absent from the analyzed code (no `HeapAlloc`/`RolClient_AllocMemory` call in constructor path). The deallocation side reaches function `0x00500CA6` which consumes imports `[0x5192EC]`, `[0x519280]` and data `[0x5581E8]`, but which allocator it belongs to is unknown.

---

## 6. What Frees the Object Block vs. List Nodes

- The destruction chain via `FUN_004e6cd7`/`0x4E7EC0`/`0x4EC736`/`0x500CA6` originates from the **5 list-cleanup functions** (per-node destruction per Phase 2.4). So `0x500CA6` most likely frees **list nodes**.
- The **parent ObjectCandidate block's own free** is not separately confirmed. `FUN_00473210` teardown does not itself call a free (it zeroes fields and calls helper `0x489750`). The parent block free may be inside helper `0x00489750` or elsewhere — UNRESOLVED.

---

## 7. Destructor-Time Vptr Transitions

No writes to the object's primary vptr field (`[this+0x0]`) were found in the destruction path (`FUN_004731E0` → `FUN_00473210` → cleanup → `FUN_004e6cd7`). So:
- No destruction-time vptr transition is evidenced.
- The object's vptr is whatever it was at construction's final state (`0x0051E4F0` / Table C) when destroyed.

---

## 8. Confidence Summary

| Question | Classification |
|----------|----------------|
| Destruction chain through `0x4EC736` → `0x500CA6` | STRONGLY SUPPORTED |
| Final call is DIRECT `CALL 0x500CA6` (not indirect `[mem]`) | PROVEN |
| `0x500CA6` is a free routine (code, not IAT) | STRONGLY SUPPORTED |
| `FUN_00473210` = atomic teardown (not decrement) | PROVEN |
| Release = exchange-to-zero + conditional teardown | PROVEN |
| Object freed exactly once | LIKELY (exchange-to-zero makes release idempotent) |
| Final free routine identity (`HeapFree` vs `RolClient_FreeMemory`) | UNKNOWN |
| Parent object block free location | UNKNOWN (may be helper `0x489750`) |
| Destruction-time vptr transition | CONFIRMED ABSENCE (none in path) |
| Allocation/deallocation symmetry | UNKNOWN |
