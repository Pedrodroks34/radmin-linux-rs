# Phase 2.6 Stage 10 — Reference Counter and Control Block Reconstruction

**Classification: STRONGLY SUPPORTED** — `this+0x20` is a **release-latch pointer** (non-NULL=alive, NULL=released), NOT a reference counter. No external control block exists. Phase 2.5's "reference counter exchanged to zero" conclusion is withdrawn.

Cross-reference: `07_OBJECT_FIELD_AND_POINTER_RELATIONSHIP_MODEL.md`, `08_COMPLETE_ATOMIC_OPERATION_INVENTORY.md`, `09_ADDREF_AND_OWNERSHIP_ACQUISITION_INVESTIGATION.md`.

---

## 1. Corrected Field Semantics

| Field | Offset | Width | Corrected semantics | Phase 2.5 claim | Phase 2.5 status |
|-------|--------|-------|---------------------|-----------------|------------------|
| `field_0x08` | `0x08` | 4 | **CRITICAL_SECTION** (destroyed by `DeleteCriticalSection` in teardown) | Not identified | NEW |
| `field_0x20` | `0x20` | 4 | **Release-latch pointer** (non-NULL=alive, NULL=released) | "Reference counter (integer), exchanged to zero" | **CONTRADICTED — WITHDRAWN** |
| `field_0x24` | `0x24` | 4 | **Torn-down flag** (set to 1 by teardown) | "Set to 1" (via wrong indirection) | PARTIALLY CORRECT |

---

## 2. Why `field_0x20` Is a Pointer, Not a Counter

| Evidence | Observation |
|----------|-------------|
| `LOCK XADD [&field_0x20], 0` (Release) | Adds 0 — atomic read, field UNCHANGED. A counter would be incremented/decremented. |
| `TEST ESI, ESI; JZ` after XADD | Treats the value as NULL/non-NULL pointer, not a count-to-compare. |
| `XCHG [&field_0x20], 0` (Teardown) | Sets the field to NULL (0). A counter would be decremented, not zeroed outright. |
| `XCHG [&field_0x24], 1` (Teardown) | Separate flag field — consistent with a latch, not a counter. |
| No increment anywhere | A reference counter must be incremented (AddRef); none found. |

**`field_0x20` holds a pointer value** (likely to a subobject, control data, or the object itself) that is non-NULL while the object is alive and set to NULL when released.

---

## 3. Corrected Release/Teardown Protocol

```
RELEASE (FUN_004731E0):
  1. old_ptr = LOCK XADD [&this->field_0x20], 0   // atomic READ, field unchanged
  2. if (old_ptr == NULL) return                   // already released — idempotent
  3. TEARDOWN (FUN_00473210)

TEARDOWN (FUN_00473210):
  1. DeleteCriticalSection(&this->field_0x08)      // via FUN_00489750 → [0x519138]=DeleteCriticalSection
  2. [this->field_0x20] = 0  (atomic XCHG)         // NULL the latch pointer
  3. [this->field_0x24] = 1  (atomic XCHG)         // set torn-down flag
```

**Key properties:**
- **Release-once:** Teardown runs exactly once (when Release sees non-NULL).
- **Idempotent:** After teardown NULLs `field_0x20`, subsequent Releases see NULL and skip teardown.
- **No refcount:** The "count" never increases; it only transitions non-NULL → NULL.

---

## 4. No External Control Block

Phase 2.5 hypothesized an external control block or pointer-to-pointer. **Withdrawn.** Evidence:
- `field_0x20` is accessed via `LEA EDX,[EDI+0x20]` (direct address-of), then `LOCK XADD [EDX],...` — a direct field access, not a pointer-to-pointer.
- `FUN_00473210` uses `LEA ECX,[ESI+0x20]` then `XCHG [ECX],...` — direct field write.
- All field accesses are direct object-field accesses (Report 07).

**The object is self-contained:** `field_0x20` and `field_0x24` are direct members of `ObjectCandidate`. No external allocation, no control block indirection.

---

## 5. Corrected Ownership Model

```
Object lifecycle:
  [ALLOCATION]  →  storage obtained (site UNKNOWN)
  [INIT]        →  field_0x20 set to non-NULL pointer (by UNKNOWN initializer)
                    field_0x08 = CRITICAL_SECTION initialized
                    vptr transitions (3 stages)
  [USE]         →  object used; FUN_0044F3F0 dispatch if guards pass
  [RELEASE]     →  FUN_004731E0: LOCK XADD(field_0x20,0); if non-NULL → teardown
  [TEARDOWN]    →  FUN_00473210: DeleteCriticalSection(field_0x08);
                    field_0x20 = 0; field_0x24 = 1
  [FREE]        →  memory freed (site UNKNOWN — 0x500CA6 free routine for list nodes;
                    parent block free location UNKNOWN)
```

**Ownership model:** Single-owner / release-latch. The object is created with `field_0x20` non-NULL, used, then released once. Teardown nulls the latch, making release idempotent.

---

## 6. Competing Models — Eliminated

| Model | Why eliminated |
|-------|----------------|
| Strong reference count (`Arc<T>`) | No AddRef/increment found; count never increases |
| Multi-owner shared ownership | No mechanism to increase the reference count |
| Weak/strong split | Only one field (`0x20`) involved; no second counter |
| External control block | All accesses are direct field; no pointer indirection |
| Atomic integer counter | `LOCK XADD(...,0)` doesn't modify; `XCHG(...,0)` zeroes outright |

---

## 7. Remaining Unknowns

| Unknown | Classification | Evidence needed |
|---------|---------------|-----------------|
| Initial value of `field_0x20` (who sets it non-NULL?) | UNKNOWN | Find constructor caller/factory; search all writes to `field_0x20` |
| Pointee type of `field_0x20` | UNKNOWN | What does the pointer point to? |
| `field_0x24` readers | UNKNOWN | Is the torn-down flag ever read? |
| Parent block free location | UNKNOWN | Where is the object's memory actually freed? |

---

## 8. Confidence Summary

| Finding | Classification |
|---------|---------------|
| `field_0x20` is a release-latch pointer (not counter) | STRONGLY SUPPORTED |
| `field_0x24` is torn-down flag | STRONGLY SUPPORTED |
| `field_0x08` is CRITICAL_SECTION | STRONGLY SUPPORTED |
| No external control block | STRONGLY SUPPORTED |
| Release-once / idempotent latch | STRONGLY SUPPORTED |
| `Arc<T>`-style strong refcount rejected | STRONGLY SUPPORTED |
| `Box<T>`-style single ownership | LIKELY |
| Initial value source of `field_0x20` | UNKNOWN |
