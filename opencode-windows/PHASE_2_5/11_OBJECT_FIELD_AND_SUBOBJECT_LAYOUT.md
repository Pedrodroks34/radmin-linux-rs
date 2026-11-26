# Phase 2.5 Stage 11 — Object Field and Subobject Layout

**Classification: STRONGLY SUPPORTED (partial)** — all offsets and vptr writes verified by raw bytes; neutral names used; semantic roles are hypotheses. Layout is provisional pending an identified object base/allocation site.

Cross-reference: `03_VTABLE_ADDRESS_POINT_CORRECTION.md`, `05_VTABLE_TRANSITION_AND_CONSTRUCTOR_ANALYSIS.md`, `10_COMPLETE_REFERENCE_COUNT_ACCESS_INVENTORY.md`, `14_DESTRUCTION_AND_DEALLOCATION_ANALYSIS.md`, `15_COMPLETE_OBJECT_LIFECYCLE_RECONSTRUCTION.md`.

---

## 1. Naming Convention

Per Section 13, no C++ class names are invented. Neutral names:
- `ObjectCandidate` — the primary object (base pointer = `this`, vptr at `+0x00`).
- `Subobject_A` through `Subobject_E` — subobjects at vptr offsets `0x38`, `0x40`, `0x50`, `0x98`, `0x9C`.
- `ReferenceCounterCandidate` — `obj + 0x20` (atomic access).
- `TeardownFlagCandidate` — `obj + 0x24`.
- `StateCandidate` — `obj + 0x28` (compared to 5).
- `FlagCandidate` — `obj + 0x2C` (compared to 0).
- `CallCounterCandidate` — `obj + 0x30` (incremented).

---

## 2. Provisional Object Layout (ObjectCandidate)

| Offset | Width | Name | Verified writes | Verified reads | Confidence | Likely role |
|--------|-------|------|-----------------|----------------|------------|-------------|
| `0x00` | 4 | vptr (primary) | Constructor ×3: `0x51FFB4`, `0x51E570`, `0x51E4F0` | `FUN_0044F3F0` `MOV EAX,[EDI]` | PROVEN | Primary vtable pointer |
| `0x04` | 4 | field_0x04 | Constructor | None confirmed | VERIFIED | Subobject pointer (per Phase 2.4) |
| `0x0C`–`0x4C4` | — | zeroing region | `FUN_0043E100` zeroing loop | — | CONFIRMED | Zeroed during construction |
| `0x20` | 4 | ReferenceCounterCandidate | `FUN_004731E0` (XCHG=0), `FUN_00473210` (XCHG=0) | `FUN_004731E0` test old | STRONGLY SUPPORTED | Refcount / release latch (atomic) |
| `0x24` | 4 | TeardownFlagCandidate | `FUN_00473210` (XCHG=1) | None confirmed | HYPOTHESIS | Torn-down flag (atomic) |
| `0x28` | 4 | StateCandidate | None found in analyzed funcs | `FUN_0044F3F0` `CMP ...,5` | HYPOTHESIS | State (compared to 5) |
| `0x2C` | 4 | FlagCandidate | None found in analyzed funcs | `FUN_0044F3F0` `CMP ...,0` | HYPOTHESIS | Handle/flag (compared to 0) |
| `0x30` | 4 | CallCounterCandidate | `FUN_0044F3F0` `INC`; init-to-0 by `FUN_00410E80`/`FUN_00410F60` | None confirmed | STRONGLY SUPPORTED | Call counter |
| `0x38` | 4 | Subobject_A vptr | Constructor `0x520014`; overwrite `0x51BE00` | — | STRONGLY SUPPORTED | Subobject A vtable pointer |
| `0x40` | 4 | Subobject_B vptr | Constructor `0x520020`; overwrite `0x51BE0C` | — | STRONGLY SUPPORTED | Subobject B vtable pointer |
| `0x50` | 4 | Subobject_C vptr | Constructor `0x520034`; overwrite `0x51BE20` | — | STRONGLY SUPPORTED | Subobject C vtable pointer |
| `0x98` | 4 | Subobject_D vptr | Constructor `0x520050`; overwrite `0x51E810` | — | STRONGLY SUPPORTED | Subobject D vtable pointer |
| `0x9C` | 4 | Subobject_E vptr | Constructor `0x5200E8`; overwrite `0x51E7F8` | — | STRONGLY SUPPORTED | Subobject E vtable pointer |
| `0x5C40` | — | init extent | Constructor initializes through here | — | VERIFIED | Last initialized field offset |

**Important normalization:** A field accessed as `[EDI+0x20]` is the same logical field as `[ESI+0x20]` **only if** EDI and ESI refer to the same `ObjectCandidate`. In `FUN_004731E0`→`FUN_00473210`, EDI==ESI==this, so A2/A5 and A4/A5 all refer to `obj+0x20` of the same object. This is verified by the call convention (ECX=this passed through).

---

## 3. Subobject Layout

| Subobject | Vptr offset | Initial vptr value | Overwrite value | Confidence |
|-----------|-------------|-------------------|-----------------|------------|
| Subobject_A | +0x38 | `0x520014` | `0x51BE00` | STRONGLY SUPPORTED |
| Subobject_B | +0x40 | `0x520020` | `0x51BE0C` | STRONGLY SUPPORTED |
| Subobject_C | +0x50 | `0x520034` | `0x51BE20` | STRONGLY SUPPORTED |
| Subobject_D | +0x98 | `0x520050` | `0x51E810` | STRONGLY SUPPORTED |
| Subobject_E | +0x9C | `0x5200E8` | `0x51E7F8` | STRONGLY SUPPORTED |

Two-phase construction: subobject vptrs set in phase 1, then all five overwritten in phase 2 (constructor VAs `0x43E49A`–`0x43E4BC`). This is consistent with base-class-then-derived-class vtable binding in multiple inheritance.

All five subobject vptr values (`0x520014`, `0x520020`, `0x520034`, `0x520050`, `0x5200E8` initially) point into `.rdata` (RVA `0x120014`–`0x1200E8`) — valid vtable locations. Overwrite values (`0x51BE00`, `0x51BE0C`, `0x51BE20`, `0x51E810`, `0x51E7F8`) also in `.rdata`.

---

## 4. Pointer Relationships (confirmed)

| From | Offset | To (value) | Section | Confidence | Notes |
|------|--------|------------|---------|------------|-------|
| ObjectCandidate vptr | +0x00 | `0x0051FFB4`/`0x0051E570`/`0x0051E4F0` | `.rdata` | PROVEN | 3 constructor-time states |
| Subobject_A vptr | +0x38 | `0x520014`→`0x51BE00` | `.rdata` | STRONGLY SUPPORTED | rebound in phase 2 |
| Subobject_B vptr | +0x40 | `0x520020`→`0x51BE0C` | `.rdata` | STRONGLY SUPPORTED | rebound in phase 2 |
| Subobject_C vptr | +0x50 | `0x520034`→`0x51BE20` | `.rdata` | STRONGLY SUPPORTED | rebound in phase 2 |
| Subobject_D vptr | +0x98 | `0x520050`→`0x51E810` | `.rdata` | STRONGLY SUPPORTED | rebound in phase 2 |
| Subobject_E vptr | +0x9C | `0x5200E8`→`0x51E7F8` | `.rdata` | STRONGLY SUPPORTED | rebound in phase 2 |
| Adjustment thunk → ctor | `0x43E85E` etc. | `SUB ECX, <off>; JMP 0x43ECF0` | `.text` | PROVEN | recovers `this` from subobject ptr |

The adjustment thunks confirm subobject-to-main-object pointer adjustment: given a subobject pointer at offset `0x38`/`0x40`/`0x50`/`0x98`/`0x9C`, subtract that offset to recover the primary `ObjectCandidate` pointer.

---

## 5. Field Access Matrix

| Field | Reads | Writes | Init | Atomic | Consumers |
|-------|-------|--------|------|--------|-----------|
| +0x00 vptr | `FUN_0044F3F0` (`MOV EAX,[EDI]`) | Constructor (3×) | Constructor | No | Indirect dispatch (`[EAX+0x34]`, `[EAX+0x58]`) |
| +0x20 counter | `FUN_004731E0` (test old) | `FUN_004731E0`, `FUN_00473210` (=0) | UNKNOWN | YES | Release/teardown decision |
| +0x24 flag | — | `FUN_00473210` (=1) | — | YES | Teardown |
| +0x28 state | `FUN_0044F3F0` (cmp 5) | none found | UNKNOWN | No | Indirect-dispatch guard |
| +0x2C flag | `FUN_0044F3F0` (cmp 0) | none found | UNKNOWN | No | Indirect-dispatch guard |
| +0x30 counter | none | `FUN_0044F3F0` (++); `FUN_00410E80`/`FUN_00410F60` (=0) | =0 by `FUN_00410E80`/`FUN_00410F60` | No | `FUN_0044F3F0` |
| +0x38/0x40/0x50/0x98/0x9C vptrs | — | Constructor (init + overwrite) | Constructor | No | Subobject virtual dispatch (not observed) |

---

## 6. Unresolved Offsets

| Offset | Status | Why |
|--------|--------|-----|
| `obj+0x20` initializer | UNKNOWN | No constructor write found; initial value unknown |
| `obj+0x24` readers | UNKNOWN | Written but never confirmed read |
| `obj+0x28` writers | UNKNOWN | 17 writers claimed by Phase 2.4, none re-verified; none in constructor |
| `obj+0x2C` writers | UNKNOWN | 7 writers claimed, none re-verified; none in constructor |
| `obj+0x30` readers | UNKNOWN | Incremented, never confirmed read |
| Object total size | UNKNOWN | No allocation site found; `0x5C40` is init extent, not size |
| `field_0x214` | REFUTED | No writes anywhere |

---

## 7. Diagram of Confirmed Pointer Relationships

```
ObjectCandidate (base = this)
├── +0x00  vptr  → .rdata table (0x51FFB4 / 0x51E570 / 0x51E4F0)
├── +0x04  subobject pointer
├── +0x20  ReferenceCounterCandidate (atomic, zeroed by Release/teardown)
├── +0x24  TeardownFlagCandidate (set to 1 by teardown)
├── +0x28  StateCandidate (cmp 5 — dispatch guard)
├── +0x2C  FlagCandidate (cmp 0 — dispatch guard)
├── +0x30  CallCounterCandidate (++ in dispatch)
├── +0x38  Subobject_A vptr → .rdata (0x520014 → 0x51BE00)
├── +0x40  Subobject_B vptr → .rdata (0x520020 → 0x51BE0C)
├── +0x50  Subobject_C vptr → .rdata (0x520034 → 0x51BE20)
├── +0x98  Subobject_D vptr → .rdata (0x520050 → 0x51E810)
└── +0x9C  Subobject_E vptr → .rdata (0x5200E8 → 0x51E7F8)

Subobject pointer → (sub this) → adjustment thunk (SUB ECX, off) → ObjectCandidate
```

---

## 8. Confidence Summary

| Item | Classification |
|------|----------------|
| vptr at +0x00, 3 constructor values | PROVEN |
| Subobject vptr offsets +0x38/+0x40/+0x50/+0x98/+0x9C | STRONGLY SUPPORTED |
| ReferenceCounterCandidate at +0x20 (atomic) | STRONGLY SUPPORTED |
| CallCounterCandidate at +0x30 | STRONGLY SUPPORTED |
| State/Flag at +0x28/+0x2C | HYPOTHESIS |
| TeardownFlag at +0x24 | HYPOTHESIS |
| Object total size | UNKNOWN |
| ObjectCandidate initializer for +0x20 | UNKNOWN |
