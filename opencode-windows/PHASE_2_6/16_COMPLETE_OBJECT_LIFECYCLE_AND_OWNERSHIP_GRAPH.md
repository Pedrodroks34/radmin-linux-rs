# Phase 2.6 Stage 16 — Complete Object Lifecycle and Ownership Graph

**Classification: STRONGLY SUPPORTED (partial)** — the release/teardown/destruction mechanism is verified; the allocation and initialization-trigger edges remain unresolved.

Cross-reference: all Phase 2.6 reports 01–15, especially `04`, `05`, `06`, `07`, `09`, `12`, `13`, `14`, `15`.

---

## 1. Corrected Object Field Model

| Offset | Width | Name | Type | Semantics | Atomic? |
|--------|-------|------|------|-----------|---------|
| `0x00` | 4 | vptr | vtable ptr | Table A→B→C transitions in ctor | No |
| `0x08` | 4 | field_0x08 | CRITICAL_SECTION | Destroyed by `DeleteCriticalSection` in teardown | N/A |
| `0x20` | 4 | field_0x20 | pointer | Release latch: non-NULL=alive, NULL=released | YES (XADD read, XCHG write) |
| `0x24` | 4 | field_0x24 | DWORD flag | Torn-down flag: set to 1 by teardown | YES (XCHG write) |
| `0x28` | 4 | field_0x28 | state | Compared to 5 in dispatch guard | No |
| `0x2C` | 4 | field_0x2C | flag | Compared to 0 in dispatch guard | No |
| `0x30` | 4 | field_0x30 | counter | Incremented in dispatch (plain INC, non-atomic) | No |

**No external control block.** All fields are direct members of `ObjectCandidate`. `field_0x20` is a pointer field, not a counter.

---

## 2. Ownership Model — Release-Once Latch (NOT Reference Counting)

```
RELEASE (FUN_004731E0):
  old_ptr = LOCK XADD [&this->field_0x20], 0   // atomic READ, field unchanged
  if (old_ptr == NULL) return                  // idempotent: already released
  FUN_00473210(this)                           // teardown (runs once)

TEARDOWN (FUN_00473210):
  DeleteCriticalSection(&this->field_0x08)     // via FUN_00489750 → [0x519138]
  InterlockedExchange([&this->field_0x20], 0)  // NULL the latch
  InterlockedExchange([&this->field_0x24], 1)  // set torn-down flag
```

**Key properties:**
- **No AddRef:** `field_0x20` is never incremented anywhere in analyzed code.
- **Release-once:** Teardown runs exactly once (when Release first sees non-NULL).
- **Idempotent:** After `field_0x20` is nulled, subsequent Releases are no-ops.
- **Single-ownership semantics:** Most consistent with `Box<T>`, not `Arc<T>`.

---

## 3. Integrated Lifecycle Graph

```
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 1 — ALLOCATION                                               │
│  (SITE UNKNOWN — no HeapAlloc/RolClientAllocMemory call found)      │
│  Caller supplies `this` pointer in ECX                              │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 2 — CONSTRUCTION                                             │
│  FUN_0043ECF0 (ctor wrapper) → FUN_0043E1A0 (primary ctor)          │
│  • Zeroing loop (0x0C–0x4C4)                                        │
│  • Vptr: +0x00 = 0x51FFB4 → 0x51E570 → 0x51E4F0 (3 stages)          │
│  • Subobject vptrs: +0x38/0x40/0x50/0x98/0x9C (2 phases)            │
│  • field_0x08 = CRITICAL_SECTION initialized                        │
│  • field_0x20 set to non-NULL (by UNKNOWN initializer)              │
│  • field_0x24 not initialized in ctor                               │
│  (NO external caller identified — constructor unreachable statically)│
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 3 — OBJECT READY                                             │
│  vptr = Table C (0x51E4F0), field_0x20 = non-NULL pointer           │
│  field_0x24 = ? (unknown initial value)                             │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 4 — USE                                                      │
│  FUN_0044F3F0 (indirect dispatch)                                   │
│  Guard: [+0x28]==5 && [+0x2C]!=0                                    │
│  CALL [vptr+0x34] → returns 16 (all tables)                         │
│  CALL [vptr+0x58] → arg-dependent (0 or 0xC5)                       │
│  INC [+0x30] (call counter, non-atomic)                             │
│  (NO direct caller identified — unreachable statically)             │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 5 — RELEASE                                                  │
│  FUN_004731E0:                                                      │
│    old = LOCK XADD [+0x20], 0  (atomic read, field unchanged)       │
│    if (old != NULL) → teardown                                      │
│    if (old == NULL) → no-op (idempotent)                            │
└─────────────────────────────────────────────────────────────────────┘
                              │
              old != NULL     │     old == NULL
                    ▼         │         ▼
┌──────────────────────┐  ┌─────────────────────────────┐
│ PHASE 6 — TEARDOWN   │  │  DONE (no further action)   │
│ FUN_00473210:        │  │                             │
│ • DeleteCriticalSection(+0x08) │                    │
│ • XCHG [+0x20], 0     │  │                             │
│ • XCHG [+0x24], 1     │  │                             │
└──────────────────────┘  └─────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 7 — DEALLOCATION                                             │
│  List nodes: FUN_004e6cd7 → thunk 0x4E7EC0 → FUN_004ec736           │
│             → CALL 0x00500CA6 → Import [0x5192EC] (likely HeapFree)│
│  Parent block: FREE LOCATION UNKNOWN                                │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 4. Pointer Flow Graph

```
this (ECX/EDI/ESI)
│
├── +0x00 ──→ vptr ──→ .rdata table (0x51FFB4 / 0x51E570 / 0x51E4F0)
│               │
│               └── [vptr+0x34] → FUN_004510A0/B0 (return 16)
│               └── [vptr+0x58] → FUN_00450FA0/C0 (arg-dependent)
│
├── +0x08 ──→ CRITICAL_SECTION ──→ DeleteCriticalSection (teardown)
│
├── +0x20 ──→ pointer (release latch)
│             READ:  LOCK XADD(...,0) → ESI = old (Release)
│             WRITE: XCHG(...,0) → NULL (Teardown)
│
├── +0x24 ──→ DWORD flag
│             WRITE: XCHG(...,1) → set to 1 (Teardown)
│
├── +0x28 ──→ state (cmp 5 — dispatch guard)
├── +0x2C ──→ flag (cmp 0 — dispatch guard)
└── +0x30 ──→ call counter (++ in dispatch)
```

**All edges are direct object-field accesses via LEA.** No pointer indirection.

---

## 5. Unresolved Edges (explicitly shown)

| # | Edge | Status | Why unresolved |
|---|------|--------|----------------|
| E1 | Allocation site → constructor (`this` production) | UNKNOWN | No caller of `FUN_0043ECF0` found; no allocator call |
| E2 | Constructor caller / factory | UNKNOWN | Byte scan of all `CALL rel32` found none |
| E3 | `field_0x20` initialization (who sets non-NULL?) | UNKNOWN | No write to `+0x20` in constructor or analyzed functions |
| E4 | `field_0x24` initial value | UNKNOWN | Not initialized in constructor |
| E5 | Object → `FUN_0044F3F0` dispatch | UNKNOWN | No caller of dispatch found |
| E6 | Active vptr at dispatch time | UNKNOWN | Constructor unreachable; no runtime trace |
| E7 | AddRef / increment of `field_0x20` | NOT FOUND | Whole-program scan: none |
| E8 | Parent object block free location | UNKNOWN | Teardown does not free memory; caller unknown |
| E9 | Import `[0x5192EC]` identity | UNKNOWN | ILT name not resolved (likely HeapFree) |

---

## 6. Ownership Classification — Final

| Question | Answer | Classification |
|----------|--------|----------------|
| Is it reference counting? | **NO** — no increment, only read-and-null | STRONGLY SUPPORTED |
| Is it single-ownership? | **LIKELY** — release-once latch matches `Box<T>` | LIKELY |
| Is there an external control block? | **NO** — all direct field access | STRONGLY SUPPORTED |
| Is release idempotent? | **YES** — NULL check skips teardown | PROVEN |
| Is `Arc<T>` appropriate? | **NO** — no AddRef | STRONGLY SUPPORTED |
| Is `Box<T>` appropriate? | **LIKELY** — single ownership | LIKELY |

---

## 7. Confidence Summary

| Element | Classification |
|---------|---------------|
| Field layout (+0x00/+0x08/+0x20/+0x24/+0x28/+0x2C/+0x30) | STRONGLY SUPPORTED |
| Release-once latch semantics | STRONGLY SUPPORTED |
| Teardown mechanism (DeleteCriticalSection + 2 XCHGs) | PROVEN |
| No AddRef / no refcount | STRONGLY SUPPORTED |
| Allocation site | UNKNOWN |
| Parent block free | UNKNOWN |
| Initial `field_0x20` value | UNKNOWN |
