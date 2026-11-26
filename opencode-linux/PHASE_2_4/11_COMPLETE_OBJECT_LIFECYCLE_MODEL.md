# Phase 2.4 Stage 11 — Complete Object Lifecycle Model

**Classification: STRONGLY SUPPORTED** (all steps traced via static evidence; some steps unresolved)

## 1. Complete Lifecycle Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ OBJECT LIFECYCLE MODEL                                                      │
│                                                                             │
│  ALLOCATION (UNKNOWN)                                                       │
│    │                                                                        │
│    │ No HeapAlloc/RolClientAllocMemory call found in constructor path      │
│    ▼                                                                        │
│  CONSTRUCTION                                                               │
│    FUN_0043ECF0 (wrapper)                                                   │
│      └─→ FUN_0043E1A0 (constructor, 853 bytes, 36 blocks)                  │
│            │                                                                │
│            ├── Vptr write #1: [obj+0x00] = 0x51FFB4 (Table A)             │
│            ├── Vptr write #2: [obj+0x00] = 0x51E570 (Table B)             │
│            ├── Vptr write #3: [obj+0x00] = 0x51E4F0 (Table C)             │
│            ├── Subobject vptrs at 0x38, 0x40, 0x50, 0x98, 0x9C            │
│            ├── Zeroing loop: 0x0C–0x4C4                                    │
│            ├── Fields initialized up to 0x5C40                            │
│            └── 12 sub-initializer calls (4 analyzed, 8 not)               │
│                                                                            │
│  CALLERS: Only 5 adjustment thunks (0x43E85E–0x43E881), which have         │
│           no callers. Construction chain is unreachable from known code.   │
│                                                                            │
│  REFERENCE COUNTING                                                         │
│    Refcount at obj + 0x20                                                    │
│    FUN_004731E0 = Release(): atomic LOCK/UNLOCK read                       │
│    FUN_00473210 = decrement-and-destroy-if-zero (NOT ANALYZED)             │
│    AddRef = NOT IDENTIFIED                                                  │
│                                                                            │
│  DESTRUCTION                                                                │
│    FUN_00473210 → list cleanup functions (5 total)                         │
│      → FUN_004e6cd7(node) per node                                         │
│        → thunk_FUN_004ec736 (JMP 0x4ec736)                                 │
│          → FUN_004ec736: CALL [0x00500ca6] (FINAL DEALLOCATION)            │
│                                                                            │
│  DEALLOCATION TARGET: UNKNOWN (IAT slot value not resolved)                │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 2. Phase-by-Phase Status

### Phase 1: Allocation — UNKNOWN

| Question | Status | Evidence |
|----------|--------|----------|
| Who allocates the object? | UNKNOWN | No factory function found |
| Which allocator API? | UNKNOWN | HeapAlloc/RolClient_AllocMemory imported but no call found |
| Allocation size? | UNKNOWN | No size argument observed |
| Stack vs heap vs global? | UNKNOWN | Not ruled in or out |

### Phase 2: Construction — CONFIRMED (static)

| Question | Status | Evidence |
|----------|--------|----------|
| Constructor function | CONFIRMED | FUN_0043E1A0, 853 bytes, 36 blocks |
| Constructor wrapper | CONFIRMED | FUN_0043ECF0 |
| Adjustment thunks | CONFIRMED | 5 thunks at 0x43E85E–0x43E881 |
| Vptr transitions | CONFIRMED | 3 writes verified via raw bytes |
| Subobject vptrs | CONFIRMED | 5 subobjects at 0x38, 0x40, 0x50, 0x98, 0x9C |
| External callers | NONE FOUND | Thunks have no callers |

### Phase 3: Reference Counting — PARTIALLY RESOLVED

| Question | Status | Evidence |
|----------|--------|----------|
| Refcount location | CONFIRMED | obj + 0x20 |
| Release function | CONFIRMED | FUN_004731E0 (atomic LOCK/UNLOCK) |
| Decrement/destroy | UNKNOWN | FUN_00473210 referenced but not analyzed |
| AddRef function | UNKNOWN | Not found |
| Multiple refcounts | UNKNOWN | Only obj+0x20 confirmed |

### Phase 4: Destruction — STRONGLY SUPPORTED (to indirect call)

| Question | Status | Evidence |
|----------|--------|----------|
| List cleanup functions | CONFIRMED | 5 functions, all call FUN_004e6cd7 |
| Destruction wrapper | CONFIRMED | FUN_004e6cd7 (14 bytes) |
| Thunk | CONFIRMED | thunk_FUN_004ec736 (5 bytes, JMP 0x4ec736) |
| Final destroy | CONFIRMED | FUN_004ec736 (27 bytes, CALL [0x00500ca6]) |
| Deallocation target | UNKNOWN | [0x00500ca6] value not resolved |

### Phase 5: Deallocation — UNKNOWN

| Question | Status | Evidence |
|----------|--------|----------|
| Actual deallocator | UNKNOWN | HeapFree or RolClient_FreeMemory likely |
| Calling convention | UNKNOWN | Depends on actual target |
| Symmetry with allocation | UNKNOWN | Allocation site not found |
| Object freed once | UNKNOWN | No allocation/deallocation pair observed |

## 3. Key Gaps

| Gap | Impact | Blocks Rust? |
|-----|--------|--------------|
| Allocation call site not found | Cannot determine object size or owner | No |
| FUN_00473210 not analyzed | Cannot confirm decrement/destroy logic | No |
| AddRef not identified | Cannot confirm complete refcount lifecycle | No |
| [0x00500ca6] target unresolved | Cannot confirm deallocation API | No |
| Runtime vptr state unknown | Cannot confirm indirect dispatch behavior | No |