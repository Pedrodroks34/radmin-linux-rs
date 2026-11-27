# Phase 2.4 Stage 16 — Unresolved Questions and Blockers

**Classification: VERIFIED** (all gaps honestly documented)

## 1. Blocker Summary

| # | Question | Classification | Blocks Rust? | Required Evidence | Blocker Type |
|---|----------|---------------|--------------|-------------------|---------------|
| B1 | Object allocation call site | BLOCKED | No | HeapAlloc/RolClient_AllocMemory call with `this` pointer | No Windows debugger |
| B2 | Object actual allocation size | BLOCKED | No | Allocation size argument observed | No Windows debugger |
| B3 | Runtime vptr state at FUN_0044F3F0 | BLOCKED | No | [EDI] value at breakpoint | No Windows debugger |
| B4 | Actual indirect-call targets at runtime | BLOCKED | No | CALL target at 0x44F501/0x44F50D/0x44F5AA/0x44F5B6 | No Windows debugger |
| B5 | FUN_00473210 body | UNKNOWN | No | REA procedure_info/procedure_pseudo_code at 0x473210 | Not yet analyzed |
| B6 | AddRef function | UNKNOWN | No | Search for increment at obj+0x20 | Not yet found |
| B7 | [0x00500ca6] IAT slot target | UNKNOWN | No | Read memory at 0x500ca6; identify resolved function | Not yet resolved |
| B8 | Allocation/deallocation symmetry | UNKNOWN | No | Pair allocation with deallocation | Both ends unresolved |
| B9 | Multiple reference counters | UNKNOWN | No | Verify 0x1E28-0x1E50 are refcounts | Not yet verified |
| B10 | field_0x28/0x2C initial values | UNKNOWN | No | Find initialization writes | Not found in constructor |

## 2. Detailed Blocker Descriptions

### B1 — Object Allocation Call Site

**What is unknown:** No function calls `HeapAlloc` or `RolClient_AllocMemory` with the object as the result. The constructor `FUN_0043E1A0` does not allocate memory.

**Why blocked:** No Windows debugger to capture runtime allocation. Static analysis found no allocation call in the constructor path.

**Required:** Breakpoint at `KERNEL32!HeapAlloc` or `RvROLClient!RolClient_AllocMemory`, capture return pointer, trace to constructor entry.

**Blocks Rust?** No — Rust uses `Box::new()`/`Arc::new()` which don't need to mirror the Windows allocation pattern.

### B2 — Object Actual Allocation Size

**What is unknown:** No allocation size argument was observed. Constructor initializes fields up to 0x5C40, but this is not the allocation size.

**Why blocked:** Depends on B1 — need to see the actual `HeapAlloc(size)` call.

**Blocks Rust?** No — Rust `Box<T>`/`Arc<T>` sizes are determined by the type, not by matching the C++ allocation size.

### B3 — Runtime Vptr State at FUN_0044F3F0

**What is unknown:** Constructor writes 3 different vptrs. Cannot determine which is active when FUN_0044F3F0 executes.

**Why blocked:** FUN_0044F3F0 has no direct callers. No runtime execution trace.

**Required:** Breakpoint at 0x44F3F0, inspect [EDI] vptr value.

**Blocks Rust?** No — Rust uses enum state machines and trait dispatch, not C++ vptr transitions.

### B4 — Actual Indirect-Call Targets at Runtime

**What is unknown:** Slot 13 (+0x34) and slot 22 (+0x58) targets depend on active vptr. Table A: both return 0. Table B/C: slot 13 returns 16, slot 22 returns 0.

**Why blocked:** Depends on B3 — need to know which vptr is active.

**Required:** Breakpoint at CALL instructions, capture actual target.

**Blocks Rust?** No — Rust uses match-based dispatch.

### B5 — FUN_00473210 Body

**What is unknown:** Referenced by FUN_004731E0 as decrement-and-destroy-if-zero, but body not decompiled.

**Why blocked:** Not in the set of functions analyzed in Phase 2.3. Need REA procedure_info at 0x473210.

**Blocks Rust?** No — Rust `Arc<T>` handles decrement-and-destroy automatically.

### B6 — AddRef Function

**What is unknown:** No function identified that increments refcount at obj+0x20.

**Why blocked:** Static search did not find an increment pattern at obj+0x20.

**Required:** Search for `LOCK` + `ADD`/`XADD` at obj+0x20, or runtime breakpoint.

**Blocks Rust?** No — `Arc::clone()` is the Rust equivalent.

### B7 — [0x00500ca6] IAT Slot Target

**What is unknown:** The function pointer at [0x00500ca6] is not resolved. Likely HeapFree or RolClient_FreeMemory.

**Why blocked:** Need to read memory at 0x500ca6 or break at FUN_004ec736.

**Required:** REA read_bytes at 0x500ca6, or breakpoint at CALL [0x500ca6].

**Blocks Rust?** No — Rust `Drop` handles deallocation automatically.

### B8 — Allocation/Deallocation Symmetry

**What is unknown:** Cannot confirm same allocator family used for both operations.

**Why blocked:** Both allocation site (B1) and deallocation target (B7) unresolved.

**Blocks Rust?** No — Rust ownership model guarantees symmetry.

### B9 — Multiple Reference Counters

**What is unknown:** obj+0x20 confirmed as refcount. Region 0x1E28–0x1E50 hypothesized but not verified.

**Why blocked:** No instruction-level analysis of 0x1E28–0x1E50 region.

**Blocks Rust?** No — Rust `Arc<T>` has one strong count.

### B10 — field_0x28/0x2C Initial Values

**What is unknown:** No constructor writes to these offsets. Initial values before first write unknown.

**Why blocked:** Constructor does not initialize these fields.

**Required:** Search for all writes to obj+0x28 and obj+0x2C to find initialization.

**Blocks Rust?** No — Rust enum/bool types don't need numeric initial values.

## 3. Questions Not Blocking Rust Implementation

All 10 blockers above do NOT block Rust implementation because:

1. Rust does not use C++ vtable semantics (B3, B4 blocked)
2. Rust does not use manual heap management (B1, B2, B8 blocked)
3. Rust `Arc<T>` handles reference counting automatically (B5, B6, B9 blocked)
4. Rust `Drop` handles deallocation (B7 blocked)
5. Rust enum state machines replace u32 field comparisons (B10 blocked)

## 4. Questions That Could Be Resolved with Additional Static Analysis

| Question | Static Action Needed | Blocks Rust? |
|----------|---------------------|--------------|
| FUN_00473210 body | REA procedure_info at 0x473210 | No |
| AddRef function | Search for increment at obj+0x20 | No |
| [0x500ca6] target | REA read_bytes at 0x500ca6 | No |
| field_0x28/0x2C initialization | Search all writes to these offsets | No |
| Multiple refcounts | Analyze 0x1E28-0x1E50 region | No |
| Subinitializer bodies (8 functions) | REA procedure_info on each | No |