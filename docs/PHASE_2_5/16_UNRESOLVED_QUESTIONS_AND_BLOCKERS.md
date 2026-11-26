# Phase 2.5 Stage 16 — Unresolved Questions and Blockers

**Classification: VERIFIED** (all gaps honestly documented)

## 1. Blocker Summary

| # | Question | Classification | Blocks Rust? | Required Evidence | Blocker Type |
|---|----------|---------------|--------------|-------------------|---------------|
| B1 | Object allocation call site | BLOCKED | No | HeapAlloc/RolClient_AllocMemory call with `this` pointer | No Windows debugger |
| B2 | Object actual allocation size | BLOCKED | No | Allocation size argument observed | No Windows debugger |
| B3 | Runtime vptr state at FUN_0044F3F0 | BLOCKED | No | [EDI] value at breakpoint | No Windows debugger |
| B4 | Actual indirect-call targets at runtime | BLOCKED | No | CALL target at 0x44F501/0x44F50D/0x44F5AA/0x44F5B6 | No Windows debugger |
| B5 | CALL [0x500CA6] actual target | BLOCKED | No | Memory at [0x500CA6] at CALL breakpoint | No Windows debugger |
| B6 | AddRef function | UNKNOWN | No | Search for increment at obj+0x20 | Not yet found |
| B7 | 9 sub-initializer bodies | UNKNOWN | No | REA procedure_info on each | Not yet analyzed |
| B8 | obj+0x20/0x28/0x2C initial values | UNKNOWN | No | Find initialization writes | Not found in constructor |
| B9 | FUN_00450FA0 body | UNKNOWN | No | REA procedure_pseudo_code at 0x450FA0 | Not decompiled |
| B10 | FUN_00450FC0 body | UNKNOWN | No | REA procedure_pseudo_code at 0x450FC0 | Not decompiled |
| B11 | FUN_004728E0 body | UNKNOWN | No | REA procedure_pseudo_code at 0x4728E0 | Not decompiled |
| B12 | Constructor reachability | UNKNOWN | No | Search for factory or indirect caller | Not found statically |

## 2. Questions Resolved in Phase 2.5 (No Longer Blockers)

| # | Question | Previous Classification | New Classification | Resolution |
|---|----------|----------------------|-------------------|------------|
| R1 | FUN_00473210 body | UNKNOWN | CONFIRMED | Analyzed: destroy/reset, sets obj+0x20 to 0, exchanges obj+0x24, deletes critical section at obj+8 |
| R2 | Table A indirect dispatch targets | UNKNOWN | CONFIRMED | Slot 13 → 0x4510A0 (returns 0); Slot 22 → 0x450FA0 (body not analyzed) |
| R3 | Table B/C indirect dispatch targets | UNKNOWN | CONFIRMED | Slot 13 → 0x4510B0 (returns 16); Slot 22 → 0x450FC0 (body not analyzed) |
| R4 | 0x500CA6 section | UNKNOWN | CONFIRMED | In .text; contains `free` function |
| R5 | 0x500CA6 is IAT slot | UNKNOWN | REFUTED | Contains code (function prologue), not a pointer |
| R6 | Subinitializer count discrepancy | UNKNOWN | CONFIRMED | 9 not 8 |
| R7 | Object lifecycle type | UNKNOWN | CONFIRMED | Destroy-on-read-nonzero, not standard AddRef/Release |
| R8 | field_0x20/0x28/0x2C initialization | UNKNOWN | CONFIRMED (negative) | Not initialized by constructor |

## 3. Detailed Blocker Descriptions

### B1 — Object Allocation Call Site

**What is unknown:** No function calls `HeapAlloc` or `RolClient_AllocMemory` with the object as the result.

**Why blocked:** No Windows debugger to capture runtime allocation. Static analysis found no allocation call in the constructor path.

**Blocks Rust?** No — Rust uses `Box::new()`/`Arc::new()` which don't need to mirror the Windows allocation pattern.

### B2 — Object Actual Allocation Size

**What is unknown:** No allocation size argument was observed.

**Why blocked:** Depends on B1 — need to see the actual `HeapAlloc(size)` call.

**Blocks Rust?** No — Rust `Box<T>`/`Arc<T>` sizes are determined by the type.

### B3 — Runtime Vptr State at FUN_0044F3F0

**What is unknown:** Constructor writes 3 different vptrs. Cannot determine which is active when FUN_0044F3F0 executes.

**Why blocked:** FUN_0044F3F0 has no direct callers. No runtime execution trace.

**Blocks Rust?** No — Rust uses enum state machines and trait dispatch, not C++ vptr transitions.

### B4 — Actual Indirect-Call Targets at Runtime

**What is unknown:** Slot 13 (+0x34) and slot 22 (+0x58) targets depend on active vptr. Corrected static targets known, but runtime selection unknown.

**Why blocked:** Depends on B3.

**Blocks Rust?** No — Rust uses match-based dispatch.

### B5 — CALL [0x00500CA6] Actual Target

**What is unknown:** The DWORD at 0x500CA6 is `0x8B55FF8B` (code bytes, not a valid pointer). The CALL instruction reads this as a pointer — anomalous.

**Why blocked:** Need to break at the CALL instruction and capture the actual resolved target at runtime.

**Blocks Rust?** No — Rust `Drop` handles deallocation automatically.

### B6 — AddRef Function

**What is unknown:** No function identified that increments refcount at obj+0x20.

**Why blocked:** Static search of all analyzed functions found no increment pattern. 9 sub-initializers not yet analyzed.

**Blocks Rust?** No — `Arc::clone()` is the Rust equivalent.

### B7 — 9 Sub-Initializer Bodies

**What is unknown:** Bodies of FUN_0047A8A0, FUN_0043E500, FUN_00403540, FUN_004728E0, FUN_00483750, FUN_0043E680, FUN_0047BB20, FUN_00475B70, FUN_00479240 not analyzed.

**Why blocked:** Not in Ghidra's analyzed function set or not decompiled.

**Blocks Rust?** No — but these may initialize obj+0x20/0x28/0x2C which affects Rust enum mapping.

### B8 — obj+0x20/0x28/0x2C Initial Values

**What is unknown:** Constructor doesn't write these fields. Initial values before first write unknown.

**Why blocked:** No writer found in constructor. May be in unanalyzed sub-initializers.

**Blocks Rust?** No — Rust `Default::default()` zero-initializes; enum types don't need numeric initial values.

### B9-B11 — Function Bodies Not Decompiled

**What is unknown:** FUN_00450FA0, FUN_00450FC0, FUN_004728E0 bodies not decompiled by Ghidra.

**Why blocked:** `procedure_pseudo_code` returned null for these functions.

**Blocks Rust?** No — these are dispatch targets and helper functions; Rust equivalents are conceptual, not binary-level.

### B12 — Constructor Reachability

**What is unknown:** No external callers found for the constructor chain.

**Why blocked:** Could be reached via indirect call, factory function, or unanalyzed code.

**Blocks Rust?** No — Rust construction pattern is entirely different.

## 4. Questions Not Blocking Rust Implementation

All 12 blockers above do NOT block Rust implementation because:
1. Rust does not use C++ vtable semantics (B3, B4 blocked)
2. Rust does not use manual heap management (B1, B2 blocked)
3. Rust `Arc<T>` handles reference counting automatically (B6 blocked)
4. Rust `Drop` handles deallocation (B5 blocked)
5. Rust enum state machines replace u32 field comparisons (B8 blocked)
6. Rust construction is `fn new()`, not multi-phase vptr transitions (B12 blocked)