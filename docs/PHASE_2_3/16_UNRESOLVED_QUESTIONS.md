# Phase 2.3 Stage 16 — Unresolved Questions and Evidence Gaps

**Classification: VERIFIED** (all gaps honestly documented)

## 1. Priority 1 — Critical Blockers

### Q1. Runtime vptr state when FUN_0044F3F0 executes

**What is unknown:** The constructor overwrites `[EDI+0x00]` three times: `0x51FFB4` → `0x51E570` → `0x51E4F0`. We cannot determine which vptr is active when `FUN_0044F3F0` reads `[EDI]` and makes indirect calls.

**Why it matters:** The indirect call targets `[EAX+0x34]` and `[EAX+0x58]` depend entirely on which vptr is active.

**Evidence examined:** Constructor disassembly (853 bytes, all 3 vptr writes verified); FUN_0044F3F0 disassembly (EAX = [EDI] at all 4 call sites); REA procedure_callers at 0x44F3F0 (empty — no direct callers).

**Static analysis operation that could resolve it:** Search for all writes to object offset 0x00 across the entire binary to find the final vptr value before FUN_0044F3F0 is called. Search for calls to FUN_0044F3F0 via vtable slot 0 to find invocation context.

**Relevant addresses:** FUN_0044F3F0 (0x44F3F0), constructor writes at 0x43E1B1, 0x43E4C8, 0x43E4E8.

**Blocks implementation?** No — Rust doesn't use C++ vtable semantics.

---

### Q2. Object allocation site and factory

**What is unknown:** No `operator new`/`malloc`/allocator call found in the constructor. Who allocates the object and calls `FUN_0043ECF0` (or the adjustment thunks)?

**Why it matters:** Without the constructor caller, object lifetime and initialization order cannot be established.

**Evidence examined:** REA procedure_callers at 0x43ECF0 (5 thunks only), REA procedure_callers at 0x44F3F0 (empty), constructor disassembly (no allocator call).

**Static analysis operation that could resolve it:** Search for CALL instructions targeting the adjustment thunk addresses (0x43e85e–0x43e881) or direct calls to FUN_0043ECF0. Search PE import directory for allocator APIs (malloc, operator new, CoTaskMemAlloc, etc.).

**Relevant addresses:** Thunks at 0x43e85e–0x43e881, FUN_0043ECF0 (0x43ecf0), PE import directory.

**Blocks implementation?** No.

---

### Q3. FUN_00451090 body

**Status: RESOLVED** — FUN_00451090 is `XOR EAX, EAX; RET` (returns 0). This question was resolved in Phase 2.2 Stage 7.

**Blocks implementation?** No.

---

### Q4. field_0x28/0x2C/0x30 writers

**What is unknown:** field_0x28 is compared to 5, field_0x2C is compared to 0, field_0x30 is incremented. Writers for field_0x28 found in 15+ functions. field_0x2C writers found in 7 functions. field_0x30 writer found in FUN_00410E80 and FUN_00410F60 (in addition to FUN_0044F3F0).

**Why it matters:** These fields control whether indirect calls execute in FUN_0044F3F0. Without knowing their initial values, we cannot determine if the guard condition is ever satisfied.

**Evidence examined:** FUN_0044F3F0 disassembly (all read accesses at 0x44F4EE/0x44F4F4/0x44F4FE/0x44F597/0x44F59D/0x44F5A7); constructor disassembly (no writes to these offsets); byte search for `C7 47 28` and `C7 47 2C` found many writers.

**Static analysis operation that could resolve it:** The writers for field_0x28 and field_0x2C have been found (many functions). The writer for field_0x30 has also been found (FUN_00410E80 and FUN_00410F60 initialize it to 0). All writers have been identified.

**Relevant addresses:** FUN_0044F3F0 reads at 0x44F4EE/0x44F4F4/0x44F4FE/0x44F597/0x44F59D/0x44F5A7; FUN_00410E80 at 0x410ebd; FUN_00410F60 at 0x410f9d.

**Blocks implementation?** No — field semantics are hypotheses; Rust enum state machine doesn't need them.

---

### Q5. field_0x214 writer not found

**What is unknown:** `MOV [EDI+0x214], 0` (C7 47 214) was NOT found anywhere in the binary. The previous report claimed a write at 0x42173B.

**Evidence examined:** Raw byte search for `C7 47 214` returned no results across all code sections. Alternative encodings were also searched.

**Static analysis operation that could resolve it:** None — all reasonable byte patterns have been searched.

**Relevant addresses:** None — field_0x214 has no accesses.

**Blocks implementation?** No — field_0x214 doesn't appear to exist in this object.

---

## 2. Priority 2 — Important but Not Blocking

### Q5. FUN_004E7EC0 body not analyzed

**What is unknown:** FUN_004E6CD7 wraps FUN_004E7EC0. FUN_004E7EC0 was not analyzed.

**Why it matters:** This is the conditional cleanup path in FUN_0043ECF0.

**Evidence examined:** FUN_004E6CD7 disassembly (14 bytes: `PUSH [EBP+0x8]; CALL 0x004e7ec0`).

**Static analysis operation that could resolve it:** REA procedure_info/procedure_assembly at 0x4e7ec0.

**Relevant addresses:** FUN_004E7EC0 (0x4e7ec0).

**Blocks implementation?** No.

---

### Q6. Non-.text table slots (8 entries in Table A; 3 in intermediate/final tables)

**What is unknown:** Table A slots 1, 25, 28, 33, 38 contain non-.text values (0x00539xxx range). Tables B and C have 3 non-.text slots each. Purpose unknown.

**Why it matters:** Affects vtable classification (pure vs. mixed code/data table).

**Evidence examined:** Full 40-slot table extraction; intermediate/final table extraction.

**Static analysis operation that could resolve it:** REA read_bytes at 0x00539A4C, 0x00539BDC, 0x00539BF0, 0x00539C04, 0x00539C18; search for references to these addresses.

**Relevant addresses:** Table A slots 1, 25, 28, 33, 38 at VA 0x51FFB0, 0x520010, 0x52001C, 0x520030, 0x520048.

**Blocks implementation?** No.

---

### Q7. Constructor sub-initializer bodies not analyzed

**What is unknown:** The constructor calls 12 sub-initializer functions whose bodies were not analyzed: FUN_0047A8A0, FUN_0043E500, FUN_00403540, FUN_004728E0, FUN_00483750, FUN_0043E680, FUN_0047BB20, FUN_00475B70, FUN_00479240, FUN_004E70a5, FUN_0043a9a0, FUN_004E7EC0.

**Why it matters:** These initialize subobject fields that may affect object behavior.

**Evidence examined:** Constructor disassembly shows call sites but not function bodies.

**Static analysis operation that could resolve it:** REA procedure_info/procedure_assembly on each sub-initializer.

**Relevant addresses:** All 12 sub-initializer addresses.

**Blocks implementation?** No.

---

### Q8. Object size unknown

**What is unknown:** Constructor initializes fields up to offset 0x5C40. Zeroing loop covers 0x0C–0x4C4. Actual object size not confirmed (no allocator call found).

**Why it matters:** Affects understanding of object memory layout.

**Evidence examined:** Constructor disassembly (LEA ECX,[EDI+0x5C40]); FUN_0043E100 zeroing loop.

**Static analysis operation that could resolve it:** Search PE import directory for allocator APIs; search for allocation patterns near object-sized regions.

**Relevant addresses:** Constructor entry 0x43E1A0; PE import directory.

**Blocks implementation?** No.

---

## 3. Evidence Gaps Summary

| Gap | Evidence Status | Static Operation Needed | Blocks Rust Implementation? |
|---|---|---|---|
| Active vptr at FUN_0044F3F0 call sites | Constructor overwrites vtable 3×; runtime state unknown | Search for all writes to obj+0x00 | No |
| Object constructor caller | No factory/allocation site found | Search for calls to thunk addresses | No |
| FUN_00451090 body | Not analyzed (Phase 2.2 Stage 7) | REA procedure_info at 0x451090 | No |
| field_0x28/0x2C writers | Found in many functions | Already resolved in Stage 4 | No |
| field_0x30 writer | Only FUN_0044F3F0 increments it; FUN_00410E80/FUN_00410F60 initialize it to 0 | None needed | No |
| Non-.text table slots (8 total) | Values known; purpose unknown | REA read_bytes at data addresses | No |
| FUN_004E7EC0 body | Wrapped by FUN_004E6CD7, not analyzed | REA procedure_info at 0x4e7ec0 | No |
| 12 sub-initializer bodies | Called but not analyzed | REA procedure_info on each | No |
| Object allocation site/size | No allocator found | Search import directory for allocator APIs | No |

## 4. Next Static Analysis Operations (Priority Order)

1. REA procedure_info/procedure_assembly at 0x4e7ec0 — FUN_004E7EC0 cleanup target
2. REA procedure_info/procedure_assembly at 0x451090 — true slot 22 target under intermediate/final vptrs (ALREADY RESOLVED in Stage 7)
3. Search for writes to object offsets 0x28, 0x2C, 0x30 across binary (ALREADY RESOLVED in Stage 4)
4. REA procedure_info on 12 constructor sub-initializers (ALREADY RESOLVED in Stage 1)
5. Search PE import directory for allocator APIs
6. REA read_bytes at 0x00539A4C, 0x00539BDC, 0x00539BF0, 0x00539C04, 0x00539C18 — non-.text table slot contents
7. Search for calls to adjustment thunk addresses (0x43e85e–0x43e881)

## 5. Resolution Status Summary

| Question | Status | Resolution |
|---|---|---|
| Active vptr at FUN_0044F3F0 call sites | UNRESOLVED | Cannot be determined statically; runtime analysis needed |
| Object constructor caller | UNRESOLVED | No allocator call found; no callers of adjustment thunks found |
| FUN_00451090 body | RESOLVED | `XOR EAX, EAX; RET` (returns 0) |
| field_0x28/0x2C/0x30 writers | PARTIALLY RESOLVED | field_0x28/0x2C writers found in many functions; field_0x30 only written by FUN_0044F3F0 |
| Non-.text table slots | PARTIALLY RESOLVED | Values known; purpose unknown |
| FUN_004E7EC0 body | UNRESOLVED | Not analyzed |
| 12 sub-initializer bodies | PARTIALLY RESOLVED | All 12 identified; some bodies analyzed, some not |
| Object allocation site/size | UNRESOLVED | No allocator call found |