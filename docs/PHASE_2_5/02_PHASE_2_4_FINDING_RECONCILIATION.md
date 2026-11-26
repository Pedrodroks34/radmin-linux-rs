# Phase 2.5 Stage 02 — Phase 2.4 Finding Reconciliation

**Classification: VERIFIED** (all corrections traceable to static REA/Ghidra evidence from Phase 2.5 re-analysis)

## 1. Purpose

Reconcile Phase 2.4 reports against Phase 2.5 static re-analysis. Identify which Phase 2.4 findings are confirmed, which are contradicted by new evidence, and which require correction.

## 2. Phase 2.4 Report Inventory (20 files)

| # | Report | Path | Status in Phase 2.5 |
|---|--------|------|---------------------|
| 00 | Environment and Repository Preservation | PHASE_2_4/00_ENVIRONMENT_AND_REPOSITORY_PRESERVATION.md | CONFIRMED |
| 01 | Complete Documentation Inventory | PHASE_2_4/01_COMPLETE_DOCUMENTATION_INVENTORY.md | CORRECTED (count discrepancy — see Report 01) |
| 02 | Phase 2.3 Findings Reconciliation | PHASE_2_4/02_PHASE_2_3_FINDINGS_RECONCILIATION.md | CONFIRMED |
| 03 | Binary Identity and Tool Validation | PHASE_2_4/03_BINARY_IDENTITY_AND_TOOL_VALIDATION.md | CONFIRMED |
| 04 | Constructor and Allocation Call Graph | PHASE_2_4/04_CONSTRUCTOR_AND_ALLOCATION_CALL_GRAPH.md | PARTIALLY CORRECTED (FUN_00473210 now analyzed) |
| 05 | Runtime Vptr and Indirect Dispatch | PHASE_2_4/05_RUNTIME_VPTR_AND_INDIRECT_DISPATCH.md | CORRECTED (vtable address-point errors) |
| 06 | Object Field Initialization and State | PHASE_2_4/06_OBJECT_FIELD_INITIALIZATION_AND_STATE.md | PARTIALLY CORRECTED (refcount semantics) |
| 07 | Reference Count and AddRef/Release Analysis | PHASE_2_4/07_REFERENCE_COUNT_AND_ADDREF_RELEASE_ANALYSIS.md | CORRECTED (FUN_00473210 analyzed, not Release) |
| 08 | Indirect Deallocation Target Analysis | PHASE_2_4/08_INDIRECT_DEALLOCATION_TARGET_ANALYSIS.md | CORRECTED (0x500CA6 is in .text, contains `free` function) |
| 09 | Allocation/Deallocation Symmetry | PHASE_2_4/09_ALLOCATION_DEALLOCATION_SYMMETRY.md | PARTIALLY CORRECTED |
| 10 | Subinitializer and Subobject Analysis | PHASE_2_4/10_SUBINITIALIZER_AND_SUBOBJECT_ANALYSIS.md | PARTIALLY CORRECTED (count discrepancy) |
| 11 | Complete Object Lifecycle Model | PHASE_2_4/11_COMPLETE_OBJECT_LIFECYCLE_MODEL.md | CORRECTED (refcount lifecycle not standard) |
| 12 | Runtime Evidence and Reproduction Log | PHASE_2_4/12_RUNTIME_EVIDENCE_AND_REPRODUCTION_LOG.md | CONFIRMED |
| 13 | Rust Compatibility Reassessment | PHASE_2_4/13_RUST_COMPATIBILITY_REASSESSMENT.md | CONFIRMED |
| 14 | Authoritative Finding Registry | PHASE_2_4/14_AUTHORITATIVE_FINDING_REGISTRY.md | CORRECTED (multiple findings updated) |
| 15 | Phase 2.3 Contradiction Resolution | PHASE_2_4/15_PHASE_2_3_CONTRADICTION_RESOLUTION.md | CONFIRMED |
| 16 | Unresolved Questions and Blockers | PHASE_2_4/16_UNRESOLVED_QUESTIONS_AND_BLOCKERS.md | PARTIALLY RESOLVED (FUN_00473210 now analyzed) |
| 17 | Final Technical Report | PHASE_2_4/17_FINAL_TECHNICAL_REPORT.md | CORRECTED (multiple findings) |
| 18 | Raw Evidence Appendix | PHASE_2_4/18_RAW_EVIDENCE_APPENDIX.md | CORRECTED (address calculations wrong) |
| 19 | Completion and Repository Preservation | PHASE_2_4/19_COMPLETION_AND_REPOSITORY_PRESERVATION.md | CONFIRMED |

## 3. Key Corrections from Phase 2.5 Static Analysis

### C1 — Vtable Address-Point Calculation (Report 05)

**Phase 2.4 error:** Used nominal table base `0x0051FFAC` instead of the actual vptr value `0x0051FFB4` written by the constructor.

**Correction:** Indirect calls use `vptr + offset`, not `table_base + offset`. The vptr is `0x51FFB4`, so:
- `CALL [EAX+0x34]` reads from `0x51FFB4 + 0x34 = 0x51FFE8`
- `CALL [EAX+0x58]` reads from `0x51FFB4 + 0x58 = 0x52000C`

**Impact:** All Table A indirect dispatch targets in Report 05 were wrong.

### C2 — Slot 22 Off-by-4 Error (Report 05)

**Phase 2.4 error:** Listed Table B slot 22 at `0x51E5C4` and Table C slot 22 at `0x51E544`. These are slot 21 addresses (`base + 0x54`), not slot 22 (`base + 0x58`).

**Correction:**
- Table B slot 22: `0x51E570 + 0x58 = 0x51E5C8` (not `0x51E5C4`)
- Table C slot 22: `0x51E4F0 + 0x58 = 0x51E548` (not `0x51E544`)

### C3 — 0x500CA6 PE Section Misclassification (Report 08)

**Phase 2.4 error:** Claimed `0x00500CA6` was in `.data` section or a gap between sections.

**Correction:** `0x00500CA6` falls within `.text` section (VA `0x401000`–`0x519000`). It is the entry address of a `free` function (`FID_conflict:_free(void * _Memory)`), NOT a pointer slot or IAT entry.

**Impact:** The `CALL [0x00500CA6]` instruction reads 4 code bytes from the start of the `free` function and interprets them as a pointer — this is anomalous and requires runtime validation.

### C4 — FUN_00473210 Is Not a Standard Release (Report 07)

**Phase 2.4 error:** Described `FUN_00473210` as "decrement-and-destroy-if-zero" without analyzing it.

**Correction:** `FUN_00473210` is fully analyzed. It:
1. Calls `DeleteCriticalSection(obj + 8)` via `FUN_00489750`
2. Sets `obj + 0x20` (refcount) to 0 — NOT decrement
3. Atomically exchanges `obj + 0x24` (gets old value, sets to 1)
4. Returns `(old_obj+0x24, critical_section_deleted_flag)`

This is a destroy/reset function, not a reference-counted Release.

### C5 — AddRef Still Not Found (Report 07)

**Status:** Still UNKNOWN. No function was found that increments `obj + 0x20`.

### C6 — Subinitializer Count Discrepancy (Report 10)

**Phase 2.4 error:** Reported "eight remaining sub-initializers" but listed nine addresses (`FUN_0047A8A0`, `FUN_0043E500`, `FUN_00403540`, `FUN_004728E0`, `FUN_00483750`, `FUN_0043E680`, `FUN_0047BB20`, `FUN_00475B70`, `FUN_00479240`).

**Correction:** There are 9 unanalyzed sub-initializers, not 8.

### C7 — Object Lifecycle Is Not Standard Refcounting (Report 11)

**Phase 2.4 error:** Described the object lifecycle as standard COM-style AddRef/Release.

**Correction:** The lifecycle is:
- `FUN_004731E0` reads `obj + 0x20` atomically; if non-zero, calls `FUN_00473210`
- `FUN_00473210` sets `obj + 0x20` to 0 (destroy), exchanges `obj + 0x24`, deletes critical section at `obj + 8`
- No AddRef found
- This is a destroy-on-read-nonzero pattern, not standard refcounting

## 4. Confirmed Phase 2.4 Findings (Unchanged by Phase 2.5)

| Finding | Report | Basis |
|---------|--------|-------|
| Constructor `FUN_0043E1A0` writes vptr 3× | 04 | Raw bytes verified |
| 5 adjustment thunks at 0x43E85E–0x43E881 | 04 | Raw bytes verified |
| Constructor has no external callers | 04 | Ghidra call graph |
| Refcount at `obj + 0x20` | 06 | FUN_004731E0 instruction operand |
| field_0x28 compared to 5 | 06 | Raw bytes at 0x44F4EE |
| field_0x2C compared to 0 | 06 | Raw bytes at 0x44F4F4 |
| field_0x30 incremented in FUN_0044F3F0 | 06 | Raw bytes at 0x44F4FE |
| field_0x214 does not exist | 06 | No writes found anywhere |
| HeapAlloc/HeapFree imported from KERNEL32 | 09 | PE import table |
| RolClient_AllocMemory/FreeMemory imported | 09 | PE import table |
| Destruction chain through FUN_004e6cd7 | 11 | Multiple function pseudocode |
| FUN_004E7EC0 is 5-byte thunk | 11 | Ghidra procedure_info |
| FamRT::CFile and CUniversalString exist | 10 | Symbol names in pseudocode |

## 5. Reports Requiring Updates

| Report | Required Update |
|--------|-----------------|
| 05 | Corrected vtable address-point dispatch matrix |
| 07 | FUN_00473210 is destroy/reset, not Release |
| 08 | 0x500CA6 is in .text, contains `free` function |
| 11 | Object lifecycle is not standard refcounting |
| 17 | Corrected technical summary |
| 18 | Corrected raw bytes and address calculations |

These corrections are documented in the corresponding Phase 2.5 reports (03, 04, 05, 06, 07).