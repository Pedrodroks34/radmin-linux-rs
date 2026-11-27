# RECONCILIATION.md

Canonical contradiction/correction record for the Radmin VPN Linux client reverse-engineering corpus.

Compiled from exactly the 12 sources whose first column is `RECONCILIATION` in `analysis_workspace/compaction/mapping.tsv`. Every contradiction and correction below preserves its source ID (C1..C13, D-201..D-216, etc.), wrong claim, corrected claim, addresses, raw bytes, evidence, and confidence exactly as stated in the source documents. Nothing is invented; where a source marks an item UNRESOLVED or UNKNOWN, this record keeps it unresolved.

## 1. Scope and Method

- Input scope: only `mapping.tsv` rows with first column `RECONCILIATION` (12 sources). No other docs were read for this draft.
- Output: exactly one file, `analysis_workspace/compaction/drafts/RECONCILIATION.md`.
- Language: English. Prose matches source-doc tone; no new claims added.
- Each correction item retains: ID, wrong claim, corrected claim, address(es), raw bytes where given, evidence citation, confidence.
- Repeated matrices are deduplicated; no correction item is dropped.

## 2. Phase 2.3 Contradictions

Sources: `docs/PHASE_2_3/02_PHASE_2_2_CONTRADICTION_MATRIX.md`, `docs/PHASE_2_3/15_HISTORICAL_RECONCILIATION.md`, `docs/PHASE_2_3/CHECKPOINT_01_REPORT_RECONCILIATION.md`.

### 2.1 Contradiction Matrix C1–C5 (Phase 2.3 Report 02)

| ID | Contradiction | Reports Involved | Wrong Claim | Corrected Claim | Evidence | Confidence |
|----|---------------|------------------|-------------|-----------------|----------|------------|
| C1 | field_0x30 writer | `04_FIELD_WRITER_READER_ANALYSIS.md` (contradicts itself) | "field_0x30 is ONLY incremented in FUN_0044F3F0 — no other function in the entire binary writes to it!" | field_0x30 is written by THREE functions: FUN_00410E80, FUN_00410F60, FUN_0044F3F0 | Raw bytes: `FF 47 30` at 0x44F4FE and 0x44F5A7; `C7 47 30 00 00 00 00` at 0x410ebd and 0x410f9d | VERIFIED |
| C2 | field_0x28 writer inventory incomplete | `04_FIELD_WRITER_READER_ANALYSIS.md` | Table claims completeness but says "(output truncated — more functions)" | Complete enumeration: 17 write sites across 15 unique functions | Raw byte search across all code sections | STRONGLY SUPPORTED (was incomplete) |
| C3 | field_0x214 writer | `04_FIELD_WRITER_READER_ANALYSIS.md` vs Phase 2.1 | `MOV [EDI+0x214], 0` (C7 47 214) was reported NOT found; a prior report claimed a write at 0x42173B | field_0x214 has no confirmed writers or readers anywhere in the binary | Raw byte search for `C7 47 214` returned no results; alternative encodings (e.g. `MOV [EDI+0x214], EAX` = `89 87 14 02 00 00`) also not found | UNRESOLVED (no writers/readers confirmed) |
| C5 | Constructor sub-initializer count | `01_INITIALIZER_INVENTORY.md` | "12 call sites, 11 unique functions" (disputed count) | VERIFIED: 12 distinct CALL instructions to sub-initializer functions; 11 unique function targets (FUN_00475B70 called twice at different ECX offsets) | Constructor disassembly | VERIFIED |

### 2.2 Authoritative Field Writer Inventory (Phase 2.3 Report 02, Sections 5–10)

| Field Offset | Writers | Readers | Writer Functions | Reader Functions | Confidence |
|--------------|---------|---------|------------------|------------------|------------|
| 0x00 | 6 | FUN_0044F3F0 (2×) | FUN_0043E1A0, FUN_0043E100, FUN_0047A8A0, FUN_00403540, FUN_0047BB20 | FUN_0044F3F0 | STRONGLY SUPPORTED |
| 0x04 | 1 | None in FUN_0044F3F0 | FUN_00479240 | 0 | VERIFIED |
| 0x0C | 2 | None in FUN_0044F3F0 | FUN_0043E100, FUN_00475B70 | 0 | VERIFIED |
| 0x20 | 0 | FUN_0044F3F0 (2×) | 0 | 1 | VERIFIED |
| 0x28 | 15+ | FUN_0044F3F0 (2×), FUN_004738C0, FUN_004739F0, FUN_00473BF0, FUN_00479A80, FUN_00481F60 | 15+ | 6 | STRONGLY SUPPORTED |
| 0x2C | 7 | FUN_0044F3F0 (4×), FUN_00479A80 | FUN_00404920, FUN_00410E80, FUN_00410F60, FUN_00414020, FUN_004142B0, FUN_00479A80, FUN_004E0780 | 6 | VERIFIED |
| 0x30 | 3 | FUN_0044F3F0 (2×) | FUN_00410E80, FUN_00410F60, FUN_0044F3F0 | 2 | VERIFIED |
| 0x214 | 0 | 0 | 0 | 0 | VERIFIED (not found anywhere) |

Complete field_0x28 writer sites (17 VA/site/function pairs), field_0x2C writer sites (7), field_0x30 writer sites (4) and reader sites (2) are preserved verbatim in source `docs/PHASE_2_3/02_PHASE_2_2_CONTRADICTION_MATRIX.md` sections 6–10. field_0x214 conclusion: no writers or readers anywhere; the previous report claiming a write at 0x42173B cannot be verified.

### 2.3 Historical Reconciliation Claims 1–13 (Phase 2.3 Report 15)

| # | Previous Report | Previous Claim | New Evidence | Final Classification | Corrected Conclusion |
|---|-----------------|----------------|--------------|----------------------|----------------------|
| 1 | Phase 2 Report 04 | Table base = 0x0051FFBC | Raw byte extraction shows constructor writes 0x51FFB4 to [EDI+0x00]; 0x51FFB4 = Table A slot 2 | VERIFIED | Table base is 0x0051FFAC; 0x51FFBC is slot 4 of Table A |
| 2 | Phase 2 Report 04 | Slot 13 = 0x00451010 | Confirmed at correct base 0x51FFAC | VERIFIED | Slot 13 = 0x00451010 (same value, different base) |
| 3 | Phase 2 Report 04 | Slot 22 = 0x0043E85E | At base 0x51FFAC, slot 22 = 0x00450FA0; 0x0043E85E is slot 26 | VERIFIED | Slot 22 = 0x00450FA0 at base 0x51FFAC; 0x0043E85E is at slot 26 |
| 4 | Phase 2 Report 04 | [EAX+0x58] targets FUN_0043E85E | At base 0x51FFAC, slot 22 = 0x00450FA0; at vptr 0x51FFB4, rel slot 22 = 0x00450FA0 | VERIFIED | [EAX+0x58] never targets FUN_0043E85E; FUN_0043E85E is at slot 24 (vptr 0x51FFB4) or slot 26 (base 0x51FFAC) |
| 5 | Phase 2 Report 04 | [EAX+0x34] targets FUN_00451010 | At vptr 0x51FFB4, rel slot 13 = 0x004510A0; at base 0x51FFAC, abs slot 13 = 0x00451010 | VERIFIED | Depends on vptr: 0x004510A0 (vptr 0x51FFB4), 0x00451010 (vptr 0x51FFAC), 0x004510B0 (vptrs 0x51E570/0x51E4F0) |
| 6 | Phase 2 Report 07 | Constructor chain not found | Constructor FUN_0043E1A0 found (853 bytes, 36 blocks) | VERIFIED | Constructor found and fully analyzed |
| 7 | Phase 2 Report 03 | FUN_0043ECF0 not investigated | Fully reconstructed (38 bytes, 3 blocks) | VERIFIED | FUN_0043ECF0 = constructor wrapper + conditional cleanup |
| 8 | Phase 2 Report 04 | 5 adjustment thunks | All 5 verified at instruction level; adjustment amounts match subobject vptr write offsets | VERIFIED | All 5 thunks confirmed; adjustments match constructor subobject offsets exactly |
| 9 | Phase 2 Report 07 | Constructor writes vptr 0x51FFB4 to [EDI+0x00] | Confirmed; constructor also overwrites with 0x51E570 then 0x51E4F0 | VERIFIED | Three vptr transitions during construction |
| 10 | Phase 2 Report 07 | Constructor writes subobject vptrs at offsets 0x38, 0x40, 0x50, 0x98, 0x9C | Confirmed via raw byte verification at each write address | VERIFIED | All 5 subobject vptr writes verified |
| 11 | Phase 2 Report 08 | Fields at 0x28, 0x2C, 0x30 accessed by FUN_0044F3F0 | Confirmed; writers not found in constructor | VERIFIED | Field accesses confirmed; writers unknown for 0x28/0x2C/0x30 |
| 12 | Phase 2 Report 04 | field_0x30 only incremented in FUN_0044F3F0 | FUN_00410E80 and FUN_00410F60 also write MOV [EDI+0x30], 0x0 | VERIFIED | field_0x30 is incremented by FUN_0044F3F0 AND initialized to 0 by FUN_00410E80/FUN_00410F60 |
| 13 | Phase 2 Report 04 | field_0x214 write at 0x42173B | No `C7 47 214` found anywhere in binary | VERIFIED | field_0x214 write not found |

### 2.4 Contradictions Explicitly Preserved (Phase 2.3 Report 15, Section 3)

| Contradiction | Side A | Side B | Resolution |
|---------------|--------|--------|------------|
| Table base | Phase 1: 0x0051FFBC | Phase 2: 0x0051FFAC | Phase 2 corrected: 0x0051FFBC is slot 4, not base |
| [EAX+0x58] target | Phase 2: FUN_0043E85E | Phase 2.3: FUN_00450FA0 (base 0x51FFAC) or 0x00450FA0 (vptr 0x51FFB4) | Phase 2.3: FUN_0043E85E is NOT at slot 22 under any vptr interpretation |
| [EAX+0x34] target | Phase 2: FUN_00451010 | Phase 2.3: FUN_004510A0 (vptr 0x51FFB4), FUN_00451010 (vptr 0x51FFAC), FUN_004510B0 (vptrs 0x51E570/0x51E4F0) | Phase 2.3: Depends on vptr state |
| field_0x30 writer | Phase 2: "ONLY incremented in FUN_0044F3F0" | Phase 2.3: FUN_00410E80/FUN_00410F60 write MOV [EDI+0x30], 0x0 | Phase 2.3: incremented by FUN_0044F3F0 AND initialized to 0 by FUN_00410E80/FUN_00410F60 |
| field_0x214 | Phase 2: "NOT FOUND" | Raw byte search for `C7 47 214` returned no results across all code sections | Phase 2.3: field_0x214 has no confirmed writers or readers |

### 2.5 Checkpoint 1 Key Contradictions (Phase 2.3 Checkpoint 01)

| # | Contradiction | Reports Involved | Status |
|---|---------------|------------------|--------|
| C1 | field_0x30: "ONLY incremented in FUN_0044F3F0" vs FUN_00410E80/FUN_00410F60 writing MOV [EDI+0x30], 0x0 | `04_FIELD_WRITER_READER_ANALYSIS.md` (itself contradicts itself) | RESOLVED - both exist |
| C2 | field_0x28 writer inventory says "output truncated — more functions" but table claims completeness | `04_FIELD_WRITER_READER_ANALYSIS.md` | OPEN - needs complete search |
| C3 | field_0x214: "NOT FOUND" vs previous report claiming write at 0x42173B | `04_FIELD_WRITER_READER_ANALYSIS.md` vs Phase 2.1 | OPEN - needs investigation |
| C4 | field_0x28/0x2C writer counts and completeness | `04_FIELD_WRITER_READER_ANALYSIS.md` | OPEN - needs complete enumeration |
| C5 | Constructor sub-initializer count: 12 vs actual call sites found | `01_INITIALIZER_INVENTORY.md` | RESOLVED - 12 call sites, 11 unique functions |

## 3. Phase 2.4 Corrections

Sources: `docs/PHASE_2_4/02_PHASE_2_3_FINDINGS_RECONCILIATION.md`, `docs/PHASE_2_4/15_PHASE_2_3_CONTRADICTION_RESOLUTION.md`.

### 3.1 Contradiction Resolution Matrix C1–C8 (Phase 2.4 Report 15)

| # | Contradiction | Reports Involved | Wrong Claim | Resolution | Status |
|---|---------------|------------------|-------------|------------|--------|
| C1 | Table base = 0x0051FFBC vs 0x0051FFAC | Phase 2 Report 04 vs Phase 2.3 Report 18 | Table base = 0x0051FFBC | Base is 0x0051FFAC. Constructor writes 0x51FFB4 to [EDI+0x00], and 0x51FFB4 = base + 8 = slot 2. 0x51FFBC = base + 16 = slot 4. | RESOLVED |
| C2 | Destruction chain described as "fully traced" but [0x00500ca6] destination unknown | Reports 17, 22 | "Fully traced" destruction chain | Chain is traced TO the indirect call, but the final target is unknown. Wording should say "traced to indirect call" not "fully traced." | CLARIFIED |
| C3 | FUN_00473210 described as decrement/destroy but not fully analyzed | Reports 16, 22 | Decrement/destroy-if-zero | FUN_00473210 body was not decompiled. Need REA procedure_info/procedure_pseudo_code at 0x473210. Expected behavior (hypothesis only): atomically decrement refcount at obj+0x20; if == 0 destroy; else return. | UNRESOLVED |
| C4 | AddRef function never identified | Reports 16, 22 | Standard refcount with AddRef | No function found that increments refcount at obj+0x20. May be inlined or in unanalyzed code. | UNRESOLVED |
| C5 | Allocator APIs found but object allocation call site unresolved | Reports 05, 21 | Allocation call exists | HeapAlloc/HeapFree/RolClient_AllocMemory imported but no call found in constructor or sub-initializers. | UNRESOLVED |
| C6 | Object size: 0x5C40 extent vs no allocation call | Reports 05, 09, 21 | 0x5C40 is allocation size | 0x5C40 is the highest initialized field offset, NOT the allocation size. Actual allocation size unknown. | CLARIFIED |
| C7 | Report file count discrepancies | Report 19 vs actual directory | File count mismatch | Resolved: 26 files (23 reports + 3 checkpoints). Reports 20-23 and CHECKPOINT_02 created after Report 19 was written. | RESOLVED |
| C8 | Rust daemon status inconsistent across docs | AGENTS.md, Report 17, Report 23, src/ | Daemon = "Not implemented" | Daemon module EXISTS as a functional IPC server with mock/stub behavior (hardcoded IP 26.100.200.1); does NOT implement real Radmin VPN networking. | RESOLVED |

### 3.2 Detailed Resolutions (Phase 2.4 Report 15)

**C3 — FUN_00473210:** Report 22 describes FUN_00473210 as "the decrement-and-destroy operation" but its complete implementation was not included. Required action: REA procedure_info/procedure_pseudo_code at 0x473210. (Later superseded by Phase 2.5: see Section 4.)

**C4 — AddRef:** Reference-count lifecycle described as complete, but AddRef (increment) never identified. No function found that writes/increments refcount at obj+0x20. Search approaches not yet tried: LOCK+ADD/XADD targeting obj+0x20; functions writing obj+0x20 with increment pattern; callers of functions modifying obj+0x20.

**C5 — Object allocation:** No HeapAlloc or RolClient_AllocMemory call found in constructor, wrapper, thunks, or sub-initializers. Possible explanations: stack-allocated/embedded; factory function not yet identified; allocated via RolClient_AllocMemory by a wrapper; globally allocated in .data/.bss.

**C8 — Rust daemon:** Correct description: "Daemon module exists as a functional IPC server with mock/stub behavior; no real Radmin networking implemented." Implements DaemonContext IPC server, Daemon start/stop lifecycle, Unix domain socket IPC with handshake and command dispatch; mock behavior with hardcoded IP 26.100.200.1. Does not implement real Radmin VPN networking, Windows named pipe compatibility, actual connection to Radmin servers, runtime interoperability with Windows client.

### 3.3 New Contradictions Identified in Phase 2.4 (Phase 2.4 Report 15, Section 7)

| # | Contradiction | Reports Involved | Resolution Needed |
|---|---------------|------------------|-------------------|
| N1 | field_0x28 initial value unknown | Reports 04, 06 | Search for all writes to obj+0x28 to find initialization |
| N2 | field_0x2C initial value unknown | Reports 04, 06 | Search for all writes to obj+0x2C to find initialization |
| N3 | Multiple refcounts (obj+0x20 vs 0x1E28-0x1E50) | Reports 06, 17 | Verify whether 0x1E28-0x1E50 are also refcounts |
| N4 | [0x500ca6] slot location (section gap?) | Report 08 | VA 0x500ca6 may fall between .rdata and .data sections |

### 3.4 Reports Superseded or Updated (Phase 2.4 Report 15, Section 6)

No Phase 2.3 reports are superseded. All remain valid as static evidence. Phase 2.4 adds new analysis on top of Phase 2.3 findings.

## 4. Phase 2.5 Correction Matrix (14 Corrections)

Sources: `docs/PHASE_2_5/02_PHASE_2_4_FINDING_RECONCILIATION.md` (C1–C7), `docs/PHASE_2_5/15_PHASE_2_4_CORRECTION_MATRIX.md` (C1–C14).

### 4.1 The 14 Corrections C1–C14 (Phase 2.5 Report 15, Section 2)

| # | Phase 2.4 Claim | Phase 2.5 Correction | Report(s) Affected | Correction Evidence | Confidence |
|---|----------------|---------------------|-------------------|---------------------|------------|
| C1 | Table A base = 0x51FFAC is the vptr | vptr = 0x51FFB4; table base is nominal only | 03, 04, 05 | Raw bytes at 0x43E1B1: C7 03 B4 FF 51 00 | CONFIRMED |
| C2 | Table B slot 22 at 0x51E5C4 | Slot 22 at 0x51E5C8 (0x51E570 + 0x58) | 05 | Arithmetic verified; raw bytes at 0x51E5C8: C0 0F 45 00 | CONFIRMED |
| C3 | Table C slot 22 at 0x51E544 | Slot 22 at 0x51E548 (0x51E4F0 + 0x58) | 05 | Arithmetic verified; raw bytes at 0x51E548: C0 0F 45 00 | CONFIRMED |
| C4 | Table A slot 13 at 0x51FFE0 → 0x451010 | Slot 13 at 0x51FFE8 → 0x4510A0 | 05 | REA read_bytes at 0x51FFE8: A0 10 45 00 | CONFIRMED |
| C5 | Table A slot 22 at 0x520004 → 0x451070 | Slot 22 at 0x52000C → 0x450FA0 | 05 | REA read_bytes at 0x52000C: A0 0F 45 00 | CONFIRMED |
| C6 | Table B slot 22 at 0x51E5C4 → 0x451090 | Slot 22 at 0x51E5C8 → 0x450FC0 | 05 | REA read_bytes at 0x51E5C8: C0 0F 45 00 | CONFIRMED |
| C7 | Table C slot 22 at 0x51E544 → 0x451090 | Slot 22 at 0x51E548 → 0x450FC0 | 05 | REA read_bytes at 0x51E548: C0 0F 45 00 | CONFIRMED |
| C8 | 0x500CA6 in .data or gap | 0x500CA6 in .text (VA 0x401000–0x519000) | 05, 08 | REA binary_overview section table | CONFIRMED |
| C9 | 0x500CA6 is IAT slot / pointer | 0x500CA6 is `free` function entry; contains code | 08 | REA read_bytes: function prologue; Ghidra: FID_conflict:_free | CONFIRMED |
| C10 | CALL [0x500CA6] reads valid pointer | DWORD at 0x500CA6 = 0x8B55FF8B (not valid) | 08 | REA read_bytes: 8B FF 55 8B | CONFIRMED |
| C11 | FUN_00473210 = decrement-and-destroy-if-zero | FUN_00473210 = destroy/reset: sets obj+0x20 to 0, exchanges obj+0x24, deletes critical section | 06, 07, 11 | REA procedure_pseudo_code at 0x473210 | CONFIRMED |
| C12 | Standard COM AddRef/Release lifecycle | Destroy-on-read-nonzero pattern; no AddRef found | 06, 07, 11 | FUN_004731E0 + FUN_00473210 analyzed | CONFIRMED |
| C13 | 8 sub-initializers not analyzed | 9 sub-initializers not analyzed | 09, 10 | Phase 2.4 Report 10 listed 9 addresses | CONFIRMED |
| C14 | obj+0x20/0x28/0x2C initialized by constructor | Not initialized by constructor | 06, 08 | Full constructor disassembly reviewed | CONFIRMED |

### 4.2 Key Corrections from Phase 2.5 Static Analysis (Phase 2.5 Report 02, Section 3)

**C1 — Vtable address-point calculation (Report 05):** Phase 2.4 used nominal table base `0x0051FFAC` instead of actual vptr value `0x0051FFB4` written by constructor. Indirect calls use `vptr + offset`, not `table_base + offset`. vptr is 0x51FFB4, so:
- `CALL [EAX+0x34]` reads from `0x51FFB4 + 0x34 = 0x51FFE8`
- `CALL [EAX+0x58]` reads from `0x51FFB4 + 0x58 = 0x52000C`
Impact: all Table A indirect dispatch targets in Report 05 were wrong.

**C2 — Slot 22 off-by-4 error (Report 05):** Table B slot 22 listed at `0x51E5C4` and Table C slot 22 at `0x51E544` — these are slot 21 addresses (`base + 0x54`), not slot 22 (`base + 0x58`). Corrections: Table B slot 22: `0x51E570 + 0x58 = 0x51E5C8` (not `0x51E5C4`); Table C slot 22: `0x51E4F0 + 0x58 = 0x51E548` (not `0x51E544`).

**C3 — 0x500CA6 PE section misclassification (Report 08):** Claimed `0x00500CA6` was in `.data` section or a gap between sections. Correction: `0x00500CA6` falls within `.text` section (VA `0x401000`–`0x519000`). It is the entry address of a `free` function (`FID_conflict:_free(void * _Memory)`), NOT a pointer slot or IAT entry. The `CALL [0x00500CA6]` instruction reads 4 code bytes from the start of the `free` function and interprets them as a pointer — anomalous, requires runtime validation.

**C4 — FUN_00473210 is not a standard Release (Report 07):** Described as "decrement-and-destroy-if-zero" without analysis. Correction: FUN_00473210 (1) calls `DeleteCriticalSection(obj + 8)` via `FUN_00489750`; (2) sets `obj + 0x20` (refcount) to 0 — NOT decrement; (3) atomically exchanges `obj + 0x24` (gets old value, sets to 1); (4) returns `(old_obj+0x24, critical_section_deleted_flag)`. This is a destroy/reset function, not a reference-counted Release.

**C5 — AddRef still not found (Report 07):** Still UNKNOWN. No function found that increments `obj + 0x20`.

**C6 — Subinitializer count discrepancy (Report 10):** Reported "eight remaining sub-initializers" but listed nine addresses (`FUN_0047A8A0`, `FUN_0043E500`, `FUN_00403540`, `FUN_004728E0`, `FUN_00483750`, `FUN_0043E680`, `FUN_0047BB20`, `FUN_00475B70`, `FUN_00479240`). Correction: there are 9 unanalyzed sub-initializers, not 8.

**C7 — Object lifecycle is not standard refcounting (Report 11):** Described as standard COM-style AddRef/Release. Correction: lifecycle is `FUN_004731E0` reads `obj + 0x20` atomically; if non-zero, calls `FUN_00473210`; `FUN_00473210` sets `obj + 0x20` to 0 (destroy), exchanges `obj + 0x24`, deletes critical section at `obj + 8`; no AddRef found. This is a destroy-on-read-nonzero pattern, not standard refcounting.

### 4.3 Corrected Dispatch Matrix (Phase 2.5 Report 15, Section 3)

| Vptr State | vptr | CALL [vptr+0x34] | Target | CALL [vptr+0x58] | Target |
|------------|------|------------------|--------|------------------|--------|
| Initial | 0x51FFB4 | 0x51FFE8 | 0x4510A0 (→0) | 0x52000C | 0x450FA0 (?) |
| Intermediate | 0x51E570 | 0x51E5A4 | 0x4510B0 (→16) | 0x51E5C8 | 0x450FC0 (?) |
| Final | 0x51E4F0 | 0x51E524 | 0x4510B0 (→16) | 0x51E548 | 0x450FC0 (?) |

### 4.4 Corrected Object Lifecycle (Phase 2.5 Report 15, Section 4)

```
ALLOCATION (UNKNOWN)
    ↓
CONSTRUCTION (FUN_0043ECF0 → FUN_0043E1A0)
    - Vptr: 0x51FFB4 → 0x51E570 → 0x51E4F0
    - Subobject vptrs at 0x38, 0x40, 0x50, 0x98, 0x9C
    - obj+0x20, 0x28, 0x2C NOT initialized
    - obj+0x30 NOT initialized by constructor
    ↓
REFERENCE COUNTING (FUN_004731E0)
    - Atomic read of obj+0x20
    - If != 0: call FUN_00473210
    ↓
DESTRUCTION (FUN_00473210)
    - DeleteCriticalSection(obj+8)
    - Set obj+0x20 to 0
    - Atomic exchange obj+0x24 (get old, set 1)
    ↓
LIST CLEANUP (5 functions → FUN_004e6cd7 per node)
    ↓
DEALLOCATION (CALL [0x500CA6] → target UNKNOWN)
```

### 4.5 Phase 2.5 Validation of Each Phase 2.4 Report (Phase 2.5 Report 02, Section 2)

| # | Phase 2.4 Report | Path | Status in Phase 2.5 |
|---|------------------|------|---------------------|
| 00 | Environment and Repository Preservation | PHASE_2_4/00 | CONFIRMED |
| 01 | Complete Documentation Inventory | PHASE_2_4/01 | CORRECTED (count discrepancy — see Report 01) |
| 02 | Phase 2.3 Findings Reconciliation | PHASE_2_4/02 | CONFIRMED |
| 03 | Binary Identity and Tool Validation | PHASE_2_4/03 | CONFIRMED |
| 04 | Constructor and Allocation Call Graph | PHASE_2_4/04 | PARTIALLY CORRECTED (FUN_00473210 now analyzed) |
| 05 | Runtime Vptr and Indirect Dispatch | PHASE_2_4/05 | CORRECTED (vtable address-point errors) |
| 06 | Object Field Initialization and State | PHASE_2_4/06 | PARTIALLY CORRECTED (refcount semantics) |
| 07 | Reference Count and AddRef/Release Analysis | PHASE_2_4/07 | CORRECTED (FUN_00473210 analyzed, not Release) |
| 08 | Indirect Deallocation Target Analysis | PHASE_2_4/08 | CORRECTED (0x500CA6 is in .text, contains `free` function) |
| 09 | Allocation/Deallocation Symmetry | PHASE_2_4/09 | PARTIALLY CORRECTED |
| 10 | Subinitializer and Subobject Analysis | PHASE_2_4/10 | PARTIALLY CORRECTED (count discrepancy) |
| 11 | Complete Object Lifecycle Model | PHASE_2_4/11 | CORRECTED (refcount lifecycle not standard) |
| 12 | Runtime Evidence and Reproduction Log | PHASE_2_4/12 | CONFIRMED |
| 13 | Rust Compatibility Reassessment | PHASE_2_4/13 | CONFIRMED |
| 14 | Authoritative Finding Registry | PHASE_2_4/14 | CORRECTED (multiple findings updated) |
| 15 | Phase 2.3 Contradiction Resolution | PHASE_2_4/15 | CONFIRMED |
| 16 | Unresolved Questions and Blockers | PHASE_2_4/16 | PARTIALLY RESOLVED (FUN_00473210 now analyzed) |
| 17 | Final Technical Report | PHASE_2_4/17 | CORRECTED (multiple findings) |
| 18 | Raw Evidence Appendix | PHASE_2_4/18 | CORRECTED (address calculations wrong) |
| 19 | Completion and Repository Preservation | PHASE_2_4/19 | CONFIRMED |

Reports requiring updates (Phase 2.5 Report 15, Section 6): 04, 05, 06, 07, 08, 09, 10, 11, 14, 17, 18.

## 5. Phase 2.7 vs Phase 2.8 Timeline Reconciliation

Source: `docs/PHASE_2_8/02_PHASE_2_7_TIMELINE_RECONCILIATION.md`.

### 5.1 Conflicting Observations (Phase 2.7 Report 07)

| # | Contradiction | Evidence |
|---|---------------|----------|
| C1 | User Connect (03:11) reported BEFORE baseline capture (03:15) | Timeline order impossible if baseline is pre-connection |
| C2 | WinDbg `lm` on PID 5572 at 03:10, but PID 5572 terminated at 03:11:10 | WinDbg must have been attached to the original service instance |
| C3 | Monitoring "activated" at 03:50, but post-connection capture at 03:12–03:13 | Monitoring start AFTER capture impossible |
| C4 | Post-connection module enum at 03:12 on PID 5476, but WinDbg `lm` on PID 5476 at 03:13 | Order plausible but both AFTER monitoring activation claim |
| C5 | Network baseline at 03:15 shows UDP 56413 on PID 5572, but PID 5572 terminated at 03:11 | Baseline capture must have occurred BEFORE connection |

### 5.2 Evidence-Based Reconstruction (Actual Chronological Order)

| Sequence | Event | Evidence |
|----------|-------|----------|
| 1 | GUI started (PID 1232) | WMI CreationDate: 20261126024400.503142-180 |
| 2 | Service started (PID 5572) | WMI CreationDate: 20261126024404.939786-180 |
| 3 | Repository cloned | Git log shows clone before Phase 2.7 work |
| 4 | Baseline capture (module enum, network baseline, file hashes) | EnumModules2 output shows PID 5572 with 91 modules; UDP 56413 on PID 5572 |
| 5 | WinDbg attached to PID 5572 | WinDbg session created for PID 5572 |
| 6 | User clicked Connect | User report; service restart observed |
| 7 | Service PID 5572 terminated | `Get-Process -Id 5572` returns nothing post-connection |
| 8 | Service restarted as PID 5476 | `Get-Process` shows PID 5476 owning TCP relay |
| 9 | Post-connection capture (module enum, network, process tree) | EnumModules2 on PID 5476 + 1232; netstat shows TCP relay |
| 10 | WinDbg `lm` on new PID 5476 | WinDbg output shows modules for PID 5476 |
| 11 | Monitoring tools configured (reported as 03:50) | Report 06 states monitoring active |

### 5.3 File Timestamp Evidence (local times UTC-3 vs claimed UTC)

Report 07 uses UTC timestamps that don't match file creation times. Local `LastWriteTime` 03:00 = 06:00 UTC. All Phase 2.7 reports were written ~06:00–06:08 UTC in a single session after the experiment.

**Actual UTC timeline from file metadata:**
- Baseline reports written: ~06:00–06:08 UTC
- Post-connection reports written: ~06:06–06:08 UTC (same batch)
- All reports written in a single session after the experiment

### 5.4 Reconciled Timeline (Best Estimate)

| UTC Time | Event | Confidence |
|----------|-------|------------|
| ~05:44 UTC | GUI Process Start (PID 1232) | HIGH (WMI CreationDate) |
| ~05:44 UTC | Service Process Start (PID 5572) | HIGH (WMI CreationDate) |
| ~06:00 UTC | Repository clone / Phase 2.7 start | HIGH (Git log) |
| ~06:00–06:08 UTC | Baseline capture (modules, network, hashes) | HIGH (Report content + file timestamps) |
| ~06:08 UTC | WinDbg attached to PID 5572 | MEDIUM (WinDbg session log) |
| ~06:09 UTC | User clicked Connect | MEDIUM (User report + service restart) |
| ~06:09 UTC | Service PID 5572 terminated | HIGH (Process gone post-connection) |
| ~06:09 UTC | Service restarted as PID 5476 | HIGH (New PID owns TCP relay) |
| ~06:09–06:10 UTC | Post-connection capture | HIGH (Report 08–11 content) |
| ~06:10 UTC | Phase 2.7 reports finalized | HIGH (File timestamps) |

### 5.5 Unresolvable Items

| Item | Status | Reason |
|------|--------|--------|
| Exact user Connect click timestamp | UNRESOLVED | Only user report; no automated GUI event capture |
| Exact service termination timestamp | UNRESOLVED | No ETW/Procmon capture at that moment |
| Exact service restart timestamp | UNRESOLVED | No SCM event log capture |
| WinDbg session exact start time | UNRESOLVED | Session log shows 05:16 UTC but may be different session |
| Whether baseline and connection were separate sessions | UNRESOLVED | File timestamps suggest single session |

### 5.6 Root Cause

The Phase 2.7 timeline (Report 07) was written retrospectively after the experiment, using estimated UTC timestamps based on local clock, mixed actual tool timestamps and human estimates, no synchronized clock across evidence sources. The "monitoring activated at 03:50 UTC" claim appears to be a documentation error — monitoring tools were prepared but the actual live capture happened during the connection experiment itself.

## 6. Phase 9C/9D Discrepancy Logs

Sources: `docs/analysis_workspace/phase_9C_audit/phase_9C_discrepancy_log.md`, `docs/analysis_workspace/phase_9D_audit/phase_9D_discrepancy_log.md`.

Severity key used by both logs: P0 contradiction · P1 factual error (correctable) · P2 imprecision/stale figure · P3 note.

### 6.1 Phase 9C Discrepancies D-01–D-18

| ID | Severity | Finding | Evidence / Location |
|----|----------|---------|---------------------|
| D-01 | P2 | `is_call=true` composition omitted COMPUTED_CALL_TERMINATOR. `32,848 = 27,770 + 5,075` is wrong; actual `32,848 = 27,770 + 5,075 + 3` (3 terminators, all `outgoing`). The 32,848 figure itself is correct. | → `phase_9C_reference_count_reconciliation.md` |
| D-02 | P1 | "22 distinct callers, no function calls it twice" for FUN_0041e280 is wrong. Rows #8/#9 (`FUN_0041d380` @ `0041d438`, `0041d468`) show same function twice. Unique callers = 21. Phase 8X's "21" was correct; the 8R summary sentence was not. | → `phase_9C_callsite_inventory.md` §2 |
| D-03 | P0 | `00423239`: 8R "CONFIRMED" vs 8W-graph "CONDITIONAL" vs 8X/8W-table "BLOCKED". All three labels refer to same instruction `E842B0FFFF CALL 0x0041e280`. Classification disagreement about one edge + internal contradiction inside `phase_8W_reachability_graph.md` (edge labeled both CONDITIONAL and BLOCKED). RESOLVED: existence DIRECTLY VERIFIED; reachability = BLOCKED UNDER EXPLICIT ASSUMPTIONS. | → `phase_9C_230c0_discrepancy.md` |
| D-04 | P1 | "Only write to [x+0x214] is MOV [EDI+0x214],0 at 0042173b" incomplete. True: no instruction stores a non-zero value into any `[X+0x214]`. Stores exist (XCHG-with-0, CMPXCHG-with-0-accumulator, direct MOV-0 at `0042173b`). Conclusion survives; evidence statement incomplete. | → `phase_9C_blocked_path_revalidation.md` §2 |
| D-05 | P1 | "JZ at 00423162 always taken" (8V) unprovable from export. Branch semantics as reported; **always-taken** premise data-dependent on `[ESI+0x214]`, only zero for constructor-built objects under A1∧A2. Not provable statically; now BLOCKED UNDER EXPLICIT ASSUMPTIONS. | → `phase_9C_blocked_path_revalidation.md` §5 |
| D-06 | P1 | 16650 target claimed opaque in 8R; actual target is a static pointer to FUN_00479d80. Dumped `.rdata`: `[0x00519db8] = [0x0051b260] = 0x00479d80` (FUN_00479d80, thiscall, 251 B). Field `[this+0x08]` statically initialized by constructor at `004214f0`/`0042155b`. | → `phase_9C_16650_pointer_chain.md` §4 |
| D-07 | P2 | e220/e280 described as one generic dispatch. Same dereference skeleton but different state machines; 16650 is a third shape. No merging permitted. | → `phase_9C_e220_pointer_chain.md`, `phase_9C_e280_pointer_chain.md`, `phase_9C_16650_pointer_chain.md` |
| D-08 | P2 | Phase-0B HEAD anchor stale. `dataset_inventory.md` and Phase-0B report say HEAD=`95e304e…`; actual HEAD is `b873cea…` (external commit 2026-11-08 19:59:30 by Pedrodroks34). Prior reports must not be assumed to reflect current tree. | → `phase_9C_main_report.md` §1 |
| D-09 | P2 | `FUN_00498fe0` treated as "unknown/unusable". Complete, linearly-scoped 82,424-byte registry/event installer; zero dispatcher significance. Decompiler timeout is size-induced; assembly usable and fully cross-referenced. | → `phase_9C_498fe0_manual_analysis.md` |
| D-10 | P1 | "22 callsites, 22 distinct callers" mismatch vs row-level data. Same root as D-02; table rows contain duplicate (#8/#9). Counting from table yields 21 despite sentence saying 22. | → `phase_9C_callsite_inventory.md` §2 |
| D-11 | P3 | `0x522c5c`/`0x258` allocator pair: operator new-size cookie. `FUN_0042d980`: `PUSH 0x522c5c; PUSH 0x258; CALL 0x004e5a66` — 0x258 = 600 bytes allocated. `FUN_004e5a66` → `FUN_004018a0` → `__malloc_base` → `HeapAlloc(…, 0x0, …)` — memory not zeroed. Constructor reliance on HeapAlloc zero-fill unsupported. | → `phase_9C_evidence_index.md` §3, `phase_9C_blocked_path_revalidation.md` §2 |
| D-12 | P3 | `FUN_00421410`'s bulk copy does not cover `+0x214`. `004216a8 REP MOVSD` copies `[EDI+0x110, EDI+0x1AC)` only (0x27 dwords). Initializer-bypass possibility closed by range proof. | → `phase_9C_blocked_path_revalidation.md` §2 |
| D-13 | P3 | Incoming/outgoing logging asymmetry for same edge. Each callsite logged exactly once, but direction not deterministic per address. Counts must match on `to`, not on direction. | → `phase_9C_reference_count_reconciliation.md` §3, `phase_9C_callsite_inventory.md` |
| D-14 | P3 | `+0x214` dead CAS at `0042316c`. `FUN_004230c0` issues second `CMPXCHG.LOCK [EDX],ECX` on same field with same zero accumulator immediately after branch — no consumer; atomic RMW with +0. Flagged to prevent wrong reading that second CAS arms next dispatch. | → `phase_9C_230c0_discrepancy.md` §5 |
| D-15 | P1 | 8W internal edge-label contradiction. `phase_8W_reachability_graph.md` labels `FUN_004230c0 → N2` at `00423239` both "CONDITIONAL" (Direct Calls) and "BLOCKED" (Blocked Edges). Single-edge authority: existence DIRECTLY VERIFIED; reachability BLOCKED UNDER EXPLICIT ASSUMPTIONS (D-05). | → `phase_9C_230c0_discrepancy.md` §6 |
| D-16 | P2 | Corpus has no `phase_8Z`/`phase_9A` reports. Mission references to "Phases 8Z and 9A" do not correspond to any file (latest: 8X). Likely intended targets ("four blocked paths") map to five BLOCKED-labeled sites analyzed here — revalidated individually. | → `phase_9C_blocked_path_revalidation.md` §0 |
| D-17 | P3 | `00498fe0`'s bogus `calling_convention: "unknown"` and giant size in CC census. 23 "unknown" CCs: 22 are PE import stubs; 23rd is `00498fe0` (82 KB monolith). Not an analysis gap; irrelevant to dispatcher work. | → `phase_9C_498fe0_manual_analysis.md` §4 |
| D-18 | P3 | Non-dispatcher `+0x214`-adjacent CAS at `00423205`/`004232c0`. `00423205 CMPXCHG.LOCK [EDI],ECX` (EDI=&[EBP-0x14], EAX=0) sits inside success path and re-zeroes local; local-flag operation, not `+0x214` operation. Only `00423157` and `0042316c` touch `ESI+0x214`; `00423205` touches the local. | → `phase_9C_230c0_discrepancy.md` §2 |

### 6.2 Phase 9D Discrepancies D-201–D-216

| ID | Severity | Finding | Evidence / Location |
|----|----------|---------|---------------------|
| D-201 | P1 | Phase 9C's "`FUN_00420b80` has 0 incoming reference" claim was wrong. Re-queried: `xref.py callers 00420b80` → **2 callsites**, both direct E8: `0041f6bd UNCONDITIONAL_CALL from_function=FUN_0041f450 to_function=FUN_00420b80`; `00420b52 UNCONDITIONAL_CALL from_function=FUN_00420b30 to_function=FUN_00420b80`. `00420b80` reclassified UNKNOWN → CONDITIONAL. e220 callsite inventory itself (15 sites / 14 unique callers) stays correct; the **reachability** verdict changes. | Phase 9C final report §6 Q7; `phase_9C_callsite_inventory.md` |
| D-202 | P2 | Phase 9C's "`FUN_0041f110` has zero incoming refs" confirmed but incomplete. True for `E8`-direct call sites and `UNCONDITIONAL_CALL` level; **not** true at `DATA`-level (1 DATA ref at `.rdata 0x0051afe8` whose contents are `0x0041f110` — vtable slot of a class hierarchy). Reachable via vtable dispatch by code outside this export. Classification: UNRESOLVED, not UNKNOWN-trivially-dead. | Phase 9C |
| D-203 | P1 | Phase 9C's claim "`[reg+0x14]` writers found: none relevant to dispatch objects" is incorrect. Exhaustive `[reg+0x2c]` scan found 111 stores but no init-complete analysis. Constructor-write analysis shows FUN_00417850-class initializes `[obj+0x14]` (Group B CAS1) and `[obj+0x2c]` (Group A CAS1) with static zeros. Group A CAS1/CAS2 initialized to zero at constructor lines `004179a1` / `004179c1`. Group B fields (`[obj+0x14]`, `[obj+0x20]`) proven static zero at `0041ea80` / `0041eaa3`. | Phase 9D constructor analysis |
| D-204 | P1 | Phase 9C's claim "Group B/C P cannot be initialized" is incorrect. Group B P = `0x0051b01c` (static); Group C P = `0x00000000` (static zero — **not** heap garbage). Earlier claim from incomplete constructor analysis (Phase 8X/9C never enumerated FUN_0041ea00). Impact: Group B chain fully resolvable to `FUN_004e7650`; Group C chain permanently broken (vs. "unknown"). | Phase 9D |
| D-205 | P2 | Phase 9C's "0 = heap garbage at [obj+0x14] etc." is overstated. Heap returns garbage from HeapAlloc with flag 0, but constructors initialize the fields. Incorrect to say "uninitialized therefore garbage" when every store is enumerated. Heap garbage only applies where constructor does not write; for Group B/C class every field is written. | Phase 9D |
| D-206 | P2 | Phase 9C's "allocator does not zero, so initial contents unknown" now irrelevant for these dispatch objects. FUN_00421410-class objects are the only +0x214-gate objects and have no Group A/B/C usage. Dispatch classes fully initialize Group A/B/C fields. Allocator-flag issue applies only to unused FUN_00421410 class. | Phase 9D |
| D-207 | P1 | Phase 9C "P is not initialized" conflated the two classes. FUN_00421410-class does not initialize any Group A/B/C field. FUN_00417850/FUN_0041ea00 classes fully initialize them. Phase conflated them. | Phase 9D |
| D-208 | P3 | Phase 9C BLOCKED verdicts' upstream condition restated imprecisely. Five blocked paths remain BLOCKED UNDER EXPLICIT ASSUMPTIONS. Assumptions (construction OBBX) doubly-verified — Radmin allocates these objects exclusively via single `FUN_00421410` / `FUN_00417850` / `FUN_0041ea00` chain. Count unchanged: 5 paths, all blocked-on-assumption. | Phase 9D |
| D-209 | P2 | `0x005a5a54` runtime-registration CALL convention incorrectly read in Phase 9C as URL-like registration target. Real meaning: CRT's `__imp__RtlCaptureContext` argument slot — unhandled-exception reporter registered. Code at `004dcb26` pushes `[EAX+0x84]` onto stack before calling `FUN_004e766c` — `[EAX+0x84]` pointer inside `_exception_info` structure (MSVC `_EXCEPTION_POINTERS`). Calling registered unhandled-exception handler. Indirect call target deterministically `0x004dd190` (unhandled-exception reporter); does not execute application logic. | Phase 9D |
| D-210 | P3 | Phase 9C's `+0x214` invariant analysis complete but used wrong wording. Real invariant: **no instruction in the export stores a non-zero value into any `[X+0x214]`** — verified exhaustively. Wording in 9C ("only the direct store at 0042173b") inferior to stronger statement. Already corrected in `phase_9C_blocked_path_revalidation.md`. | Phase 9D |
| D-211 | P2 | `FUN_00420b80` marked ""UNKNOWN"" in `phase_9D_*` attempts to resolve identity of its real dispatchers — DONE (see D-201). 2 direct callers (`FUN_0041f450`, `FUN_00420b30`); both call through `LEA ECX,[EBX+0x10]` form at callsites. Objects received are GROUP B objects (FUN_0041ea00-class). | Phase 9D |
| D-212 | P3 | Phase 9C's table of blocked-path callers kept verbatim. None added (correct — +0x214 gates unchanged), none removed (correct — exact callsites by function and address all remain blocked-on-assumption). | Phase 9D |
| D-213 | P3 | `FUN_00416650`'s vtable-based variant store sequence (4 vtables, identical entries). 4 CF-Guard-style vtables stored by FUN_00421410-class and homologues all point at `FUN_004e7650`. When derived class overrides one virtual method at construction time (`CreateThread`-equivalent), it stores application callback as alternative vtable-slot value — CFG-instrumented dispatch calls it. That's how "dispatch" happens for real app logic. Support infrastructure exists; block selecting feature on call site not followed through in this export. | Phase 9D |
| D-214 | P3 | Phase 9C's `+0x244` / `[+0x2cc]` vs. `[+0x214]` distinction now crystal-clear. Two different 0x0F-range offsets — not the same. `[obj + 0x244]` stores **dispatch vtable slot (target 0x00519e54)** — part of object layout; `[obj + 0x214]` stores the **+0x214 gate target** — interlocked bool gate. Both verified zero-initialized at construction. Different purposes. | Phase 9D |
| D-215 | P2 | Export contains no signs of derived-class instantiation. Both candidate creation chains (`FUN_00421410_class → FUN_00417850_class → FUN_0041ea00_class`) build only pure-virtual objects. If Radmin instantiates derived classes, it overrides vtable slots to application code — none found in this export. Either dispatched methods never called, or Windows-side Radmin service callback module does it. | Phase 9D |
| D-216 | P2 | Global name-shape of CFG-instrumented dispatch stub. All references to `FUN_004e7650` use that name precisely because Ghidra's export uses it; `__guard_dispatch_icall` is Microsoft SDK convention for equivalent function (read global function pointer → call `guard_check_icall` (no-op `RET 0` in this build, per `004e69b7: C20000`) → `CALL` the global → `CALL 0x004fc479` crash path). Role identical to `__guard_dispatch_icall` semantically, but evidence is disassembly itself — not the name. Do NOT claim exact CRT internal symbol `__guard_dispatch_icall` / `_guard_dispatch_icall_fptr` exists at `0x004e7650` (naming conjecture); only CF-Guard-instrumented callback dispatch behavior verified. | Phase 9D |

### 6.3 Summary of Phase-9D-Discovered Errors in Phase 9C (Phase 9D Report, Section "Summary")

| ID | What was wrong | Impact | Fix |
|----|----------------|--------|-----|
| D-201 | `FUN_00420b80` reported as 0 callers / UNKNOWN; actual 2 direct callers (`FUN_0041f450 @ 0041f6bd`, `FUN_00420b30 @ 00420b52`) | **1 callsite misclassified** (CONDITIONAL, not UNKNOWN) | Reclassified |
| D-203 | CAS fields "not initialized / unknown" | CAS initialization now fully known for all classes (Group A/B/C = static zero except Group C CAS1 = `0x0051b014`) | CAS verdict refined |
| D-204 | Group B/C P "not initialized" | Group B/C chains fully statically resolvable (P = `0x0051b01c` / `0x00000000`) | Group lifecycle reports |

## 7. Crypto Reconciliation (Phase 10.10)

Source: `docs/CRYPTO_PHASE_10_10_RECONCILIATION.md`.

### 7.1 Binary Evidence

| Binary | SHA-256 | Format | Path |
|--------|---------|--------|------|
| `shelper.dll` | d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4 | PE32 i386 DLL | claude-handoff/binaries/radmin_ext/shelper.dll |
| `RvROLClient.dll` | 6ba7dfecd38183d4bff0fc53f1c8c05d25e636077fe753b1220912aa58938177 | PE32 i386 DLL | claude-handoff/binaries/radmin_ext/RvROLClient.dll |
| `RvControlSvc.exe` | 546efad9ab3ff85c2a50d61524d754bec94a3f3e30d6ae8addef481a1e8daa1e | PE32 i386 EXE | claude-handoff/binaries/radmin_ext/RvControlSvc.exe |
| `Radmin_VPN_2.1.4951.1.exe` | e16711e2e3e59f6603f51f437197215b1914a3d8316e1f633260178b959921f7 | PE32 i386 EXE (installer) | claude-handoff/binaries/radmin_ext/ |

HEAD: `95e304e0855a6faf4eece932484cb00e36620a6e`; working tree modified (Fase 10.5 changes uncommitted). Tools: Ghidra 12.2, objdump, Ghidra headless, tshark/Wireshark.

### 7.2 Main Reconciliation Findings

1. SRP-6a confirmed as the key-exchange algorithm used by the official Windows client — NOT SRP-6 with k=3 hardcoded in the current Rust implementation.
2. Multiplier k computed dynamically as `k = SHA-1(N || PAD192(g))`, not a fixed value of 3.
3. Computation of u (scrambling parameter) is symmetric between client and server: both compute `SHA-1(A || B)`, where A is client ephemeral and B is server ephemeral.
4. Identity identification in calculation of x uses UTF-16LE, not UTF-8 as currently implemented in Rust.
5. 64-byte key split into two AES-256 keys (32 bytes each) remains unresolved — specific mapping of which half goes to enc vs dec could not be determined through static reverse engineering.

### 7.3 Cryptographic Dispatcher (shelper.dll API Table)

`RvROLClient.dll` does not import crypto functions directly from `shelper.dll`; imports only `SHelper_Init` and resolves others dynamically via `GetProcAddress`. Function pointers stored in an API table filled during initialization. Offset mapping (+0x58 SHelper_Init … +0xec CheckExeFileSignature) preserved in source Section 3.1. `ROLClient_InitDll` (`0x10041010` in RvROLClient.dll) is main entry point; calls `FUN_1003fbd0` to resolve all `shelper.dll` functions via `GetProcAddress`; global `0x10187030` points to object containing the function table.

### 7.4 Incompatibilities (Rust vs Official Binary)

| Item | Current Rust | Official Binary | Status |
|------|-------------|-----------------|--------|
| Multiplier k | k = 3 (hardcoded) | k = SHA-1(N||PAD(g)) (dynamic) | INCOMPATIBLE |
| Identity in hash x | UTF-8 (`username.as_bytes()`) | UTF-16LE (raw bytes of obj+0x8) | CONFIRMED_MISMATCH |

Evidence: `FUN_10060810` (client descriptor) computes `SHA-1(N || g)` with 192-byte padding; `FUN_10060ec0` (server) computes `k = SHA-1(N||PAD(g))`; `FUN_100607d0` (k=3) is dead code — not referenced by any SRP-6a descriptor. `compute_srp_x` in shelper.dll (`0x10060340` client, `0x10060c80` server) hashes identity as UTF-16LE bytes directly from session object. Impact: non-ASCII identities produce different `x` between client and server, handshake fails completely.

### 7.5 Confirmed Cryptographic Parameters

| Parameter | Value | Source | Confidence |
|-----------|-------|--------|------------|
| N (prime) | 1536-bit (192 bytes) | `0x100ac280` in shelper.dll | CONFIRMED |
| g (generator) | 0x05 (1 byte) | `0x100ac279` in shelper.dll | CONFIRMED |
| k (multiplier) | SHA-1(N||PAD192(g)) | Computed dynamically | CONFIRMED |
| SRP variant | SRP-6a | Both client and server | CONFIRMED |
| u (scrambling) | SHA-1(A||B) both sides | Symmetric | CONFIRMED |
| KDF | SHA-1(S‖BE32(0))‖SHA-1(S‖BE32(1)) = 40 bytes | FUN_10061790 | CONFIRMED |
| Session key size | First 32 bytes of KDF | Confirmed | CONFIRMED |

### 7.6 Unresolved Crypto Items

| Item | Status | Reason |
|------|--------|--------|
| AES key split (which half → enc/dec) | Unknown | Consumer call site not traced |
| Exact password encoding | Unknown | Caller of `0x10060340`/`0x10060c80` not traced |
| context+0x20 = A (client) / B (server)? | Unconfirmed | Not traced dynamically |
| Is FUN_100607d0 (k=3) used in any path? | Unknown | Not referenced by SRP-6a descriptors, may be another path |

### 7.7 Corrections Implemented (Phase 10.5)

In `src/session/control_handshake.rs`: replaced `RADMIN_SRP_K = 3` constant with `srp_k()` computing `SHA-1(N||PAD192(g))` dynamically as BigNum; changed `compute_srp_x` to use `encode_identity(username)` (UTF-16LE) instead of `username.as_bytes()` (UTF-8); updated `test_srp_group_parameters` to verify `k = SHA-1(N||PAD(g))`.

Pending (blocked): AES key split mapping; handshake step endianness (out of scope); RSA key provenance; full interop test against Windows client.

## 8. PCAP Previous-Report Corrections

Source: `docs/PCAP_PREVIOUS_REPORT_CORRECTIONS.md`. Audited document: `docs/PCAP_FORENSICS_REPORT.md` (NOT modified). Audit date: 06 nov 2026. Original document rule: not modified; all corrections listed here.

### 8.1 Corrections Summary (#1–#12)

| # | Section/Line | Problem | Classification | Recommended Correction |
|---|--------------|---------|----------------|------------------------|
| 1 | Section 9.1, offset table | Declared size 137 bytes, but offsets go only to 0x72 (120 bytes). 17 bytes missing. | CRITICAL | Extend table to 0x8a (137 bytes) or revise size to 120 bytes |
| 2 | Section 9.1 | Field `00 04` interpreted as TLV without specifying endianness | MEDIUM | Specify big-endian for IP and port |
| 3 | Section 4.1 | Server table omits 45.162.230.182:17351 | LOW | Add entry for 45.162.230.182:17351 |
| 4 | Section 4.5 | IP `[IP_PUBLICO_MASCARADO]` not masked | CRITICAL (privacy) | Replace with `[IP_PUBLICO_MASCARADO]` |
| 5 | Section 9.3 | Relay classified as HYPOTHESIS without specific flow evidence | LOW | Keep as HYPOTHESIS, add specific flow observed |
| 6 | Section 11 | TLV 0x30 not mentioned as not found | LOW | Add note that it was not found in PCAPs |
| 7 | Section 5.1 | TPKT detected by Wireshark mentioned as "possible dissector misinterpretation" without investigation | MEDIUM | Investigate whether TPKT is dissector artifact or real protocol |
| 8 | Section 10 | Does not mention alternative UDP/9993 sizes (33, 28, 99 bytes) | MEDIUM | Add complete size distribution |
| 9 | Section 3 | Does not mention UDP/47836 keepalive in `radmin-connect.pcapng` | LOW | Add keepalive timeline to connection capture |
| 10 | Section 13 | Does not specify STUN uses non-standard Radmin ports (not 3478) | MEDIUM | Explicitly list ports 17309, 17341, 17342, 17357, 17358 |
| 11 | Section 6.2 | STUN response size stated as 98 bytes (confuses frame.len with UDP payload) | MEDIUM | Clarify: 56 bytes UDP payload, 98 bytes Ethernet frame |
| 12 | Section 13 | Claims standard RFC 5389 STUN with magic cookie; actual packets have no magic cookie and 16-byte TXID | CRITICAL | Reclassify as non-standard STUN variant |

### 8.2 Detailed Corrections

**#1 — UDP/9993 Message Size Error (CRITICAL):** Frame 116 of `radmin-mine.pcapng` (interface 1): frame.len=179, udp.length=145, UDP payload=137 bytes. Report documents only first 120 bytes (0x00–0x77); last 17 bytes (0x78–0x8a) not described. Extend offset table with bytes 0x78–0x8a (`00 00`, `00 08 ea c9`, `0a 00`, `00`, `00 01 94 db 79 5b`, `4e`, `0b`, `2c` — mostly INCONCLUSIVE) or revise declared size to 120 bytes.

**#2 — Endianness of Field 0x0004 (MEDIUM):** Frame 116 offset 0x71–0x74: `1a ac b2 4f` = 26.172.178.79 big-endian; 0x75–0x76: `27 09` = 9993 big-endian. Frame 127 offset 0x71–0x74: `b1 70 4f e2` = [IP_PUBLICO_MASCARADO] big-endian; 0x75–0x76: `27 09` = 9993 big-endian. Specify big-endian (network byte order) for IP and port; correct offset from 0x5e to 0x6f.

**#3 — Missing Server 45.162.230.182:17351 (LOW):** `radmin_vm.pcap`: TCP connections to 45.162.230.182:17351 (frames 5483–5528). Add as alternative control server entry.

**#4 — Public IP Not Masked (CRITICAL — Privacy):** `[IP_PUBLICO_MASCARADO]` appears in high-volume flow (10,156 packets, 3.1 MB) in `radmin-mine-host.pcapng`. Replace all occurrences. Status: corrected in `docs/PCAP_FORENSICS_REPORT.md` version (7 occurrences replaced).

**#5 — Relay as HYPOTHESIS Without Specific Flow (LOW):** Flow `192.168.15.15:43139 ↔ [IP_PUBLICO_MASCARADO]:58358` (UDP, 10,156 packets, 3.1 MB) may be relay but no direct evidence it is a Radmin relay server. Keep as HYPOTHESIS; add: uses port 58358 (not 9993), no TLV structure in first bytes, could be another service/background app.

**#6 — TLV 0x30 Not Found (LOW):** Exhaustive search of all 6 PCAPs found no 192-byte field associated with tag `0x30`. Add note: TLV `0x30` 192-byte field from previous static RE reports not found in any PCAP; may be present only in initial handshake (not captured) or message types not observed.

**#7 — TPKT Detected by Wireshark (MEDIUM):** Wireshark TPKT dissector may incorrectly interpret encrypted payload first bytes as TPKT header (ISO 8073). Disable TPKT dissector and re-analyze raw data.

**#8 — Alternative UDP/9993 Sizes (MEDIUM):** Complete size distribution across all PCAPs: 28 (82), 33 (223), 37 (38), 59 (30), 67 (20), 93 (28), 99 (74), 114 (28), 137 (93), 149 (16), 215 (27), 247 (12), 249 (8), 309 (12), 369 (14), 629 (6), 641 (3).

**#9 — UDP/47836 Keepalive in Connection Capture (LOW):** `radmin-connect.pcapng` frames 312–1287: keepalive UDP/47836 with sequential counter (0x9e–0xac) between 26.228.88.155 and 26.239.229.134.

**#10 — Non-Standard STUN Ports (MEDIUM):** STUN observed on Radmin-specific ports: 17309, 17310, 17341, 17342, 17347, 17348, 17349, 17357, 17358. No observation on standard STUN port 3478.

**#11 — STUN Response Size Confusion (MEDIUM):** Frame 5489: frame.len=98, udp.length=64, UDP payload=56 bytes. Clarify: 56 bytes UDP payload, 98 bytes Ethernet frame; do not conflate.

**#12 — Non-Standard STUN Protocol (CRITICAL):** Frame 5477 raw UDP payload (20 bytes): `00 01 00 00 24 df 38 03 cb e7 64 ea 10 67 38 b6 1d 31 4c 66`. Type `00 01` (Binding Request), Length `00 00`, Transaction ID 16 bytes `24 df 38 03 cb e7 64 ea 10 67 38 b6 1d 31 4c 66`, **no magic cookie**. RFC 5389 would have magic cookie 0x2112A442 and 12-byte TXID. Reclassify as non-standard STUN variant; standard STUN libraries may not work without modification.

### 8.3 Corrections Not Applied (Insufficient Evidence)

| # | Potential Correction | Reason Not Applied |
|---|---------------------|--------------------|
| A | Reclassify UDP/9993 as encrypted | No keys to verify; encrypted appearance is not proof |
| B | Identify encryption algorithm | No reference material or keys |
| C | Classify NAT type | Single STUN response insufficient |
| D | Confirm relay for [IP_PUBLICO_MASCARADO]:58358 | No evidence it is Radmin server |
| E | Confirm handshake `00 00 00 04 03 00 00 00` | Does not appear in any capture |
| F | Correct STUN magic cookie claim | See Correction #12 |
| G | Correct STUN transaction ID size | See Correction #12 |

### 8.4 New Documents Generated (original not modified)

`docs/PCAP_FORENSICS_DEEP_DIVE.md`, `docs/PCAP_MESSAGE_CATALOG.md`, `docs/PCAP_FLOW_MAP.md`, `docs/PCAP_IMPLEMENTATION_READINESS.md`, `docs/PCAP_PREVIOUS_REPORT_CORRECTIONS.md` (this corrections document), `docs/PCAP_THIRD_ROUND_AUDIT.md`.

## 9. Validation Discrepancies

The validation-discrepancy topic is represented in the consumed sources by the Phase 2.5 stage-02 report-inventory validation matrix (Section 4.5 above), which validates each Phase 2.4 report against Phase 2.5 static re-analysis evidence, and by the Phase 2.7/2.8 timeline conflicts (Section 5) where file timestamps contradict claimed UTC timestamps (local UTC-3 vs claimed UTC; all reports written ~06:00–06:08 UTC in a single session). No separate validation-discrepancies source exists among the 12 RECONCILIATION-mapped files; validation-relevant items are consolidated in Sections 4.5 and 5.

## 10. Supersession Decisions

| Conflict | Documents Involved | Winning Document | Rationale |
|----------|-------------------|------------------|-----------|
| Table base (0x0051FFBC vs 0x0051FFAC) | Phase 2 Report 04 vs Phase 2.3 Report 18 (`docs/PHASE_2_3/02_PHASE_2_2_CONTRADICTION_MATRIX.md`, `docs/PHASE_2_3/15_HISTORICAL_RECONCILIATION.md`) | **Phase 2.3 Report 18 / Report 15** | Raw byte extraction shows constructor writes 0x51FFB4 to [EDI+0x00]; 0x51FFBC is slot 4, not base. Base confirmed 0x0051FFAC. |
| [EAX+0x58] / [EAX+0x34] indirect-call targets | Phase 2 Report 04 vs Phase 2.3 Report 15 vs Phase 2.5 Report 05 | **Phase 2.5 Report 05** (`docs/PHASE_2_5/15_PHASE_2_4_CORRECTION_MATRIX.md`) | vptr = 0x51FFB4 (actual constructor-written value), not nominal table base 0x51FFAC. Corrected matrix in Section 4.3. |
| field_0x30 writer | Phase 2 Report 04 vs Phase 2.3 Reports 02/15 | **Phase 2.3 Reports 02 and 15** | FUN_00410E80 and FUN_00410F60 also write MOV [EDI+0x30], 0x0; verified via raw bytes `C7 47 30 00 00 00 00`. |
| field_0x214 writer | Phase 2.1 vs Phase 2.3 Reports 02/15 | **Phase 2.3 Reports 02 and 15** | No `C7 47 214` anywhere; field_0x214 has no confirmed writers or readers. |
| FUN_00473210 semantics | Phase 2.4 Report 07 vs Phase 2.5 Reports 07/15 | **Phase 2.5 Reports 07 and 15** | FUN_00473210 analyzed: destroy/reset (sets obj+0x20 to 0, exchanges obj+0x24, deletes critical section), not decrement-and-destroy-if-zero Release. |
| Object lifecycle | Phase 2.4 Report 11 vs Phase 2.5 Report 11 | **Phase 2.5 Report 11** | Destroy-on-read-nonzero pattern, not standard COM AddRef/Release; no AddRef found. |
| Subinitializer count | Phase 2.4 Report 10 ("8") vs Phase 2.5 Reports 10/15 ("9") | **Phase 2.5 Reports 10 and 15** | Nine addresses listed; 9 unanalyzed sub-initializers, not 8. |
| 0x500CA6 nature | Phase 2.4 Report 08 (.data/gap) vs Phase 2.5 Reports 05/08/15 (.text) | **Phase 2.5 Reports 05, 08, 15** | 0x500CA6 in .text (VA 0x401000–0x519000); entry of `free` function; DWORD there = 0x8B55FF8B, not a valid pointer. |
| Phase 2.7 timeline | Phase 2.7 Report 07 vs Phase 2.8 Report 02 | **Phase 2.8 Report 02** (`docs/PHASE_2_8/02_PHASE_2_7_TIMELINE_RECONCILIATION.md`) | Report 07 written retrospectively with mismatched UTC/local timestamps; file metadata and report content support the Section 5.4 reconstructed order (baseline before connection). |
| FUN_00420b80 callers | Phase 9C (`phase_9C_discrepancy_log.md`) vs Phase 9D (`phase_9D_discrepancy_log.md`) | **Phase 9D D-201** | `xref.py callers 00420b80` → 2 direct E8 callsites (`FUN_0041f450 @ 0041f6bd`, `FUN_00420b30 @ 00420b52`); reclassified UNKNOWN → CONDITIONAL. |
| Crypto k multiplier | Rust `k=3` vs shelper.dll dynamic | **shelper.dll evidence** (`docs/CRYPTO_PHASE_10_10_RECONCILIATION.md`) | k = SHA-1(N||PAD192(g)) computed dynamically; k=3 code (FUN_100607d0) is dead code unreferenced by SRP-6a descriptors. |
| Identity encoding | Rust UTF-8 vs shelper.dll UTF-16LE | **shelper.dll evidence** (`docs/CRYPTO_PHASE_10_10_RECONCILIATION.md`) | compute_srp_x hashes identity as UTF-16LE raw bytes (obj+0x8); `0x10060340` client / `0x10060c80` server. |
| PCAP report corrections | `docs/PCAP_FORENSICS_REPORT.md` vs `docs/PCAP_PREVIOUS_REPORT_CORRECTIONS.md` | **`docs/PCAP_PREVIOUS_REPORT_CORRECTIONS.md`** as corrections layer; original PCAP_FORENSICS_REPORT.md NOT modified | Corrections document preserves original; original remains as historical evidence. Corrections #1–#12 applied as recommendations; #A–#G not applied (insufficient evidence). |

Standing rule across all supersession decisions: superseded reports remain as historical evidence and are NOT modified, deleted, or overwritten (per Phase 2.3 Report 15 Section 6 and Phase 2.4 Report 15 Section 6).

## 11. Sources

All 12 sources read (first column `RECONCILIATION` in `analysis_workspace/compaction/mapping.tsv`), in mapping order:

1. `docs/CRYPTO_PHASE_10_10_RECONCILIATION.md` — Phase 10.9/10.10 crypto lifecycle reconciliation (SRP-6a, dynamic k, UTF-16LE identity, AES key split unresolved).
2. `docs/PCAP_PREVIOUS_REPORT_CORRECTIONS.md` — PCAP previous-report corrections (#1–#12, not-applied #A–#G) for `docs/PCAP_FORENSICS_REPORT.md`.
3. `docs/PHASE_2_3/02_PHASE_2_2_CONTRADICTION_MATRIX.md` — Phase 2.2 contradiction matrix (C1, C2, C3, C5; field writer/reader inventories).
4. `docs/PHASE_2_3/15_HISTORICAL_RECONCILIATION.md` — Phase 1/2 historical reconciliation (claims 1–13; preserved contradictions table; authoritative finding IDs).
5. `docs/PHASE_2_3/CHECKPOINT_01_REPORT_RECONCILIATION.md` — Report reconciliation checkpoint (C1–C5 statuses).
6. `docs/PHASE_2_4/02_PHASE_2_3_FINDINGS_RECONCILIATION.md` — Phase 2.3 findings reconciliation (report inventory; confirmed findings; unresolved questions Q1–Q8; contradictions C1–C8; workstream mapping).
7. `docs/PHASE_2_4/15_PHASE_2_3_CONTRADICTION_RESOLUTION.md` — Phase 2.3 contradiction resolution (C1–C8 resolutions; new contradictions N1–N4; detailed C3/C4/C5/C8).
8. `docs/PHASE_2_5/02_PHASE_2_4_FINDING_RECONCILIATION.md` — Phase 2.4 finding reconciliation (report status matrix; corrections C1–C7; confirmed findings; reports requiring updates).
9. `docs/PHASE_2_5/15_PHASE_2_4_CORRECTION_MATRIX.md` — Phase 2.4 correction matrix (14 corrections C1–C14; corrected dispatch matrix; corrected object lifecycle; reports requiring updates).
10. `docs/PHASE_2_8/02_PHASE_2_7_TIMELINE_RECONCILIATION.md` — Phase 2.7 vs 2.8 timeline reconciliation (conflicts C1–C5; reconstructed timeline; file-timestamp evidence; unresolvable items).
11. `docs/analysis_workspace/phase_9C_audit/phase_9C_discrepancy_log.md` — Phase 9C discrepancy log (D-01–D-18).
12. `docs/analysis_workspace/phase_9D_audit/phase_9D_discrepancy_log.md` — Phase 9D discrepancy log (D-201–D-216; incl. FUN_00420b80 D-201; summary of Phase-9D-discovered Phase-9C errors).

## Provenance note

This document was produced by the Docs subagent for task 1.11 (consolidate the RECONCILIATION document). It consumes exactly the 12 `mapping.tsv` rows whose first column is `RECONCILIATION`; no other files were read, and no other files were written. All contradiction/correction IDs (C1–C13, D-201–D-216, N1–N4, Q1–Q8), wrong claims, corrected claims, addresses, raw bytes, evidence citations, and confidence levels are transcribed from the source documents without invention. Where a source marks an item UNRESOLVED, UNKNOWN, or OPEN, this record preserves that status rather than asserting a resolution. Repeated matrices (e.g. the vptr/0x500CA6/FUN_00473210/subinitializer corrections appearing in both Phase 2.5 Report 02 and Report 15) are presented once under Section 4 with cross-references; no correction item is dropped. The `## Sources` section lists every source read. English prose throughout; no code changes; no speculation beyond what the sources state as hypothesis.

---

## Evidence appendix (exact tokens from consolidated sources)

Exact addresses, hashes and identifiers from the consolidated sources that are not repeated in the prose above. They are preserved here so that no evidence anchor is lost during compaction; the full narrative for each source remains available in git history.

- `docs/PHASE_2_3/02_PHASE_2_2_CONTRADICTION_MATRIX.md`: `0x404936`, `0x410eb6`, `0x410f96`, `0x41414e`, `0x414155`, `0x4143de`, `0x4143e5`, `0x418972`, `0x418b2e`, `0x44f513`, `0x44f5bc`, `0x45a15a`, `0x45ae1a`, `0x45e151`, `0x45e1e8`, `0x462705`, `0x464901`, `0x465069`, `0x474413`, `0x474438`, `0x479c8d`, `0x479c94`, `0x4820af`, `0x4b1358`, `0x4b1372`, `0x4e085f`, `0x51bf58`, `0x51bf64`, `0x51c9e4`, `0x51ceb8`, `fun_00418950`, `fun_0045a0a0`, `fun_0045ad60`, `fun_0045e130`, `fun_004626a0`, `fun_004648e0`, `fun_00464fe0`, `fun_00474370`, `fun_004b1320`
- `docs/PHASE_2_3/15_HISTORICAL_RECONCILIATION.md`: `0x0011e9bc`, `0x0011ffbc`, `0x00400000`, `0x44f40a`, `0x44f4ee`, `0x44f4f4`, `0x44f519`, `0x44f5aa`, `0x44f5b6`
- `docs/PHASE_2_4/02_PHASE_2_3_FINDINGS_RECONCILIATION.md`: `0x44f501`, `0x44f50d`, `0x4ec736`, `fun_0043a9a0`, `fun_00451090`, `fun_004802f0`, `fun_004e7ec0`, `fun_004ec736`
- `docs/PHASE_2_5/02_PHASE_2_4_FINDING_RECONCILIATION.md`: `0x43e881`, `0x44f4ee`, `0x44f4f4`, `fun_004e7ec0`
