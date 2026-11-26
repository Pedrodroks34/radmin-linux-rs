# Phase 2.4 Stage 15 — Phase 2.3 Contradiction Resolution

**Classification: VERIFIED** (all resolutions based on static evidence)

## 1. Contradiction Matrix

| # | Contradiction | Reports Involved | Resolution | Status |
|---|--------------|------------------|------------|--------|
| C1 | Table base = 0x0051FFBC vs 0x0051FFAC | Phase 2 Report 04 vs Phase 2.3 Report 18 | **Resolved:** Base is 0x0051FFAC. Constructor writes 0x51FFB4 to [EDI+0x00], and 0x51FFB4 = base + 8 = slot 2. 0x51FFBC = base + 16 = slot 4. | RESOLVED |
| C2 | Destruction chain described as "fully traced" but [0x00500ca6] destination unknown | Reports 17, 22 | **Clarified:** Chain is traced TO the indirect call, but the final target is unknown. Wording in reports should say "traced to indirect call" not "fully traced." | CLARIFIED |
| C3 | FUN_00473210 described as decrement/destroy but not fully analyzed | Reports 16, 22 | **Unresolved:** FUN_00473210 body was not decompiled. Need REA procedure_info/procedure_pseudo_code at 0x473210. | UNRESOLVED |
| C4 | AddRef function never identified | Reports 16, 22 | **Unresolved:** No function found that increments refcount at obj+0x20. May be inlined or in unanalyzed code. | UNRESOLVED |
| C5 | Allocator APIs found but object allocation call site unresolved | Reports 05, 21 | **Unresolved:** HeapAlloc/HeapFree/RolClient_AllocMemory imported but no call found in constructor or sub-initializers. | UNRESOLVED |
| C6 | Object size: 0x5C40 extent vs no allocation call | Reports 05, 09, 21 | **Clarified:** 0x5C40 is the highest initialized field offset, NOT the allocation size. Actual allocation size unknown. | CLARIFIED |
| C7 | Report file count discrepancies | Report 19 vs actual directory | **Resolved:** 26 files (23 reports + 3 checkpoints). Reports 20-23 and CHECKPOINT_02 created after Report 19 was written. | RESOLVED |
| C8 | Rust daemon status inconsistent across docs | AGENTS.md, Report 17, Report 23, src/ | **Resolved:** Daemon module EXISTS and is functional as IPC server, but does NOT implement real Radmin networking. It is a mock/stub. | RESOLVED |

## 2. Detailed Resolution: C3 — FUN_00473210

**The contradiction:** Report 22 describes FUN_00473210 as "the decrement-and-destroy operation" but its complete implementation was not included in the destruction analysis.

**Current status:** FUN_00473210 at 0x473210 was referenced by FUN_004731E0 but was never analyzed via REA procedure_info/procedure_pseudo_code.

**Required action:** Run `REA procedure_info` at address 0x473210 and `REA procedure_pseudo_code` at 0x473210 to obtain its complete implementation.

**Expected behavior (hypothesis only):**
1. Atomically decrement refcount at obj + 0x20
2. If result == 0, destroy object (call list cleanup functions)
3. If result != 0, return without destruction

## 3. Detailed Resolution: C4 — AddRef

**The contradiction:** Reference-count lifecycle described as complete, but AddRef (increment) was never identified.

**Current status:** No function was found that writes/increments the refcount at obj + 0x20.

**Search approaches not yet tried:**
1. Search for `LOCK` + `ADD` or `XADD` targeting `obj + 0x20`
2. Search for functions writing to `obj + 0x20` with increment pattern
3. Search for callers of functions that modify `obj + 0x20`

**Possibility:** AddRef may be inlined at call sites, or may be in unanalyzed code.

## 4. Detailed Resolution: C5 — Object Allocation

**The contradiction:** Allocator APIs present in PE imports, but object allocation call site unresolved.

**Current status:** No `HeapAlloc` or `RolClient_AllocMemory` call found in constructor, wrapper, thunks, or sub-initializers.

**Possible explanations (all unverified):**
1. Object is stack-allocated or embedded in parent object
2. Object allocated by factory function not yet identified
3. Object allocated via `RolClient_AllocMemory` by a wrapper
4. Object is globally allocated in `.data`/`.bss`

## 5. Detailed Resolution: C8 — Rust Daemon Status

**The contradiction:** AGENTS.md says daemon = "Not implemented", but `src/daemon/mod.rs` and `src/daemon/ipc.rs` exist with substantial code.

**Resolution:** The daemon module EXISTS and compiles (presumably). It implements:
- `DaemonContext` with IPC server
- `Daemon` with start/stop lifecycle
- Unix domain socket IPC with handshake and command dispatch
- Mock behavior (hardcoded IP 26.100.200.1)

However, it does NOT implement:
- Real Radmin VPN networking
- Windows named pipe compatibility
- Actual connection to Radmin servers
- Runtime interoperability with Windows client

**Correct description:** "Daemon module exists as a functional IPC server with mock/stub behavior; no real Radmin networking implemented."

## 6. Reports Updated vs. Preserved

No Phase 2.3 reports were modified. All contradictions are documented here in Phase 2.4 report 15. Phase 2.3 reports remain as historical evidence.

## 7. New Contradictions Identified in Phase 2.4

| # | Contradiction | Reports Involved | Resolution Needed |
|---|--------------|------------------|-------------------|
| N1 | field_0x28 initial value unknown | Reports 04, 06 | Search for all writes to obj+0x28 to find initialization |
| N2 | field_0x2C initial value unknown | Reports 04, 06 | Search for all writes to obj+0x2C to find initialization |
| N3 | Multiple refcounts (obj+0x20 vs 0x1E28-0x1E50) | Reports 06, 17 | Verify whether 0x1E28-0x1E50 are also refcounts |
| N4 | [0x500ca6] slot location (section gap?) | Report 08 | VA 0x500ca6 may fall between .rdata and .data sections |