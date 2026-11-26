# Phase 2.5 Stage 19 — Unresolved Questions and Next Evidence

**Classification: HONEST DOCUMENTATION** — every question that remains unresolved after this phase is listed, with the evidence already inspected, the exact next evidence required, and a priority. No hypothesis is presented as fact.

Cross-reference: all reports 01–18, especially `02_PHASE_2_4_EVIDENCE_RECONCILIATION.md`, `07_INDIRECT_DEALLOCATION_CALL_CHAIN.md`, `09_FUN_004731E0_AND_REFERENCE_COUNT_PAIRING.md`, `12_ALLOCATION_AND_FACTORY_CALL_GRAPH.md`, `14_DESTRUCTION_AND_DEALLOCATION_ANALYSIS.md`, `15_COMPLETE_OBJECT_LIFECYCLE_RECONSTRUCTION.md`.

---

## 1. Unresolved Question Register

| # | Question | Classification | Evidence already inspected | Why unresolved | Exact next evidence required | Priority |
|---|----------|----------------|---------------------------|----------------|------------------------------|----------|
| U1 | Object allocation call site (which function allocates `ObjectCandidate`, with what size) | BLOCKED | Constructor `FUN_0043E1A0`/`FUN_0043ECF0` and all 5 thunks and analyzed sub-initializers contain no `HeapAlloc`/`GetProcessHeap`/`RolClient_AllocMemory` call (Reports 04, 12). Allocator APIs imported but unused in object path. | No function in the analyzed constructor path allocates storage; constructor takes `this` in ECX (caller supplies it). The caller/factory is unidentified. | Find the caller of `FUN_0043ECF0`/`FUN_0043E1A0` or the factory that calls `HeapAlloc`/`RolClient_AllocMemory` then invokes the constructor. Whole-program caller analysis or a breakpoint at `HeapAlloc`/`RolClient_AllocMemory` capturing the return address. | High |
| U2 | Object actual allocation size | BLOCKED | Constructor initializes through `0x5C40` (minimum init extent); zeroing loop `0x0C`–`0x4C4` (Reports 04, 12). | `0x5C40` is the highest initialized offset, not the allocation size; no `HeapAlloc(size)` argument observed. | The allocation call site's size argument (depends on U1). | High |
| U3 | Runtime-active vptr at `FUN_0044F3F0` (Table A/B/C?) | BLOCKED | Constructor writes 3 vptrs (Report 05); `FUN_0044F3F0` has no direct callers (Report 02 R9). | Cannot determine which constructor stage's vptr is live at dispatch without execution. | Breakpoint at `0x44F3F0`, inspect `[EDI]` vptr value; or identify the caller of `FUN_0044F3F0`. | High |
| U4 | Actual indirect-call targets of `[EAX+0x34]`/`[EAX+0x58]` at runtime | PARTIALLY BLOCKED | Slot addresses/targets resolved per active vptr (Reports 03, 04); Table A slot 13/22 bodies (`0x4510A0`, `0x450FA0`) and Table B/C slot 22 (`0x450FC0`) not disassembled. | Targets depend on unknown active vptr (U3); two Table-A and one Table-B/C bodies not yet read. | Disassemble `0x4510A0`, `0x450FA0`, `0x450FC0`; then determine active vptr (U3). | High |
| U5 | AddRef / increment function for `obj+0x20` | UNKNOWN | No `LOCK ADD`/`LOCK XADD`/`LOCK INC` on `obj+0x20` found; `FUN_004731E0` zeroes via `LOCK XCHG`; `FUN_00473210` zeroes via `XCHG` (Reports 08, 09, 10). | No increment path found in analyzed code; may be inlined or in unanalyzed sub-initializers. | Search all functions for writes/increments to `obj+0x20`; decompile the 8 initializer candidates' bodies; confirm whether any increment `+0x20`. | High |
| U6 | `FUN_00489750` helper role (called by `FUN_00473210` on `[this+0x8]`) | UNKNOWN | `FUN_00473210` calls `0x00489750` (Report 08); body not disassembled. | Function body not read. | Disassemble `0x00489750`. | Medium |
| U7 | Identity of free routine `0x00500CA6` (`HeapFree`? `RolClient_FreeMemory`?) | UNKNOWN | `0x00500CA6` is code in `.text` (Report 06); called directly by `FUN_004ec736`; references IAT `[0x5192EC]`, `[0x519280]` and data `[0x5581E8]` (Report 07). | `0x00500CA6` is not an IAT entry; no import name bound to it. | Identify which imported function `0x00500CA6` corresponds to, or confirm via symbols/PDB/runtime breakpoint. | Medium |
| U8 | Parent ObjectCandidate block free location | UNKNOWN | Teardown `FUN_00473210` does not itself call a free (Report 14); list nodes freed via `0x500CA6`. | Parent block free may be inside helper `0x489750` (U6) or elsewhere; not traced. | Trace `FUN_00473210` → helper `0x489750` and find the block free. | Medium |
| U9 | `obj+0x24` reader / meaning (teardown flag?) | UNKNOWN | `FUN_00473210` sets `[this+0x24]=1` via atomic XCHG (Report 08); no confirmed reader. | No read of `+0x24` found in analyzed code. | Search for reads of `obj+0x24`. | Low |
| U10 | `obj+0x28` / `obj+0x2C` writers and initial values | UNKNOWN | Phase 2.4 claimed 17 writers of `+0x28`, 7 of `+0x2C` across functions; none found in constructor; none re-verified in this phase (Reports 06, 10). | Writers not re-verified; initial values unknown. | Search all writes to `obj+0x28`/`obj+0x2C`; find initialization. | Low |
| U11 | `obj+0x30` readers (call counter incremented but never read?) | UNKNOWN | `FUN_0044F3F0` increments `+0x30` (Report 10); no confirmed read. | No read confirmed. | Search for reads of `obj+0x30`. | Low |
| U12 | Whether the 9 sub-initializers initialize any subobject of ObjectCandidate | STRONGLY SUPPORTED (unrelated) | All write vtables in `0x51BDxx`–`0x522xxx`; ObjectCandidate's subobject vptrs are `0x5200xx`/`0x51BExx`/`0x51Exx` (disjoint ranges) (Report 13). | Could still share an object not yet identified. | Confirm no ObjectCandidate subobject uses `0x522xxx` vtables. | Low |
| U13 | Whether Table A is a conventional C++ vtable (slot 0 = constructor wrapper `0x43ECF0`, not destructor) | LIKELY unconventional | Table A slot 0 = `0x0043ECF0` (constructor wrapper), not a destructor (Reports 03, 04). | Unusual for a vtable; may indicate non-standard layout. | Examine more Table A slots and their targets; compare to Table B/C. | Low |

---

## 2. Questions Resolved in This Phase (previously open, now answered)

| # | Previously open (Phase 2.4) | Resolution | Report |
|---|----------------------------|------------|--------|
| 1 | Table A nominal base vs actual vptr | Actual vptr = `0x0051FFB4`, not `0x0051FFAC`; off-by-one slot error corrected | 02, 03 |
| 2 | Table A slot 13/22 targets | Corrected: slot 13 = `0x0051FFE8`→`0x4510A0`; slot 22 = `0x52000C`→`0x450FA0` | 03, 04 |
| 3 | Table B/C slot 22 off-by-four | Corrected: slot 22 = `0x51E5C8`/`0x51E548`→`0x450FC0` (not `0x51E5C4`/`0x51E544`) | 03, 04 |
| 4 | `FUN_00473210` body | Disassembled: atomic XCHG `+0x20`=0 and `+0x24`=1 + helper `0x489750`; NOT decrement | 08 |
| 5 | `FUN_004731E0` semantics | `LOCK XCHG [obj+0x20],0` = exchange-to-zero (not decrement) | 09 |
| 6 | `CALL [0x00500CA6]` indirect slot | CORRECTED: it's `CALL 0x00500CA6` direct to a function in `.text`, not an indirect slot/IAT entry | 06, 07 |
| 7 | Nine-address vs eight-initializer discrepancy | `0x479240` is a pure JMP thunk; 8 initializer candidates + 1 thunk = 9 addresses; all UNRELATED to ObjectCandidate | 13 |
| 8 | `field_0x214` existence | Refuted (no writes anywhere) | 02 R17 |

---

## 3. Genuinely BLOCKED Items (specific static limitation)

| # | Operation needed | Why cannot be performed statically | Alternatives attempted | Can static analysis partially answer? | Minimum evidence to resolve |
|---|------------------|-----------------------------------|------------------------|--------------------------------------|-----------------------------|
| B1 | Capture runtime allocation (`HeapAlloc`/`RolClient_AllocMemory` call + size + return pointer) | No allocation call in any analyzed static path; caller unknown | Searched constructor, thunks, sub-initializers; no alloc call | Partially: constructor does not allocate; caller-supplied `this` likely | Breakpoint at `HeapAlloc`/`RolClient_AllocMemory`, capture return address → factory/caller |
| B2 | Observe active vptr at `FUN_0044F3F0` | `FUN_0044F3F0` has no direct callers; no execution trace | Static caller analysis (empty) | Partially: all 3 possible vptr states and their targets enumerated | Breakpoint at `0x44F3F0`, read `[EDI]` |
| B3 | Read memory at a runtime-populated slot / resolve indirect target at runtime | No indirect slot at `0x500CA6` (it's code); runtime call targets depend on active vptr | Disassembled `0x500CA6` (code); enumerated slot targets per vptr | Partially: all statically-possible targets enumerated | Runtime breakpoint at `0x44F501`/`0x44F50D` |

Note: "No Windows debugger" is NOT used as a blanket BLOCKED justification; only the three operations above are genuinely blocked because they require runtime state that no static evidence can produce.

---

## 4. Recommended Next Evidence-Gathering Steps (in priority order)

1. **Identify the constructor caller / factory.** Whole-program analysis to find who calls `FUN_0043ECF0` or `FUN_0043E1A0`; this likely reveals the allocation site (U1, U2).
2. **Disassemble `0x4510A0`, `0x450FA0`, `0x450FC0`** — the remaining unresolved vtable slot-13/22 bodies (U4).
3. **Search for AddRef/increment of `obj+0x20`** across all functions, including unanalyzed sub-initializers (U5) — decides `Arc` vs `Box` in Rust.
4. **Identify `0x00500CA6` free routine** via symbols/PDB or runtime breakpoint (U7).
5. **Trace `FUN_00473210` → helper `0x489750`** to find the parent block free (U6, U8).
6. (Runtime, if available) Breakpoint at `HeapAlloc`, `FUN_0043ECF0`, `0x44F3F0`, and `0x44F501`/`0x44F50D` to capture allocation, vptr state, and indirect targets (U1–U4).
