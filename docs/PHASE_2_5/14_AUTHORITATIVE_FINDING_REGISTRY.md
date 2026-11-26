# Phase 2.5 Stage 14 — Authoritative Finding Registry

**Classification: VERIFIED** (all findings traceable to static REA/Ghidra evidence)

## 1. Finding ID Format

`P2.5-{CATEGORY}-{NNN}`

Categories:
- `ALOC` — Allocation
- `CTOR` — Constructor
- `DEST` — Destruction / deallocation
- `REF` — Reference counting
- `VT` — VTable / pointer table
- `ICALL` — Indirect call
- `FIELD` — Object field
- `PE` — PE section / address
- `RUST` — Rust compatibility
- `BLOCK` — Blocked / unresolved
- `UNK` — Unknown
- `CORR` — Correction of Phase 2.4

## 2. Registry

| ID | Technical Claim | Supporting Evidence | Contradicting Evidence | Confidence | Affected Functions | Affected Offsets | Related Reports | Rust Relevance | Open Questions |
|----|----------------|---------------------|------------------------|------------|-------------------|-----------------|-----------------|----------------|----------------|
| P2.5-CORR-001 | Table A base is NOT the vptr; vptr = 0x51FFB4 | Raw bytes at 0x43E1B1 (C7 03 B4 FF 51 00) | Phase 2.4 Report 05 used table base 0x51FFAC | CONFIRMED | FUN_0043E1A0, FUN_0044F3F0 | 0x00 | 03, 04, 05 | Not applicable (Rust rejects vtables) | Which vptr active at runtime |
| P2.5-CORR-002 | Table B slot 22 at 0x51E5C8 (not 0x51E5C4) | Arithmetic: 0x51E570 + 0x58 = 0x51E5C8 | Phase 2.4 Report 05 listed 0x51E5C4 | CONFIRMED | FUN_0044F3F0 | 0x58 | 05 | Not applicable | None |
| P2.5-CORR-003 | Table C slot 22 at 0x51E548 (not 0x51E544) | Arithmetic: 0x51E4F0 + 0x58 = 0x51E548 | Phase 2.4 Report 05 listed 0x51E544 | CONFIRMED | FUN_0044F3F0 | 0x58 | 05 | Not applicable | None |
| P2.5-CORR-004 | Table A slot 13 at 0x51FFE8 → 0x4510A0 | REA read_bytes at 0x51FFE8: A0 10 45 00 | Phase 2.4 Report 05 listed 0x51FFE0 → 0x451010 | CONFIRMED | FUN_0044F3F0 | 0x34 | 05 | match dispatch | Whether guard satisfied |
| P2.5-CORR-005 | Table A slot 22 at 0x52000C → 0x450FA0 | REA read_bytes at 0x52000C: A0 0F 45 00 | Phase 2.4 Report 05 listed 0x520004 → 0x451070 | CONFIRMED | FUN_0044F3F0 | 0x58 | 05 | match dispatch | FUN_00450FA0 body not analyzed |
| P2.5-CORR-006 | Table B slot 22 at 0x51E5C8 → 0x450FC0 | REA read_bytes at 0x51E5C8: C0 0F 45 00 | Phase 2.4 Report 05 listed 0x51E5C4 → 0x451090 | CONFIRMED | FUN_0044F3F0 | 0x58 | 05 | match dispatch | FUN_00450FC0 body not analyzed |
| P2.5-CORR-007 | Table C slot 22 at 0x51E548 → 0x450FC0 | REA read_bytes at 0x51E548: C0 0F 45 00 | Phase 2.4 Report 05 listed 0x51E544 → 0x451090 | CONFIRMED | FUN_0044F3F0 | 0x58 | 05 | match dispatch | FUN_00450FC0 body not analyzed |
| P2.5-PE-001 | 0x500CA6 is in .text, not .data | REA binary_overview: .text VA 0x401000–0x519000; 0x500CA6 in range | Phase 2.4 Report 08 claimed .data or gap | CONFIRMED | N/A | N/A | 05, 08 | Not applicable | None |
| P2.5-PE-002 | 0x500CA6 contains `free` function code | REA read_bytes: 8B FF 55 8B EC... (function prologue); Ghidra: FID_conflict:_free | Phase 2.4 Report 08 hypothesized IAT slot | CONFIRMED | FUN_004ec736 | N/A | 08 | `Drop` deallocator | CALL [0x500CA6] reads code as pointer — anomalous |
| P2.5-PE-003 | File offset of 0x500CA6 is 0x1000A6 | Computed: 0x400 + (0x100CA6 − 0x1000) = 0x1000A6 | Not previously calculated | UNVERIFIED | N/A | N/A | 05 | Not applicable | Not verified against raw file |
| P2.5-REF-001 | FUN_00473210 is destroy/reset, not Release | REA procedure_pseudo_code at 0x473210: sets obj+0x20 to 0, exchanges obj+0x24 | Phase 2.4 Report 07 claimed "decrement-and-destroy-if-zero" | CONFIRMED | FUN_00473210, FUN_004731E0 | 0x20, 0x24 | 07 | Arc<T> drop | AddRef not found |
| P2.5-REF-002 | FUN_00473210 calls DeleteCriticalSection(obj+8) | REA procedure_pseudo_code; FUN_00489750 = DeleteCriticalSection wrapper | None | CONFIRMED | FUN_00473210, FUN_00489750 | 0x08 | 06, 07 | Mutex drop | None |
| P2.5-REF-003 | AddRef not found | Searched all 13 analyzed functions; no INC/ADD/XADD on obj+0x20 | Phase 2.4 Report 07 claimed AddRef unknown | CONFIRMED (absence) | N/A | 0x20 | 07 | Arc::clone() | Search 9 unanalyzed sub-initializers |
| P2.5-FIELD-001 | obj+0x20 not initialized by constructor | Full constructor disassembly reviewed; no write to 0x20 | Phase 2.4 Report 06 assumed initialization | CONFIRMED | FUN_0043E1A0 | 0x20 | 06, 08 | Default::default() | Who initializes obj+0x20? |
| P2.5-FIELD-002 | obj+0x28 not initialized by constructor | Full constructor disassembly reviewed; no write to 0x28 | Phase 2.4 Report 06 assumed initialization | CONFIRMED | FUN_0043E1A0 | 0x28 | 06, 08 | Enum state machine | Who initializes obj+0x28? |
| P2.5-FIELD-003 | obj+0x2C not initialized by constructor | Full constructor disassembly reviewed; no write to 0x2C | Phase 2.4 Report 06 assumed initialization | CONFIRMED | FUN_0043E1A0 | 0x2C | 06, 08 | Enum/bool | Who initializes obj+0x2C? |
| P2.5-FIELD-004 | field_0x30 initialized to 0 by FUN_00410E80/FUN_00410F60 | Phase 2.4 Report 04 data | None | CONFIRMED | FUN_00410E80, FUN_00410F60 | 0x30 | 04, 06 | Atomic counter | None |
| P2.5-ALOC-001 | No allocation call site found | Searched constructor, wrapper, thunks, 4 analyzed sub-initializers | Phase 2.4 Report 04 claimed unknown | CONFIRMED (absence) | N/A | N/A | 04, 09, 11 | Box::new / Arc::new | Find factory or allocation call |
| P2.5-CTOR-001 | 9 sub-initializers not analyzed (not 8) | Phase 2.4 Report 10 listed 9 addresses but said "eight" | Phase 2.4 Report 10 count error | CONFIRMED | 9 sub-initializers | N/A | 09, 10 | Not applicable | Analyze 9 sub-initializers |
| P2.5-BLOCK-001 | Object allocation site | No HeapAlloc/RolClientAllocMemory call found | None | BLOCKED | N/A | N/A | 04, 09, 11 | Box::new | Windows debugger needed |
| P2.5-BLOCK-002 | Object allocation size | No allocation size argument observed | None | BLOCKED | N/A | N/A | 04, 09 | Box<T> size | Windows debugger needed |
| P2.5-BLOCK-003 | Runtime vptr state | No execution trace available | None | BLOCKED | FUN_0044F3F0 | 0x00 | 03, 05 | Not applicable | Windows debugger needed |
| P2.5-BLOCK-004 | Indirect call targets at runtime | No execution trace available | None | BLOCKED | FUN_0044F3F0 | N/A | 04, 05 | match dispatch | Windows debugger needed |
| P2.5-BLOCK-005 | CALL [0x500CA6] actual target | DWORD at 0x500CA6 = 0x8B55FF8B (not valid pointer) | Phase 2.4 Report 08 hypothesized HeapFree/RolClientFreeMemory | BLOCKED | FUN_004ec736 | N/A | 08 | Drop deallocator | Windows debugger needed |
| P2.5-RUST-001 | Daemon module is mock/stub | src/daemon/mod.rs inspection | Phase 2.4 Report 13 claimed consistent | CONFIRMED | src/daemon/mod.rs, src/daemon/ipc.rs | N/A | 13 | Not applicable | Real networking not implemented |