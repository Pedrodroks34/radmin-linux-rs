# Phase 2.4 Stage 14 — Authoritative Finding Registry

**Classification: VERIFIED** (all findings traceable to static evidence)

## 1. Finding ID Format

`P2.4-{CATEGORY}-{NNN}`

Categories:
- `ALOC` — Allocation
- `CTOR` — Constructor
- `DEST` — Destruction / deallocation
- `REF` — Reference counting
- `VT` — VTable / pointer table
- `ICALL` — Indirect call
- `FIELD` — Object field
- `RUST` — Rust compatibility
- `BLOCK` — Blocked / unresolved
- `UNK` — Unknown

## 2. Registry

| ID | Technical Claim | Supporting Evidence | Contradicting Evidence | Confidence | Affected Functions | Affected Offsets | Related Reports | Rust Relevance | Open Questions |
|----|----------------|---------------------|------------------------|------------|-------------------|-----------------|-----------------|----------------|----------------|
| P2.4-ALOC-001 | HeapAlloc/HeapFree/HeapReAlloc/HeapSize/GetProcessHeap imported from KERNEL32.dll | PE import table (REA inspect_pe_imports) | None | CONFIRMED | N/A | N/A | 04, 21 | HeapAlloc→Box::new, HeapFree→Drop | Exact allocation call site not found |
| P2.4-ALOC-002 | RolClient_AllocMemory/RolClient_FreeMemory imported from RvROLClient.dll | PE import table | None | CONFIRMED | N/A | N/A | 04, 21 | RolClient_AllocMemory→custom allocator | Exact allocation call site not found |
| P2.4-ALOC-003 | No malloc/operator new/CoTaskMemAlloc/VirtualAlloc imported | PE import table | None | CONFIRMED | N/A | N/A | 04, 21 | None | N/A |
| P2.4-CTOR-001 | FUN_0043E1A0 is 853-byte constructor with 36 blocks | REA procedure_info | None | CONFIRMED | FUN_0043E1A0 | 0x00 | 03, 04 | fn new() + explicit init | External callers not found |
| P2.4-CTOR-002 | Constructor writes vptr 3×: 0x51FFB4→0x51E570→0x51E4F0 | Raw bytes at 0x43E1B1, 0x43E4C8, 0x43E4E8 | None | CONFIRMED | FUN_0043E1A0 | 0x00 | 03, 05 | Not applicable (Rust rejects) | Which vptr active at runtime |
| P2.4-CTOR-003 | 5 adjustment thunks at 0x43E85E–0x43E881 | Raw bytes verified | None | CONFIRMED | 5 thunks | N/A | 04 | Not applicable (Rust rejects) | No callers found |
| P2.4-CTOR-004 | Subobject vptrs at 0x38, 0x40, 0x50, 0x98, 0x9C | Raw bytes verified | None | CONFIRMED | FUN_0043E1A0 | 0x38, 0x40, 0x50, 0x98, 0x9C | 03, 10 | Not applicable | Vtable overwrite purpose unknown |
| P2.4-DEST-001 | FUN_004731E0 = Release() with atomic LOCK/UNLOCK read at obj+0x20 | REA procedure_pseudo_code at 0x4731E0 | None | STRONGLY SUPPORTED | FUN_004731E0 | 0x20 | 07, 22 | Arc<T> drop = Release | FUN_00473210 not analyzed |
| P2.4-DEST-002 | Destruction chain: FUN_004e6cd7 → thunk → FUN_004ec736 → CALL [0x500ca6] | REA procedure_pseudo_code (multiple functions) | None | STRONGLY SUPPORTED | FUN_004e6cd7, FUN_004ec736 | N/A | 07, 08, 22 | Drop::drop() | [0x500ca6] target unknown |
| P2.4-DEST-003 | 5 list cleanup functions all call FUN_004e6cd7 per node | REA procedure_pseudo_code (5 functions) | None | CONFIRMED | 5 cleanup functions | N/A | 07, 10 | Vec<Arc<T>> drop | None |
| P2.4-DEST-004 | FUN_004E7EC0 = 5-byte thunk JMP 0x4ec736 | REA procedure_info at 0x4e7ec0 | None | CONFIRMED | FUN_004E7EC0 | N/A | 20, 22 | Not applicable | None |
| P2.4-REF-001 | Refcount at obj + 0x20 | FUN_004731E0 instruction operand | None | CONFIRMED | FUN_004731E0 | 0x20 | 06, 07 | AtomicUsize in Arc<T> | AddRef not found |
| P2.4-REF-002 | AddRef function not identified | Static search complete | None | UNKNOWN | N/A | 0x20 | 07 | Arc::clone() = AddRef | Search for increment at obj+0x20 |
| P2.4-REF-003 | FUN_00473210 referenced but not analyzed | FUN_004731E0 calls it | None | UNKNOWN | FUN_00473210 | N/A | 07 | Decrement-and-destroy-if-zero | Analyze FUN_00473210 body |
| P2.4-VT-001 | Table A base = 0x0051FFAC (40 slots) | Raw byte extraction | None | CONFIRMED | N/A | 0x00 | 05, 08 | Not applicable (Rust rejects) | Table sharing across object types |
| P2.4-VT-002 | Table B = 0x0051E570, Table C = 0x0051E4F0 | Raw byte extraction | None | CONFIRMED | N/A | 0x00 | 05, 08 | Not applicable | Non-.text slots purpose unknown |
| P2.4-ICALL-001 | FUN_0044F3F0 calls [EAX+0x34] (slot 13) and [EAX+0x58] (slot 22) | Raw bytes at 0x44F501, 0x44F50D, 0x44F5AA, 0x44F5B6 | None | CONFIRMED | FUN_0044F3F0 | N/A | 05 | match-based dispatch | Actual targets at runtime unknown |
| P2.4-ICALL-002 | Guard: field_0x28==5 && field_0x2C!=0 | Raw bytes at 0x44F4EE, 0x44F4F4 | None | CONFIRMED | FUN_0044F3F0 | 0x28, 0x2C | 05, 06 | Enum state machine | Whether guard ever satisfied |
| P2.4-FIELD-001 | field_0x28 has 17 writers across 15 functions | Byte search + instruction analysis | None | CONFIRMED | 15 functions | 0x28 | 04, 06 | Not applicable (use enum) | Initial value unknown |
| P2.4-FIELD-002 | field_0x2C has 7 writers across 7 functions | Byte search + instruction analysis | None | CONFIRMED | 7 functions | 0x2C | 04, 06 | Not applicable (use bool/Option) | Initial value unknown |
| P2.4-FIELD-003 | field_0x30 incremented in FUN_0044F3F0, init to 0 by FUN_00410E80/FUN_00410F60 | Instruction analysis | None | CONFIRMED | FUN_0044F3F0, FUN_00410E80, FUN_00410F60 | 0x30 | 04, 06 | AtomicU64 | Purpose unknown |
| P2.4-FIELD-004 | field_0x214: no writes found anywhere | Byte search for C7 47 214 | None | REFUTED | N/A | 0x214 | 04 | Not applicable | N/A |
| P2.4-DEAL-001 | CALL [0x00500ca6] is final deallocation | FUN_004ec736 pseudocode | None | CONFIRMED (call exists), UNKNOWN (target) | FUN_004ec736 | N/A | 08 | Custom Drop deallocator | Actual target function unknown |
| P2.4-BLOCK-001 | Runtime vptr state at FUN_0044F3F0 | No Windows debugger available | None | BLOCKED | FUN_0044F3F0 | 0x00 | 05 | Not applicable | Need Windows debugger |
| P2.4-BLOCK-002 | Object allocation site | No HeapAlloc/RolClientAllocMemory call found | None | BLOCKED | N/A | N/A | 04 | Box::new / custom allocator | Need factory function or allocation call |
| P2.4-BLOCK-003 | Object actual allocation size | No allocation size argument observed | None | BLOCKED | N/A | N/A | 04, 09 | Box<T> size | Need allocation call |
| P2.4-BLOCK-004 | Runtime indirect call targets | No execution trace | None | BLOCKED | FUN_0044F3F0 | N/A | 05 | match dispatch | Need Windows debugger |
| P2.4-RUST-001 | Daemon module exists but is mock/stub | src/daemon/mod.rs inspection | None | CONFIRMED | src/daemon/mod.rs, src/daemon/ipc.rs | N/A | 13 | Not applicable | Real networking not implemented |
| P2.4-RUST-002 | SessionState enum implemented | src/session/mod.rs inspection | None | CONFIRMED | src/session/mod.rs | N/A | 12, 13 | Session state machine | Not verified against Windows binary |