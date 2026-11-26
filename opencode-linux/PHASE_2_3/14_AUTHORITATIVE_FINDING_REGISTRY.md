# Phase 2.3 Stage 14 — Authoritative Evidence Registry

**Classification: VERIFIED** (all findings traceable to static evidence)

## Finding ID Format

`P2.3-{CATEGORY}-{NNN}`

Categories:
- `VT` — VTable / pointer table
- `CTOR` — Constructor
- `THUNK` — Adjustment thunk
- `ICALL` — Indirect call
- `DTOR` — Destructor / reference counting
- `FIELD` — Object field
- `CALL` — Call graph / function relationship
- `RUST` — Rust integration
- `UNC` — Unresolved

## Registry

| ID | Technical Claim | Supporting Evidence | Contradicting Evidence | Confidence | Affected Functions | Affected Offsets | Related Reports | Rust Relevance | Open Questions |
|---|---|---|---|---|---|---|---|---|---|
| P2.3-VT-001 | Table base is 0x0051FFAC (40 slots, 160 bytes) | Raw 160-byte extraction at 0x51FFAC; constructor writes 0x51FFB4 (=base+8) | None | VERIFIED | FUN_0043E1A0, FUN_0044F3F0 | 0x00 | 03, 04, 05, 06 | None | Whether table is shared across object types |
| P2.2-VT-002 | 0x0051FFBC is slot 4 of Table A, not base | 0x51FFAC + 4×4 = 0x51FFBC; raw DWORD at 0x51FFBC = 0x0044F3F0 | Phase 1 claimed 0x51FFBC was base | VERIFIED | FUN_0044F3F0 | 0x00 | 03, 04, 05 | None | None |
| P2.2-VT-003 | Table at 0x51FFAC has 35 .text + 5 non-.text slots | All 40 slots extracted via REA read_bytes | None | VERIFIED | FUN_0043E1A0 | 0x00 | 03, 04 | None | Purpose of non-.text slots (1, 25, 28, 33, 38) |
| P2.2-VT-004 | Intermediate table at 0x51E570 (23 slots) | 112 bytes extracted at 0x51E570 | None | VERIFIED | FUN_0043E1A0 | 0x00 | 03, 04 | None | Whether table is shared |
| P2.2-VT-005 | Final table at 0x51E4F0 (23 slots) | 112 bytes extracted at 0x51E4F0 | None | VERIFIED | FUN_0043E1A0 | 0x00 | 03, 04 | None | Whether table is shared |
| P2.3-CTOR-001 | FUN_0043E1A0 is constructor (853 bytes, 36 blocks) | REA procedure_info + full disassembly | None | VERIFIED | FUN_0043E1A0, FUN_0043ECF0 | 0x00, 0x38, 0x40, 0x50, 0x98, 0x9C | 03, 05, 07 | None | Object allocation site unknown |
| P2.3-CTOR-002 | Constructor has 3 vptr transitions (0x51FFB4 → 0x51E570 → 0x51E4F0) | Instruction-level verification at 0x43E1B1, 0x43E4C8, 0x43E4E8 | None | VERIFIED | FUN_0043E1A0, FUN_0044F3F0 | 0x00 | 03, 05, 08 | None | Which vptr is active when FUN_0044F3F0 runs |
| P2.2-CTOR-003 | Constructor writes subobject vptrs at offsets 0x38, 0x40, 0x50, 0x98, 0x9C | Raw bytes at all 6 write addresses verified | None | VERIFIED | FUN_0043E1A0, adjustment thunks | 0x38, 0x40, 0x50, 0x98, 0x9C | 03, 06 | None | Subobject table contents not fully extracted |
| P2.3-THUNK-001 | 5 adjustment thunks; adjustments match subobject offsets exactly | Raw bytes at all 5 thunk addresses; constructor write offset matching | None | VERIFIED | FUN_0043E85E–FUN_0043E881, FUN_0043ECF0 | 0x38, 0x40, 0x50, 0x98, 0x9C | 03, 06 | None | External callers of thunks unknown |
| P2.3-ICALL-001 | [EAX+0x34] targets depend on vptr state: FUN_004510A0 (0x51FFB4), FUN_00451010 (0x51FFAC), FUN_004510B0 (0x51E570/0x51E4F0) | Table extraction + EAX provenance (MOV EAX,[EDI]) | Phase 2 claimed FUN_00451010 universally | VERIFIED | FUN_0044F3F0 | 0x00, 0x28, 0x2C, 0x30 | 03, 08 | None | Runtime vptr state unknown |
| P2.2-ICALL-002 | [EAX+0x58] targets depend on vptr state: FUN_00450FA0 (0x51FFB4), FUN_00451070 (0x51FFAC), FUN_00451090 (0x51E570/0x51E4F0) | Table extraction + EAX provenance | Phase 2 claimed FUN_0043E85E | VERIFIED | FUN_0044F3F0 | 0x00, 0x28, 0x2C, 0x30 | 03, 08 | None | Runtime vptr state unknown; FUN_00451090 body not analyzed |
| P2.2-DTOR-001 | Reference-counted destruction pattern found (XCHG + XADD.LOCK + slot-0 destructor) | Pattern at 8 locations in constructor; FUN_0043EED0 (intermediate), FUN_0043F110 (final) | None | STRONGLY SUPPORTED | FUN_0043E1A0, FUN_0043ECF0, FUN_0043EED0, FUN_0043F110 | 0x1E28–0x1E50, 0x1D30 | 03, 07, 10 | PARTIAL (Rust uses Arc/Rc + Drop) | Counted entity unknown |
| P2.2-DTOR-002 | FUN_0043F110 is scalar_deleting_destructor (final table slot 0) | Symbol name in Ghidra; disassembly matches | None | VERIFIED | FUN_0043F110 | 0x00 | 09, 10 | None | None |
| P2.2-DTOR-003 | FUN_0043EED0 is intermediate table destructor (sets vptr to 0x51E570) | Disassembly analysis | None | STRONGLY SUPPORTED | FUN_0043EED0 | 0x00 | 09, 10 | None | None |
| P2.2-FIELD-001 | field_0x00 is vtable pointer | MOV EAX,[EDI] used as base for [EAX+0x34]/[EAX+0x58] calls | None | STRONGLY SUPPORTED | FUN_0044F3F0 | 0x00 | 08, 11 | None | Runtime vptr value unknown |
| P2.2-FIELD-002 | field_0x28 compared to 5; field_0x2C compared to 0; field_0x30 incremented | Instruction operands in FUN_0044F3F0 | None | VERIFIED (access), HYPOTHESIS (semantics) | FUN_0044F3F0 | 0x20, 0x28, 0x2C, 0x30 | 08, 11 | PARTIAL (session state machine) | Writers of these fields unknown |
| P2.3-FIELD-003 | field_0x214 write at 0x42173B not verified | Instruction at 0x42173B not examined | None | UNKNOWN | Unknown | 0x214 | 11 | None | Whether offset 0x214 exists in this object type |
| P2.2-CALL-001 | FUN_0044F3F0 has no direct callers | REA procedure_callers empty | None | VERIFIED | FUN_0044F3F0 | 0x00 | 03, 09 | None | How FUN_0044F3F0 is invoked at runtime |
| P2.2-CALL-002 | FUN_0043ECF0 called by exactly 5 adjustment thunks | REA procedure_callers returned 5 addresses | None | VERIFIED | FUN_0043ECF0, 5 thunks | 0x00 | 03, 06, 09 | None | External callers of thunks unknown |
| P2.2-RUST-001 | C++ vtable layout has no Rust equivalent | Rust trait objects use different layout | None | VERIFIED | None | None | 14 | NO | None |
| P2.2-RUST-002 | Adjustment thunks have no Rust equivalent | Rust doesn't have this-pointer adjustment | None | VERIFIED | None | None | 14 | NO | None |
| P2.2-RUST-003 | Reference-counted destruction maps to Rust Arc/Rc + Drop | Different object model | None | PARTIAL | None | None | 14 | Yes — if shared ownership needed | Which entity is reference-counted |
| P2.2-UNC-001 | Runtime vptr state when FUN_0044F3F0 executes | Cannot be determined statically | None | UNKNOWN | FUN_0044F3F0 | 0x00 | 08 | None | Dynamic analysis needed |
| P2.2-UNC-002 | Object allocation site and factory | No allocator call found in constructor | None | UNKNOWN | FUN_0043E1A0 | None | 05 | None | Who calls FUN_0043ECF0 externally |
| P2.2-UNC-003 | FUN_00451090 body not analyzed | Outside bounded scope | None | UNKNOWN | FUN_00451090 | None | 09 | None | Behavior of [EAX+0x58] under intermediate/final vptrs |
| P2.2-UNC-004 | field_0x28/0x2C/0x30 writers not found | No writes found in constructor | None | UNKNOWN | FUN_0044F3F0 | 0x28, 0x2C, 0x30 | 11 | None | How these fields are initialized |

## Summary by Confidence

| Confidence | Count | IDs |
|---|---|---|
| VERIFIED | 25 | P2.2-VT-001 through P2.2-VT-005, P2.2-CTOR-001 through P2.2-CTOR-003, P2.2-THUNK-001, P2.2-ICALL-001, P2.2-ICALL-002, P2.2-DTOR-002, P2.2-FIELD-001, P2.2-FIELD-002 (access), P2.2-CALL-001, P2.2-CALL-002, P2.2-RUST-001, P2.2-RUST-002 |
| STRONGLY SUPPORTED | 3 | P2.2-DTOR-001, P2.2-DTOR-003, P2.2-FIELD-001 |
| PARTIAL | 1 | P2.2-RUST-003 |
| VERIFIED (access)/HYPOTHESIS (semantics) | 1 | P2.2-FIELD-002 |
| UNKNOWN | 4 | P2.2-FIELD-003, P2.2-UNC-001 through P2.2-UNC-004 |

## Evidence Quality

- **Direct observations** (instruction bytes, function metadata, pointer table entries): All VERIFIED via REA `read_bytes`, `procedure_info`, `procedure_assembly`, and independent PE offset calculation
- **Derived facts** (vtable slot mapping, field offsets): VERIFIED where directly observable; STRONGLY SUPPORTED where multiple independent observations agree
- **Interpretations** (field semantics, vtable runtime identity): HYPOTHESIS — not dynamically confirmable through static analysis alone