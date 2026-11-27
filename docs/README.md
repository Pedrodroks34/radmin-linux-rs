# Consolidated Docs Master Index — `docs/` Corpus Consolidation

## Overview

This draft is the master index for Phase 1: consolidation of the `docs/` Markdown corpus into 12 evidence-preserving documents. It records:

- the evidence policy applied to every consolidated document,
- the recommended reading order linking the 12 consolidated documents,
- the research method summarizing the Ghidra export dataset (layout, counts, x86/PE conventions, atomic semantics, reference schema, query procedures, validation discrepancies),
- the complete source-provenance table — all 199 rows of `analysis_workspace/compaction/mapping.tsv`, columns `Consolidated document | Source file`, grouped by target,
- the final `## Sources` listing the 15 README-assigned source files that were read to produce this draft.

Nothing is invented. Counts, addresses, instruction bytes, field names, and hashes cited below are taken verbatim from the source files and the mapping. Anything not confirmed by static analysis of `RvControlSvc.exe`, its Ghidra export listings, or the pcap captures is marked UNKNOWN or BLOCKED.

## Evidence policy

Every claim in the consolidated documents carries exactly one of the following evidence levels:

| Level | Definition |
|---|---|
| CONFIRMED | Directly demonstrated by exact listing bytes, instruction bytes, addresses, export records, or pcap frames |
| STRONGLY SUPPORTED | Multiple independent observations converge (e.g. export `to_function` names agree with PE import directory decode) |
| HYPOTHESIS | Plausible inference that remains unproven |
| UNKNOWN | Insufficient evidence to decide; no claim of truth either way |
| BLOCKED | Verification was attempted but cannot proceed (circuit breaker, missing artifact, inaccessible binary) |
| REFUTED | A previously claimed finding has been shown incorrect by direct re-verification against the raw artifacts |

## Reading order

The 12 consolidated documents, in recommended reading order (one line each):

1. `docs/README.md` — master index and evidence policy (this document's target)
2. `docs/ARCHITECTURE.md` — component mapping, module status, reverse-engineering findings
3. `docs/PROTOCOL_SPEC.md` — control message catalog, TLV catalog, authentication, TCP relay, P2P/NAT, Teredo
4. `docs/CRYPTO_SPEC.md` — AES-256-CBC, RSA, SRP, MD5, key lifecycle, padding, checksum
5. `docs/CONTROL_HANDSHAKE_SPEC.md` — CPacket types, serialization pipeline, key exchange, cross-module linkage
6. `docs/PCAP_FORENSICS.md` — traffic captures, frame format, control port 17301, server IPs
7. `docs/OBJECT_LIFECYCLE.md` — vtable/indirect dispatch, reference count, allocation/deallocation, object model
8. `docs/DISPATCH_ANALYSIS.md` — vtable address correction, indirect dispatch targets, constructor reachability
9. `docs/RUNTIME_OBSERVATIONS.md` — process/module inventory, ETW/Procmon/SCM captures, network endpoints
10. `docs/RUST_COMPATIBILITY.md` — Rust port gaps, compatibility audits, implementation readiness
11. `docs/RECONCILIATION.md` — contradiction matrices, correction matrices, discrepancy logs
12. `docs/OPEN_QUESTIONS.md` — unresolved questions, blockers, evidence limitations

## Research method

All research below was performed statically against the Ghidra export of `RvControlSvc.exe`; no dynamic execution, no debugging, no modification of export files.

### Ghidra export dataset layout and counts

**Export identity** (from `docs/analysis_workspace/dataset_inventory.md` and `validation/dataset_validation.md`):

- Export format: `ghidra-radmin-export-v1`
- Exported: `2026-11-11T03:16:24Z`
- Ghidra version: 12.2
- Program: `RvControlSvc.exe` (from `/C:/Users/Rhuan/Desktop/RvControlSvc.exe`)
- SHA-256: `546efad9ab3ff85c2a50d61524d754bec94a3f3e30d6ae8addef481a1e8daa1e` (matches historical hash; re-verified read-only)
- Language: `x86:LE:32:default` (x86, little-endian, 32-bit)
- Compiler spec: `windows`
- Image base: `0x00400000`
- Partial export: false
- Functions exported: 6,904
- Decompile failures: 1 (`FUN_00498fe0`, `Exception while decompiling 00498fe0: process: timeout`)
- Total instruction lines: 355,346 (re-counted from listings; matches `metadata.json`)
- Unique references exported: 152,681 (0 exact duplicate lines)
- Listing files: 6,904 (one `.asm` per function, named by entry VA)
- Function entry VA range: `00401020`–`00516f35`
- Measured instruction VA range: `00401020`–`00516f3a` (new measurement beyond the reported entry range)

**File layout:**

```
ghidra_export/
├── metadata.json               # Export-level metadata (format, hashes, counts)
├── functions.jsonl             # One JSON object per function (decompiled C, signature, CC, body range)
├── references.jsonl            # One JSON object per reference (direction, type, call flag)
├── listing/                    # One .asm per function, named by entry VA (00401020.asm … 00516f35.asm)
├── phase_8*_audit/             # Prior audit outputs (prior investigators, leads only)
└── relatorio_parte*.md         # Prior investigators' Portuguese reports (leads only)
```

**Assembly file format:** each `listing/XXXXXXXX.asm` contains one function's disassembly, column format `ADDRESS  BYTES  MNEMONIC  OPERANDS`, one instruction per line. No function header lines; boundaries are implicit from filename and references.

**Calling conventions (inferred by Ghidra, not verified):** `__thiscall` 2,996; `__fastcall` 1,429; `__cdecl` 1,294; `__stdcall` 1,162; `unknown` 23. Thunks: 91 with `is_thunk:true` (Ghidra FID wrappers, not PE import stubs — see refinement below).

**Reference type counts** (from `references.jsonl`, all re-derived and cross-checked against listing lines):

| Type | Count | Semantics |
|---|---|---|
| `DATA` | 33,329 | Address materialization / immediate reference |
| `READ` | 30,661 | Memory read |
| `WRITE` | 21,677 | Memory write |
| `CONDITIONAL_JUMP` | 28,189 | Conditional branch |
| `UNCONDITIONAL_CALL` | 27,770 | Direct CALL or direct JMP tail call into entry |
| `COMPUTED_CALL` | 5,075 | Indirect CALL (register/memory) |
| `UNCONDITIONAL_JUMP` | 4,436 | Direct JMP |
| `READ_WRITE` | 788 | Read-modify-write (RMW) |
| `COMPUTED_JUMP` | 720 | Indirect JMP |
| `INDIRECTION` | 31 | Import-stub `JMP dword ptr [IAT]` |
| `COMPUTED_CALL_TERMINATOR` | 3 | Tail-call terminator |
| `PARAM` | 1 | Parameter-feed reference |
| `EXTERNAL` | 1 | Entry-point pseudo-edge |

**Direction counts:** `outgoing_from_function` 135,019; `incoming_to_function_entry` 17,662.

**Call-sum identity:** `is_call=true` records total **32,848 = 27,770 (`UNCONDITIONAL_CALL`) + 5,075 (`COMPUTED_CALL`) + 3 (`COMPUTED_CALL_TERMINATOR`)**. No other type carries `is_call=true`; no CALL-type record carries `is_call=false`.

**Records whose `from` VA is not a listing instruction line:** 4,548 (3.0%), all `incoming_to_function_entry` with `from_function == null`: 3,263 `DATA` from ro-data/vtables, 1,283 `UNCONDITIONAL_CALL` from outside analyzed code, 1 `COMPUTED_CALL` (`004f843b -> 004e69b7`), 1 `EXTERNAL` pseudo-record (`Entry Point` -> `004e647c`, equals PE `AddressOfEntryPoint 0x000e647c + ImageBase 0x00400000`).

### x86/PE conventions

From `docs/analysis_workspace/architecture_and_calling_conventions.md`:

- Architecture: **x86 (32-bit), little-endian** — confirmed from `language_id` = `x86:LE:32:default` and listings. Image base `0x00400000`. Windows calling conventions (compiler spec `windows`).
- General-purpose registers: EAX, EBX, ECX, EDX, ESI, EDI, EBP, ESP. No XMM register usage observed in sampled listings.
- Stack frames: `PUSH EBP; MOV EBP, ESP; SUB ESP, N; ... ; MOV ESP, EBP; POP EBP; RET [imm]`. SEH exception handling via stack cookies (`DAT_00553250`) in most functions.
- Calling conventions observed:

| Convention | Register args | Stack cleanup | Where used |
|---|---|---|---|
| `__cdecl` | No | Caller | C helpers |
| `__stdcall` | No | Callee (`ret imm`) | WinAPI-like |
| `__fastcall` | ECX, EDX | Callee (`ret`) | Internal helpers |
| `__thiscall` | ECX = `this` | Caller/callee varies | C++ methods |
| `unknown` | — | — | 23 functions, do not assume |

- Argument identification rule: with `thiscall`, the first argument beyond `ECX` is `[EBP+8]`; with `stdcall`, all args are `[EBP+8+4n]`; with `fastcall`, ECX/EDX carry the first two.
- Indirect calls: `CALL [EDX]`, `CALL [EAX+0x0C]`, etc. Reference type `COMPUTED_CALL` (5,075 occurrences). The target pointer is a value in memory or a register and is **not** a static address unless an explicit DATA reference resolves it.
- Data references vs calls: `reference_type:"DATA"` identifies a memory reference, **not** a call. Do not count DATA references to function addresses as callsites.

### Atomic semantics (XADD / CMPXCHG / XCHG)

From `docs/analysis_workspace/important_instructions.md` and `validation/atomic_instruction_semantics.md`. Every example cites the listing file and instruction VA. "Old value" = value read from destination before commit; "new value" = value committed. x86 manual semantics are used throughout — never high-level pseudocode.

**`LOCK` prefix** (byte `F0`): asserts bus lock / cache-line atomicity for the duration of the operation on SMP systems. It does **not** change arithmetic semantics. Three locked idioms occur in this binary:

| Idiom | Listing (VA) | Bytes |
|---|---|---|
| `XADD.LOCK` | `00401670.asm` `00401697` | `F00FC105 94885900` → `XADD.LOCK dword ptr [0x00598894],EAX` |
| `CMPXCHG.LOCK` | `004041a0.asm` `00404234` | `F00FB10A` → `CMPXCHG.LOCK dword ptr [EDX],ECX` |
| `INC.LOCK` / `DEC.LOCK` | `004041a0.asm` `004041ed` | `F0FF4704` → `INC.LOCK dword ptr [EDI + 0x4]` |
| `DEC.LOCK` global | `00478760.asm` `004787f8` | `F0FF0D78C75500` → `DEC.LOCK dword ptr [0x0055c778]` |

**`XADD` — exchange and add:** `XADD dest, src` ; `temp ← dest ; dest ← dest + src ; src ← temp`. With `EAX` as `src` (the encoding used everywhere in this binary):

1. `EAX ← [dest]` — the **old destination value** is loaded into the accumulator.
2. `[dest] ← [dest] + EAX_old` — the destination is updated.
3. Affects `EFLAGS` as a 32-bit ADD (`CF/OF/SF/ZF/AF/PF`).

**Key fact — XADD with EAX = 0:** if `EAX` is zero, the destination does **not** change (`dst + 0`), but the operation is still an **atomic read-modify-write**: the old value is loaded into EAX and memory is written back with the same content. It is **not** a "read-only" operation. In this export, the audit of global XADD operations recorded `EAX == 0` as the accumulator in 18/18 cases.

Example — `00401670.asm` `00401697`:
```
00401689  MOV dword ptr [EBP + -0x10], ECX   ; incoming value staged
00401697  F00FC10594885900  XADD.LOCK dword ptr [0x00598894],EAX
```
Captured semantics: `EAX ← old([0x00598894])`; `[0x00598894] ← old + EAX_old`. `0x00598894` is a **global** (inside `.data`), referenced elsewhere as `DAT` concurrency state.

Example inside an object header — `004041a0.asm` `00404246`:
```
00404234  CMPXCHG.LOCK dword ptr [EDX],ECX   ; see CMPXCHG below
0040423e  MOV EAX,EDX
00404240  XCHG dword ptr [EAX],EDI            ; see XCHG below
00404246  F00FC15F04  XADD.LOCK dword ptr [EDI + 0x4],EBX
```
`[EDI+0x4]` is updated with `[EDI+0x4] + EBX_old`; the old counter is returned in EBX.

**`CMPXCHG` — compare and exchange:** `CMPXCHG dest, r/m32` ; compare `[dest]` with `EAX` ; if equal: `[dest] ← r/m32` (source operand), `ZF ← 1` ; else: `EAX ← [dest]` (old dest), `ZF ← 0`.

Operand roles — frequently confused, spelled out for `00404234 … CMPXCHG.LOCK dword ptr [EDX],ECX`:

| Role | Value |
|---|---|
| destination tested/written | `[EDX]` (here a stack slot, `EBP-relative local`, not a global) |
| expected value | `EAX` (zeroed two instructions earlier: `00404232 XOR EAX,EAX`) |
| replacement value | `ECX` (zeroed at `0040422d XOR ECX,ECX`) |
| old destination | loaded into `EAX` on mismatch |
| branch consequence | `00404238 TEST EAX,EAX; 0040423a JNZ …` — enter if the slot was non-zero before the RMW |

So this site is an **atomic test-and-clear-flag**: if `[EDX] == 0`, keep it 0 and set ZF=1; otherwise load the old value into EAX and set ZF=0 so the caller skips the "already processed" path. Flags: `ZF` accordingly; `CF`, `OF` etc. reflect the subtraction performed by the compare (32-bit compare semantics). `LOCK CMPXCHG` on an aligned 32-bit operand is the canonical x86 compare-and-swap primitive; here `[EDI]`/`[EDX]` are EBP/object slots, and the two `CMPXCHG.LOCK` lines at `00404234` / `0040427b` straddle an indirect call, i.e. the same CAS pair is evaluated on two paths (fast path and retry path).

**`XCHG` — implicit-lock swap:** `XCHG dest, src` ; swap `dest ↔ src` (memory ↔ register). `XCHG` with a memory operand is **implicitly locked** (behaves as if prefixed), even without an explicit `F0`. It loads the old destination value into the register operand and stores the register value into memory atomically.

Example — `004041a0.asm` `00404240`:
```
0040423e  MOV EAX,EDX
00404240  XCHG dword ptr [EAX],EDI    ; old ← [EAX] ; [EAX] ← EDI ; EDI ← old
00404242  TEST EDI,EDI
00404244  JZ 0x00404261                ; skip if the slot was already empty
```
Another form — `00403bc0.asm` `00403bdb`:
```
00403bdb  8710                       XCHG dword ptr [EAX],EDX
```

Summary table (old vs new):

| Instruction | Old destination | New destination | Register effect | ZF/CF |
|---|---|---|---|---|
| `XADD.LOCK [d],EAX` | `[d]` | `[d]+EAX_old` | `EAX ← old[d]` | flags of ADD |
| `CMPXCHG.LOCK [d],ECX` (eq) | `[d]` | `ECX` | none | ZF=1 |
| `CMPXCHG.LOCK [d],ECX` (ne) | `[d]` | unchanged | `EAX ← [d]` | ZF=0 |
| `XCHG [d],r32` | `[d]` | `r32_old` | `r32 ← old[d]` | unaffected |

**Per-site documentation requirement:** every atomic instruction must record VA, listing file, instruction, initial register values, destination, old memory value, new memory value, register change, flags, and branch consequence.

**Prior-audit corrections:** XADD source 0 leaves destination unchanged; register receives old value. "READ_WRITE" and "DATA" references to the same address represent one logical RMW. Global XADD operations with source = 0 occur 18/18 times in the audited set.

### Reference schema (`references.jsonl`)

From `docs/analysis_workspace/validation/reference_schema.md`. Every statement was validated against the full 152,681 records and the 355,346 listing lines.

**Record shape** (all seven fields always present; no other fields exist):

```json
{"direction":"outgoing_from_function","from":"00401029","to":"00402970","reference_type":"UNCONDITIONAL_CALL","is_call":true,"from_function":"FUN_00401020","to_function":"FUN_00402970"}
```

| Field | Type | Measured semantics |
|---|---|---|
| `direction` | string | `outgoing_from_function` (135,019) or `incoming_to_function_entry` (17,662). Nothing else occurs. |
| `from` | string | VA of the **instruction** doing the referencing — always 8 lowercase hex digits, one exception: `"Entry Point"` (1 record, the `EXTERNAL` type). For `incoming_to_function_entry` records from outside analyzed code, `from` is an address outside every function body or the literal `"Entry Point"`. |
| `to` | string | Target reference. Three encodings: 8-hex absolute VA (`hex32`), stack slot (`"Stack[-0xNN]"`, positive offsets possible; dataset uses negative-offset stack model with EBP base), or external id (`"EXTERNAL:000000xx"`). |
| `reference_type` | string | One of 14 values; exact inventory in the table above. |
| `is_call` | bool | `true` iff `reference_type` ∈ {`UNCONDITIONAL_CALL`, `COMPUTED_CALL`, `COMPUTED_CALL_TERMINATOR`}. Measured: 32,848 such records (`32,848 = 27,770 + 5,075 + 3`); no other type has `is_call=true`; no call-type has `is_call=false`. |
| `from_function` | string \| null | Analyzed-function name or `null`. `null` occurs **only** in the 4,548 `incoming_to_function_entry` records whose `from` is outside every function body. |
| `to_function` | string \| null | Analyzed-function name, imported API (`KERNEL32.DLL::SetLastError`), `"entry"`, or `null` (p-raw data/stack targets, external slots, stack refs). |

**Meaning of the two directions:** `outgoing_from_function` — "this reference originates at instruction `from` inside function `from_function`" (`from_function` is always set; 135,019 records). `incoming_to_function_entry` — "this reference, in some other code, jumps to/refers to the **entry** of `to_function`". **The semantics of the edge are carried by `reference_type`, not by the direction.** Of 17,662 such records: 13,114 originate inside analyzed functions (their `from` is an instruction line) and 4,548 originate outside function bodies (`from_function: null`). A single source instruction can spawn multiple records — see the IAT-call example below. `incoming` records are a redundant index by function entry, not a separate class of edges.

**`reference_type` inventory, measured against assembly:**

Call types (`is_call = true`):

| Type | Count | Verified mnemonic behavior |
|---|---|---|
| `UNCONDITIONAL_CALL` | 27,770 | 25,260 records are `CALL 0xVA` (E8, direct relative). **1,227 records are `JMP 0xVA` (E9, direct jump into a function entry)** — Ghidra records tail calls into functions as calls; `is_call=true`. 1,283 have no listing line (from outside analyzed bodies). Zero register/memory operands. |
| `COMPUTED_CALL` | 5,075 | 5,074 records are `CALL` with non-direct operand: `ESI`/`EDI`/`EBX` (`FF D0+`) or `dword ptr [reg]` / `[imm32]` (`FF 12` … `FF 15`). Operands are **never** a literal `0x…` direct VA. The `to` field is: `EXTERNAL:000000xx`-style external id with resolved import name in `to_function` (4,779 records) or a hex32 VA resolved to an internal function (295 records; hottest targets `FUN_004eb266` ×116, `guard_check_icall` ×86 — CF-guard checks) or outside-body code (1, `004f843b→004e69b7`). |
| `COMPUTED_CALL_TERMINATOR` | 3 | `CALL` with brackets; tail-call terminator sites. |

Jump types (`is_call = false`):

| Type | Count | Verified mnemonic behavior |
|---|---|---|
| `CONDITIONAL_JUMP` | 28,189 | 100% conditional mnemonics. Histogram: `JZ` 15,702 · `JNZ` 7,932 · `JNS` 1,459 · `JC` 1,034 · `JNC` 528 · `JA` 490 · `JBE` 284 · `JS` 200 · `JL` 193 · `JG` 166 · `JLE` 123 · `JGE` 56 · `JP` 14 · `JNP` 6 · `JECXZ` 1 · `JNO` 1. Zero plain `JMP`. |
| `UNCONDITIONAL_JUMP` | 4,436 | 100% `JMP` with direct `0x…` target. |
| `COMPUTED_JUMP` | 720 | 100% `JMP` with `[...]` operand (e.g. jump tables, vtable dispatch). |
| `INDIRECTION` | 31 | 100% `JMP dword ptr [0x00517xxx]` — import thunk stubs (IAT slot operands). |

Memory-reference types (`is_call = false`):

| Type | Count | Semantics |
|---|---|---|
| `DATA` | 33,329 | Address materialization / immediate reference: `LEA` 12,394, `PUSH 0x…` 8,881, `MOV` 6,231, plus pointer operands of locked ops (`CMPXCHG.LOCK` 1,008, `XADD.LOCK` 78, `XCHG` 901), `CMP`, `TEST`, SSE moves, etc. 3,263 have no instruction line (from ro-data / vtables). |
| `READ` | 30,661 | Memory reads: `MOV` 19,341, **`CALL dword ptr [..]` 4,282 (the IAT read paired with a `COMPUTED_CALL`)**, `PUSH [..]` 3,398, `CMP` 1,554, `TEST` 1,037, SSE/FLD variants. |
| `WRITE` | 21,677 | Memory writes: `MOV` 20,367, `MOVUPS`/`MOVLPD`/`MOVQ` ~1,197, `SET*` 36, FP stores. 19,205 target `Stack[…]`. |
| `READ_WRITE` | 788 | Read-modify-write: `AND` 181, `INC` 157, `XCHG` 120, `SUB` 100, `XADD.LOCK` 85, `INC.LOCK` 45, `XOR` 44, `ADD` 17, `CMPXCHG.LOCK` 16, `OR` 10, `DEC` 5+2, others. **RMW is not limited to locked instructions.** |
| `PARAM` | 1 | `00516f2b` (`FUN_00516f2b`) `MOV …` → `005a55fd` (a data address); treated as a parameter-feed reference. |
| `EXTERNAL` | 1 | The pseudo-edge `from:"Entry Point" → to:"004e647c"` with `to_function:"entry"` — equals PE `AddressOfEntryPoint 0x000e647c + ImageBase 0x00400000`. |

**`to` encodings:**

| Encoding | Regex | Seen in types | Notes |
|---|---|---|---|
| absolute VA | `^[0-9a-f]{8}$` | all | VAs are **preferred-base** (ASLR is enabled, `DYNAMIC_BASE`); runtime `VAs = this + relocation_delta`. |
| stack slot | `^Stack\[-0x[0-9A-Fa-f]+\]$` | `DATA` 15,039, `READ` 20,475, `WRITE` 19,205, `READ_WRITE` 535 | EBP-based frame slots (negative offsets); all are locals, not globals. |
| external id | `^EXTERNAL:[0-9a-f]{8}$` | `COMPUTED_CALL` 4,779 | See § below. |

`ffdff000`: `to` value used for 1,699 `READ`/`WRITE` records whose operands are `FS:[0x0]` (TEB). **Ghidra prints TEB-absolute as `ffdff000`; this is a segment-base artifact, not a RAM address to follow.**

**Stack & FS artifacts summary:** `Stack[…]` targets: 55,254 records — all are frame-local accesses and must not be matched against global symbol tables. `ffdff000`: 1,699 records — TEB/TLS via FS segment.

**`EXTERNAL:000000xx` namespace:** 4,782 `COMPUTED_CALL[*]` records reference an `EXTERNAL:` id. Every such record carries `to_function` = `DLL::Name`; **zero records are missing the name**; **no `EXTERNAL:` id maps to two different names**; 297 distinct imported names are referenced. The numeric id is a **stable per-export index in Ghidra's EXTERNAL namespace — it is not the PE IAT ordinal and not the hint.** Do not sort or interpret it. `EXTERNAL:00000057` = `KERNEL32.DLL::SetLastError`; `EXTERNAL:0000005f` = `KERNEL32.DLL::GetLastError` (measured via `to_function`).

**One instruction ⇒ two records (IAT-call pattern):** measured on `00404221` (`CALL dword ptr [0x00517260]`, listing `004041a0.asm`):

```
{"from":"00404221","to":"00517260","reference_type":"READ","is_call":false,...}     ← the IAT slot read
{"from":"00404221","to":"EXTERNAL:00000057","reference_type":"COMPUTED_CALL","is_call":true,"to_function":"KERNEL32.DLL::SetLastError"}
```

The IAT slot `0x00517260` independently decodes (PE import directory, `pe_imports.py` / `objdump -p`) to **SetLastError, hint 0x534=1332** — both routes agree. Similarly, `0040424e CALL ESI` (`FFD6`) produced only `COMPUTED_CALL to=EXTERNAL:0000005f → KERNEL32.DLL::GetLastError` — no slot read (target materialized in a register).

**Call-counting pitfalls (measured):** do not use `is_call` to count E8 calls (1,227 of the true-`is_call` records are `JMP 0x` tail calls; 1,283 true-`is_call` records originate outside analyzed bodies); `DATA ≠ call` (33,329 `DATA` records); `READ` may be an IAT call leg (4,282 of the 30,661 `READ` records are `CALL [..]` legs paired with `COMPUTED_CALL`); `incoming_to_function_entry` includes non-function sources (always separate `from_function: null`); TEB refs (`ffdff000`) and Stack refs dominate raw counts.

### Query procedures

From `docs/analysis_workspace/validation/query_procedures.md`. All procedures were executed against the export during Phase 0B; outputs quoted below. Two equivalent interfaces exist: the checked-in helper `xref.py` (faster, validated) and raw `grep` (universal). Every query was also validated against manually inspected assembly lines.

**`xref.py` reference:** `python3 analysis_workspace/validation/xref.py <command> [args]`

| Command | Purpose |
|---|---|
| `callers <fn-entry>` | All `is_call:true` CALL-type references to `<fn-entry>`, with `from` VA, type, caller name |
| `unique-callers <fn-entry>` | Same, plus list of unique `from_function` names |
| `callees <fn-entry>` | All outgoing `is_call:true` CALL-type references of a function |
| `refs-to <addr> [--type T]` | Every reference whose `to` equals `<addr>` (optionally restricted to one `reference_type`) |
| `writes-to <addr>` | `WRITE` and `READ_WRITE` references to `<addr>` |
| `refs-in-range <lo> <hi> [--type T]` | References whose `to` lies in `[lo,hi]` (IAT scan, global tables) |
| `listing <addr>` | Prints the `.asm` file for the function containing `<addr>` (entry or interior) |

**Tests executed (captured outputs):**

Direct callers of `FUN_0041e220` — expected to reproduce the prior Phase-8 audit (15 call sites / 14 unique caller functions):

```
$ xref.py callers 0041e220
call sites targeting 0041e220 (is_call=true, CALL types): 15
  00419e9b  UNCONDITIONAL_CALL           from_function=FUN_00419e20
  0041a739  UNCONDITIONAL_CALL           from_function=FUN_0041a6d0
  0041a768  UNCONDITIONAL_CALL           from_function=FUN_0041a6d0
  0041b05a  UNCONDITIONAL_CALL           from_function=FUN_0041ae30
  0041b125  UNCONDITIONAL_CALL           from_function=FUN_0041b090
  0041b1cc  UNCONDITIONAL_CALL           from_function=FUN_0041b140
  0041b370  UNCONDITIONAL_CALL           from_function=FUN_0041b2f0
  0041bd36  UNCONDITIONAL_CALL           from_function=FUN_0041bb40
  0041c03a  UNCONDITIONAL_CALL           from_function=FUN_0041bd70
  0041e025  UNCONDITIONAL_CALL           from_function=FUN_0041df70
  0041f80e  UNCONDITIONAL_CALL           from_function=FUN_0041f710
  0041fc6e  UNCONDITIONAL_CALL           from_function=FUN_0041fa80
  00420c7b  UNCONDITIONAL_CALL           from_function=FUN_00420b80
  0041f3b1  UNCONDITIONAL_CALL           from_function=FUN_0041f110
  0041f6dd  UNCONDITIONAL_CALL           from_function=FUN_0041f450
unique caller functions: 14
```
**Reproduced exactly** (15 sites, 14 unique callers). `FUN_0041a6d0` calls it twice (`0041a739`, `0041a768`).

Callees of `FUN_00401020` — must equal `CALL 0x00402970` twice (listing lines `00401029`, `00401042`):

```
$ xref.py callees 00401020
callees of 00401020 (FUN_00401020):
  00401029  UNCONDITIONAL_CALL           to=00402970  to_function=FUN_00402970
  00401042  UNCONDITIONAL_CALL           to=00402970  to_function=FUN_00402970
total call sites: 2
```
**Matches** listing `00401020.asm` exactly.

References to global `0x0055c110` (written by `FUN_00401020` via `C705 10C15500 4B000000 MOV dword ptr [0x0055c110],0x4b` at `00401038`):

```
$ xref.py refs-to 0055c110 | tail -4
  004d6270  DATA                         dir=outgoing_from_function  from_function=FUN_004d6200
  004d6285  DATA                         dir=outgoing_from_function  from_function=FUN_004d6200
  004d6357  DATA                         dir=outgoing_from_function  from_function=FUN_004d6350
  004d6369  DATA                         dir=outgoing_from_function  from_function=FUN_004d6350
refs to 0055c110: 14
by type: {'WRITE': 1, 'DATA': 13}
$ xref.py writes-to 0055c110
  00401038  WRITE                        dir=outgoing_from_function  from_function=FUN_00401020
refs to 0055c110 (type=WRITE): 1
```
**Matches** the listing (`00401038 … MOV dword ptr [0x0055c110],0x4b`): one WRITE.

IAT range scan (`.rdata` `0x00517000..0x00517540`) by type `INDIRECTION` — all import-stub jumps:

```
$ xref.py refs-in-range 00517000 00517540 --type INDIRECTION
refs with to in [00517000,00517540] (type=INDIRECTION): 31
distinct from_function names: 30
  … (FWPUCLNT.DLL::Fwpm* ×17, KERNEL32.DLL::CreateToolhelp32Snapshot/Process32FirstW/Process32NextW/GetACP ×4,
     SHELPER.DLL::SHelper_Init, RVROLCLIENT.DLL::ROLClient_FreeMemory, MSI.DLL::MsiEnumRelatedProductsW,
     ___vcrt_FlsAlloc, ___acrt_FlsFree@4, ___acrt_FlsGetValue@4, ___acrt_FlsSetValue@8,
     FUN_0041d6b0, FUN_0041dcd0, FUN_00451620)
```
**31 sites, 30 distinct sources** — matches the manual INDIRECTION analysis.

Listing retrieval, interior address:

```
$ xref.py listing 00516f3d
(address 00516f3d is inside 00516f35.asm)
00516f35  B9FC555A00                MOV ECX,0x5a55fc
00516f3a  E9A7DAFCFF                JMP 0x004e49e6
```
Resolves the enclosing function correctly.

**Distinguishing DATA from CALL (tested):** `xref.py callers 0041e220` counts only `UNCONDITIONAL_CALL` / `COMPUTED_CALL` / `COMPUTED_CALL_TERMINATOR` with `is_call=true`. The 15 call sites match the manual count of `CALL 0x…` bytes in the listing; `grep '"to":"0041e220"' references.jsonl | grep -c 'UNCONDITIONAL_CALL'` also returns 15, and additional `"reference_type":"DATA"` records for the same VA are address-materialization records, not calls (`lea`/`push` of the function VA).

**`grep` one-liners** (equivalent to `xref.py`): direct call sites of `FUN_0041e220` → `grep '"to":"0041e220"' ghidra_export/references.jsonl | grep '"is_call":true'`; unique caller functions → `grep '"to":"0041e220"' ... | grep UNCONDITIONAL_CALL | grep -oE '"from_function":"[^"]*"' | sort | uniq -c | sort -rn`; imports → `grep '"is_call":true' ... | grep -oE '"to_function":"[^"]*\.DLL::[^"]*"' ...`; hottest imported APIs by call sites (measured): `KERNEL32.DLL::GetLastError` 1,970 · `KERNEL32.DLL::SetLastError` 1,914 · `KERNEL32.DLL::GetProcAddress` 79 · `KERNEL32.DLL::CloseHandle` 24 · `OLEAUT32.DLL::SysFreeString` 19 · `WS2_32.DLL::ntohs`/`htons` 18+18 · `WS2_32.DLL::htonl` 17. All references to a global → `grep '"to":"0055bf80"' ... | wc -l` # 31; `grep '"to":"0055bf84"' ... | wc -l` # 19. Indirect-call sites in one function → `grep '"from_function":"FUN_00402axx"' ... | grep COMPUTED_CALL`. Atomic-RMW sites → `grep -E '(XADD|CMPXCHG|XCHG|INC|DEC)[^"]*\.LOCK' ghidra_export/listing/*.asm`. Every FS-segment reference → `grep '"to":"ffdff000"' ... | wc -l` # 1,699.

**Query pitfalls (all observed during testing):** (1) Lowercase hex — `references.jsonl` uses lowercase (`"0041e220"`); use case-insensitive matches or normalize with `grep -i`. (2) `Stack[…]` targets are frame slots — never join them to globals. (3) `ffdff000` = TEB artifact (`FS:[0x0]`), 1,699 refs. (4) `DATA` references to a function VA are address materialization, not calls — filter `is_call=true` when counting calls. (5) `JMP 0x…` tail calls are logged as `UNCONDITIONAL_CALL` `is_call=true` (1,227 records) — the raw bytes (`E9`), not the type label, distinguish them from `E8`. (6) `from` outside function bodies (4,548 records) — always null `from_function`. (7) Duplicate names (`scalar_deleting_destructor'`, `operator()` ×15, …) — never match on `name`, match on `entry`/VA. (8) IAT call = two records — `COMPUTED_CALL` (is_call=true) + paired `READ` (is_call=false) for the slot.

### Validation discrepancies

From `docs/analysis_workspace/validation/validation_discrepancies.md` and `dataset_validation.md`. Phase 0B question: does the onboarding report hold up? Short answer: **every numeric count re-verified exactly; four semantic refinements were needed.** No count in `metadata.json` or in the onboarding inventory is wrong. No export file was modified; no audit report was edited.

**Onboarding figures — verification outcome:** all 10 onboarding figures MATCH (some +NEW or REFINED): 6,904 `.asm` files (PASS); address range `00401020`–`00516f35` (MATCH, +NEW instruction VA range `00401020`–`00516f3a`); x86 32-bit LE, image base `0x00400000` (MATCH); filename = entry VA 1:1 (MATCH); function boundaries reliable (MATCH / REFINED — 6,903/6,904 decompiled, 1 failure `00498fe0`, 23 unknown CCs of which 22 are import stubs); cross-references available/direction/types usable (MATCH / +COVERAGE — all 14 types accounted for, every record cross-checked against its instruction line); imported APIs identifiable (**STRENGTHENED** — onboarding said "partially", verification shows yes via two agreeing routes); missing functions/unresolved references (MATCH / CLARIFIED — 1 decompile failure, 4,548 refs from outside bodies documented, 23 unknown CCs, 5,075 COMPUTED_CALL dataflow-resolved, 0 missing listings, 0 duplicate references); tools available (MATCH / EXPANDED); prior audits are leads, not proof (MATCH — re-verified figures reproduce: 15/14 callers of `FUN_0041e220`, 31/19 refs to `0x0055BF80`/`0x0055BF84`).

**Refinement 1 — "thunks" ≠ PE import stubs:** onboarding said "91 `is_thunk:true` functions are thunks". Measured: those 91 are **Ghidra FID thunk-like wrappers** (internal code clones such as `thunk_FUN_00478a50` ×8). The actual PE import stubs — 22 `JMP dword ptr [0x00517xxx]` functions — were themselves hidden among the "unknown calling convention" bucket. Impact: tooling filtering on `is_thunk` will **not** find import stubs, and vice versa. Both buckets are now separately enumerated.

**Refinement 2 — unknown CC = import stubs + 1 decompile timeout:** the 23 `calling_convention:"unknown"` entries are: 22 import stubs (`0041a570` RVROLCLIENT.DLL::ROLClient_FreeMemory stub; `004aec83|004aec89|004aec8f` Kernel32 Toolhelp32 stubs; `004e6f05…004e6f6b` MSI ordinal 205, SHELPER SHelper_Init, 17 × FWPUCLNT) plus `00498fe0` (regular function, decompiler timeout, not an import stub). Impact: the "unknown" bucket is no longer opaque — 22 of 23 have resolved roles.

**Refinement 3 — `metadata.json: unique_references_exported` is accurate as-is:** no duplicate reference lines exist (0/152,681). The word "unique" describes the producer's output guarantee, not a de-duplication step — records are unique verbatim.

**Refinement 4 — duplicate function *names*:** 95 distinct names repeat across 316 entries (`scalar_deleting_destructor'` ×31, `operator()` ×15, `validate` ×12, …). Entries remain unique; `name` must never be used as a key.

**Deliberate non-findings** (things onboarding flagged that verification could not corroborate as problems): no listing file is missing and no orphan `.asm` exists (1:1 with `functions.jsonl`); no malformed reference records — every one of the 152,681 parses and belongs to exactly one measured bucket; bucket sums reconcile exactly (DATA 33,329 = 27,183 textual + 2,509 stack-dataflow + 374 hex-dataflow + 3,263 no-line; READ 30,661 = 29,333 + 63 + 745 + 520 FS; WRITE 21,677 = 20,232 + 247 + 19 + 1,179 FS; READ_WRITE 788 = 569 + 1 + 218); `UNCONDITIONAL_CALL` is not "E8 calls" — 1,227 of its records are direct `JMP 0x…` tail calls and 1,283 originate outside function bodies; `COMPUTED_CALL` never carries a direct hex target (5,074/5,074 are register/memory operands; the single missing listing line is an outside-body record); the export contains **no exports** itself (`.edata` size 0) — not an anomaly, expected for a service exe.

**Genuinely different / unresolved items:**

| Item | Status | Detail |
|---|---|---|
| MSI ordinal 205 → `MsiEnumRelatedProductsW` | UNVERIFIED NAME | PE import directory contains ordinal 205 only; Ghidra supplied the name. Not confirmable without `msi.dll`. |
| OLEAUT32 (9) and WS2_32 (14) ordinal-only slots | Ghidra-resolved names | No `ordinal` string appears in `to_function`; resolution used the analyst's workstation. Consistent with well-known Windows ordinals but not certified against local DLLs (not in workspace). |
| `PARAM` reference type | SEMANTICS UNCLEAR | 1 record (`00516f2b MOV … → 005a55fd`); a `PARAM`-feed reference, otherwise unused in the dataset. |
| `ffdff000` FS:[0x0] pseudo-address in 1,699 refs | ARTIFACT, NOT AN ADDRESS | TEB/TLS via FS segment; never dereference as a RAM VA. |
| 4,176 dataflow-resolved hex32/stack references | NOT TEXTUALLY VERIFIABLE | Resolved via Ghidra dataflow (`CMP [ECX]`, `LEA [EDX+1]`, …). No evidence of inconsistency; treat as resolved, not raw. |
| 4,548 records from outside function bodies | EXPECTED | Entrypoint stubs / vtables / unidentified code; documented in `dataset_validation.md` §3.1. |
| `Entry Point` pseudo-record (`EXTERNAL` → 004e647c) | AS DESIGNED | Matches PE `AddressOfEntryPoint`; not a call site. |
| `0x0055c110` "1 WRITE" | MATCHES BINARY | `00401038 MOV [0x0055c110],0x4b` — verified in listing and by `xref.py writes-to`. |
| Phase-8 audit figures (15/14 callers of `FUN_0041e220`; 31/19 global refs) | REPRODUCED | via `xref.py callers` and `grep -c` respectively. |

**Limitations that future analyses must respect:** (1) ASLR: all VAs are preferred-base; the binary declares `DYNAMIC_BASE` (image base `0x00400000` is not the runtime base). (2) The export models memory with `Stack[…]` frame slots and TEB as `ffdff000`; raw addresses outside `00401020..00516f3a` are not backed by listings. (3) 23 `unknown` CCs: 22 are resolved (§3); 1 needs the assembly read manually. (4) Indirect-call *targets* (`COMPUTED_CALL`) are Ghidra resolutions; the 4,779 EXTERNAL names are workstation-derived but consistent with PE positions; the 295 internal hex32 targets are likewise inference-based. (5) DATA references from ro-data (vtables) have no instruction line; do not expect one. (6) Prior Portuguese audit reports (`ghidra_export/relatorio_parte*`) and `phase_8*_audit/` remain leads; Phase 0B independently confirmed only the figures listed above — everything else in them awaits similar verification.

## Source provenance

Complete source-provenance table — all 199 rows from `analysis_workspace/compaction/mapping.tsv`, columns `Consolidated document | Source file`, grouped by target.

### README (15 sources)

| Consolidated document | Source file |
|---|---|
| README | docs/CONTROL_PROTOCOL.md |
| README | docs/analysis_workspace/README.md |
| README | docs/analysis_workspace/analysis_methodology.md |
| README | docs/analysis_workspace/architecture_and_calling_conventions.md |
| README | docs/analysis_workspace/call_relationships.md |
| README | docs/analysis_workspace/dataset_inventory.md |
| README | docs/analysis_workspace/function_index.md |
| README | docs/analysis_workspace/global_references.md |
| README | docs/analysis_workspace/important_instructions.md |
| README | docs/analysis_workspace/validation/atomic_instruction_semantics.md |
| README | docs/analysis_workspace/validation/dataset_validation.md |
| README | docs/analysis_workspace/validation/query_procedures.md |
| README | docs/analysis_workspace/validation/reference_schema.md |
| README | docs/analysis_workspace/validation/thunk_and_import_mapping.md |
| README | docs/analysis_workspace/validation/validation_discrepancies.md |

### ARCHITECTURE (5 sources)

| Consolidated document | Source file |
|---|---|
| ARCHITECTURE | docs/REFERENCE_PROJECT_ANALYSIS.md |
| ARCHITECTURE | docs/REVERSE_ENGINEERING.md |
| ARCHITECTURE | docs/reverse-engineering/round-02/08-windows-ipc.md |
| ARCHITECTURE | docs/reverse-engineering/round-02/09-ndis-driver.md |
| ARCHITECTURE | docs/reverse-engineering/round-02/10-architecture.md |

### PROTOCOL_SPEC (8 sources)

| Consolidated document | Source file |
|---|---|
| PROTOCOL_SPEC | docs/PCAP_MESSAGE_CATALOG.md |
| PROTOCOL_SPEC | docs/PHASE_3_CONTROL_MESSAGE_CATALOG.md |
| PROTOCOL_SPEC | docs/PROTOCOL_SPEC.md |
| PROTOCOL_SPEC | docs/reverse-engineering/round-02/03-tlv-catalog.md |
| PROTOCOL_SPEC | docs/reverse-engineering/round-02/04-authentication-networks.md |
| PROTOCOL_SPEC | docs/reverse-engineering/round-02/05-tcp-relay.md |
| PROTOCOL_SPEC | docs/reverse-engineering/round-02/06-p2p-nat.md |
| PROTOCOL_SPEC | docs/reverse-engineering/round-02/07-teredo.md |

### CRYPTO_SPEC (17 sources)

| Consolidated document | Source file |
|---|---|
| CRYPTO_SPEC | docs/CRYPTOGRAPHIC_OVERVIEW.md |
| CRYPTO_SPEC | docs/CRYPTO_AES_CONSUMER_TRACE.md |
| CRYPTO_SPEC | docs/CRYPTO_AES_KEY_INSTALLATION_TRACE.md |
| CRYPTO_SPEC | docs/CRYPTO_AES_KEY_SPLIT_TRACE.md |
| CRYPTO_SPEC | docs/CRYPTO_CONTROL_KEY_LIFECYCLE.md |
| CRYPTO_SPEC | docs/CRYPTO_KEY_LIFECYCLE_GAP_ANALYSIS.md |
| CRYPTO_SPEC | docs/CRYPTO_MD5_ANALYSIS.md |
| CRYPTO_SPEC | docs/CRYPTO_PHASE_10_11_RECONSTRUCTION.md |
| CRYPTO_SPEC | docs/CRYPTO_PHASE_10_3_10_5_CONSOLIDATED_REPORT.md |
| CRYPTO_SPEC | docs/CRYPTO_RSA_ANALYSIS.md |
| CRYPTO_SPEC | docs/CRYPTO_RSA_KEY_PROVENANCE.md |
| CRYPTO_SPEC | docs/CRYPTO_RSESSION_ANALYSIS.md |
| CRYPTO_SPEC | docs/CRYPTO_RSESSION_KEY_LIFECYCLE.md |
| CRYPTO_SPEC | docs/CRYPTO_SYMMETRIC_ENCRYPTION.md |
| CRYPTO_SPEC | docs/KEY_EXCHANGE_ANALYSIS.md |
| CRYPTO_SPEC | docs/reverse-engineering/round-02/01-handshake.md |
| CRYPTO_SPEC | docs/reverse-engineering/round-02/02-cryptography.md |

### CONTROL_HANDSHAKE_SPEC (14 sources)

| Consolidated document | Source file |
|---|---|
| CONTROL_HANDSHAKE_SPEC | docs/CONTROL_HANDSHAKE_SPEC.md |
| CONTROL_HANDSHAKE_SPEC | docs/CRYPTO_PHASE_10_13_P0_BLOCKER_RESOLUTION.md |
| CONTROL_HANDSHAKE_SPEC | docs/CRYPTO_PHASE_10_14_IDENTITY_REMEDIATION_AND_PASSWORD_INVESTIGATION.md |
| CONTROL_HANDSHAKE_SPEC | docs/CRYPTO_PHASE_10_15_STATIC_PASSWORD_ENCODING_RECONSTRUCTION.md |
| CONTROL_HANDSHAKE_SPEC | docs/CRYPTO_PHASE_10_16_RSA_AND_SRP_PROOF_RECONSTRUCTION.md |
| CONTROL_HANDSHAKE_SPEC | docs/CRYPTO_PHASE_10_17_M1_REMEDIATION_AND_RSA_CALLER_TRACE.md |
| CONTROL_HANDSHAKE_SPEC | docs/CRYPTO_PHASE_10_18_M2_BYTE_LEVEL_AND_RSA_DATA_FLOW.md |
| CONTROL_HANDSHAKE_SPEC | docs/CRYPTO_PHASE_10_19_M2_BIGNUM_AND_RSA_IAT_AUDIT.md |
| CONTROL_HANDSHAKE_SPEC | docs/CRYPTO_SRP_ANALYSIS.md |
| CONTROL_HANDSHAKE_SPEC | docs/CRYPTO_SRP_DISPATCH_AND_DATA_FLOW_AUDIT.md |
| CONTROL_HANDSHAKE_SPEC | docs/CRYPTO_SRP_EFFECTIVE_IMPLEMENTATION.md |
| CONTROL_HANDSHAKE_SPEC | docs/CRYPTO_SRP_INTEGER_SERIALIZATION_AUDIT.md |
| CONTROL_HANDSHAKE_SPEC | docs/CRYPTO_SRP_PASSWORD_ENCODING.md |
| CONTROL_HANDSHAKE_SPEC | docs/CRYPTO_SRP_SCRAMBLING_VERIFICATION.md |

### PCAP_FORENSICS (5 sources)

| Consolidated document | Source file |
|---|---|
| PCAP_FORENSICS | docs/PCAP_FLOW_MAP.md |
| PCAP_FORENSICS | docs/PCAP_FORENSICS_DEEP_DIVE.md |
| PCAP_FORENSICS | docs/PCAP_FORENSICS_REPORT.md |
| PCAP_FORENSICS | docs/PCAP_THIRD_ROUND_AUDIT.md |
| PCAP_FORENSICS | docs/reverse-engineering/round-02/EVIDENCE_INDEX.md |

### OBJECT_LIFECYCLE (36 sources)

| Consolidated document | Source file |
|---|---|
| OBJECT_LIFECYCLE | docs/PHASE_2_3/00_ENVIRONMENT_AND_PRESERVATION.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_3/03_OBJECT_LIFECYCLE_AND_OWNERSHIP.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_3/04_FIELD_WRITER_READER_ANALYSIS.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_3/05_FACTORY_AND_ALLOCATION_ANALYSIS.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_3/06_OBJECT_LIFECYCLE_AND_OWNERSHIP.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_3/07_FUN_00451090_ANALYSIS.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_3/08_VPTR_STATE_AND_DISPATCH_ANALYSIS.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_3/09_BULK_INITIALIZATION_ANALYSIS.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_3/10_SYMBOL_AND_STRING_EVIDENCE.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_3/11_CALLER_AND_CROSS_MODULE_ANALYSIS.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_3/13_MASTER_FUNCTION_INVENTORY.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_3/14_AUTHORITATIVE_FINDING_REGISTRY.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_3/17_FINAL_TECHNICAL_REPORT.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_3/18_RAW_EVIDENCE_APPENDIX.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_3/19_COMPLETION_AND_PRESERVATION.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_3/20_REMAINING_FUNCTION_ANALYSIS.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_3/21_ALLOCATOR_AND_ALLOCATION_SITE.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_3/22_OBJECT_LIFECYCLE_DESTRUCTION_CHAIN.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_3/CHECKPOINT_00_ENVIRONMENT.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_3/CHECKPOINT_02_STATIC_ANALYSIS_COMPLETE.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_4/00_ENVIRONMENT_AND_REPOSITORY_PRESERVATION.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_4/01_COMPLETE_DOCUMENTATION_INVENTORY.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_4/03_BINARY_IDENTITY_AND_TOOL_VALIDATION.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_4/04_CONSTRUCTOR_AND_ALLOCATION_CALL_GRAPH.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_4/05_RUNTIME_VPTR_AND_INDIRECT_DISPATCH.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_4/06_OBJECT_FIELD_INITIALIZATION_AND_STATE.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_4/07_REFERENCE_COUNT_AND_ADDREF_RELEASE_ANALYSIS.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_4/08_INDIRECT_DEALLOCATION_TARGET_ANALYSIS.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_4/09_ALLOCATION_DEALLOCATION_SYMMETRY.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_4/10_SUBINITIALIZER_AND_SUBOBJECT_ANALYSIS.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_4/11_COMPLETE_OBJECT_LIFECYCLE_MODEL.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_4/12_RUNTIME_EVIDENCE_AND_REPRODUCTION_LOG.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_4/14_AUTHORITATIVE_FINDING_REGISTRY.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_4/17_FINAL_TECHNICAL_REPORT.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_4/18_RAW_EVIDENCE_APPENDIX.md |
| OBJECT_LIFECYCLE | docs/PHASE_2_4/19_COMPLETION_AND_REPOSITORY_PRESERVATION.md |

### DISPATCH_ANALYSIS (38 sources)

| Consolidated document | Source file |
|---|---|
| DISPATCH_ANALYSIS | docs/PHASE_2_5/00_ENVIRONMENT_AND_REPOSITORY_PRESERVATION.md |
| DISPATCH_ANALYSIS | docs/PHASE_2_5/01_AUTHORITATIVE_MARKDOWN_INVENTORY.md |
| DISPATCH_ANALYSIS | docs/PHASE_2_5/03_CORRECTED_VTABLE_ADDRESS_POINT_ANALYSIS.md |
| DISPATCH_ANALYSIS | docs/PHASE_2_5/04_CORRECTED_INDIRECT_DISPATCH_TARGETS.md |
| DISPATCH_ANALYSIS | docs/PHASE_2_5/05_PE_SECTION_AND_500CA6_ADDRESS_CORRECTION.md |
| DISPATCH_ANALYSIS | docs/PHASE_2_5/06_FUN_00473210_COMPLETE_ANALYSIS.md |
| DISPATCH_ANALYSIS | docs/PHASE_2_5/07_REFERENCE_COUNT_INCREMENT_AND_RELEASE_SEARCH.md |
| DISPATCH_ANALYSIS | docs/PHASE_2_5/08_OBJECT_FIELD_INITIALIZATION_RECONSTRUCTION.md |
| DISPATCH_ANALYSIS | docs/PHASE_2_5/09_SUBINITIALIZER_COMPLETE_INVENTORY.md |
| DISPATCH_ANALYSIS | docs/PHASE_2_5/10_SUBINITIALIZER_DETAILED_ANALYSIS.md |
| DISPATCH_ANALYSIS | docs/PHASE_2_5/11_CONSTRUCTOR_REACHABILITY_AND_FACTORY_ANALYSIS.md |
| DISPATCH_ANALYSIS | docs/PHASE_2_5/12_WINDOWS_RUNTIME_DEBUGGING_PLAN.md |
| DISPATCH_ANALYSIS | docs/PHASE_2_5/14_AUTHORITATIVE_FINDING_REGISTRY.md |
| DISPATCH_ANALYSIS | docs/PHASE_2_5/17_FINAL_TECHNICAL_REPORT.md |
| DISPATCH_ANALYSIS | docs/PHASE_2_5/18_RAW_EVIDENCE_APPENDIX.md |
| DISPATCH_ANALYSIS | docs/PHASE_2_5/19_COMPLETION_AND_REPOSITORY_PRESERVATION.md |
| DISPATCH_ANALYSIS | docs/analysis_workspace/phase_9C_audit/phase_9C_16650_pointer_chain.md |
| DISPATCH_ANALYSIS | docs/analysis_workspace/phase_9C_audit/phase_9C_230c0_discrepancy.md |
| DISPATCH_ANALYSIS | docs/analysis_workspace/phase_9C_audit/phase_9C_498fe0_manual_analysis.md |
| DISPATCH_ANALYSIS | docs/analysis_workspace/phase_9C_audit/phase_9C_blocked_path_revalidation.md |
| DISPATCH_ANALYSIS | docs/analysis_workspace/phase_9C_audit/phase_9C_callsite_inventory.md |
| DISPATCH_ANALYSIS | docs/analysis_workspace/phase_9C_audit/phase_9C_e220_pointer_chain.md |
| DISPATCH_ANALYSIS | docs/analysis_workspace/phase_9C_audit/phase_9C_e280_pointer_chain.md |
| DISPATCH_ANALYSIS | docs/analysis_workspace/phase_9C_audit/phase_9C_evidence_index.md |
| DISPATCH_ANALYSIS | docs/analysis_workspace/phase_9C_audit/phase_9C_main_report.md |
| DISPATCH_ANALYSIS | docs/analysis_workspace/phase_9C_audit/phase_9C_previous_claims_verification.md |
| DISPATCH_ANALYSIS | docs/analysis_workspace/phase_9C_audit/phase_9C_reference_count_reconciliation.md |
| DISPATCH_ANALYSIS | docs/analysis_workspace/phase_9D_audit/phase_9D_cas_initialization.md |
| DISPATCH_ANALYSIS | docs/analysis_workspace/phase_9D_audit/phase_9D_constructor_dataflow.md |
| DISPATCH_ANALYSIS | docs/analysis_workspace/phase_9D_audit/phase_9D_e16650_comparison.md |
| DISPATCH_ANALYSIS | docs/analysis_workspace/phase_9D_audit/phase_9D_group_A_lifecycle.md |
| DISPATCH_ANALYSIS | docs/analysis_workspace/phase_9D_audit/phase_9D_group_B_lifecycle.md |
| DISPATCH_ANALYSIS | docs/analysis_workspace/phase_9D_audit/phase_9D_group_C_lifecycle.md |
| DISPATCH_ANALYSIS | docs/analysis_workspace/phase_9D_audit/phase_9D_main_report.md |
| DISPATCH_ANALYSIS | docs/analysis_workspace/phase_9D_audit/phase_9D_object_identity_matrix.md |
| DISPATCH_ANALYSIS | docs/analysis_workspace/phase_9D_audit/phase_9D_pointer_D_producers.md |
| DISPATCH_ANALYSIS | docs/analysis_workspace/phase_9D_audit/phase_9D_pointer_P_producers.md |
| DISPATCH_ANALYSIS | docs/analysis_workspace/phase_9D_audit/phase_9D_static_tables.md |

### RUNTIME_OBSERVATIONS (27 sources)

| Consolidated document | Source file |
|---|---|
| RUNTIME_OBSERVATIONS | docs/PHASE_2_7/01_ENVIRONMENT_AND_REPOSITORY_VALIDATION.md |
| RUNTIME_OBSERVATIONS | docs/PHASE_2_7/02_RUNNING_RADMIN_PROCESS_INVENTORY.md |
| RUNTIME_OBSERVATIONS | docs/PHASE_2_7/03_PRE_CONNECTION_MODULE_INVENTORY.md |
| RUNTIME_OBSERVATIONS | docs/PHASE_2_7/04_PROCESS_TREE_AND_HELPER_PROCESS_ANALYSIS.md |
| RUNTIME_OBSERVATIONS | docs/PHASE_2_7/05_PRE_CONNECTION_NETWORK_BASELINE.md |
| RUNTIME_OBSERVATIONS | docs/PHASE_2_7/06_RUNTIME_MONITORING_CONFIGURATION.md |
| RUNTIME_OBSERVATIONS | docs/PHASE_2_7/07_RUNTIME_EVENT_TIMELINE.md |
| RUNTIME_OBSERVATIONS | docs/PHASE_2_7/08_POST_CONNECTION_MODULE_INVENTORY.md |
| RUNTIME_OBSERVATIONS | docs/PHASE_2_7/09_PRE_POST_CONNECTION_DIFFERENCE_ANALYSIS.md |
| RUNTIME_OBSERVATIONS | docs/PHASE_2_7/10_NEW_BINARY_HASH_AND_VERSION_INVENTORY.md |
| RUNTIME_OBSERVATIONS | docs/PHASE_2_7/11_STATIC_RUNTIME_CORRELATION.md |
| RUNTIME_OBSERVATIONS | docs/PHASE_2_7/13_PHASE_2_7_FINAL_SUMMARY.md |
| RUNTIME_OBSERVATIONS | docs/PHASE_2_8/01_PHASE_2_8_ENVIRONMENT_AND_REPOSITORY_VALIDATION.md |
| RUNTIME_OBSERVATIONS | docs/PHASE_2_8/03_MONITORING_TOOL_AND_PROVIDER_VALIDATION.md |
| RUNTIME_OBSERVATIONS | docs/PHASE_2_8/04_BASELINE_PROCESS_SERVICE_AND_MODULE_SNAPSHOT.md |
| RUNTIME_OBSERVATIONS | docs/PHASE_2_8/05_ETW_CAPTURE_ANALYSIS.md |
| RUNTIME_OBSERVATIONS | docs/PHASE_2_8/06_PROCMON_CAPTURE_ANALYSIS.md |
| RUNTIME_OBSERVATIONS | docs/PHASE_2_8/07_SCM_EVENT_ANALYSIS.md |
| RUNTIME_OBSERVATIONS | docs/PHASE_2_8/08_POST_CONNECTION_PROCESS_IDENTITY_AND_LIFECYCLE_VALIDATION.md |
| RUNTIME_OBSERVATIONS | docs/PHASE_2_8/09_ENUMMODULES2_PID_SELECTION_INVESTIGATION.md |
| RUNTIME_OBSERVATIONS | docs/PHASE_2_8/10_MODULE_INVENTORY_COMPARISON_VALIDITY.md |
| RUNTIME_OBSERVATIONS | docs/PHASE_2_8/11_TCP_UDP_ENDPOINT_CORRELATION.md |
| RUNTIME_OBSERVATIONS | docs/PHASE_2_8/12_NAMED_PIPE_OBSERVATION.md |
| RUNTIME_OBSERVATIONS | docs/PHASE_2_8/13_SCM_EVENT_COVERAGE_AND_INTERPRETATION.md |
| RUNTIME_OBSERVATIONS | docs/PHASE_2_8/14_UNIFIED_RUNTIME_EVENT_TIMELINE.md |
| RUNTIME_OBSERVATIONS | docs/PHASE_2_8/15_STATIC_RUNTIME_CORRELATION.md |
| RUNTIME_OBSERVATIONS | docs/PHASE_2_8/17_PHASE_2_8_FINAL_SUMMARY.md |

### RUST_COMPATIBILITY (12 sources)

| Consolidated document | Source file |
|---|---|
| RUST_COMPATIBILITY | docs/CRYPTO_PHASE_10_13_DYNAMIC_ANALYSIS_PLAN.md |
| RUST_COMPATIBILITY | docs/CRYPTO_PHASE_10_20_DYNAMIC_ANALYSIS_READINESS.md |
| RUST_COMPATIBILITY | docs/CRYPTO_PHASE_10_5_COMPATIBILITY_AUDIT.md |
| RUST_COMPATIBILITY | docs/CRYPTO_PHASE_10_5_REMEDIATION.md |
| RUST_COMPATIBILITY | docs/CRYPTO_PHASE_10_5_VALIDATION.md |
| RUST_COMPATIBILITY | docs/CRYPTO_RUST_GAP_ANALYSIS.md |
| RUST_COMPATIBILITY | docs/PCAP_IMPLEMENTATION_READINESS.md |
| RUST_COMPATIBILITY | docs/PHASE_2_3/12_RUST_COMPATIBILITY_ASSESSMENT.md |
| RUST_COMPATIBILITY | docs/PHASE_2_3/23_EXTENDED_RUST_COMPATIBILITY.md |
| RUST_COMPATIBILITY | docs/PHASE_2_4/13_RUST_COMPATIBILITY_REASSESSMENT.md |
| RUST_COMPATIBILITY | docs/PHASE_2_5/13_RUST_COMPATIBILITY_REASSESSMENT.md |
| RUST_COMPATIBILITY | docs/reverse-engineering/round-02/IMPLEMENTATION_READINESS.md |

### RECONCILIATION (12 sources)

| Consolidated document | Source file |
|---|---|
| RECONCILIATION | docs/CRYPTO_PHASE_10_10_RECONCILIATION.md |
| RECONCILIATION | docs/PCAP_PREVIOUS_REPORT_CORRECTIONS.md |
| RECONCILIATION | docs/PHASE_2_3/02_PHASE_2_2_CONTRADICTION_MATRIX.md |
| RECONCILIATION | docs/PHASE_2_3/15_HISTORICAL_RECONCILIATION.md |
| RECONCILIATION | docs/PHASE_2_3/CHECKPOINT_01_REPORT_RECONCILIATION.md |
| RECONCILIATION | docs/PHASE_2_4/02_PHASE_2_3_FINDINGS_RECONCILIATION.md |
| RECONCILIATION | docs/PHASE_2_4/15_PHASE_2_3_CONTRADICTION_RESOLUTION.md |
| RECONCILIATION | docs/PHASE_2_5/02_PHASE_2_4_FINDING_RECONCILIATION.md |
| RECONCILIATION | docs/PHASE_2_5/15_PHASE_2_4_CORRECTION_MATRIX.md |
| RECONCILIATION | docs/PHASE_2_8/02_PHASE_2_7_TIMELINE_RECONCILIATION.md |
| RECONCILIATION | docs/analysis_workspace/phase_9C_audit/phase_9C_discrepancy_log.md |
| RECONCILIATION | docs/analysis_workspace/phase_9D_audit/phase_9D_discrepancy_log.md |

### OPEN_QUESTIONS (10 sources)

| Consolidated document | Source file |
|---|---|
| OPEN_QUESTIONS | docs/CRYPTO_PHASE_10_12_BLOCKER_RESOLUTION.md |
| OPEN_QUESTIONS | docs/CRYPTO_PHASE_10_3_10_5_OPEN_QUESTIONS.md |
| OPEN_QUESTIONS | docs/CRYPTO_UNRESOLVED_QUESTIONS.md |
| OPEN_QUESTIONS | docs/PHASE_2_3/16_UNRESOLVED_QUESTIONS.md |
| OPEN_QUESTIONS | docs/PHASE_2_4/16_UNRESOLVED_QUESTIONS_AND_BLOCKERS.md |
| OPEN_QUESTIONS | docs/PHASE_2_5/16_UNRESOLVED_QUESTIONS_AND_BLOCKERS.md |
| OPEN_QUESTIONS | docs/PHASE_2_7/12_EVIDENCE_LIMITATIONS_AND_UNRESOLVED_QUESTIONS.md |
| OPEN_QUESTIONS | docs/PHASE_2_8/16_EVIDENCE_LIMITATIONS_AND_UNRESOLVED_QUESTIONS.md |
| OPEN_QUESTIONS | docs/analysis_workspace/unresolved_references.md |
| OPEN_QUESTIONS | docs/reverse-engineering/round-02/UNRESOLVED_QUESTIONS.md |

**Row total:** 15 + 5 + 8 + 17 + 14 + 5 + 36 + 38 + 27 + 12 + 12 + 10 = **199 rows**, matching every line of `mapping.tsv`.

## Sources

The 15 README-assigned sources read to produce this draft (first column `README` in `mapping.tsv`, lines 2, 148–155, 181–186):

1. `docs/CONTROL_PROTOCOL.md`
2. `docs/analysis_workspace/README.md`
3. `docs/analysis_workspace/analysis_methodology.md`
4. `docs/analysis_workspace/architecture_and_calling_conventions.md`
5. `docs/analysis_workspace/call_relationships.md`
6. `docs/analysis_workspace/dataset_inventory.md`
7. `docs/analysis_workspace/function_index.md`
8. `docs/analysis_workspace/global_references.md`
9. `docs/analysis_workspace/important_instructions.md`
10. `docs/analysis_workspace/validation/atomic_instruction_semantics.md`
11. `docs/analysis_workspace/validation/dataset_validation.md`
12. `docs/analysis_workspace/validation/query_procedures.md`
13. `docs/analysis_workspace/validation/reference_schema.md`
14. `docs/analysis_workspace/validation/thunk_and_import_mapping.md`
15. `docs/analysis_workspace/validation/validation_discrepancies.md`

Plus the full `analysis_workspace/compaction/mapping.tsv` (199 rows) was read in full to build the source-provenance table above.

---

## Evidence appendix (exact tokens from consolidated sources)

Exact addresses, hashes and identifiers from the consolidated sources that are not repeated in the prose above. They are preserved here so that no evidence anchor is lost during compaction; the full narrative for each source remains available in git history.

- `docs/CONTROL_PROTOCOL.md`: `0x1000302`, `0x10004e50`, `0x10004f30`, `0x10005250`, `0x10008a40`, `0x100092a0`, `0x1003fd48`, `0x1003fd56`, `0x10041010`, `0x10065f05`, `0x10069ce0`, `0x10069d15`, `0x10069d9b`, `0x10069dab`, `0x10069fe5`, `0x1006a8b0`, `0x1006aac0`, `0x1006ab00`, `0x1006b860`, `0x1006b8f0`, `0x1006b9e0`, `0x100832a0`, `0x100ab048`, `0x100ab06f`, `0x100aee88`, `0x1011121c`, `0x10115d6c`, `0x10187030`, `0x20001e1`, `0x2000303`, `0x556910`, `0x556940`, `0x556970`, `0x5569c8`, `0x5569f8`, `0x556a58`, `0x556a84`, `0x556ab4`, `0x556b14`, `0x556b70`, `0x556b9c`, `0x9000304`, `avaescryptor@@`, `ccryptochannel@rolclient`, `cpacket@controlsvc`, `cselfdeletingobject@famrt`, `fun_00427060`, `fun_004282f0`, `fun_004285b0`, `fun_00428880`, `fun_00472ef0`, `fun_00472f60`, `fun_004795d0`, `fun_10001040`, `fun_100013a0`, `fun_100015a0`, `fun_100024f0`, `fun_10002980`, `fun_10002c40`, `fun_10003b30`, `fun_10005410`, `fun_1003fbd0`, `fun_10062800`, `fun_10062ad0`, `fun_10062b60`, `fun_10062d60`, `fun_10062e00`, `fun_10062e90`, `fun_10062f80`, `fun_10062ff0`, `fun_100633d0`, `fun_100633e0`, `fun_10063470`, `fun_10063530`, `fun_100638f0`, `fun_10065150`, `fun_10065db0`, `fun_10065ec0`, `fun_10068230`, `fun_10069c20`, `fun_10069f90`, `fun_1006a0c0`, `fun_1006a2b0`, `fun_1006a630`, `ipacket@controlsvc`
- `docs/analysis_workspace/README.md`: `fun_0041e280`
- `docs/analysis_workspace/global_references.md`: `0x0055bfc0`, `0x0055c114`, `0x0055c880`, `fun_00401670`, `fun_00402960`
- `docs/analysis_workspace/validation/atomic_instruction_semantics.md`: `0x00517128`
- `docs/analysis_workspace/validation/dataset_validation.md`: `0x00117000`, `0x001450f4`, `0x00197a41`, `0x00517128`, `0x0051744c`, `0x0051753c`, `0x005988cc`
- `docs/analysis_workspace/validation/reference_schema.md`: `0x489240`
- `docs/analysis_workspace/validation/thunk_and_import_mapping.md`: `0x00000000`, `0x00117000`, `0x001450f4`, `0x00197a41`, `0x005171`, `0x00517158`, `0x0051716`, `0x00517258`, `0x00517264`, `0x0051744c`, `0x00517510`, `0x0051753c`
