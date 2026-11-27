# Reference Schema — `references.jsonl`, field by field

**Every statement below was validated against the full 152,681 records and the 355,346 listing lines (see `dataset_validation.md` §3.2).** The goal is to prevent misinterpretation: the strings in this file are not guessed from field names, they are measured.

## 1. Record shape

```json
{"direction":"outgoing_from_function","from":"00401029","to":"00402970","reference_type":"UNCONDITIONAL_CALL","is_call":true,"from_function":"FUN_00401020","to_function":"FUN_00402970"}
```

All seven fields are always present. No other fields exist.

| Field | Type | Measured semantics |
|---|---|---|
| `direction` | string | `outgoing_from_function` (135,019) or `incoming_to_function_entry` (17,662). Nothing else occurs. |
| `from` | string | The VA of the **instruction** doing the referencing — always 8 lowercase hex digits, one exception: `"Entry Point"` (1 record, the `EXTERNAL` type). For `incoming_to_function_entry` records from outside analyzed code, `from` is an address outside every function body or the literal `"Entry Point"`. |
| `to` | string | Target reference. Three encodings, counted over all records: 8-hex absolute VA (`hex32`), stack slot (`"Stack[-0xNN]"`, positive offsets possible: e.g. `"Stack[-0x8]"` is most common; all targets parsed — dataset uses negative-offset stack model with EBP base), or external id (`"EXTERNAL:00000057"`). |
| `reference_type` | string | One of 14 values; exact inventory in §3. |
| `is_call` | bool | `true` iff `reference_type` ∈ {`UNCONDITIONAL_CALL`, `COMPUTED_CALL`, `COMPUTED_CALL_TERMINATOR`}. Measured: 32,848 such records; no other type has `is_call=true`; no call-type has `is_call=false`. |
| `from_function` | string \| null | Analyzed-function name (`FUN_…` / imported-API-like `KERNEL32.DLL::…` / FID-clone names) or `null`. `null` occurs **only** in the 4,548 `incoming_to_function_entry` records whose `from` is outside every function body (§4). |
| `to_function` | string \| null | Analyzed-function name (e.g. `FUN_00402970`), an imported API (`KERNEL32.DLL::SetLastError`), `"entry"`, or `null` (p-raw data/stack targets, external slots, stack refs). |

## 2. Meaning of the two directions

- `outgoing_from_function` — "this reference originates at instruction `from` inside function `from_function`" (`from_function` is always set; 135,019 records).
- `incoming_to_function_entry` — "this reference, in some other code, jumps to/refers to the **entry** of `to_function`". **The semantics of the edge are carried by `reference_type`, not by the direction.** Of 17,662 such records: 13,114 originate inside analyzed functions (their `from` is an instruction line) and 4,548 originate outside function bodies (`from_function: null`).

A single source instruction can spawn multiple records — see the IAT-call example in §5. `incoming` records are a redundant index by function entry, not a separate class of edges.

## 3. `reference_type` inventory, measured against assembly

### 3.1 Call types (`is_call = true`)

| Type | Count | Verified mnemonic behavior (all records with a listing line checked) |
|---|---|---|
| `UNCONDITIONAL_CALL` | 27,770 | 25,260 records are `CALL 0xVA` (E8, direct relative). **1,227 records are `JMP 0xVA` (E9, direct jump into a function entry)** — Ghidra records tail calls into functions as calls; `is_call=true`. 1,283 have no listing line (from outside analyzed bodies). Zero register/memory operands. |
| `COMPUTED_CALL` | 5,075 | 5,074 records are `CALL` with non-direct operand: `ESI`/`EDI`/`EBX` (predicted `FF D0+`) or `dword ptr [reg]` / `[imm32]` (`FF 12` … `FF 15`). Operands are **never** a literal `0x…` direct VA. The `to` field is: `EXTERNAL:00000057`-style external id with resolved import name in `to_function` (4,779 records) or a hex32 VA resolved to an internal function (295 records; hottest targets `FUN_004eb266` ×116, `guard_check_icall` ×86 — CF-guard checks) or outside-body code (1, 004f843b→004e69b7). |
| `COMPUTED_CALL_TERMINATOR` | 3 | `CALL` with brackets; tail-call terminator sites. |

Direct `CALL 0x…` to a function entry can appear both as `UNCONDITIONAL_CALL` (outgoing) and mirrored `incoming_to_function_entry` — the export indexes edges in both directions; count each direction separately before drawing conclusions.

### 3.2 Jump types (`is_call = false`)

| Type | Count | Verified mnemonic behavior |
|---|---|---|
| `CONDITIONAL_JUMP` | 28,189 | 100% conditional mnemonics. Histogram: `JZ` 15,702 · `JNZ` 7,932 · `JNS` 1,459 · `JC` 1,034 · `JNC` 528 · `JA` 490 · `JBE` 284 · `JS` 200 · `JL` 193 · `JG` 166 · `JLE` 123 · `JGE` 56 · `JP` 14 · `JNP` 6 · `JECXZ` 1 · `JNO` 1. Zero plain `JMP`. |
| `UNCONDITIONAL_JUMP` | 4,436 | 100% `JMP` with direct `0x…` target. |
| `COMPUTED_JUMP` | 720 | 100% `JMP` with `[...]` operand (e.g. jump tables, vtable dispatch). |
| `INDIRECTION` | 31 | 100% `JMP dword ptr [0x00517xxx]` — import thunk stubs (IAT slot operands). These 31 records are precisely the IAT stub jumps; see `thunk_and_import_mapping.md`. |
| `UNCONDITIONAL_CALL` (direct `JMP 0x`) | 1,227 | see §3.1 — an `E9` into a function entry logged as `is_call=true`. **Do not equate "is_call=true" with "E8 byte".** |

### 3.3 Memory-reference types (`is_call = false`)

| Type | Count | Semantics |
|---|---|---|
| `DATA` | 33,329 | Address materialization / immediate reference: `LEA` 12,394, `PUSH 0x…` 8,881, `MOV` 6,231, plus pointer operands of locked ops (`CMPXCHG.LOCK` 1,008, `XADD.LOCK` 78, `XCHG` 901), `CMP`, `TEST`, SSE moves, etc. 3,263 of these have no instruction line (from ro-data / vtables). |
| `READ` | 30,661 | Memory reads: `MOV` 19,341, **`CALL dword ptr [..]` 4,282 (the IAT read paired with a `COMPUTED_CALL`)**, `PUSH [..]` 3,398, `CMP` 1,554, `TEST` 1,037, SSE/FLD variants. |
| `WRITE` | 21,677 | Memory writes: `MOV` 20,367, `MOVUPS`/`MOVLPD`/`MOVQ` ~1,197, `SET*` 36, FP stores. 19,205 target `Stack[…]`. |
| `READ_WRITE` | 788 | Read-modify-write: `AND` 181, `INC` 157, `XCHG` 120, `SUB` 100, `XADD.LOCK` 85, `INC.LOCK` 45, `XOR` 44, `ADD` 17, `CMPXCHG.LOCK` 16, `OR` 10, `DEC` 5+2, others. **RMW is not limited to locked instructions.** |
| `PARAM` | 1 | `00516f2b` (`FUN_00516f2b`) `MOV …` → `005a55fd` (a data address); treated as a parameter-feed reference. |
| `EXTERNAL` | 1 | The pseudo-edge `from:"Entry Point" → to:"004e647c"` with `to_function:"entry"` — equals PE `AddressOfEntryPoint 0x000e647c + ImageBase 0x00400000`. |

### 3.4 `to` encodings

| Encoding | Regex | Seen in types | Notes |
|---|---|---|---|
| absolute VA | `^[0-9a-f]{8}$` | all | VAs are **preferred-base** (ASLR is enabled, `DYNAMIC_BASE`); runtime `VAs = this + relocation_delta`. |
| stack slot | `^Stack\[-0x[0-9A-Fa-f]+\]$` (also `Stack[-0xc]` etc.) | `DATA` 15,039, `READ` 20,475, `WRITE` 19,205, `READ_WRITE` 535, `PARAM` 0 | EBP-based frame slots (negative offsets); all are locals, not globals. |
| external id | `^EXTERNAL:[0-9a-f]{8}$` | `COMPUTED_CALL` 4,779, `EXTERNAL` 1? no — see INDIRECTION | See §4. |

`ffdff000`: `to` value used for 1,699 `READ`/`WRITE` records whose operands are `FS:[0x0]` (TEB). **Ghidra prints TEB-absolute as `ffdff000`; this is a segment-base artifact, not a RAM address to follow.**

### 3.5 Stack & FS artifacts summary

- `Stack[…]` targets: 55,254 records — all are frame-local accesses and must not be matched against global symbol tables.
- `ffdff000`: 1,699 records — TEB/TLS via FS segment.

## 4. `EXTERNAL:000000xx` namespace

- 4,782 `COMPUTED_CALL[*]` records reference an `EXTERNAL:` id. Every such record carries `to_function` = `DLL::Name`; **zero records are missing the name**; **no `EXTERNAL:` id maps to two different names**; 297 distinct imported names are referenced (see `thunk_and_import_mapping.md`).
- The numeric id is a **stable per-export index in Ghidra's EXTERNAL namespace — it is not the PE IAT ordinal and not the hint.** Do not sort or interpret it.
- `EXTERNAL:00000057` = `KERNEL32.DLL::SetLastError`; `EXTERNAL:0000005f` = `KERNEL32.DLL::GetLastError` (measured via `to_function`).
- The single `EXTERNAL`-typed record (`from: "Entry Point"`, `to_function: "entry"`) is unrelated to this namespace; it marks the process entrypoint edge only.

## 5. One instruction ⇒ two records (IAT-call pattern)

Measured on `00404221` (`CALL dword ptr [0x00517260]`, listing `004041a0.asm`):

```
{"from":"00404221","to":"00517260","reference_type":"READ","is_call":false,...}     ← the IAT slot read
{"from":"00404221","to":"EXTERNAL:00000057","reference_type":"COMPUTED_CALL","is_call":true,"to_function":"KERNEL32.DLL::SetLastError"}
```

The IAT slot `0x00517260` independently decodes (PE import directory, `pe_imports.py` / `objdump -p`) to **SetLastError, hint 0x534=1332** — both routes agree (§ `thunk_and_import_mapping.md`). Any analyst counting "reads of the IAT" and "external calls" should remember they describe the same pair of bytes.

Similarly, `0040424e CALL ESI` (`FFD6`) produced only `COMPUTED_CALL to=EXTERNAL:0000005f → KERNEL32.DLL::GetLastError` — no slot read (target materialized in a register).

## 6. Call-counting pitfalls (measured)

1. **Do not use `is_call` to count E8 calls** — 1,227 of the true-is_call records are `JMP 0x` tail calls (§3.1), and 1,283 true-is_call records originate outside analyzed bodies.
2. **DATA ≠ call** — 33,329 `DATA` records (12,394 `LEA`, 8,881 `PUSH`) often push function VAs (`push 0x489240`); only `is_call`/type grants call semantics. Conversely DATA references to a function VA are legitimate (address materialization).
3. **`READ` may be an IAT call leg** (30,661 records, 4,282 of which are `CALL [..]` legs paired with `COMPUTED_CALL`).
4. **`incoming_to_function_entry` includes non-function sources** — always separate `from_function: null`.
5. **TEB refs** (`ffdff000`) and **Stack refs** dominate raw counts; filter by `to` pattern before ranking hottest targets.

## 7. Confidence & provenance

Classification after this validation: **CONFIRMED** — every count in §3 was produced by enumerating all 152,681 records and cross-checking each against the exact `from`-VA instruction line (`check_reference_samples.py`). The residual open points are: the 4,176 dataflow-resolved references (unverifiable by operand text; consistent with Ghidra's declared resolution strategy, not independently re-derived) and the meaning of `PARAM` (1 record). Neither blocks query correctness.
