# Export Validation — Dataset Integrity Check

**Independent validation of the RvControlSvc.exe Ghidra export.** Performed without modifying any export file. All counts below were re-derived from the raw artifacts, not copied from `metadata.json` or the onboarding report.

Artifacts used for verification:

| Script / file | Purpose |
|---|---|
| `validate_dataset.py` | File/entry/instruction/reference integrity + metadata.json comparison |
| `check_reference_samples.py` | Cross-checks **all 152,681** references against the 355,346 listing instruction lines |
| `analyze_unmatched_refs.py` | Decomposes the 4,548 references whose `from` VA is not an instruction line |
| `xref.py` | Query/verification helper (see `query_procedures.md`) |
| `analyze_imports_thunks.py` | EXTERNAL-id → DLL::Name mapping; INDIRECTION IAT stubs |
| `pe_imports.py` + `import_iat_map.txt` | PE import directory decoded read-only from the local binary |
| `crosscheck_iat.py` | Cross-checks export INDIRECTION slot→API names vs PE import directory |
| `validation_output.txt`, `reference_check_output.txt`, `reference_check_mismatches.txt`, `import_mapping_output.txt` | Raw captured outputs |

SHA-256 of the analyzed binary (unmodified, read-only): `546efad9ab3ff85c2a50d61524d754bec94a3f3e30d6ae8addef481a1e8daa1e` (matches the historical hash; re-verified).

## 1. Headline results

| Item | Onboarding claim | Independently verified | Result |
|---|---|---|---|
| `.asm` files present | 6,904 | 6,904 (all `.asm`, no extras) | **PASS** |
| `functions.jsonl` entries | 6,904 | 6,904 parsed, 0 JSON parse failures | **PASS** |
| entries unique | yes | 0 duplicate `entry` values | **PASS** |
| listing ↔ jsonl 1:1 | implied | no missing, no extra listings | **PASS** |
| function entry VA range | `00401020`–`00516f35` | `00401020`–`00516f35` | **PASS** |
| instruction VA range | not reported | **`00401020`–`00516f3a`** (instruction count and range now measured) | **NEW** |
| instruction lines | 355,346 (metadata) | 355,346 counted in listings | **PASS** |
| references records | 152,681 | 152,681 parsed, 0 JSON parse failures, **0 exact duplicate lines** | **PASS** |
| missing listings vs jsonl | none | none | **PASS** |
| unknown calling conventions | 23 | 23 (list of VAs recorded in `validation_output.txt`) | **PASS** |
| decompile failures | 1 | 1 — `FUN_00498fe0` (`Exception while decompiling 00498fe0: process: timeout`) | **PASS** |
| thunks | 91 | 91 (`is_thunk:true`), **but NOT import stubs** — see §4 | **REFINED** |
| externals | not reported | 0 (`is_external:true`) | **NEW** |

## 2. `functions.jsonl` details

- 6,904 entries, every `entry` present in the listing, every listing matched by an entry.
- Decompile status: 6,903 success, 1 failure (`00498fe0`; the function reads global `0x005988cc`, tests `AL & 1`, conditional jump — a regular function, not an import stub; bounded by the JNZ at `00498feb`).
- Calling conventions: `thiscall` 2,996, `fastcall` 1,429, `cdecl` 1,294, `stdcall` 1,162, **`unknown` 23**.
  - **Corrected composition of the 23 `unknown` CCs:**
    - 22 are 5–6-byte import thunk stubs (`JMP dword ptr [IAT]`) named by the import analysis: `0041a570` (RVROLCLIENT.DLL::ROLClient_FreeMemory), `004aec83/004aec89/004aec8f` (KERNEL32: CreateToolhelp32Snapshot / Process32FirstW / Process32NextW), `004e6f05`…`004e6f6b` (MSI ordinal 205, SHELPER.DLL::SHelper_Init, 17 × FWPUCLNT.DLL Fwpm* signals).
    - 1 is `00498fe0` (decompiler timeout, regular code).
  - Verified directly from listings, e.g. `004aec83.asm` = `FF2528715100 JMP dword ptr [0x00517128]`; `004e6f0b.asm` = `FF254C745100 JMP dword ptr [0x0051744c]`.
- Duplicate **names** exist but entries are unique: 95 distinct names appear more than once, covering 316 entries (`scalar_deleting_destructor'` ×31, `operator()` ×15, `validate` ×12, `thunk_FUN_00478a50` ×8, …). This is expected CRT/template duplication, not a data-integrity problem. Function lookup must therefore always key on `entry`, never on `name`.

## 3. `references.jsonl` integrity

- 152,681 records, 0 parse failures, **0 exact duplicate lines** — consistent with `metadata.json: unique_references_exported = 152681` (records are unique, no de-duplication to apply).
- All records carry the 7 fields `direction`, `from`, `to`, `reference_type`, `is_call`, `from_function`, `to_function`; no missing keys.
- Directions: `outgoing_from_function` 135,019; `incoming_to_function_entry` 17,662.
- `is_call=true` records: **32,848** = 27,770 (`UNCONDITIONAL_CALL`) + 5,075 (`COMPUTED_CALL`) + 3 (`COMPUTED_CALL_TERMINATOR`). No other type carries `is_call=true`; no CALL-type record carries `is_call=false`.
- `reference_type` histogram: `DATA` 33,329 · `READ` 30,661 · `CONDITIONAL_JUMP` 28,189 · `UNCONDITIONAL_CALL` 27,770 · `WRITE` 21,677 · `COMPUTED_CALL` 5,075 · `UNCONDITIONAL_JUMP` 4,436 · `READ_WRITE` 788 · `COMPUTED_JUMP` 720 · `INDIRECTION` 31 · `EXTERNAL` 1 · `COMPUTED_CALL_TERMINATOR` 3 · `PARAM` 1.

### 3.1 Records whose `from` VA is not a listing instruction line

4,548 records (3.0%) — all `incoming_to_function_entry` with `from_function == null`:

| Kind | Count | Example |
|---|---|---|
| `DATA` refs from outside function bodies (read-only data, vtables, tables of function pointers) | 3,263 | `00517560 -> 00401020` |
| `UNCONDITIONAL_CALL` from non-analyzed code (entrypoint stubs, unidentified code) | 1,283 | `004013e5 -> 00471bc0` (from < 0x00401020 region of `.text`, or gaps) |
| `COMPUTED_CALL` from non-analyzed code | 1 | `004f843b -> 004e69b7` |
| `EXTERNAL` pseudo-record (`from: "Entry Point"`, `to_function: "entry"`, `to: 004e647c`) | 1 | equals PE `AddressOfEntryPoint (0x000e647c) + ImageBase` = **0x004e647c** |

`from` outside every function body is present in **0** records with `direction: outgoing_from_function` (all outgoing refs originate inside analyzed functions). The Entry Point record is a pseudo-edge, not a code site.

### 3.2 Instruction-line cross-check of every record

Every record whose `from` VA is an instruction line (148,133 records) was matched against the parsed mnemonic/operands:

- All `COMPUTED_CALL` lines are `CALL` with a non-direct operand (`ESI`, `EDI`, `EBX`, `dword ptr […]`). Zero `CALL 0x…` direct operands were found under `COMPUTED_CALL`.
- `UNCONDITIONAL_CALL` lines are either `CALL 0x…` direct (25,260) or **`JMP 0x…` direct (1,227)** — direct jumps into a function entry recorded as tail calls (`is_call=true`). This is a deliberate Ghidra classification; the raw byte is `E9`, not `E8`.
- All `CONDITIONAL_JUMP` are genuinely conditional mnemonics (`JZ` 15,702, `JNZ` 7,932, `JNS` 1,459, `JC` 1,034, `JNC` 528, `JA` 490, `JBE` 284, `JS` 200, `JL` 193, `JG` 166, `JLE` 123, `JGE` 56, `JP` 14, `JNP` 6, `JECXZ` 1, `JNO` 1). Zero `JMP`s.
- `UNCONDITIONAL_JUMP` 4,436/4,436 are `JMP 0x…` direct; `COMPUTED_JUMP` 720/720 are `JMP` with brackets (`JMP dword ptr […]`); `INDIRECTION` 31/31 are import-stub `JMP dword ptr [IAT]`.
- Non-instruction-line records classified in §3.1.
- DATA/READ/WRITE/READ_WRITE references split into three buckets (exact sums shown in `reference_check_output.txt`):
  1. **Textual match** — the target VA (or `EBP`/`ESP` for `Stack[…]`) appears in the operands (77,349 records). E.g. `LEA`, `PUSH 0x…`, `MOV [0x…], …`.
  2. **FS segment** — 1,699 records with `to = ffdff000`, operands `FS:[0x0]` — Ghidra's absolute rendering of the FS-base segment reference (TEB); `ffdff000` is not a RAM address.
  3. **Dataflow-resolved** — 4,176 records (`DATA` 374+2,509; `READ` 63+745; `WRITE` 19+247; `READ_WRITE` 1+218) where the operand uses a register/memory other than the resolved target — e.g. `00401da2 READ 00521710 CMP EAX,dword ptr [ECX]`, `00402d75 DATA Stack[-0x5b] LEA ECX,[EDX + 0x1]`. These are not mismatches; they are references resolved by Ghidra's dataflow and are unverifiable by operand text alone.

## 4. Thunk semantics — correction of onboarding language

The onboarding inventory wrote that "91 `is_thunk:true` functions are thunks". Verification shows those 91 are **CRT thunk-like wrappers recognized by Function-ID (FID)** — e.g. `thunk_FUN_0047 a000` ×2 — not PE import thunks. The real import thunks (`JMP [IAT]`) are the 22 `unknown`-CC functions listed in §2 plus a few `JMP [absolute]` import calls typed `COMPUTED_CALL`. See `thunk_and_import_mapping.md`.

## 5. `metadata.json` vs observed

| Field | metadata.json | Observed | Result |
|---|---|---|---|
| functions_total | 6904 | 6904 | PASS |
| functions_processed | 6904 | 6904 (all exported) | PASS |
| decompile_failures | 1 | 1 | PASS |
| instructions_exported | 355346 | 355346 (counted) | PASS |
| unique_references_exported | 152681 | 152,681 records, 0 duplicate lines | PASS |
| image_base | 00400000 | PE32 ImageBase 0x00400000; ASLR (`DYNAMIC_BASE`) enabled — all VAs are preferred-base | PASS (with note) |
| partial_export | false | false — full export | PASS |

No count differs. The differences vs the onboarding report are semantic refinements (§4) plus the added measurements in §1 (instruction VA range, duplicate name groups, FS pseudo-VAs, no-line references, `Entry Point` record).

## 6. Binary-level confirmation (read-only, static)

`objdump -p` / PE directory parse (`pe_imports.py`): PE32, `image base 0x00400000`, `AddressOfEntryPoint 0x000e647c`, import directory RVA `0x001450f4`, IAT directory RVA `0x00117000` (VA `0x00517000..0x0051753c`; 335 slots, 322 decoded names, 13 unused), sections `.text .rdata .data .rsrc .reloc`, Subsystem 3 (CUI), `DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVICE_AWARE`, `TimeDateStamp Wed Jul 29 09:12:40 2026`, checksum `0x00197a41`. Findings feed `thunk_and_import_mapping.md`.
