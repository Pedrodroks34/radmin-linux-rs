# Validation Discrepancies — what matches, what differs, what remains

Phase 0B question: does the onboarding report hold up? Short answer: **every numeric count re-verified exactly; four semantic refinements were needed.** No count in `metadata.json` or in the onboarding inventory is wrong. No export file was modified; no audit report was edited.

## 1. Onboarding figures — verification outcome

| # | Onboarding figure | Verified value | Outcome |
|---|---|---|---|
| 1 | 6,904 `.asm` files | 6,904 (no extras, no non-`.asm` entries) | MATCH |
| 2 | address range `00401020`–`00516f35` (function entries) | `00401020`–`00516f35` (same); instruction VA range is `00401020`–`00516f3a` (new measurement) | MATCH (+NEW) |
| 3 | x86 32-bit LE, image base `0x00400000` | confirmed from `language_id`, compiler spec, and the PE itself | MATCH |
| 4 | filename = entry VA, 1:1 | confirmed (0 missing, 0 extra listings) | MATCH |
| 5 | function boundaries reliable | 6,903/6,904 decompiled; 1 failure (`00498fe0`, timeout); 23 unknown CCs (22 of which are import stubs — not ambiguous boundaries) | MATCH / REFINED |
| 6 | cross-references available; direction/types usable | confirmed and **fully decoded** — see `reference_schema.md`; all 14 types accounted for; every record cross-checked against its instruction line | MATCH (+COVERAGE) |
| 7 | imported APIs identifiable | **yes** — export carries resolved names; PE decodes independently; routes agree; see `thunk_and_import_mapping.md` | **STRENGTHENED** (onboarding said "partially") |
| 8 | missing functions / unresolved references | 1 decompile failure; 4,548 refs from outside bodies (documented); 23 unknown CCs; 5,075 COMPUTED_CALL dataflow-resolved; **0** missing listings; **0** duplicate references | MATCH / CLARIFIED |
| 9 | tools available | confirmed: `grep`, `jq`, `xref.py`, `pe_imports.py`, `adb`-free static decode; all tested | MATCH / EXPANDED |
| 10 | prior audits are leads, not proof | still true; re-verified figures reproduce (15/14 callers of `FUN_0041e220`, 31/19 refs to `0x0055BF80`/`0x0055BF84`) | MATCH |

## 2. Refinement 1 — "thunks" ≠ PE import stubs

Onboarding said "91 `is_thunk:true` functions are thunks". Measured: those 91 are **Ghidra FID thunk-like wrappers** (internal code clones such as `thunk_FUN_00478a50` ×8). The actual PE import stubs — 22 `JMP dword ptr [0x00517xxx]` functions — were themselves hidden among the "unknown calling convention" bucket. Impact: any tooling that filters on `is_thunk` will **not** find import stubs, and vice versa. Both buckets are now separately enumerated.

## 3. Refinement 2 — unknown CC = import stubs + 1 decompile timeout

The 23 `calling_convention:"unknown"` entries are: `0041a570` (RVROLCLIENT.DLL::ROLClient_FreeMemory stub), `004aec83|004aec89|004aec8f` (Kernel32 Toolhelp32 stubs), `004e6f05…004e6f6b` (MSI ordinal 205, SHELPER SHelper_Init, 17 × FWPUCLNT) = 22 import stubs, plus `00498fe0` (regular function, decompiler timeout, not an import stub). Impact: the "unknown" bucket is no longer opaque — 22 of 23 have resolved roles.

## 4. Refinement 3 — `metadata.json: unique_references_exported` is accurate as-is

No duplicate reference lines exist (0/152,681). The word "unique" describes the producer's output guarantee, not a de-duplication step — records are unique verbatim.

## 5. Refinement 4 — duplicate function *names* (onboarding only said "entries unique")

95 distinct names repeat across 316 entries (`scalar_deleting_destructor'` ×31, `operator()` ×15, `validate` ×12, …). Entries remain unique; `name` must never be used as a key. Onboarding did not contradict this but now it is quantified.

## 6. Deliberate non-findings (things onboarding flagged that verification could not corroborate as "problems")

- **No listing file is missing and no orphan `.asm` exists** (1:1 with `functions.jsonl`).
- **No malformed reference records** — every one of the 152,681 parses and belongs to exactly one measured bucket; bucket sums reconcile to the raw counts exactly (DATA 33,329 = 27,183 textual + 2,509 stack-dataflow + 374 hex-dataflow + 3,263 no-line; READ 30,661 = 29,333 + 63 + 745 + 520 FS; WRITE 21,677 = 20,232 + 247 + 19 + 1,179 FS; READ_WRITE 788 = 569 + 1 + 218).
- **`UNCONDITIONAL_CALL` is not "E8 calls"** — 1,227 of its records are direct `JMP 0x…` tail calls and 1,283 originate outside function bodies; both subclasses were previously unquantified.
- **`COMPUTED_CALL` never carries a direct hex target** (5,074/5,074 are register/memory operands; the single missing listing line is an outside-body record).
- The export contains **no exports** itself (`.edata` size 0) — not an anomaly, expected for a service exe.

## 7. Genuinely different / unresolved items

| Item | Status | Detail |
|---|---|---|
| MSI ordinal 205 → `MsiEnumRelatedProductsW` | **UNVERIFIED NAME** | PE import directory contains ordinal 205 only; Ghidra supplied the name. Not confirmable without `msi.dll`. |
| OLEAUT32 (9) and WS2_32 (14) ordinal-only slots | **Ghidra-resolved names** | No `ordinal` string appears in `to_function`; resolution used the analyst's workstation. Consistent with well-known Windows ordinals (e.g. 115=WSAStartup, 2/3/23=socket-related on WS2_32) but not certified against local DLLs (not in workspace). |
| `PARAM` reference type | **SEMANTICS UNCLEAR** | 1 record (`00516f2b MOV … → 005a55fd`); a `PARAM`-feed reference, otherwise unused in the dataset. |
| `ffdff000` FS:[0x0] pseudo-address in 1,699 refs | **ARTIFACT, NOT AN ADDRESS** | TEB/TLS via FS segment; never dereference as a RAM VA. |
| 4,176 dataflow-resolved hex32/stack references | **NOT TEXTUALLY VERIFIABLE** | Resolved via Ghidra dataflow (`CMP [ECX]`, `LEA [EDX+1]`, …). No evidence of inconsistency; treat as resolved, not raw. |
| 4,548 records from outside function bodies | **EXPECTED** | Entrypoint stubs / vtables / unidentified code; documented in `dataset_validation.md` §3.1. |
| `Entry Point` pseudo-record (`EXTERNAL` → 004e647c) | **AS DESIGNED** | Matches PE `AddressOfEntryPoint`; not a call site. |
| `0x0055c110` "1 WRITE" | **MATCHES BINARY** | `00401038 MOV [0x0055c110],0x4b` — verified in listing and by `xref.py writes-to`. |
| Phase-8 audit figures (15/14 callers of `FUN_0041e220`; 31/19 global refs) | **REPRODUCED** | via `xref.py callers` and `grep -c` respectively. |

## 8. Limitations that future analyses must respect

1. ASLR: all VAs are preferred-base; the binary declares `DYNAMIC_BASE` (image base `0x00400000` is not the runtime base).
2. The export models memory with `Stack[…]` frame slots and TEB as `ffdff000`; raw addresses outside `00401020..00516f3a` are not backed by listings.
3. 23 `unknown` CCs: 22 are resolved (§3); 1 needs the assembly read manually.
4. Indirect-call *targets* (`COMPUTED_CALL`) are Ghidra resolutions; the 4,779 EXTERNAL names are workstation-derived but consistent with PE positions; the 295 internal hex32 targets (`FUN_004eb266`, `guard_check_icall`, …) are likewise inference-based.
5. DATA references from ro-data (vtables) have no instruction line; do not expect one.
6. Prior Portuguese audit reports (`ghidra_export/relatorio_parte*`) and `phase_8*_audit/` remain leads; Phase 0B independently confirmed only the figures listed in §7 — everything else in them awaits similar verification.
