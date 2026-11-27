# Phase 9C — Evidence Index

All evidence is reproducible from the artifacts listed here. Nothing outside the listed files was used; no binary was executed; nothing outside `analysis_workspace/phase_9C_audit/` and `analysis_workspace/validation/` was written.

## 1. Subject binary and export

| Item | Location / value |
|---|---|
| Binary (read-only) | `claude-handoff/binaries/radmin_ext/RvControlSvc.exe`, SHA-256 `546efad9ab3ff85c2a50d61524d754bec94a3f3e30d6ae8addef481a1e8daa1e` (relpath `claude-handoff/binaries/radmin_ext/`) |
| Export root | `ghidra_export/` |
| Function list | `ghidra_export/functions.jsonl` (6,904 records; `body_min`/`body_max`, `calling_convention`, `is_thunk`, `decompile_status`) |
| References | `ghidra_export/references.jsonl` (152,681 records) |
| Listings | `ghidra_export/listing/<entry-va>.asm` (6,904 files; 355,346 instruction lines; all parsed) |
| Export metadata | `ghidra_export/metadata.json` (Ghidra 12.2, x86 LE 32, image base `0x00400000`, `exported_utc 2026-11-11`) |
| PE (import directory, checksum, TimeDateStamp, entry point) | decoded read-only by `pe_imports.py` → `import_iat_map.txt`; cross-checked with `objdump -p` |

## 2. Tools used (all checked-in, read-only)

| Tool | Path | Role |
|---|---|---|
| `xref.py` | `analysis_workspace/validation/xref.py` | callers/callees/refs-to/writes-to/refs-in-range/listing/unique-callers — used for every inventory query and IAT range scan |
| `check_reference_samples.py` | `analysis_workspace/validation/check_reference_samples.py` | full cross-check of all 152,681 references vs listing lines |
| `validate_dataset.py` / `validation_output.txt` | `analysis_workspace/validation/` | Phase-0B integrity numbers (re-quoted, not re-run with edits) |
| `analyze_unmatched_refs.py` | `analysis_workspace/validation/` | the 4,548 outside-body records |
| `analyze_imports_thunks.py` + `import_mapping_output.txt` | `analysis_workspace/validation/` | EXTERNAL→API names; ranges |
| `pe_imports.py` + `import_iat_map.txt` | `analysis_workspace/validation/` | PE import directory decode (322 APIs / 13 DLLs / 335 IAT slots / 13 unused) |
| `verify_callsites.py` | `analysis_workspace/phase_9C_audit/` | prints the exact listing line per callsite VA |
| `count_iscall.py` | `analysis_workspace/phase_9C_audit/` | is_call composition by direction/type |
| `count_uncond.py` | `analysis_workspace/phase_9C_audit/` | E8 vs E9 vs no-line decomposition of `UNCONDITIONAL_CALL` |
| `which_function.py` | `analysis_workspace/phase_9C_audit/` | maps a VA to its containing exported function |
| `dump_rdata.py` | `analysis_workspace/phase_9C_audit/` | read-only `.rdata` dumps of tables `0x00521710`, `0x00519dac`, `0x0051b254`, `0x0051a9d0`, `0x00515830`, `0x0055bf80`, `0x0055bf84` |
| `ash` ghidra grep recipes | inline shell | exhaustive `0x214` / `0x2c` store-site scans (all outputs quoted in docs) |

## 3. Primary evidence (exact files and VAs)

### Callsite verification (all 38 sites instruction-verified)

- e220 sites: `00419e20.asm:00419e9b` · `0041a6d0.asm:0041a739,0041a768` · `0041ae30.asm:0041b05a` · `0041b090.asm:0041b125` · `0041b140.asm:0041b1cc` · `0041b2f0.asm:0041b370` · `0041bb40.asm:0041bd36` · `0041bd70.asm:0041c03a` · `0041df70.asm:0041e025` · `0041f710.asm:0041f80e` · `0041fa80.asm:0041fc6e` · `00420b80.asm:00420c7b` · `0041f110.asm:0041f3b1` · `0041f450.asm:0041f6dd`
- e280 sites: `00419b30.asm:00419bce` · `0041a640.asm:0041a6b2` · `0041a6d0.asm:0041a7f1` · `0041aa40.asm:0041aaee` · `0041b1e0.asm:0041b2a1` · `0041c300.asm:0041c3fd` · `0041c870.asm:0041c8df` · `0041d380.asm:0041d438,0041d468` · `0041d6e0.asm:0041d757` · `0041d770.asm:0041d87e` · `0041de60.asm:0041dec2` · `0041e1f0.asm:0041e20d` · `0041e360.asm:0041e457` · `0041f450.asm:0041f67e` · `00422840.asm:004229d9` · `00422e00.asm:00422ed0` · `004230c0.asm:00423239` · `00423980.asm:00423ad2` · `004240f0.asm:0042411c` · `0042f810.asm:0042f889` · `00430510.asm:0043057d`
- 16650 site: `00415300.asm:00415585`

### Gate and dispatch listings (all read in full)

- `listing/0041e220.asm` → Chain A (§ phase_9C_e220_pointer_chain.md)
- `listing/0041e280.asm` → Chain B
- `listing/00416650.asm` → Chain C
- `listing/00422f20.asm` (B1 gate) — `00422f99 LEA EDX,[EDI+0x214]`, `00422fa3 CMPXCHG.LOCK`, `00422fa9 JZ`, `00422fb9` dead CAS, `00423030 CALL 0x00419e20`
- `listing/004230c0.asm` (B2 gate) — `0042314d`, `00423157 CMPXCHG.LOCK [EDX],ECX`, `00423162 JZ`, `0042316c` dead CAS, `004231f7 CALL 0041a6d0`, `00423239 CALL 0041e280`
- `listing/00421410.asm` (constructor; single creation site at `0042daf2` in `FUN_0042d980`) — `004216a3 MOV ECX,0x27` / `004216a8 REP MOVSD` (copies `0x110..0x1AB`), `0042173b MOV [EDI+0x214],0`, `00421745 MOV [EDI+0x218],0`, `00421756 MOVUPS [EDI+0x21C],[0x00521710]`, `0042175d`, single `RET` at `00421777`, field never reached by bulk copy
- `listing/00422ce0.asm` — message switch `MOVZX EAX,byte ptr [EAX+0x422dc8]; JMP dword ptr [EAX*4+0x422da0]`
- `listing/0041a6d0.asm` — `0041a739`/`0041a768`/`0041a7f1`
- `listing/0041ee90.asm` — swap helper (CAS + XCHG pattern on local/field)
- `listing/00415585.asm`, `listing/00415300.asm` — 16650 caller
- `listing/00498fe0.asm` — 82,424-byte registry/event megafunction; zero dispatcher references
- `listing/004ff788.asm` (`__malloc_base`) → `HeapAlloc(0x005a61a0, 0x0, size)` — not zeroing (import `0x005172f0` = HeapAlloc hint 840 ✓ `objdump -p`)
- `listing/004019c0`-family n/a

### Static table dumps (read-only)

- `0x00519dac` → `[+0x0C]` = `0x00479d80` (`FUN_00479d80`)
- `0x0051b254` → `[+0x0C]` = `0x00479d80`
- `0x00521710` = all-zero leading 16 bytes (the MOVUPS source constant) + repeated 16-byte pattern `dcb00000 4a9b570f 9f19698d 3b72a5db` / `dcb00c01 …`
- `0x0055bf80` / `0x0055bf84` = all-zero `.data` (shared-state pair)

### Reference records cited verbatim

- All `0041e220` / `0041e280` / `00416650` callsite records: exactly one each (verified; list in `phase_9C_callsite_inventory.md`).
- `{"from":"00423239","to":"0041e280","reference_type":"UNCONDITIONAL_CALL","is_call":true,"from_function":"FUN_004230c0","to_function":"FUN_0041e280"}`
- `{"from":"004231f7","to":"0041a6d0","reference_type":"UNCONDITIONAL_CALL","is_call":true,...}`
- `{"from":"00404221","to":"00517260","reference_type":"READ",...}` and `…"COMPUTED_CALL"…to_function":"KERNEL32.DLL::SetLastError"` — the two-record IAT-call pair

### Git preservation record

- HEAD before Phase 9C: `b873cea0bd1f3890925a0c0f79bbe2abc16db6cd` (`main`) — external commit by Pedrodroks34 2026-11-08 19:59:30 ("docs: add SRP reverse engineering evidence phases 10.3-10.20"); the Phase-0B documented `95e304e…` is stale — recorded in `phase_9C_main_report.md` §1.
- No commits made by this session; no resets/checkouts/stashes; no file modified outside `analysis_workspace/phase_9C_audit/`.
- `git status --short` at phase end: same three modified tracked files (`.gitignore`, `src/session/control_handshake.rs`, `src/session/mod.rs`) + untracked pre-existing scripts + my Phase 0B and Phase 9C directories.
