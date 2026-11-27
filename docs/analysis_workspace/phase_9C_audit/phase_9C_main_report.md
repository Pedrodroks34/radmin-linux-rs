# Phase 9C — Main Report: Independent Revalidation of Dispatcher Findings

**Date:** 2026-11-13 · **Repository:** `/home/pedrodroks/Downloads/radmin`
**HEAD:** `b873cea0bd1f3890925a0c0f79bbe2abc16db6cd` (`main`)
**Binary analyzed:** `RvControlSvc.exe`, SHA-256 `546efad9ab3ff85c2a50d61524d754bec94a3f3e30d6ae8addef481a1e8daa1e` (unmodified, read-only)
**Export:** `ghidra_export/` (6,904 listings, 355,346 instructions, 152,681 references)

## 1. Git state (Phase 9C preservation record)

Verified before any work:

- `HEAD` = `b873cea0bd1f3890925a0c0f79bbe2abc16db6cd`, branch `main`.
  **Discrepancy vs the Phase 0B baseline:** the environment moved from `95e304e…` to `b873cea…` via commit **"docs: add SRP reverse engineering evidence phases 10.3-10.20"** authored by **Pedrodroks34, 2026-11-08 19:59:30**. The commit predates this session; the prior onboarding/Phase-0B documentation stated HEAD=`95e304e…`, which is **stale**. No commits were made during Phase 0B or Phase 9C.
- `git status --short` at start of Phase 9C: `M .gitignore` · `M src/session/control_handshake.rs` · `M src/session/mod.rs` · untracked `analysis_workspace/` and pre-existing analysis scripts (preserved).
- `.gitignore` contains `ghidra_export/` (added by the external commit) — the export directory is git-ignored, which is correct for proprietary binaries.
- No reset/checkout/stash/commit/push was performed. No Rust file, export file, or prior audit report was modified.
- New deliverables: `analysis_workspace/phase_9C_audit/` only.

## 2. Scope and method

Revalidation of the Phase-8 series findings (dispatcher family: `FUN_0041e220`, `FUN_0041e280`, `FUN_00416650`) with instruction-level verification:

- every callsite reference record cross-checked against the listing line at the `from` VA (exact bytes + mnemonic);
- every blocked-path gate instruction and branch read in full context;
- exhaustive grep over all 6,904 listings for all stores/atomics targeting `+0x214`;
- direct PE import-directory decode (`pe_imports.py`) for the IAT slots involved in the traced paths;
- read-only `.rdata` dumps of the two static tables referenced by the constructor;
- all cross-checks reproducible with the checked-in scripts listed in `phase_9C_evidence_index.md`.

## 3. Answers to the final questions (§12)

1. **Are the e220 and e280 callsite inventories still correct?**
   Yes — **15 callsites / 14 unique callers** for `FUN_0041e220` and **22 callsites / 21 unique callers** for `FUN_0041e280`, all `E8 rel32` direct `CALL` instructions, verified byte-wise. **Correction:** the `relatorio_parte8R_caller_table.md` claim "22 distinct caller functions (no function calls it twice)" is **wrong** — `FUN_0041d380` calls `FUN_0041e280` twice (`0041d438`, `0041d468`). The Phase-8X count of 21 unique callers was correct.
2. **Is `FUN_004230c0` actually a direct e280 caller?** **YES — directly.** `00423239` is `E842B0FFFF CALL 0x0041e280` in `listing/004230c0.asm`, and `references.jsonl` contains a matching record. It additionally calls `FUN_0041a6d0` at `004231f7`, which directly calls e280 at `0041a7f1`. The alleged e280 call at `00423239` is real and is not misattributed; `0041a7f1` lives in the callee, not in `FUN_004230c0`.
3. **Which of the four blocked classifications survive independent verification?**
   None survive as "PROVEN BLOCKED". All five BLOCKED-labeled sites (**E1** `00419e9b`, **E2a** `0041a739`, **E2b** `0041a768`, **E3** `0041a7f1`, **E4** `00423239`) are **BLOCKED UNDER EXPLICIT ASSUMPTIONS** (the `+0x214 == 0` gate). See `phase_9C_blocked_path_revalidation.md`. The branches are correctly read; the "always 0" premise is not provable from the export alone.
4. **Are the three indirect pointer chains accurately reconstructed?**
   Yes, reconstructed completely. **e220/e280 chain:** `target = [V]` where `V = [[EDI + [P + 0x04] + 0x0C]]`, `P = [EDI+0x0C]` — resolvable as a chain, target not statically resolvable. **16650 chain:** `target = [P16650 + 0x0C]`, `P16650 = [this+0x08]` statically initialized by the constructor to `0x00519dac` or `0x0051b254`; the dword at `0x00519db8` and at `0x0051b260` is **`0x00479d80`** — the 16650 dispatch target is statically resolvable to `FUN_00479d80`. The chains are three different shapes; they were not merged.
5. **Does `FUN_00498fe0` contain information relevant to the dispatcher investigation?**
   **No.** 20,878 instructions, 82,424 bytes, zero references to the dispatcher family, to `+0x214`, or to the `0x0055BF80/0x0055BF84` globals. Its decompiler timeout is a size problem, not a semantics problem.
6. **Did the validated dataset tools reveal any errors in earlier phases?**
   Yes — see `phase_9C_discrepancy_log.md` (D-01…D-14), including the `relatorio_parte8R_caller_table.md` unique-caller claim, the `is_call=true` composition (COMPUTED_CALL_TERMINATOR omitted), the 8R "CONFIRMED" vs 8X "BLOCKED" inconsistency for `00423239`, and the corrected `+0x214` store inventory. The 15/14 and 22/21 inventories, the three-chain structure, and the `+0x214 == 0` write inventory all re-verified.
7. **Which previous conclusions should be retained, downgraded, or withdrawn?**
   - Retained: inventories (15/14, 22/21, 1/1), the `+0x214` gate logic, the constructor-zeroes-`+0x214` fact, `FUN_0041f110`/`FUN_00420b80` having no direct callers, the global-state spin (0x0055BF80/0x0055BF84).
   - Downgraded: all "PROVEN BLOCKED / unreachable" claims → **BLOCKED UNDER EXPLICIT ASSUMPTIONS**; "only write to +0x214 is MOV [EDI+0x214],0" → "no instruction in the export stores a non-zero value into [x+0x214]" (the conclusion stands, the evidence statement was wrong).
   - Withdrawn: "22 distinct callers" (unique count is 21) in `relatorio_parte8R_caller_table.md`; the framing that `FUN_004230c0` does not/cannot call e280 at `00423239`; the `8W`/`8X` internal "CONDITIONAL"-vs-"BLOCKED" inconsistency for the same edge.
8. **What is the single most valuable next investigation after Phase 9C?**
   **Object-identity and sub-object initialization of the dispatch family** — specifically, which code path writes `[this+0x0C]` (P) and `[P+0x04]` (D) for the Group-A sub-object at `base+0x28`, and whether any path writes them before the first gate. Every dispatch-target question (e220/e280) and every blocked-path verdict reduce to this single underdetermined node; it alone decides whether the dispatcher is statically dead, dynamically live, or data-driven opaque. Tools needed: a dataflow-capable view (Ghidra scripting over `references.jsonl`+listings) or, better, one authorized dynamic session per the Phase 10.20 plan (break on `FUN_0041e220`/`FUN_0041e280` and dump `EDI`, `[EDI+0x0C]`, `[P+0x04]`).

## 4. Executive summary

### Confirmed facts (DIRECTLY VERIFIED / CROSS-VALIDATED)
- `is_call=true` total is **32,848** = 27,770 `UNCONDITIONAL_CALL` + 5,075 `COMPUTED_CALL` + 3 `COMPUTED_CALL_TERMINATOR`. Machine-level CALL instructions number 30,338 (25,260 direct E8 + 5,074 indirect with listing line + 3 terminators + 1 from outside non-analyzed code); 1,227 of the flagged records are direct `JMP` tail calls and 1,284 originate from outside analyzed bodies.
- e220: 15 direct-call sites, 14 unique callers; e280: 22 direct-call sites, 21 unique callers; FUN_00416650: 1 call site (FUN_00415300 @ 00415585). Every callsite verified byte-wise against its listing line; every is_call site is logged exactly once in `references.jsonl`.
- `FUN_004230c0` **directly calls** `FUN_0041e280` at `00423239` (`E842B0FFFF`); additionally calls `FUN_0041a6d0` at `004231f7` (`E8D474FFFF`), which directly calls e280 at `0041a7f1` (`E88A3A0000`).
- `00423157` = `F00FB10A CMPXCHG.LOCK dword ptr [EDX],ECX` with `EDX = ESI + 0x214` (`0042314d LEA EDX,[ESI + 0x214]`), `EAX = 0` (`00423155`), `ECX = 0`; `JNZ` at `00423162` gates the work block; gate semantics verified.
- Exhaustively across all 6,904 listings: **no instruction stores a non-zero value into any `[reg + 0x214]`** — the only direct store is `MOV dword ptr [EDI + 0x214],0x0` (`0042173b`, FUN_00421410, on every completed construction; single RET at `00421777`); every other write is `XCHG` with 0 or `CMPXCHG`/`CMPXCHG.LOCK` with a zero accumulator; the constructor's 156-byte (`0x27` dword) `REP MOVS` copies only `[EDI+0x110..0x1AB]` and cannot reach `+0x214`; no bulk copy, callback, or pool path writes the field non-zero **within the export**.
- `FUN_00416650`'s indirect target is statically resolvable (conditional): constructor writes `[this+0x08]` := `0x00519dac` or `0x0051b254` (`004214f0`, `0042155b`); both `.rdata` tables store `0x00479d80` at `+0x0C` (`0x00519db8`, `0x0051b260`) — target = **`FUN_00479d80`** (`thiscall`, 251 bytes).
- Allocator chain `FUN_004e5a66 → FUN_004018a0 → __malloc_base (FUN_004ff788 → HeapAlloc, flag 0x0)` does **not** zero memory (`pe_imports.py`: IAT `0x005172f0` = KERNEL32.DLL::HeapAlloc).
- `FUN_00498fe0` = 82,424-byte megafunction (20,878 instructions); zero dispatcher-related references; its decompiler timeout (`process: timeout`) is size-induced.
- IAT slots in traced paths match the PE directory: `0x00517260` SetLastError (hint 0x534=1332) ✓ `objdump -p`; `0x00517280` GetLastError (hint 0x264=612) ✓.

### Conditional conclusions (evidence strong, assumptions explicit)
- The five BLOCKED-labeled callsites are **BLOCKED UNDER EXPLICIT ASSUMPTIONS**, not PROVEN BLOCKED: (A1) every gate object is constructed via `FUN_00421410` — its only creation site is `0042daf2` (`FUN_0042d980`), the only constructor writing `+0x214`, so all such objects carry `+0x214 == 0` (STRONGLY_SUPPORTED, conditional on no object bypassing this constructor); (A2) no code outside the export (RVROLCLIENT.DLL, SHELPER.DLL, other processes, memory corruption) writes `+0x214 != 0` (UNKNOWN); (A3) the gate's base register denotes the same allocation the constructor decorated (STRONGLY_SUPPORTED: `EDI`/`ESI` loaded from `ECX` at entry in both gates).
- The e220/e280 indirect target chain is correctly reconstructed (`[EDI + [P+0x04] + 0x0C]` dereferenced twice), but `P` and `D` are runtime pointers — **target not statically resolvable**; producers of `P = [obj+0x0C]` are not isolated in the export (403 candidate `[reg+0xc]` store sites, none provably tied to dispatch objects); no export code provably writes `[P+0x04]`.
- `REACHABILITY` of the blocked callsites is independent of the vtables; they are reachable iff the assumptions fail or an external agent sets `+0x214 != 0`.

### Unresolved questions
- Who writes `[this+0x0C]` and `[P+0x04]` for the Group-A sub-object at `base+0x28` (Group C: `base+0x08`)? What is the initial state of the sub-object's CAS1/CAS2 fields on a fresh `HeapAlloc` allocation (HeapAlloc flag 0x0 — **not zeroed**); nothing in the export initializes them.
- Can `FUN_00416650`'s path be entered with `[this+0x8]` pointing at a table other than the two constructor-set ones (e.g., from a different object class)?
- Is `FUN_00498fe0` reachable from the dispatcher family at all? (Incoming references: only FUN_004891d0 — a CRT-ish caller — no, but the analysis of 82 KB was not performed.)
- Does any hot-plug/callback path mutate `+0x214`? (None in-export; unknown at runtime.)
- The `PARAM`-typed reference and the fourteen `READ` refs to `[reg+0x1e8 region` were not needed for any Phase-9C conclusion.

## 5. Bottom line

Phase 8's core quantitative claims survive independent verification; Phase 9C refines them: one factual error in a caller table (unique-caller count), one understated evidence statement (`+0x214` stores), one internal classification inconsistency, and one misdiagnosed meaning of the 32,848 records. The blocked-path family is **not proven dead**; it is **blocked under explicit, testable assumptions** — exactly the gap dynamic analysis (Phase 10.20 plan section) is designed to close.
