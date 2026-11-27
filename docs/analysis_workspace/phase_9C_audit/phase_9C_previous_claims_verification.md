# Phase 9C — Verification of Previous Reports' Claims

Each claim was re-derived from the raw artifacts. Verdicts: **CONFIRMED** · **CONFIRMED-CORRECTED** (conclusion right, statement imprecise) · **REFUTED** · **DOWNGRADED** · **UNRESOLVED** · **NOT RE-VERIFIED**.

## A. Quantitative claims

| # | Claim (source) | Verdict | Evidence |
|---|---|---|---|
| A1 | `is_call=true` total = **32,848** (Phase 0B/9C) | **CONFIRMED** | `grep -c '"is_call":true"` → exactly 32,848; breakdown in `phase_9C_reference_count_reconciliation.md` |
| A2 | 32,848 = 27,770 + 5,075 (earlier phrasing) | **REFUTED (incomplete)** | Missing `COMPUTED_CALL_TERMINATOR` ×3. Corrected: 27,770 + 5,075 + 3 |
| A3 | 15 direct callsites / **14** unique callers, `FUN_0041e220` (8W/8X) | **CONFIRMED** | `xref.py callers` + byte verification of all 15 sites (all `E8` DIRECT CALL) |
| A4 | 22 callsites, `FUN_0041e280` (8X/8R/8W) | **CONFIRMED** | 22 sites, all `E8` direct CALL |
| A5 | "**22 distinct caller functions** (no function calls it twice)" (8R caller table §5.1) | **REFUTED** | `FUN_0041d380` calls it twice (`0041d438`, `0041d468`) → 21 unique callers |
| A6 | `FUN_0041e1f0` wrapper called from exactly 3 sites (`0041b043`, `0041bc76`, `0041bed2`) (8R) | **CONFIRMED** | `xref.py callers 0041e1f0` → 3 sites, all from FUN_0041ae30/0041bb40/0041bd70 |
| A7 | `FUN_0041e1f0` itself calls e280 at `0041e20d` (8R) | **CONFIRMED** | Bytes `E86E000000`, target resolves to `0x0041e280`; references.jsonl has the edge |
| A8 | `FUN_00416650` has exactly 1 caller: `FUN_00415300` @ `00415585` (8S) | **CONFIRMED** | `xref.py callers 00416650` → 1 site |
| A9 | `FUN_0041e1f0`'s e220-family relevance; dispatch family has 15/14 and 22/21 | **CONFIRMED** | see A3/A4/A6 |
| A10 | `FUN_0041f110` and `FUN_00420b80` have **no** incoming calls (8W) | **CONFIRMED** | `xref.py callers` → 0 sites each |
| A11 | 31 `INDIRECTION` records = IAT stub jumps (Phase 0B) | **CONFIRMED** | re-checked this phase (`refs-in-range 00517000 00517540 --type INDIRECTION` → 31) |
| A12 | `0x00517260` = SetLastError, `0x00517280` = GetLastError (PE import map) | **CONFIRMED** | PE decode matches `objdump -p` (hints 0x534/0x264) and is used by exactly the traced paths |

## B. Mechanism claims

| # | Claim (source) | Verdict | Evidence |
|---|---|---|---|
| B1 | `FUN_004230c0` **directly calls** `FUN_0041e280` at `00423239` (8R "CONFIRMED", 8W table "BLOCKED", 8W graph edge "CONDITIONAL") | **CONFIRMED** (existence) — **DOWNGRADED** (reachability) | bytes `E842B0FFFF`; `references.jsonl` edge; `xref.py callers 0041e280` #22. Blocked-path analysis in `phase_9C_blocked_path_revalidation.md` |
| B2 | `0041a7f1` is an e280 call alleged against `FUN_004230c0` | **REFUTED as written** — `0041a7f1` is inside `FUN_0041a6d0`, a **callee** of `004230c0` (bytes `E88A3A0000`); `FUN_004230c0` reaches e280 through `004231f7` (→`0041a6d0`) and directly at `00423239` | `listing/0041a6d0.asm:0041a7f1`; `xref.py callers 0041a6d0` → 1 site; `xref.py callers 0041a7f1` → n/a (internal) |
| B3 | "The CMPXCHG at `00423157` always reads 0, so `JZ` at `00423162` is always taken" (8V) | **DOWNGRADED** → CONDITIONAL | branch semantics exactly as reported; the "always 0" premise is **not provable from the export** (constructor zeroes it, A1 holds for the only creation path — but A2/A3 caveats apply). Not PROVEN BLOCKED |
| B4 | "The only write to `[x+0x214]` is `MOV [EDI+0x214],0` at `0042173b`" (8V/8X writers) | **REFUTED as stated** → **CONFIRMED-CORRECTED** | no instruction in the export stores a **non-zero** value into `[X+0x214]`; direct store (0) at `0042173b`; XCHG/CAS-with-0 writes elsewhere; the conclusion survives, the evidence statement was incomplete |
| B5 | `FUN_00416650` chain `CALL [EDX+0x0C]` with EDX=[EBX+0x8] (8R indirect) | **CONFIRMED** | `FF520C`, EDX=[EBX+0x8], EBX=ECX; static producer found (see B8) — chain target resolvable |
| B6 | `FUN_0041e220`/`FUN_0041e280` chain `CALL [EDX]` with `P=[EDI+0xc]`, `D=[P+4]`, `A=EDI+D+0xc`, `V=[A]` (8R indirect) | **CONFIRMED** | `FF12`; full register trace in `phase_9C_e220_pointer_chain.md` / `phase_9C_e280_pointer_chain.md`; IAT slots re-verified (B12) |
| B7 | The e220/e280 chains are "the same dispatch mechanism" (mergeable) | **REFUTED** | same dereference skeleton, **different** argument state machines (e220: raw arg1/constant 6; e280: BL-blended arg1/arg2/5/1); different RET (0x4 vs 0x8); different prologue semantics. 16650 is a *third, unrelated* shape |
| B8 | 16650's target `CALL [EDX+0x0C]` is an opaque dynamic pointer | **CORRECTED** — target is **statically resolvable**: `0x00479d80` (`FUN_00479d80`, thiscall, 251 B), stored at `0x00519db8`/`0x0051b260` (constructor tables A/B); both dump-verified |
| B9 | `FUN_00422ce0` is the message dispatcher (jump table at `0x422da0`) (8R) | **CONFIRMED** | `listing/00422ce0.asm`: `MOVZX EAX,byte ptr [EAX+0x422dc8]; JMP dword ptr [EAX*0x4+0x422da0]` |
| B10 | `FUN_0041a6d0` is the "wrapper-reproducing" caller of e220/e280 (8R) | **CONFIRMED (mechanics) / REFUTED (framing)** | mechanics verified (2× `CALL 0x00415f80`, `PUSH EDI/PUSH EDX` pattern); but it is not a wrapper — it is a **distinct message handler** in the same family (analyzed `0041a6d0` in full) |
| B11 | `FUN_0041e1f0`'s callers pass `EDI+0x28` (8R) | **CONFIRMED** | all three wrappers' callers verified (`0041ae30`, `0041bb40`, `0041bd70`) |
| B12 | `0x0055BF80` / `0x0055BF84` shared pair (8S/8T/8U leads) | **RE-VERIFIED — CONFIRMED as shared-state candidates** | `FUN_00416650` uses both (`XADD.LOCK` @ `0041670b`/`00416745`, sentinel `0xf423f`, 10-iteration spin) — global pair in `.data`, zero-initialized |
| B13 | `FUN_00498fe0` decompile failure is "just a timeout" | **CONFIRMED** | 82,424 bytes; largest function in export; zero dispatcher-related refs |

## C. Classification claims

| # | Claim | Verdict |
|---|---|---|
| C1 | "BLOCKED (proven unreachable)", `phase_8W/8X` (all 5 gate-reached sites) | **DOWNGRADED** → **BLOCKED UNDER EXPLICIT ASSUMPTIONS** (A1–A3 in `phase_9C_blocked_path_revalidation.md`) |
| C2 | "CONDITIONAL" groups for independent callers | **RETAINED** (10 sites), with the additional caveat that Group-A sub-object CAS1 fields are uninitialized heap garbage (HeapAlloc flag 0x0) — conditional on the allocator's zero-fill behavior or an external zeroing |
| C3 | "UNKNOWN" for `FUN_00420b80`, `FUN_0041f110` | **RETAINED** (0 incoming refs) — may be called only via indirect/vtable, which statics cannot resolve |
| C4 | "Only write to `+0x214` is the MOV-0 at `0042173b`" | **REFUTED as evidence statement** — inventory now complete: no non-zero store exists anywhere; conclusion survives |
| C5 | `relatorio_parte8R_caller_table.md` says e280 caller table "22 distinct callers" | **REFUTED** — 21 unique callers; the table's own rows show `FUN_0041d380` twice |

## D. Tool/schema claims (Phase 0B)

| # | Claim | Verdict |
|---|---|---|
| D1 | `.asm` 6,904 / references 152,681 / instructions 355,346 | **CONFIRMED** (re-measured) |
| D2 | `COMPUTED_CALL` has no direct-hex targets | **CONFIRMED** |
| D3 | `UNCONDITIONAL_CALL` includes 1,227 tail-JMPs | **CONFIRMED** (580 outgoing + 647 incoming) |
| D4 | Incoming-vs-outgoing asymmetry — each edge logged once | **CONFIRMED** (all 38 dispatcher callsites logged exactly once; direction split is not deterministic per address) |
| D5 | `FUN_00498fe0` is the largest analyzed function | **CONFIRMED** (82,424 B) |
| D6 | Export has no exports (`.edata` null) | **CONFIRMED** — binary can only be entered via vtable/CRT entry points |
| D7 | IAT slots resolve to 322 APIs, 13 DLLs, 13 unused slots | **CONFIRMED** |
| D8 | `ffdff000` = FS:[0x0] TEB artifact (1,699 refs) | **CONFIRMED** |

## E. Summary matrix

| Decision | Retain | Downgrade | Withdraw |
|---|---|---|---|
| Callsite inventories (15/14, 22/21, 1/1) | ✔ | — | — |
| `is_call` total 32,848 composition | ✔ (corrected breakdown) | — | — |
| +0x214 gate existence and branch semantics | ✔ | — | — |
| "+0x214 is never written non-zero" | ✔ (CORRECTED evidence) | — | as phrased |
| "PROVEN BLOCKED / unreachable" for the 5 sites | — | BLOCKED UNDER EXPLICIT ASSUMPTIONS | ✔ (as phrased) |
| "22 distinct e280 callers" (8R) | — | — | ✔ |
| "`00423239` is not a direct e280 call / misattributed" | — | — | ✔ (it IS one) |
| 16650 target opaque | — | CORRECTED → `FUN_00479d80` | ✔ (as opaque) |
| `FUN_00498fe0` unknown/blocker-ish | — | irrelevant | ✔ |
| e280 unique-caller count | 21 | — | 22-distinct-claim |
| CAS-success values `0xf423f`/`0x6`/`0x5`/arg | ✔ | — | — |
