# Phase 9C — Discrepancy Log

Numbered findings. Severity: **P0** contradiction · **P1** factual error (correctable) · **P2** imprecision / stale figure · **P3** note.

## D-01 — `is_call=true` composition omitted COMPUTED_CALL_TERMINATOR (P2)
Phase 0B wrote `32,848 = 27,770 + 5,075`. Actual: `32,848 = 27,770 + 5,075 + 3` (3 terminators, all `outgoing`). The 32,848 figure itself is correct. → `phase_9C_reference_count_reconciliation.md`

## D-02 — "22 distinct callers, no function calls it twice" for FUN_0041e280 (P1)
`relatorio_parte8R_caller_table.md` §5.1. Rows #8/#9 (`FUN_0041d380` @ `0041d438`, `0041d468`) show the same function twice. Unique callers = **21**. Phase 8X's "21" was correct; the 8R summary sentence was not. → `phase_9C_callsite_inventory.md` §2

## D-03 — 8R "CONFIRMED" vs 8W-graph "CONDITIONAL" vs 8X/8W-table "BLOCKED" for `00423239` (P0, unresolved-by-prior-phases)
All three labels refer to the same instruction `E842B0FFFF CALL 0x0041e280`. The phases never produced instruction-level disagreement; they produced **classification disagreement** about one edge, and an internal contradiction inside `phase_8W_reachability_graph.md` (edge labeled both CONDITIONAL and BLOCKED). → **RESOLVED**: existence DIRECTLY VERIFIED; reachability = **BLOCKED UNDER EXPLICIT ASSUMPTIONS**. → `phase_9C_230c0_discrepancy.md`

## D-04 — "Only write to [x+0x214] is MOV [EDI+0x214],0 at 0042173b" (P1)
True statement: **no instruction in the export stores a non-zero value into any `[X+0x214]`**. Stores exist (XCHG-with-0, CMPXCHG-with-0-accumulator, and the direct MOV-0 at `0042173b`). The conclusion survives; the evidence statement was incomplete. Prior phases relied on the incomplete version. → `phase_9C_blocked_path_revalidation.md` §2

## D-05 — "JZ at 00423162 always taken" (8V) → unprovable from export (P1)
Branch semantics are exactly as reported; the **always-taken** premise is data-dependent on `[ESI+0x214]`, which is only zero for constructor-built objects under A1∧A2. Not provable statically; now **BLOCKED UNDER EXPLICIT ASSUMPTIONS**. → `phase_9C_blocked_path_revalidation.md` §5

## D-06 — 16650 target claimed opaque in 8R; actual target is a static pointer to FUN_00479d80 (P1)
Dumped `.rdata`: `[0x00519db8] = [0x0051b260] = 0x00479d80` (`FUN_00479d80`, thiscall, 251 B). The field `[this+0x08]` is statically initialized by the constructor at `004214f0`/`0042155b`. → `phase_9C_16650_pointer_chain.md` §4

## D-07 — e220/e280 described as one generic dispatch (P2)
Same dereference skeleton but different state machines; 16650 is a third shape. No merging permitted. → `phase_9C_e220_pointer_chain.md`, `phase_9C_e280_pointer_chain.md`, `phase_9C_16650_pointer_chain.md`

## D-08 — Phase-0B HEAD anchor stale (P2)
`analysis_workspace/dataset_inventory.md` and the Phase-0B report say HEAD=`95e304e…`; the actual HEAD is `b873cea…` (external commit 2026-11-08 19:59:30 by Pedrodroks34 — "docs: add SRP reverse engineering evidence phases 10.3-10.20"). Prior reports must not be assumed to reflect the current tree. → `phase_9C_main_report.md` §1

## D-09 — `FUN_00498fe0` treated as "unknown/unusable" (P2)
It is a complete, linearly-scoped 82,424-byte registry/event installer; zero dispatcher significance. The decompiler timeout is size-induced; the assembly is usable and fully cross-referenced. → `phase_9C_498fe0_manual_analysis.md`

## D-10 — "22 callsites, 22 distinct callers" mismatch vs row-level data (P1)
Same root as D-02; the table's own rows contain the duplicate (#8/#9). Anyone counting from the table gets 21 without noticing the sentence above it says 22. → `phase_9C_callsite_inventory.md` §2

## D-11 — `0x522c5c`/`0x258` allocator pair: operator new-size cookie (P3)
`FUN_0042d980`: `PUSH 0x522c5c; PUSH 0x258; CALL 0x004e5a66` — 0x258 = 600 bytes allocated. `FUN_004e5a66` → `FUN_004018a0` → `__malloc_base` → `HeapAlloc(…, 0x0, …)` — **memory not zeroed**. Constructor reliance on HeapAlloc zero-fill is therefore unsupported. → `phase_9C_evidence_index.md` §3, `phase_9C_blocked_path_revalidation.md` §2 (Pool/reuse)

## D-12 — `FUN_00421410`'s bulk copy does not cover `+0x214` (P3, confirmation)
`004216a8 REP MOVSD` copies `[EDI+0x110, EDI+0x1AC)` only (0x27 dwords). A prior phase floated the possibility of initializer-bypass; the range proof closes that vector. → `phase_9C_blocked_path_revalidation.md` §2 (Bulk-copy check)

## D-13 — incoming/outgoing logging asymmetry for the same edge (P3)
Each callsite is logged exactly once, but the *direction* is not deterministic per address (some callsites appear as `outgoing_from_function`, some as `incoming_to_function_entry`, e.g. e220 #11–#15 vs #1–#10). Counts must match on `to`, not on direction. → `phase_9C_reference_count_reconciliation.md` §3, `phase_9C_callsite_inventory.md` (inventory legends)

## D-14 — `+0x214` dead CAS at `0042316c` (P3)
`FUN_004230c0` issues a second `CMPXCHG.LOCK [EDX],ECX` on the same field with the same zero accumulator immediately after the branch — no consumer; an atomic RMW with +0. Not an error per se (it "writes 0 to guarantee the field stays 0"?), but flagging it prevents a wrong reading that the second CAS arms the next dispatch. → `phase_9C_230c0_discrepancy.md` §5

## D-15 — 8W internal edge-label contradiction (P1)
`phase_8W_reachability_graph.md` labels `FUN_004230c0 → N2` at `00423239` both "CONDITIONAL" (Direct Calls section) and "BLOCKED" (Blocked Edges section). Single-edge authority established this phase: existence DIRECTLY VERIFIED; reachability BLOCKED UNDER EXPLICIT ASSUMPTIONS (D-05). → `phase_9C_230c0_discrepancy.md` §6

## D-16 — Corpus has no `phase_8Z`/`phase_9A` reports (P2)
Mission references to "Phases 8Z and 9A" do not correspond to any file under `ghidra_export/` (latest: 8X) or `analysis_workspace/`. The likely intended targets ("the four blocked paths") map to the five BLOCKED-labeled sites analyzed here — revalidated individually rather than matched to a literal count of four. → `phase_9C_blocked_path_revalidation.md` §0

## D-17 — `00498fe0`'s bogus `calling_convention: "unknown"` and giant size in the CC census (P3)
23 "unknown" CCs: 22 are PE import stubs (Phase 0B §2); the 23rd is `00498fe0` (82 KB monolith). Not an analysis gap, just a CC the Ghidra analyser could not infer; irrelevant to dispatcher work. → `phase_9C_498fe0_manual_analysis.md` §4

## D-18 — Non-dispatcher `+0x214`-adjacent CAS at `00423205`/`004232c0` (P3, note)
The `00423205 CMPXCHG.LOCK [EDI],ECX` (EDI=&[EBP-0x14], EAX=0) sits **inside** the success path and re-zeroes the local; it is a local-flag operation, not a `+0x214` operation; the prior "+0x214 CAS inventory" language in some notes lumped these together. This phase separates them: only `00423157` and `0042316c` touch `ESI+0x214`; `00423205` touches the local. → `phase_9C_230c0_discrepancy.md` §2
