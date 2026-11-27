# Phase 9D — Discrepancy Log

Numbered findings. Severity: **P0** contradiction · **P1** factual error · **P2** imprecision / stale figure · **P3** note.

## D-201 — Phase 9C's "`FUN_00420b80` has 0 incoming reference" claim was wrong (P1)
**Bug:** Phase 9C reported (final report §6, Q7 and `phase_9C_callsite_inventory.md` line for `00420c7b`): "UNKNOWN (0 incoming refs)". Re-queried this phase: `xref.py callers 00420b80` → **2 callsites**, both direct E8:

```
0041f6bd  UNCONDITIONAL_CALL  from_function=FUN_0041f450  to_function=FUN_00420b80
00420b52  UNCONDITIONAL_CALL  from_function=FUN_00420b30  to_function=FUN_00420b80
```

**Impact:** `00420b80` reclassified **UNKNOWN → CONDITIONAL** (not blocked; the two callers invoke it directly via direct `E8` calls, both reach dispatchers that route their objects through the +0x10 sub-object adjustment). The e220 callsite inventory itself (15 sites / 14 unique callers) stays correct — the **reachability** verdict changes.

## D-202 — Phase 9C's "`FUN_0041f110` has zero incoming refs" is confirmed but incomplete (P2)
**Context:** True for `E8`-direct call sites; also true at `UNCONDITIONAL_CALL` level; **not** true at `DATA`-level (1 DATA ref at `.rdata 0x0051afe8` whose contents are `0x0041f110` — the vtable slot of a class hierarchy). The function is reachable via vtable dispatch by code outside this export (Radmin framework / WindowsService logic).
**Classification:** UNRESOLVED, not UNKNOWN-trivially-dead.

## D-203 — Phase 9C's claim "`[reg+0x14]` writers found: none relevant to dispatch objects" is incorrect (P1)
**Bug:** Phase 9C's exhaustive `[reg+0x2c]` scan found 111 stores but provided no init-complete analysis for any single object. Constructor-write analysis in this phase shows **FUN_00417850-class initializes `[obj+0x14]` (Group B CAS1) and `[obj+0x2c]` (Group A CAS1) with static zeros**. Individual Group A CAS1/CAS2 are initialized to zero — verified at constructor line numbers `004179a1` / `004179c1`. The Group B fields (`[obj+0x14]`, `[obj+0x20]`) are proven static zero at `0041ea80` / `0041eaa3`.
**Impact:** CAs1 = 0 at construction for Group A; no "object reached dispatcher with nonzero CAS field" case exists for this class.

## D-204 — Phase 9C's claim "Group B/C P cannot be initialized" is incorrect (P1)
**Evidence:** Group B P = `0x0051b01c` (static); Group C P = `0x00000000` (static zero — **not** heap garbage). The earlier claim was derived from incomplete constructor analysis (Phase 8X/9C never enumerated FUN_0041ea00).
**Impact:** Group B chain is fully resolvable to `FUN_004e7650`. Group C chain is permanently broken (vs. "unknown").

## D-205 — Phase 9C's claim "0 = heap garbage at [obj+0x14] etc." is overstated (P2)
**Note:** the heap does return garbage from HeapAlloc with flag 0, but the constructors initialize the fields — it is incorrect to say "uninitialized therefore garbage" when every store is enumerated. Heap garbage only applies where the constructor does not write — and for the Group B/C class, every field is written.

## D-206 — Phase 9C's "allocator does not zero, so initial contents are unknown" is now irrelevant for these dispatch objects (P2)
The FUN_00421410-class objects are the only +0x214-gate objects and they have no Group A/B/C usage. The dispatch classes fully initialize their Group A/B/C fields. The allocator-flag issue applies only to the (unused here) FUN_00421410 class.

## D-207 — In Phase 9C, "P is not initialized" conflated the two classes (P1)
FUN_00421410-class does not initialize any Group A/B/C field. FUN_00417850 / FUN_0041ea00 classes fully initialize them. The phase conflated them.

## D-208 — Phase 9C's BLOCKED verdicts' upstream condition was restated imprecisely (P3)
The five blocked paths remain **BLOCKED UNDER EXPLICIT ASSUMPTIONS**. The assumptions themselves (construction OBBX) are now doubly-verified — Radmin allocates these objects exclusively via the single `FUN_00421410` / `FUN_00417850` / `FUN_0041ea00` chain. No change in the count: 5 paths, all blocked-on-assumption.

## D-209 — `0x005a5a54` runtime-registration CALL convention was incorrectly read in Phase 9C as a URL-like registration target (P2)
**Real meaning:** it is the CRT's `__imp__RtlCaptureContext` argument slot — the unhandled-exception reporter is registered. Specifically, the code at `004dcb26` pushes `[EAX+0x84]` onto the stack before calling `FUN_004e766c` — `[EAX+0x84]` is a pointer inside the `_exception_info` structure (MSVC `_EXCEPTION_POINTERS`). It is calling the registered unhandled-exception handler.
**Impact:** Confirms the indirect call target is deterministically `0x004dd190` (the unhandled-exception reporter) — i.e., the e220/e280 indirect call resolves at runtime to the Radmin crash/terminate handler. It does not execute any application logic.

## D-210 — Phase 9C's `+0x214` invariant analysis was complete but used the wrong wording (P3)
The real invariant: **no instruction in the export stores a non-zero value into any `[X+0x214]`** — verified exhaustively; the wording in 9C ("only the direct store at 0042173b") is inferior to the stronger statement that nothing non-zero is ever stored. Already corrected in `phase_9C_blocked_path_revalidation.md`.

## D-211 — `FUN_00420b80` marked ""UNKNOWN"" in `phase_9D_*` attempts to resolve the identity of its real dispatchers — DONE (see D-201). (P2)
It has 2 direct callers (`FUN_0041f450` and `FUN_00420b30`); both call through `LEA ECX,[EBX+0x10]` form at their callsites. Objects received are GROUP B objects (FUN_0041ea00-class).

## D-212 — Phase 9C's table of blocked-path callers was kept verbatim (P3, note)
None were added (correct — the +0x214 gates are unchanged), none were removed (correct — the exact callsites, by function and address, all remain blocked-on-assumption).

## D-213 — `FUN_00416650`'s vtable-based variant store sequence (4 vtables, identical entries) (P3)
The 4 CF-Guard-style vtables stored by `FUN_00421410`-class and homologues all point at `FUN_004e7650`. When a derived class overrides one of these virtual methods at construction time (`CreateThread`-equivalent), it stores an application callback as an alternative vtable-slot value — and the CFG-instrumented dispatch calls it. That's how "dispatch" actually happens for real app logic. The support infrastructure exists; the block that selects the feature on call site is not followed through in this export.

## D-214 — Phase 9C's `+0x244 / [+0x2cc]` vs. `[+0x214]` distinction now crystal-clear (P3)
Two different 0x0F-range offsets — not the same. `[obj + 0x244]` stores the **dispatch vtable slot (target 0x00519e54)** — part of the object layout; `[obj + 0x214]` stores the **+0x214 gate target** — the interlocked bool gate. Both verified zero-initialized at construction. Different purposes.

## D-215 — The export contains no signs of derived-class instantiation (P2)
Both candidate creation chains (`FUN_00421410_class → FUN_00417850_class → FUN_0041ea00_class`) build only pure-virtual objects. If Radmin ever instantiates derived classes, it overrides vtable slots to application code — and none of those overrides were found in this export. Either the dispatched methods are never called, or a Windows-side Radmin service callback module does it.

## D-216 — Global name-shape of the CFG-instrumented dispatch stub (P2, note)
All references in this report to `FUN_004e7650` use that name precisely because **Ghidra's export uses it**; the name `__guard_dispatch_icall` is the Microsoft SDK convention for the equivalent function (read global function pointer → call `guard_check_icall` (a no-op `RET 0` in this build, per `004e69b7: C20000`) → `CALL` the global → `CALL 0x004fc479` crash path). The function's role here is identical to `__guard_dispatch_icall` semantically, but the evidence is the disassembly itself — not the name. We do not claim the exact CRT internal symbol `__guard_dispatch_icall` / `_guard_dispatch_icall_fptr` exists at `0x004e7650` (that would be a naming conjecture); only its **CF-Guard-instrumented callback dispatch behavior** is verified.

---

## Summary of all Phase-9D-discovered errors in Phase 9C

| ID | What was wrong | Impact | Fix |
|---|---|---|---|
| D-201 | `FUN_00420b80` reported as 0 callers / UNKNOWN; actual 2 direct callers (`FUN_0041f450 @ 0041f6bd`, `FUN_00420b30 @ 00420b52`) | **1 callsite misclassified** (CONDITIONAL, not UNKNOWN) | Reclassified |
| D-203 | CAS fields "not initialized / unknown" | **CAS initialization now fully known for all classes** (Group A/B/C = static zero except Group C CAS1 = `0x0051b014`) | CAS verdict refined |
| D-204 | Group B/C P "not initialized" | **Group B/C chains fully statically resolvable** (P = `0x0051b01c` / `0x00000000`) | Group lifecycle reports |
| D-207 | "P not initialized" conflated FUN_00421410-class (never writes) vs FUN_00417850/FUN_0041ea00-classes (all write) | Corrects the class-differentiation error | Principle clarified |
