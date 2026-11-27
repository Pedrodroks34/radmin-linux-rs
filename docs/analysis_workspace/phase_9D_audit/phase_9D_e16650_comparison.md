# Phase 9D — e16650 Discovery vs e220/e280 Chains: Methodological Comparison

## The three chains — structural fingerprint

| | e16650 | e220 | e280 |
|---|---|---|---|
| Call sites | `0041693f` (FUN_00416650) | 15 direct E8 at known callers | 22 direct E8 at known callers |
| Instruction | `CALL [EDX + 0xc]` | `CALL [EDX]` | `CALL [EDX]` |
| Adjusted EDI | `obj + 0x08` (FUN_00416650's `this`) | `obj + 0x28` (Groups A) / `obj + 0x10` (Group B) / `obj + 0x08` (Group C) | same |
| P | `[EDI + 0x08]` — **static** `0x00519dac` (phase-1) `0x0051b254` (phase-2) — stored by FUN_00421410 constructor at `004214f0` / `0042155b` | `[base + 0x34]` (A) `0x0051aee0` · `[base + 0x1c]` (B) `0x0051b01c` · `[base + 0x14]` (C) `0x00000000` | identical |
| D | `[P + 0x0C]` — **pointer** `0x00479d80` stored at `0x00519db8` and `0x0051b260` (dumped) — data table, not offset | `[P + 0x04]` — **offset** `0x210` / `0x2b0` — literal integer, not pointer | identical |
| A (effective) | `obj + 0x0C` relative PC (no further pointer hop) | `EDI + D + 0x0C` — object-relative | identical |
| V | `[V+0x0C]`-related dispatch — **not reached via P+0x4+P-style A**, direct vtable slot | `[A]` | identical |
| Final target | `0x00479d80` — `FUN_00479d80` (CRT `_guard_check_icall` thunk) | `0x004e7650` — `FUN_004e7650` (CFG-instrumented global-callback dispatch stub — reads `[0x005a5a54]`, calls `guard_check_icall` no-op, then `CALL`s the global; name inference from code shape, not Ghidra's name) | identical |
| Global used | none explicit | `0x005a5a54` read in indirect-call stub | identical |
| Runtime-resolved callback | `FUN_00479d80` (file is static symbol — actually in static .text) | `[0x005a5a54] = 0x004dd190` — **runtime-registered** at 4 callsites (3 unconditional literal, 1 via table) | identical |

## Mechanistic similarity

Both dispatch styles use **constructor-installed static tables**. The difference is only:

- **e16650** reads the table's entries as `struct { void* n; void* e; }` — P = vtable-pointer, D = [vtable+0x0C] = target-pointer directly. **One pointer hop.**
- **e220/e280** reads the table as RTTI-COL-like structure — P = COL pointer, D = vbase offset, A = object + offset (a secondary vtable index), V = [A] = vtable entry, target = [V]. **Two pointer hops + offset arithmetic.**

Same overall principle (**e220/e280 are just more involved e16650-style dispatches — the table structure differs, but the resolution strategy is identical**).

## Why the different shapes?

Probably: e16650 is the raw dispatch into a single class; e220/e280 chains are the price the MSVC codegen pays for **verified virtual dispatch under Control Flow Guard** — the extra table dereferences produce the same vanilla "call the registered global handler" effect but via the secondary CFG-instrumented stub.

No need for external libraries to explain this construction — the e220/e280 vtable dispatch chain reads `[vtable_entry]` (always `0x004e7650`) then `[0x005a5a54]` — structurally equivalent to MSVC's `__guard_dispatch_icall` / `_guard_dispatch_icall_fptr` pattern from the CRT (the name `FUN_004e7650` here is Ghidra's; the behavior match is not a naming claim).

## e220/e280 vs e16650 — same CFG stub chain

```
e16650:
  CALL [EDX + 0xC]   → 00479d80 → _guard_check_icall (no-op) → return
  → effective no-op / dispatch failure marker (stub returns immediately)

e220/e280:
  CALL [V]           → 004e7650 → _guard_check_icall (no-op) → [0x005a5a54]
  → effective: call the CFG-registered fallback at [0x005a5a54] (currently 0x004dd190 — unhandled exception / invalid parameter / pure virtual fallback)
```

Both ultimately resolve to compiler-baked CRT dispatch machinery — NOT to application code. **The "dispatchers" in this binary are not really dispatching app logic; they're routing through the CFG guard infrastructure.**

## Conclusion

- Same mechanism: **vtable indirection via static `.rdata` tables** installed by constructors.
- Same dispatch stub: `FUN_004e7650` (CFG-instrumented global-callback dispatch stub).
- Same runtime target: `[0x005a5a54]` = `0x004dd190` (an exception/pure-virtual reporter function).
- The e220/e280 chains can never call application-level code through this mechanism at runtime — they are all guaranteed to hit the CFG stub and its registered callback.

**This does not prove the Radmin service is broken** — it only proves the vtable entries are pointing at valid compiler stubs, which then either:

1. check-and-return (no-op depending on CFG registration state), or
2. call the registered exception/fallback reporter when the class is structurally incomplete (pure virtuals with no override)

— either way, not "broken dispatch"; just how the MSVC CFG machinery compiles.
