# Unresolved References

## Categories of unresolved data

1. **Runtime pointer values** — `[EDI+0x0C]`, `[P+0x04]`, `[A]` where A is computed. Cannot be resolved statically; require constructor tracing or dynamic evidence.
2. **Indirect call targets** — `CALL [EDX]` (5,075 `COMPUTED_CALL` references). Target depends on memory/register values.
3. **Thunk targets** — 91 `is_thunk:true` functions forward to imported APIs; API names are in import table but not yet cross-mapped in this inventory.
4. **Missing functions** — 1 decompile failure; the function's C reconstruction is incomplete.
5. **Unknown-convention functions** — 23 functions; register/stack argument layout must be recovered per-function.

## Known-good leads from prior audits (use as hypotheses, verify)

- `FUN_0041e220` (15 callsites / 14 unique functions) and `FUN_0041e280` (22 callsites / 21 unique) — a concurrent-object family around globals `0x0055BF80` / `0x0055BF84`.
- `FUN_00415f80` (113 callers) — retry loop, up to 10 iterations.
- `FUN_00416650` — CAS-based helper.
- Globals `0x0055BF80`/`0x0055BF84` — STRONGLY SUPPORTED as a shared concurrent-state pair; semantic meaning UNKNOWN.
- `0xf423f` sentinel — meaning UNKNOWN.
- `[EDI+0x0C]`-style object fields in these families — layout inferred but structure type UNKNOWN.

## What must not be assumed

- That `CALL [EDX]`'s target is a known function address.
- That DATA references to a function VA are callsites.
- That same-offset accesses imply the same structure.
- That ASLR/runtime values match export-time addresses.

## Exact next steps for future investigations

1. Constructor tracing of object families around `0x0055BF80/0x0055BF84`.
2. PE `.data`/`.bss` static initialisation review for those globals.
3. `[EDI+0x0C]` write-site tracing for indirect-target resolution.
