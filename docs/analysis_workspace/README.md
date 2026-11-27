# Analysis Workspace — `RvControlSvc.exe` Ghidra Export

Onboarding established by Phase: dataset understanding only. No function family deep-dive performed yet.

## Deliverables in this directory

| File | Contents |
|---|---|
| `dataset_inventory.md` | Dataset layout, counts, limitations |
| `architecture_and_calling_conventions.md` | x86/LE/PE, CCs, atomics overview |
| `call_relationships.md` | Function identification, direct/indirect calls, globals |
| `global_references.md` | Known global symbols and access rules |
| `important_instructions.md` | Atomic XADD/CMPXCHG/XCHG semantics, sample sites |
| `unresolved_references.md` | Gaps, prior-audit leads, next steps |
| `analysis_methodology.md` | Evidence levels, workflow, rules |

## Ground rule

Original `.asm` files and `references.jsonl` are read-only. Do not modify them.

## Next step

Wait for the next investigation objective (e.g. the FUN_0041e220/FUN_0041e280 concurrent-object family, or another function family of interest).
