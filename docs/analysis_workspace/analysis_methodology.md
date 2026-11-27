# Analysis Methodology

## Evidence levels

| Level | Definition |
|---|---|
| CONFIRMED | Directly demonstrated by listing bytes/instructions |
| STRONGLY SUPPORTED | Multiple independent observations converge |
| PARTIALLY CONFIRMED | Some links proven, others missing |
| HYPOTHESIS | Plausible, unproven |
| UNKNOWN | Insufficient evidence |

Every claim cites: listing file, exact VA, exact instruction bytes where applicable.

## Workflow per investigation

1. **Inventory first** — open the `.asm` file(s) and `references.jsonl` records for the target.
2. **Map call graph** — direct callees (UNCONDITIONAL_CALL), indirect (COMPUTED_CALL), tail jumps.
3. **Classify atomic ops** — use `important_instructions.md` template.
4. **Trace pointer provenance** — entry args → stores → loads; mark base identity level (offset/type/instance).
5. **Classify confidence** per conclusion; never promote without new evidence.
6. **Record unknowns explicitly** — every UNKNOWN gets a "next evidence needed" line.

## Rules

- Never execute the binary. Never modify `.asm` files or `references.jsonl`.
- Never treat DATA refs as calls.
- Never assume register roles without checking the instruction's operands and preceding MOV/LEA chain.
- XADD/CMPXCHG semantics must follow x86 manual exactly (see `important_instructions.md`).
- Windows thunk resolution: map `00489xxx`-style internal thunks to imported API names before drawing functional conclusions.
- Prior audit folders are leads, not proof.

## Reproducibility

All conclusions must be reproducible from:
`ghidra_export/listing/*.asm` + `ghidra_export/references.jsonl` + `ghidra_export/functions.jsonl` + `ghidra_export/metadata.json`.
