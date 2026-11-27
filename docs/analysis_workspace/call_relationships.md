# Function Index and Call Relationships

## Function identification

- Filename = entry VA (hex). Mapping is 1:1.
- `functions.jsonl` provides name, signature, calling convention, body range, size, decompile status.

## Direct calls

A direct call is `CALL <va>` with a literal address. In `references.jsonl` these appear as:

- `reference_type:"UNCONDITIONAL_CALL"`, `is_call:true`, `to` = callee VA.
- Wrapper/thunk functions often forward (e.g. `FUN_00402970` returns its argument unchanged — a `GetLastError`-style passthrough used with `SetLastError`).

## Indirect calls

`COMPUTED_CALL` (5,075) — through registers or memory, e.g. `CALL [EDX]`. The resolved target is not in the reference; resolve via preceding MOV/LEA and any DATA reference to the pointer slot.

## Tail calls

`UNCONDITIONAL_JUMP` to another function's entry is effectively a tail call. `COMPUTED_CALL_TERMINATOR` (3) are tail-call terminators.

## Callers and callees

- Callers of X: `grep '"to":"X"' references.jsonl` filtered to `is_call:true`.
- Callees of F: `grep '"from":"<F-range-start>'` — better: list all references whose `from_function` = F and `is_call:true`.

## Imported APIs

References to external Windows APIs appear as DATA/READ references to import thunks (`00489240`-style thunks jumping to `00474b60`, etc.). Thunks are listed in `functions.jsonl` (`is_thunk:true`, 91 occurrences). These must be resolved to their API name before conclusions about behavior are drawn.

## Global variables

- `DAT_xxxxxxxx` symbols in decompiled C; raw VAs in assembly (e.g. `[0x0055c110]`).
- Globals frequently appear in SEH cookie checks (`DAT_00553250`).
- No struct definitions are present in this export; field semantics must be reconstructed per-function.

## Provenance rules for pointers

Distinguish (per mission section 5):

1. **Same offset in same struct layout** — common but not proof of same object.
2. **Same object type** — requires shared vtable or constructor lineage.
3. **Same object instance** — requires unique global or unique allocation identity.

Record each access with: base register, base provenance (argued from entry/args), offset, access size, and whether the base is known to be the same object across functions.
