# Dataset Inventory — Ghidra Export of `RvControlSvc.exe`

**Export format:** `ghidra-radmin-export-v1`
**Exported:** 2026-11-11T03:16:24Z
**Ghidra version:** 12.2
**Program:** `RvControlSvc.exe` (from `/C:/Users/Rhuan/Desktop/RvControlSvc.exe`)
**SHA-256 (historical, verify):** `546efad9ab3ff85c2a50d61524d754bec94a3f3e30d6ae8addef481a1e8daa1e` (reported by earlier phases; not re-verified in this export)
**Language:** `x86:LE:32:default` (x86, little-endian, 32-bit)
**Compiler spec:** `windows`
**Image base:** `00400000`
**Partial export:** false

## Scope of the export

| Item | Value |
|---|---|
| Functions exported | 6904 |
| Decompile failures | 1 |
| Total instruction lines | 355,346 |
| Unique references exported | 152,681 |
| Listing files | 6904 (one `.asm` per function) |
| Address range | `00401020` – `00516f35` |

## File layout

```
ghidra_export/
├── metadata.json               # Export-level metadata (format, hashes, counts)
├── functions.jsonl             # One JSON object per function (decompiled C, signature, CC)
├── references.jsonl            # One JSON object per reference (direction, type, call flag)
├── listing/                    # One .asm per function, named by entry VA
│   └── 00401020.asm … 00516f35.asm
├── phase_8*_audit/             # Prior audit outputs (prior investigators)
└── relatorio_parte*.md         # Prior investigators' Portuguese reports
```

## Assembly file format

Each `listing/XXXXXXXX.asm` contains one function's disassembly:

```
00401020  55                        PUSH EBP
00401021  8BEC                      MOV EBP,ESP
00401023  51                        PUSH ECX
...
```

Column format: `ADDRESS  BYTES  MNEMONIC  OPERANDS`

Lines are plain text, one instruction per line. No function header lines are present — function boundaries are implicit from filename and references.

## Function entry conventions

- Filename = entry VA (hex, 8 digits), e.g. `00401020.asm` = `FUN_00401020`.
- Names follow `FUN_<va>` unless the analyser renamed them.
- Thunks: 91 (`is_thunk: true`).

## Calling conventions (inferred by Ghidra, not verified by us)

| Convention | Count | Typical use |
|---|---|---|
| `__thiscall` | 2996 | C++ methods (`this` in ECX) |
| `__fastcall` | 1429 | Register args (ECX/EDX) |
| `__stdcall` | 1162 | WinAPI-style |
| `__cdecl` | 1294 | C default |
| `unknown` | 23 | Unrecovered |

## Decompile status

- 6903 / 6904 functions decompiled successfully.
- 1 failure (function not identified in this inventory; see `functions.jsonl` for `decompile_status != "success"`).

## References (`references.jsonl`)

JSONL, one record per reference. Fields:

| Field | Meaning |
|---|---|
| `direction` | `outgoing_from_function` or `incoming_to_function_entry` |
| `from` / `to` | VA hex string |
| `reference_type` | See table below |
| `is_call` | Boolean (true for CALL-type) |
| `from_function` / `to_function` | Function name or null |

Reference type counts:

| Type | Count | Semantics |
|---|---|---|
| `DATA` | 33,329 | Memory/constant reference |
| `READ` | 30,661 | Memory read |
| `WRITE` | 21,677 | Memory write |
| `CONDITIONAL_JUMP` | 28,189 | Conditional branch |
| `UNCONDITIONAL_CALL` | 27,770 | Direct CALL |
| `COMPUTED_CALL` | 5,075 | Indirect CALL (register/memory) |
| `UNCONDITIONAL_JUMP` | 4,436 | Direct JMP |
| `COMPUTED_JUMP` | 720 | Indirect JMP |
| `READ_WRITE` | 788 | RMW |
| `INDIRECTION` | 31 | |
| `COMPUTED_CALL_TERMINATOR` | 3 | Tail-call |
| `PARAM` / `EXTERNAL` | 1 each | |

Direction counts: 135,019 outgoing, 17,662 incoming to function entry.

## Limitations and caveats

1. **One `.asm` per function** — no cross-function listing headers. Function boundaries are reliable only where Ghidra identified them; 23 `unknown` convention entries exist.
2. **Image base `00400000`** — all VAs are absolute; add/subtract base as needed for RVA.
3. **References are Ghidra's inference** — `COMPUTED_CALL` does not identify the target; cross-reference manually.
4. **1 decompile failure** — the affected function's C reconstruction is incomplete; rely on assembly.
5. **No dynamic data** — runtime pointers, thread state, and ASLR-relative addresses are not present.
6. **Prior audit folders** (`phase_8*_audit`, `relatorio_parte*`) contain earlier investigators' outputs in Portuguese. Use as leads only — verify against raw artifacts.
7. **`references.jsonl` `is_call:true` only for CALL types** — `DATA` references to function addresses exist and must not be treated as callsites.
8. **Address range ends at `00516f35`**, below the documented `.text` end; some internal data may reside above this range.

## Reliable search starting points

| Goal | Method |
|---|---|
| Find callers of function X | `grep '"to":"X"' references.jsonl` (or `direction incoming`) |
| Find callees of function F | `grep '"from":"F' references.jsonl` filtered by `is_call:true` |
| Find indirect calls | `grep COMPUTED_CALL references.jsonl` or `grep -E 'CALL.*\[' listing\*` |
| Find atomic ops | `grep -E 'LOCK|XADD|CMPXCHG' listing\*` |
| Find data refs | `grep '"reference_type":"DATA"' references.jsonl` |
