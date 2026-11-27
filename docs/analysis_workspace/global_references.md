# Global References

## Known global symbols (from decompiled C)

| Symbol | Raw VA | Observed use |
|---|---|---|
| `DAT_00553250` | `0x00553250` | SEH stack-cookie xor mask (security cookie) |
| `DAT_0055c110` | `0x0055c110` | Written by `FUN_00401020` (`MOV dword ptr [0x0055c110],0x4b`) |
| `DAT_0055c114` | `0x0055c114` | Written by `FUN_00401020` |
| `DAT_0055c880` | `0x0055c880` | Referenced in `FUN_00401670` |
| `DAT_0055bfc0` | `0x0055bfc0` | Return thunk in `FUN_00402960` |
| `DAT_00598894` | `0x00598894` | Target of `XADD.LOCK` in `FUN_00401670` |
| `DAT_00598895` region | — | Shared concurrent state (see prior audits) |

## Access patterns

- `references.jsonl` separates `DATA` (pointer materialisation / constant) from `READ`/`WRITE`/`READ_WRITE` (actual memory traffic).
- Atomic RMW sequences are listed as both a `DATA` and a `READ_WRITE` reference to the same address — one logical access, not two.

## Guidance

Do not infer struct layouts from single offsets. Cross-reference all accesses to the same VA and require constructor-lineage evidence before assigning a type.
