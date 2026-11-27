# Function Index — Ghidra Export of RvControlSvc.exe

**Source:** `ghidra_export/listing/*.asm`, `ghidra_export/functions.jsonl`  
**Total functions:** 6,904

## Index Format (future reference)

For each function, record:
- Entry address
- Filename (`<entry>.asm`)
- Calling convention (from `functions.jsonl`)
- Body min/max (`body_min`, `body_max`)
- Size (`size_bytes`)
- Is thunk?
- Direct calls made (from `references.jsonl` where `is_call == true` and `from == entry`)
- Indirect calls (COMPUTED_CALL entries)
- Imported APIs (from import table or DATA references to external addresses)

## Finding Functions by Address

```bash
# Single function listing
cat listing/<entry>.asm

# Function metadata
jq 'select(.entry == "<entry>")' ../ghidra_export/functions.jsonl

# References FROM a function (outgoing calls and data accesses)
jq 'select(.from == "<entry>" and .is_call == true)' ../ghidra_export/references.jsonl
jq 'select(.from == "<entry>" and .is_call == false)' ../ghidra_export/references.jsonl

# Incoming calls to a function entry
jq 'select(.to == "<entry>" and .is_call == true)' ../ghidra_export/references.jsonl
```

## Calling Convention Quick Count

| Convention | Count |
|---|---|
| `__thiscall` | 2,996 |
| `__fastcall` | 1,429 |
| `__cdecl` | 1,294 |
| `__stdcall` | 1,162 |
| `unknown` | 23 |

## Address Range Coverage

- Lowest entry: `0x00401020`
- Highest entry: `0x00516f35`
- Image base: `0x00400000`

## Notes

- 91 thunk wrappers (direct JMP pass-throughs) may be present as `is_thunk: true`
- 1 function failed decompilation (see `functions.jsonl` for the failing entry)
- Do not assume every function in the original PE is present (export reported `partial_export: false`, but only 6,904 entries are listed)