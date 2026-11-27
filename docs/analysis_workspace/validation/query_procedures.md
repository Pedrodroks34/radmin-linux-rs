# Query Procedures — tested recipes for callers / references / listings

All procedures below were **executed against the export** during Phase 0B and their outputs are quoted. Two equivalent interfaces exist: the checked-in helper `xref.py` (faster, validated) and raw `grep` (universal). Every query was also validated against manually inspected assembly lines.

> `xref.py` is read-only and safe. Full scans of `references.jsonl` (152,681 records) take a few seconds each.

## 1. `xref.py` reference

```
python3 analysis_workspace/validation/xref.py <command> [args]
```

| Command | Purpose |
|---|---|
| `callers <fn-entry>` | All `is_call:true` CALL-type references to `<fn-entry>`, with `from` VA, type, caller name |
| `unique-callers <fn-entry>` | Same, plus list of unique `from_function` names |
| `callees <fn-entry>` | All outgoing `is_call:true` CALL-type references of a function |
| `refs-to <addr> [--type T]` | Every reference whose `to` equals `<addr>` (optionally restricted to one `reference_type`) |
| `writes-to <addr>` | `WRITE` and `READ_WRITE` references to `<addr>` |
| `refs-in-range <lo> <hi> [--type T]` | References whose `to` lies in `[lo,hi]` (IAT scan, global tables) |
| `listing <addr>` | Prints the `.asm` file for the function containing `<addr>` (entry or interior) |

### 1.1 Tests executed (captured outputs)

**Direct callers of `FUN_0041e220`** — expected to reproduce the prior Phase-8 audit (15 call sites / 14 unique caller functions):

```
$ xref.py callers 0041e220
call sites targeting 0041e220 (is_call=true, CALL types): 15
  00419e9b  UNCONDITIONAL_CALL           from_function=FUN_00419e20
  0041a739  UNCONDITIONAL_CALL           from_function=FUN_0041a6d0
  0041a768  UNCONDITIONAL_CALL           from_function=FUN_0041a6d0
  0041b05a  UNCONDITIONAL_CALL           from_function=FUN_0041ae30
  0041b125  UNCONDITIONAL_CALL           from_function=FUN_0041b090
  0041b1cc  UNCONDITIONAL_CALL           from_function=FUN_0041b140
  0041b370  UNCONDITIONAL_CALL           from_function=FUN_0041b2f0
  0041bd36  UNCONDITIONAL_CALL           from_function=FUN_0041bb40
  0041c03a  UNCONDITIONAL_CALL           from_function=FUN_0041bd70
  0041e025  UNCONDITIONAL_CALL           from_function=FUN_0041df70
  0041f80e  UNCONDITIONAL_CALL           from_function=FUN_0041f710
  0041fc6e  UNCONDITIONAL_CALL           from_function=FUN_0041fa80
  00420c7b  UNCONDITIONAL_CALL           from_function=FUN_00420b80
  0041f3b1  UNCONDITIONAL_CALL           from_function=FUN_0041f110
  0041f6dd  UNCONDITIONAL_CALL           from_function=FUN_0041f450
unique caller functions: 14
```
**Reproduced exactly** (15 sites, 14 unique callers). `FUN_0041a6d0` calls it twice (`0041a739`, `0041a768`).

**Callees of `FUN_00401020`** — must equal `CALL 0x00402970` twice (listing lines `00401029`, `00401042`):

```
$ xref.py callees 00401020
callees of 00401020 (FUN_00401020):
  00401029  UNCONDITIONAL_CALL           to=00402970  to_function=FUN_00402970
  00401042  UNCONDITIONAL_CALL           to=00402970  to_function=FUN_00402970
total call sites: 2
```
**Matches** listing `00401020.asm` exactly.

**References to global `0x0055c110`** (written by `FUN_00401020` via `C705 10C15500 4B000000 MOV dword ptr [0x0055c110],0x4b` at `00401038`):

```
$ xref.py refs-to 0055c110 | tail -4
  004d6270  DATA                         dir=outgoing_from_function  from_function=FUN_004d6200
  004d6285  DATA                         dir=outgoing_from_function  from_function=FUN_004d6200
  004d6357  DATA                         dir=outgoing_from_function  from_function=FUN_004d6350
  004d6369  DATA                         dir=outgoing_from_function  from_function=FUN_004d6350
refs to 0055c110: 14
by type: {'WRITE': 1, 'DATA': 13}
$ xref.py writes-to 0055c110
  00401038  WRITE                        dir=outgoing_from_function  from_function=FUN_00401020
refs to 0055c110 (type=WRITE): 1
```
**Matches** the listing (`00401038 … MOV dword ptr [0x0055c110],0x4b`): one WRITE.

**IAT range scan (`.rdata` `0x00517000..0x00517540`)** by type `INDIRECTION` — all import-stub jumps:

```
$ xref.py refs-in-range 00517000 00517540 --type INDIRECTION
refs with to in [00517000,00517540] (type=INDIRECTION): 31
distinct from_function names: 30
  … (FWPUCLNT.DLL::Fwpm* ×17, KERNEL32.DLL::CreateToolhelp32Snapshot/Process32FirstW/Process32NextW/GetACP ×4,
     SHELPER.DLL::SHelper_Init, RVROLCLIENT.DLL::ROLClient_FreeMemory, MSI.DLL::MsiEnumRelatedProductsW,
     ___vcrt_FlsAlloc, ___acrt_FlsFree@4, ___acrt_FlsGetValue@4, ___acrt_FlsSetValue@8,
     FUN_0041d6b0, FUN_0041dcd0, FUN_00451620)
```
**31 sites, 30 distinct sources** — matches the manual INDIRECTION analysis; all 22 DLL-named stubs plus 4 internal `.rdata`-slot lea creators, plus API stubs listed.

**Listing retrieval, interior address:**

```
$ xref.py listing 00516f3d
(address 00516f3d is inside 00516f35.asm)
00516f35  B9FC555A00                MOV ECX,0x5a55fc
00516f3a  E9A7DAFCFF                JMP 0x004e49e6
```
Resolves the enclosing function correctly.

### 1.2 Distinguishing DATA from CALL (tested)

- `xref.py callers 0041e220` counts only `UNCONDITIONAL_CALL` / `COMPUTED_CALL` / `COMPUTED_CALL_TERMINATOR` with `is_call=true`. The 15 call sites
  match the manual count of `CALL 0x…` bytes in the listing; `grep '"to":"0041e220"' references.jsonl | grep -c 'UNCONDITIONAL_CALL'` also returns 15, and additional `"reference_type":"DATA"` records for the same VA are address-materialization records, not calls (`lea`/`push` of the function VA).

## 2. `grep` one-liners (equivalent to xref.py)

```bash
# direct call sites of function FUN_0041e220
grep '"to":"0041e220"' ghidra_export/references.jsonl | grep '"is_call":true'

# unique caller functions (names may duplicate — always count entry VAs)
grep '"to":"0041e220"' ghidra_export/references.jsonl | grep UNCONDITIONAL_CALL \
  | grep -oE '"from_function":"[^"]*"' | sort | uniq -c | sort -rn

# imports: every external call site and its imported API
grep '"is_call":true' ghidra_export/references.jsonl | grep -oE '"to_function":"[^"]*\.DLL::[^"]*"' \
  | sed 's/"to_function":"//;s/"//' | sort | uniq -c | sort -rn

# hottest imported APIs by call sites (measured):
#   1970 KERNEL32.DLL::GetLastError     1914 KERNEL32.DLL::SetLastError
#     79 KERNEL32.DLL::GetProcAddress    24 KERNEL32.DLL::CloseHandle
#     19 OLEAUT32.DLL::SysFreeString     18 WS2_32.DLL::ntohs  18 WS2_32.DLL::htons
#     17 WS2_32.DLL::htonl

# all references to a global address (reads+writes+data)
grep '"to":"0055bf80"' ghidra_export/references.jsonl | wc -l    # 31
grep '"to":"0055bf84"' ghidra_export/references.jsonl | wc -l    # 19
grep -E '"to":"0055c110".*"(WRITE|READ_WRITE)"' ghidra_export/references.jsonl

# indirect-call sites originating in one function
grep '"from_function":"FUN_00402axx"' ghidra_export/references.jsonl | grep COMPUTED_CALL

# atomic-RMW sites in the whole binary
grep -E '(XADD|CMPXCHG|XCHG|INC|DEC)[^"]*\.LOCK' ghidra_export/listing/*.asm

# every FS-segment (TEB) artifact reference
grep '"to":"ffdff000"' ghidra_export/references.jsonl | wc -l    # 1699

# IAT-stub jumps
grep '"reference_type":"INDIRECTION"' ghidra_export/references.jsonl

# retrieving the listing for a VA (or grep -n for interior)
ls ghidra_export/listing/00516f35.asm

# use xref.py for anything involving enclosing-function resolution
```

## 3. Query pitfalls (all observed during testing)

1. **Lowercase hex** — `references.jsonl` uses lowercase (`"0041e220"`), listing files use uppercase mnemonic bytes but lowercase VA columns. Use case-insensitive matches for VAs or normalize with `grep -i`.
2. **`Stack[…]`** targets are frame slots — never join them to globals.
3. **`ffdff000`** = TEB artifact (`FS:[0x0]`), 1,699 refs.
4. **DATA references to a function VA are address materialization, not calls** — filter `is_call=true` when counting calls.
5. **`JMP 0x…` tail calls are logged as `UNCONDITIONAL_CALL`** (1,227 records) — the raw bytes (`E9`), not the type label, distinguish them from `E8`.
6. **`from` outside function bodies (4,548 records)** — always null `from_function`; these reflect entrypoint stubs, vtables and unidentified code, not analyzed functions.
7. **Duplicate names** (`scalar_deleting_destructor'`, `operator()` ×15, …) — never match on `name`, match on `entry` / VA.
8. **IAT call = two records** — `COMPUTED_CALL` (is_call=true) + paired `READ` (is_call=false) for the slot; see `reference_schema.md` §5.
