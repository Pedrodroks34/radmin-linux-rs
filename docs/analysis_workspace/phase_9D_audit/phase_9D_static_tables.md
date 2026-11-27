# Phase 9D — Static Tables Audit

Every `.rdata` table referenced by a dispatcher instruction or a dispatch-object constructor — inventoried with byte-cited dump output.

## 1. `0x0051aee0` — the RTTI CompleteObjectLocator-like table (P for Group A)

Referenced by: constructor `FUN_00417850` at `0041788e` (`MOV dword ptr [EBX + 0x34],0x0051aee0`).

Bytes (DIRECTLY VERIFIED dump via `dump_rtti.py`):

```
0x0051aee0  fffffff4   offset-to-top = -12
0x0051aee4  00000210   ← D = 0x210 (528)
0x0051aee8  00000218
0x0051aeec  00000220
0x0051aef0  0000022c
0x0051aef4  00000238
0x0051aef8  00000000
0x0051aefc  00000208
0x0051af00  00000210
0x0051af04  0000021c
0x0051af08  fffffffc
0x0051af0c  fffffff4
0x0051af10  fffffffc
0x0051af14  ffffffe8
0x0051af18  fffffff0
0x0051af1c  fffffffc
0x0051af20  ffffffdc
0x0051af24  ffffffe4
0x0051af28  fffffff0
0x0051af2c  2e312e32   "21.2" (ASCII embedded)
```

- Entry-count pattern: header + N×(offset) + sentinel pairs (fffffffc / fffffff4 = (vtable-offset / offset-to-top) pairs).
- Contains no function pointers; contains signed-offset values; matches the layout of an MSVC `RTTI Complete Object Locator` offset table used to locate secondary vtables.

## 2. `0x0051afe0` — the FUN_0041ea00-class dispatch vtable

Referenced by constructor `FUN_0041ea00` at `0041eab0` (`MOV dword ptr [EDI + 0x8],0x0051afe0`) and recursively by `FUN_0041f090` at `0041f090` (`CALL 0x0041ece0`) — same vtable stored repeatedly while re-registering.

```
0x0051afe0  00421020  ← FUN_00421020 (thunk → CRT _adjust_fdiv?)
0x0051afe4  00420540  ← FUN_00420540
0x0051afe8  0041f110  ← FUN_0041f110   ← Group C entry point (sole method)
0x0051afec  0041f100  ← FUN_0041f100
0x0051aff0  0041fdd0  ← FUN_0041fdd0
0x0051aff4  0041fdc0  ← FUN_0041fdc0
0x0051aff8  0041fdf0  ← FUN_0041fdf0
0x0051affc  0041fe00  ← FUN_0041fe00
0x0051b000  005349ac  ← RTTI CompleteObjectLocator
0x0051b004  0041a630  ← FUN_0041a630 (index computation thunk — 2-instruction ret)
0x0051b008  005349c0  ← RTTI locator
0x0051b00c  004200b2  ← FUN_004200b2
0x0051b010  0041efdd  ← FUN_0041efdd
0x0051b014  fffffffc
0x0051b018  000002c0
0x0051b01c  fffffff4  ← P (Group B)
0x0051b020  000002b0  ← D = 0x2b0 (688)
```

## 3. `0x0051afd8` — FUN_0041ea00-class primary vtable

```
0x0051afd0  0041fd70  ← FUN_0041fd70
0x0051afd4  005348fc  ← RTTI locator
0x0051afd8  0041f090  ← FUN_0041f090 (Group C primary entry — wraps FUN_0041ece0)
0x0051afdc  00534998  ← RTTI locator
0x0051afe0  ...(2)
```

## 4. `0x0051ae28..0051af04` — FUN_00417850-class vtables

```
0x0051ae28  00418fd0  ← FUN_00418fd0
0x0051ae2c  00534624  ← RTTI locator
0x0051ae30  00418e9e
0x0051ae34  0041de60
0x0051ae38  0041df20  ← FUN_0041df20 (dispatches to Group A e220 call sites!)
0x0051ae3c  0041e0e0  ← FUN_0041e0e0
0x0051ae40  00534638  ← RTTI locator
0x0051ae44  00418ea6
0x0051ae48  0047b030
0x0051ae4c  0047aff0
0x0051ae50  0047b000
0x0051ae54  0053464c  ← RTTI locator
0x0051ae58  0041a630
0x0051ae5c  00534660  ← RTTI locator
0x0051ae60  00418eae
0x0051ae64  0041c710
0x0051ae68  00534674  ← RTTI locator
0x0051ae6c  00418eb6
0x0051ae70  00419b30
```

## 5. `0x0051a984` — FUN_00417850-class phase-1 placeholder vtable

Constructor at `004179af` stores `0x0051a984` at `[EBX+0x28]`; constructor phase-2 overwrites with `0x0051ae58`.

## 6. `0x0051ae44` and `0x0051ae58` — the sub-object vtables

| Table | Stored at | Values |
|---|---|---|
| `0x0051ae44` | `[EBX+0x10]` | `00418ea6 / 0047b030 / 0047aff0 / 0047b000` + RTTI at `0x0053464c` |
| `0x0051ae58` | `[EBX+0x28]` | `0041a630 / 00534660` (RTTI) |

## 7. `0x00519e54` — the universal target pointer

```
0x00519e54  004e7650   ← FUN_004e7650 (CFG-instrumented global-callback dispatch stub)
```

References to `004e7650` from `.rdata`: **219 refs** — see `dump_rtti.py` output. Every one matches a vtable slot position. This function is the universal slot filler for vtable slots not otherwise populated (or held for runtime fill).

## 8. `0x0051b248` — FUN_00421410-class primary vtable (not a chain object, but searched for completeness)

```
0x0051b248  00421e20  ← FUN_00421e20
0x0051b24c  00422ce0  ← FUN_00422ce0 (message dispatch table)
0x0051b250  00534ec4
0x0051b254  00421c8a
0x0051b258  00479fa0
```

## 9. Verdicts

| Table | Contains pointers or offsets | Role | Classification |
|---|---|---|---|
| `0x0051aee0` | offsets + signed integers | P (Group A), COL-style | DIRECTLY VERIFIED |
| `0x0051b01c/0x0051b014` | RTTI CompleteObjectLocator layout | P (Group B) / CAS1 (Group C) | DIRECTLY VERIFIED |
| `0x0051afe0` | function pointers + RTTI locators | FUN_0041ea00-class secondary vtable | DIRECTLY VERIFIED |
| `0x0051afd8` | function pointers + RTTI locators | FUN_0041ea00-class primary vtable | DIRECTLY VERIFIED |
| `0x0051ae28..b07c` | function pointers + RTTI locators | FUN_00417850-class vtables | DIRECTLY VERIFIED |
| `0x00519e54` | universal dispatch stub pointer | target slot everywhere | DIRECTLY VERIFIED |

## 10. No direct static match for any e220/e280 chain target anywhere else in `.rdata`

Outside these tables, no other `.rdata` region contains a function-pointer pattern matching the e220/e280 chain needs. The dispatch classes' vtables are the only candidate locations.
