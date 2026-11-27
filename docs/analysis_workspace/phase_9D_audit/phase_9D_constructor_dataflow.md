# Phase 9D — Constructor Dataflow Graph

All dispatch-object classes trace to a single allocation chain traversed once at program startup (or once per RadminService service-init event):

```
ServiceEntry points (e.g., FUN_0042d980, FUN_0042d3a0)
  └── FUN_0042d980 (parent-class entry; calls FUN_00421410)
        └── FUN_00421410 (FUN_00421410-class constructor)
              └── FUN_0047ac80 (sub-MSVC vtable installer — primary-stage vtables 00520604/0052060c/00520620)
              └── FUN_00479510 (sub-init for [EDI+0x1b0] and [EDI+0x1c8])
              └── ... writes [EDI+0x214] = 0        (B2-gate object's +0x214 slot — gate remains closed)
  └── FUN_00422260 + FUN_00422150  (the +0x214-gated parents' parallel factories for the child)
        ├── FUN_00422150 → FUN_00422060 → FUN_00424550   (child allocation callsite 00422230)
        │     └── allocates 0x274 bytes; calls FUN_00417850
        └── FUN_00422260 → FUN_00424550                  (child allocation callsite 00422340)
              └── allocates 0x274 bytes; calls FUN_00417850

FUN_00417850 (FUN_00417850-class constructor)
  ├── allocates nothing itself — called by FUN_00424550
  ├── phase-1 (arg1 == 0x00000001 literal — always true)
  │     stores vtables at 0051ae28 / 0051ae30 / 0051ae44 / 0051aee0 / 0051ae58 …
  └── phase-2 ([EBP+0x24] == 0 — never taken for this path)
        alternative vtable set at 0051a984/0051a998/...

FUN_00417850 → calls FUN_0041ea00   (at 00417bc6)
              └── FUN_0041ea00 (FUN_0041ea00-class constructor)
                    calls FUN_00478710 (lock init)
                    calls FUN_004183d0 (base-object vtable registration)
                    calls FUN_0047f4b0 / FUN_0046e4f0 / FUN_0046ab80 / FUN_004794e0 / FUN_00487900
                    calls FUN_00479510 (sub-init for [EDI+0x150] and [EDI+0x154])
                    calls FUN_0047a650
                    allocates sub-objects via FUN_004e5a66
                    writes [EDI+0] = 0x0051afd8   (primary vtable)
                    writes [EDI+0x8] = 0x0051afe0 (secondary vtable)
                    writes [EDI+0x10] = 0x0051b004
                    writes [EDI+0x2cc] = 0x00519e54
                    writes [EDI+0x210] = 0x00000000 (word, zero)
                    writes [EDI+0x238] = 0x00000000 (byte, zero)
                    registers runtime elements via multiple IAT calls (WriteFile, etc.)
```

## Class relationships (final)

```
Radmin Service (process)
 ├── FUN_00421410-class (parent)           size 0x258  [the +0x214 gate family]
 │     └── FUN_00417850-class (child)       size 0x2d0  [Group A object]
 │           └── FUN_0041ea00-class (grandchild) size 0x2d0 [Group B/C object, Group A's own sub-object]
 └── additional homologous hierarchies at 0051afd8 (vtable chain-like II_UNKNOWN structures)
```

## Constructor calling paths identified

| Constructor | Caller(s) | Callsite | Size (bytes) | Role |
|---|---|---|---|---|
| `FUN_00421410` | `FUN_0042d980` | `0042daf2` | 600 (0x258) | Grandparent; the +0x214-gate class |
| `FUN_00424550` | `FUN_00422150`, `FUN_00422260` | `00422230`, `00422340` | 628 (0x274) | Factory for the dispatch object |
| `FUN_00417850` | `FUN_00424550` (×2, from both sites) | `004245f6` | 628 (0x274) | Group A constructor |
| `FUN_0041ea00` | `FUN_00417850` | `00417bc6` | 720 (0x2d0) | Group B/C constructor |

Verification: all call relationships read from listings; allocation sizes read from push of constant before `CALL 0x004e5a66`; sizes are decimal payload args.

## Constructor init-completion sequence (FUN_00417850-class)

1. `00417878  EBX = ECX` — this = new child
2. `0041787d  CMP [EBP+0x24],0x0` — branch phase
3. `0041788e  [EBX+0x34] = 0x0051aee0` — P initialized
4. `00417895  [EBX+0x44] = 0x0051aef8` — RTTI-COL chain entry
5. `0041789c  [EBX+0x258] = 0x0051af08` — last vtable slot first-entry
6. `004179a1  [EBX+0x2c] = 0` — CAS1 zero (Group A)
7. `004179a8  [EBX+0x30] = 0` — CAS1-witness slot
8. `004179af  [EBX+0x28] = 0x0051a984` — temporary sub-object vtable (replaced in phase 2)
9. `004179c1  [EBX+0x38] = 0` — CAS2 zero (Group A)
10. `004179d4  [EBX+0x234]..[EBX+0x254] = 0x0051a9d0-attribution patch ladder` — RTTI patches
11. Phase 2 (`00417a0f onwards`) — overwrite the temporary sub-object vtable with the real one:
    `[EBX+0x28] = 0x0051ae58`
    `[EBX]     = 0x0051ae28`
    `[EBX+0x8] = 0x0051ae30`
    `[EBX+0x10] = 0x0051ae44`

## Completion timing for Group A fields

| Field | Initialized when | Direction |
|---|---|---|
| `[obj+0x34] (P)` | before phase 1 ends | static |
| `[obj+0x2c] (CAS1)` | phase 1, `004179a1` | static zero |
| `[obj+0x38] (CAS2)` | phase 1, `004179c1` | static zero |
| `[obj+0x244]` | phase 1, `004178ba` | static `0x00519e54` |

## CAS field nullability invariant

The invocation pattern of the dispatcher's CAS1/CAS2: compares `[EDI+0x04]` with `0` (accumulator). If CAS1 always returns zero on freshly-constructed objects — the dispatcher passes CAS1 and **does not shelter** behind the `JZ 0x0041e237`-like "argument caches" logic. The first dispatch after object creation always does the full work. This is how real dispatch happens for freshly-spawned work items — direct confirmation that the dispatcher is not just collect-then-ready logic.

## Nothing initialized to non-zero non-sentinel anywhere in the chain except:

- `0x0051aee8fffffff4 / fffffff4` (offset-pairs sentinel in COL entries)
- `0x0051aee8 00000218 / 00000220` — sub-vtable offsets (static)
- `[obj+0xcat+...]` sequence deliberately null at completion, enabling first-dispatch semantics
