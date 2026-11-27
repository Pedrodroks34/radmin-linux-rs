# Phase 9D — Group C Lifecycle

**Layout (Phase-8X layout, now supported by instruction-level proof):**

| Slot | Offset from base | Content after proper construction |
|---|---|---|
| Adjusted EDI (sub-object ptr) | `base + 0x08` | points at this Group C sub-object |
| CAS1 | `base + 0x0c` | **`0x0051b014`** — static `.rdata` (path A: `0041ea2d`, `MOV dword ptr [EDI + 0xc],0x0051b014`) |
| P | `base + 0x14` | **`0x00000000`** — literal zero (`0041ea80`, `MOV dword ptr [EDI + 0x14],0x0`) |
| CAS2 | `base + 0x18` | **`0x00000000`** — literal zero (`0041ea8e`, `MOV dword ptr [EDI + 0x18],0x0`) |

## 1. Allocation path

Same as Group B — FUN_0041ea00-class grandchild of FUN_00417850-class child of FUN_00421410-class parent:

```
FUN_00421410 (0x258-byte parent)
  └── FUN_00424550 (/FUN_00422260 parallel class factory)
        └── FUN_00417850 (0x2d0-byte child)
              └── FUN_0041ea00 (0x2d0-byte grandchild)
                    ├── path A: [EBP + 0x10] != 0
                    │      [EDI + 0xc] = 0x0051b014
                    │      [EDI + 0x1c] = 0x0051b01c
                    │      [EDI + 0x2cc] = 0x00519e54
                    └── common tail
                          [EDI + 0x14] = 0x00000000
                          [EDI + 0x18] = 0x00000000
                          [EDI + 0x20] = 0x00000000
```

## 2. End-to-end chain

```
Adjusted EDI = obj + 0x08
P = [obj + 0x14] = 0x00000000              ← LITERAL ZERO (DIRECTLY VERIFIED)
D = [P + 0x04 ] = [0x00000004]             ← ABSOLUTE UNMAPPED READ — fault
A = EDI + 0 + 0x0C (if D read succeeded)   ← unreachable
V = [A]                                   ← unreachable
target                                   ← *never reaches the call site*
```

The chain faults at D — **it cannot produce a dispatch target, under any runtime state**.

## 3. Identity and reachable-class analysis

| Stage | Certainty |
|---|---|
| Object = FUN_0041ea00-class grandchild | **DIRECTLY VERIFIED** (sole construction site `00417bc6`) |
| P = 0 for all constructed objects | **DIRECTLY VERIFIED** — constructor stores the literal `0x0` at `0041ea80` |
| P is ever set non-zero at runtime elsewhere | **UNKNOWN** — no constructor-store evidence exists; no external write found in export's stores-inventory |
| The chain can reach the callsite at `0041f3b1` | **NOT POSSIBLE** without a P re-initialization outside any code path visible in the export |

## 4. The single Group C call site

| Callsite | Caller | Instruction | Adjustment |
|---|---|---|---|
| `0041f3b1` | `FUN_0041f110` | `8D4B08  LEA ECX,[EBX + 0x8]` | `ECX = obj + 0x08` |

The FUN_0041f110 function (`listing/0041f110.asm`) reads arguments via `EBP+0x8` → into EBX, calls through vtable indirection at `0041f39f`, and reaches e220 only on the fall-through path. The object pointing to the FUN_0041ea00-class vtable at `0x0051afe0` — whose `[0x0051afe0]` slot points to `FUN_0041f110` itself (vtable reference at `.rdata 0x0051afe8`) — is what this caller receives.

## 5. CAS state at Group C objects

- **CAS1 = `0x0051b014`** (static non-zero) — the CAS1 gate at `CALL dword ptr [ESI]` (dispatcher at `0041e231`) never succeeds → argument-caching path never runs → this doesn't block the dispatch, oddly (the dispatcher continues to CAS2 gate).
- **CAS2 = `0x00000000`** — the CAS2 gate **does pass** (zero at construction), so the dispatcher continues into the work block regardless of CAS1.
- But Group C P = 0 faults before a target is ever read.

## 6. Verdict

- **Group C objects exist** (the FUN_0041ea00-class grandchild is created every time a FUN_00417850-class child is built — only construction path).
- **Group C objects cannot reach the dispatch target** — the static chain faults at `[P+0x04] = [4]` with P = 0.
- Whether the e280 chain through this group actually executes at runtime is untestable statically, but the math proves the dispatch cannot reach the `CALL [EDX]` instruction without first crashing.
- **No caller of FUN_0041f110 can be shown to reach e220/e280 through Group C** — it is not a viable code path.
