# Phase 9D — Group B Lifecycle

**Layout (Phase-8X layout, now supported by instruction-level proof):**

| Slot | Offset from base | Content after proper construction |
|---|---|---|
| Adjusted EDI (sub-object ptr) | `base + 0x10` | points at this Group B sub-object |
| CAS1 | `base + 0x14` | **`0x00000000`** — static zero (`0041ea80`, `MOV dword ptr [EDI + 0x14],0x0`) |
| P | `base + 0x1c` | **`0x0051b01c`** — static `.rdata` pointer (`0041ea3b`, path A) |
| CAS2 | `base + 0x20` | **`0x00000000`** — static zero (`0041eaa3`, `MOV dword ptr [EDI + 0x20],0x0`) |

## 1. Allocation path

```
FUN_00417850 (FUN_00417850-class child, Group A object)
   └── allocates 0x2d0-byte grandchild via FUN_004e5a66 → __malloc_base → HeapAlloc(0, 0x2d0, 0)
         └── FUN_0041ea00 (FUN_0041ea00-class constructor)
               ├── path A ([EBP + 0x10] != 0 — always true at this construction site)
               │     [EDI + 0x0c] = 0x0051b014   (RTTI-COL value, non-zero)
               │     [EDI + 0x1c] = 0x0051b01c   (P)
               │     [EDI + 0x2cc] = 0x00519e54  (vtable-ladder entry)
               └── common tail (all paths)
                     [EDI + 0x14] = 0x00000000  (CAS1)
                     [EDI + 0x10] = 0x0051a984 → overwritten to 0x0051b004 at 0041eab7
                     [EDI + 0x18] = 0x00000000  (Group C P-like field)
                     [EDI + 0x20] = 0x00000000  (CAS2)
                     [EDI + 0x28] = 0x00000000
                     [EDI + 0x2b4] = 0x0051afc0 → overwritten to 0x0051afcc at 0041eb62-phase
                     [EDI + 0x2c0] = 0x00000000
                     [EDI + 0]     = 0x0051afd8  (primary vtable)
                     [EDI + 0x8]   = 0x0051afe0  (secondary vtable)
```

Verification: `listing/0041ea00.asm` — every store listed has a byte-cited instruction address. Construction path confirmed unambiguous.

## 2. End-to-end chain through the Group B e220 call sites

```
For FUN_0041ea00-class FUN_0041ea00-instantiation:
  adjusted EDI = obj + 0x10
  P = [obj + 0x1c] = 0x0051b01c  (static)
  D = [P + 0x04] = 0x000002b0    (static)
  A = obj + 0x10 + 0x2b0 + 0x0C = obj + 0x2cc   (static offset)
  V = [obj + 0x2cc] = 0x00519e54 (static)
  target = [V] = 0x004e7650      (STATIC — CFG-instrumented global-callback dispatch stub)
```

Group B dispatch equally funnels into `FUN_004e7650` → `[0x005a5a54]` (runtime-registered global, `0x004dd190`).

## 3. Identity uncertainty

| Stage | Certainty |
|---|---|
| Identity = FUN_0041ea00-class | **DIRECTLY VERIFIED** (single creation site `00417bc6`; only reachable via FUN_00417850-class child of FUN_00421410-class parent) |
| Path A taken | **DIRECTLY VERIFIED** (`[EBP + 0x10] = 0x00000001` at the only construction chain) |
| Group B layout match | **DIRECTLY VERIFIED** (all four fields stored by constructor, with known static final values) |
| Individual Group B dispatcher entry | **CONDITIONAL** — same as Group A; the chain code is shared (`CALL [EDX]`), the adjusted pointer differs |

## 4. Group B call sites — object at each adjustment

All Group B call sites use `EDI = adjusted pointer at obj+0x10`:

| Callsite | Caller | Adjustment |
|---|---|---|
| `0041f80e` | `FUN_0041f710` | `LEA ECX,[EDI + 0x10]` |
| `0041fc6e` | `FUN_0041fa80` | `LEA ECX,[EBX + 0x10]` |
| `00420c7b` | `FUN_00420b80` | `LEA ECX,[ESI + 0x10]` |
| `0041f6dd` | `FUN_0041f450` | `LEA ECX,[EDI + 0x10]` |

Report earlier noted all four reach e220. All four use `LEA ECX,[EDI + 0x10]` or `[EBX/ESI + 0x10]` — confirmed instruction-level this phase.

## 5. Verdict

- Group B is a sub-object of the same FUN_0041ea00-class grandchild that the FUN_00417850-class child is built from.
- P / D / A / V / target are all **statically resolvable** — target = `FUN_004e7650`.
- Object identity for these callsites: **CONFIRMED via the locked three-class hierarchy** (parent FUN_00421410-class → child FUN_00417850-class → grandchild FUN_0041ea00-class).
- No CAS gate or per-class gate blocks the chain — the chain state is consistent with dispatch on any object reached through the Radmin framework's vtable dispatch mechanism.
