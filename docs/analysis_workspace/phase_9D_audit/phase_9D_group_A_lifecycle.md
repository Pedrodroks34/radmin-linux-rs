# Phase 9D — Group A Lifecycle: `FUN_0041e220` / `FUN_0041e280` chain

**Layout (Phase-8X layout, now supported by instruction-level proof):**

| Slot | Offset from base | Content after proper construction |
|---|---|---|
| Adjusted EDI (sub-object ptr) | `base + 0x28` | points at this Group A sub-object |
| CAS1 | `base + 0x2c` | **`0x00000000`** — static zero (constructor `004179a1`, `MOV dword ptr [EBX + 0x2c],0x0`) |
| P | `base + 0x34` | **`0x0051aee0`** — static `.rdata` pointer (`0041788e`) |
| CAS2 | `base + 0x38` | **`0x00000000`** — static zero (`004179c1`, `MOV dword ptr [EBX + 0x38],0x0`) |
| sub-object gate | `base + 0x10` | `0x0051ae44` (constructor final value) |

## 1. Allocation path

```
FUN_0042d980 (created by FUN_0042d2a0 @ 0042d2f8 and FUN_0042d3a0 @ 0042d3f6)
  └── Allocates 0x258-byte parent via FUN_004e5a66 → __malloc_base → HeapAlloc(0, size=0x258, ...)  [HeapAlloc flag 0x0 — NOT zeroed]
      └── FUN_00421410 (constructor for parent-class)
          ├── phase-1 (cond. [EBP + 0x24] != 0 — always true here, arg is literal 1)
          │     Writes vtables at 0051b248/0051b254/0051b268/0051b284
          └── phase-2 ([EBP + 0x24] == 0 branch — never reached for this path)
              Writes vtables at 0051a984/0051a9b4/0051a9ac
      └── FUN_00422260 (the +0x214-gated parallel factory of the parent class)
          └── FUN_00424550 → allocates 0x274-byte child via FUN_004e5a66 → FUN_00417850
              └── FUN_00417850 (FUN_00417850-class constructor)
                  ├── phase-1 (always true: arg [EBP + 0x24] = 0x00000001 literal)
                  │     [EBX + 0x34] = 0x0051aee0   (P)
                  │     [EBX + 0x2c] = 0            (CAS1)
                  │     [EBX + 0x38] = 0            (CAS2)
                  │     [EBX + 0x28] = 0x0051a984   (sub-object vtable placeholder)
                  │     [EBX + 0x244] = 0x00519e54  (vtable-ladder entry)
                  └── phase-2 (unconditionally executed, overwrites the sub-object values to their terminal addresses)
                        [EBX]     = 0x0051ae28   (primary vtable)
                        [EBX+0x8] = 0x0051ae30   (secondary vtable)
                        [EBX+0x10] = 0x0051ae44
                        [EBX+0x28] = 0x0051ae58   (final)
                        [EBX+0x3c] = 0x0051ae60
                        [EBX+0x40] = 0x0051ae6c
```

Verification: `listing/00424550.asm`, `listing/00417850.asm`, `listing/00421410.asm`, `listing/00422260.asm`. Creation path confirmed unambiguous.

## 2. End-to-end chain through the group A call sites

```
parent (created by FUN_0042d980, gate = parent class)
   └── child (FUN_00424550 → FUN_00417850)        ← Group A object
         └── grandchild (FUN_00417850 → FUN_0041ea00)  ← Group B / Group C object
```

Member functions of the FUN_00417850-class (the Group A class) call:

```
this ──vtable slot (at 0x0051ae34..0x0051ae38 region)
          └── FUN_0041df20    ← vtable slot [+0x10] at .rdata 0x0051ae38
                └── FUN_0041e090   (calls through its own path with ECX = obj - 0x8)
                      └── FUN_0041ae30 → 0041b05a: e220 (`LEA ECX,[EDI + 0x28]`)
                      └── FUN_0041bb40 → 0041bd36: e220 (`LEA ECX,[EDI + 0x28]`)
                      └── FUN_0041bd70 → 0041c03a: e220 (`LEA ECX,[EDI + 0x28]`)
                      └── FUN_0041e1f0 → FUN_0041e1f0: e280 (`CALL 0041e280`)
```

Direct blockers for FUN_00417850-class dispatchers (the FUN_0041df20 path, and the FUN_0041e090 sub-dispatch): these callers (FUN_0041ae30/0041bb40/0041bd70 — Group A e220 callers invoked from the vtable dispatch loop) do **not** pass through the +0x214 gates — the gates gate only the `FUN_00422ce0 → FUN_00422f20/004230c0` chain. All other e220/e280 callers invoke `e220`/`e280` directly. (Counter-example: `00423239`, the blocked path (BLOCKED UNDER EXPLICIT ASSUMPTIONS), is downstream of `FUN_004230c0`'s gate — it cannot execute while the gate stands.)

## 3. Identity uncertainty — where the chain becomes ambiguous

| Stage | Certainty | Reason |
|---|---|---|
| Child object is FUN_00417850-class | **CONFIRMED** | Construction sites match perfectly (FUN_00424550 → FUN_00417850 invariably) |
| vtable at `0x0051ae38` is dispatched by the framework | **STRONGLY_SUPPORTED** — the vtable slot contains `FUN_0041df20` (DATA ref) and `FUN_0041df20`'s body dispatches to the Group A e220 callers | Direct vtable slot entry + `from_function` = `FUN_0041df20` (is_call=true count = 0 direct callers → reached via vtable) |
| Which object of this class reaches any particular callsite | **INCONCLUSIVE** | All construction/storage paths verified, but DATA refs from rodata into vtables for these slots (e.g. `0051ae38`) could be reached from multiple parent subsystems; identity depends on which Radmin session invokes it first |

## 4. Object reachability of the Group A call sites

| Callsite | Caller | Object adjustment |
|---|---|---|
| `00419e9b` | `FUN_00419e20` | `ECX = EDI + 0x28` |
| `0041a739` | `FUN_0041a6d0` | `ECX = EDI + 0x28` |
| `0041a768` | `FUN_0041a6d0` | `ECX = EDI + 0x28` |
| `0041b05a` | `FUN_0041ae30` | `ECX = EDI + 0x28` |
| `0041b125` | `FUN_0041b090` | `ECX = EDI + 0x28` |
| `0041b1cc` | `FUN_0041b140` | `ECX = EDI + 0x28` |
| `0041b370` | `FUN_0041b2f0` | `ECX = ESI + 0x28` |
| `0041bd36` | `FUN_0041bb40` | `ECX = EDI + 0x28` |
| `0041c03a` | `FUN_0041bd70` | `ECX = EDI + 0x28` |
| `0041e025` | `FUN_0041df70` | `ECX = EDI + 0x28` |

## 5. Verdict

- **Object type: FUN_00417850-class child, created via FUN_00424550 → FUN_00417850.** Verified at three levels (allocation, constructor, vtable entry).
- **P is initialized** (`0x0051aee0`) for these objects; **CAS1 = CAS2 = 0** (static zero at construction); **D = `0x00000210`**, **A = obj + 0x244**, **V = [obj+0x244] = `0x00519e54`**, **target = `0x004e7650`** (CFG-instrumented global-callback dispatch stub — reads `[0x005a5a54]`).
- Object class identity STRONGLY SUPPORTED by four independent witnesses (constructor, vtable layout, callsite LEA, allocation chain).
- Individual Radmin session dispatch into this vtable chain is RUNTIME-DEPENDENT, not statically resolvable beyond the class/method identification.
