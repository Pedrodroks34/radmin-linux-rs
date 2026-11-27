# Important Instructions — Atomic and Synchronisation Semantics

## Atomic read-modify-write template

Canonical sequence observed in this codebase:

```
00401689  MOV dword ptr [EBP + -0x10], ECX   ; store incoming value
...
00401697  XADD.LOCK dword ptr [0x00598894], EAX
```

### `XADD.LOCK [dst], EAX` (x86)

1. `EAX_old ← [dst]`
2. `[dst] ← [dst] + EAX_old`
3. `EAX ← EAX_old` (the *previous* memory value)

If `EAX == 0` before the XADD, `[dst]` is unchanged and `EAX` receives the old `[dst]`. It is **not** a write-zero. All prior "XADD of zero == read-only" conclusions are incorrect; it is an atomic RMW.

### `CMPXCHG [dst], ECX`

1. Compare `[dst]` with `EAX`.
2. If equal: `[dst] ← ECX`, ZF=1.
3. If not equal: `EAX ← [dst]`, ZF=0.

### `XCHG [dst], reg`

Atomic swap of register and memory operand; loads old memory into register.

## Per-site documentation requirement

Every atomic instruction must record:

| Field | Example |
|---|---|
| VA | `00401697` |
| Listing file | `00401670.asm` |
| Instruction | `XADD.LOCK dword ptr [0x00598894],EAX` |
| Initial register values | EAX = ? (from preceding MOV) |
| Destination | `0x00598894` (global) |
| Old memory value | UNKNOWN (not static) |
| New memory value | `[0x00598894] + EAX_old` |
| Register change | EAX := old memory |
| Flags | ZF/SF/… set per XADD rules |
| Branch consequence | Any following JZ/JNZ on ZF |

## Observed atomic sites (sample — not exhaustive)

| Listing | VA | Instruction | Destination |
|---|---|---|---|
| `00401670.asm` | 00401697 | `XADD.LOCK dword ptr [0x00598894],EAX` | global `0x00598894` |
| `00403770.asm` | 00403794 | `XADD.LOCK dword ptr [EDI],EAX` | `[EDI]` |
| `00403770.asm` | 004037da | `XCHG dword ptr [EDI],ECX` | `[EDI]` |
| `00403c50.asm` | 00403c65 | `XADD.LOCK dword ptr [EDI],EAX` | `[EDI]` |

Full inventory: `grep -E 'LOCK|XADD|CMPXCHG|XCHG' ghidra_export/listing/*.asm`.

## Prior-audit corrections (from `phase_8S_audit/PHASE_8S_SUMMARY.md`)

- XADD source 0 leaves destination unchanged; register receives old value.
- "READ_WRITE" and "DATA" references to the same address represent one logical RMW.
- Global XADD operations with source = 0 occur 18/18 times in the audited set.
