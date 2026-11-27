# Atomic Instruction Semantics — x86 (validated against the export)

**Scope.** The exact x86 semantics of the instructions this codebase uses for concurrent synchronisation. Every example cites the listing file and instruction VA. "Old value" = the value read from the destination before the operation is committed; "new value" = the value committed to the destination. The x86 manual semantics are used throughout — never high-level pseudocode.

## 1. The `LOCK` prefix

`LOCK` (byte `F0`) prefixes a read-modify-write instruction and asserts the bus lock / cache-line atomicity for the duration of the operation on SMP systems. It does **not** change the arithmetic semantics — the operands, flags and register effects below apply with or without `LOCK`, but only the locked form is safe across cores. Three locked idioms occur in this binary:

| Idiom | Listing (VA) | Bytes |
|---|---|---|
| `XADD.LOCK` | `00401670.asm` `00401697` | `F00FC105 94885900` → `XADD.LOCK dword ptr [0x00598894],EAX` |
| `CMPXCHG.LOCK` | `004041a0.asm` `00404234` | `F00FB10A` → `CMPXCHG.LOCK dword ptr [EDX],ECX` |
| `INC.LOCK` / `DEC.LOCK` | `004041a0.asm` `004041ed` | `F0FF4704` → `INC.LOCK dword ptr [EDI + 0x4]` |
| `DEC.LOCK` global | `00478760.asm` `004787f8` | `F0FF0D78C75500` → `DEC.LOCK dword ptr [0x0055c778]` |

## 2. `XADD` — exchange and add

```
XADD dest, src    ; temp ← dest ; dest ← dest + src ; src ← temp
```

With `EAX` as `src` (the encoding used everywhere in this binary):

1. `EAX ← [dest]` — the **old destination value** is loaded into the accumulator.
2. `[dest] ← [dest] + EAX_old` — the destination is updated.
3. Affects `EFLAGS` as a 32-bit ADD (`CF/OF/SF/ZF/AF/PF`).

**Key fact — XADD with EAX = 0.** If `EAX` is zero, the destination does **not** change (`dst + 0`), but the operation is still an **atomic read-modify-write**: the old value is loaded into EAX and memory is written back with the same content. It is *not* a "read-only" operation. In this export, the audit of global XADD operations recorded `EAX == 0` as the accumulator in 18/18 cases (see `ghidra_export/phase_8S_audit/PHASE_8S_SUMMARY.md`).

Example — `00401670.asm` `00401697`:
```
00401689  MOV dword ptr [EBP + -0x10], ECX   ; incoming value staged
00401697  F00FC10594885900  XADD.LOCK dword ptr [0x00598894],EAX
```
Captured semantics: `EAX ← old([0x00598894])`; `[0x00598894] ← old + EAX_old`. The new value equals the old value iff `EAX_old == 0`; either way the operation is an atomic RMW. `0x00598894` is a **global** (inside `.data`), referenced elsewhere as `DAT` concurrency state.

Example inside an object header — `004041a0.asm` `00404246`:
```
00404234  CMPXCHG.LOCK dword ptr [EDX],ECX   ; see §3
0040423e  MOV EAX,EDX
00404240  XCHG dword ptr [EAX],EDI            ; see §4
00404246  F00FC15F04  XADD.LOCK dword ptr [EDI + 0x4],EBX
```
`[EDI+0x4]` is updated with `[EDI+0x4] + EBX_old`; the old counter is returned in EBX. Interlocked decrement-and-test pattern follows (`0040424b DEC EBX; 0040424c JNS …`).

## 3. `CMPXCHG` — compare and exchange

```
CMPXCHG dest, r/m32   ; compare [dest] with EAX
                      ; if equal:   [dest] ← r/m32 (source operand), ZF ← 1
                      ; else:        EAX ← [dest] (old dest),        ZF ← 0
```

Operand roles — frequently confused, so spelled out:

| Role | For `00404234 … CMPXCHG.LOCK dword ptr [EDX],ECX` |
|---|---|
| destination tested/written | `[EDX]` (here a `Stack[-0x8]` EBP-relative local, i.e. a *stack* slot, not a global) |
| expected value | `EAX` (zeroed two instructions earlier: `00404232 XOR EAX,EAX`) |
| replacement value | `ECX` (zeroed at `0040422d XOR ECX,ECX`) |
| old destination | loaded into `EAX` on mismatch |
| branch consequence | `00404238 TEST EAX,EAX; 0040423a JNZ …` — enter if the slot was non-zero before the RMW |

So this site is an **atomic test-and-clear-flag**: if `[EDX] == 0`, keep it 0 and set ZF=1; otherwise load the old value into EAX and set ZF=0 so the caller skips the "already processed" path.

Flags: `ZF` accordingly; `CF`, `OF` etc. reflect the subtraction performed by the compare (32-bit compare semantics). `LOCK CMPXCHG` on an aligned 32-bit operand is the canonical x86 compare-and-swap primitive; here `[EDI]`/`[EDX]` are EBP/object slots, and the two `CMPXCHG.LOCK` lines at `00404234` / `0040427b` straddle an indirect call, i.e. the same CAS pair is evaluated on two paths (fast path and retry path).

## 4. `XCHG` — implicit-lock swap

```
XCHG dest, src   ; swap dest ↔ src (memory ↔ register)
```

`XCHG` with a memory operand is **implicitly locked** (behaves as if prefixed), even without an explicit `F0`. It loads the old destination value into the register operand and stores the register value into memory atomically.

Example — `004041a0.asm` `00404240`:
```
0040423e  MOV EAX,EDX
00404240  XCHG dword ptr [EAX],EDI    ; old ← [EAX] ; [EAX] ← EDI ; EDI ← old
00404242  TEST EDI,EDI
00404244  JZ 0x00404261                ; skip if the slot was already empty
```
Another form — `00403bc0.asm` `00403bdb`:
```
00403bdb  8710                       XCHG dword ptr [EAX],EDX
```

Summary table (old vs new):

| Instruction | Old destination | New destination | Register effect | ZF/CF |
|---|---|---|---|---|
| `XADD.LOCK [d],EAX` | `[d]` | `[d]+EAX_old` | `EAX ← old[d]` | flags of ADD |
| `CMPXCHG.LOCK [d],ECX` (eq) | `[d]` | `ECX` | none | ZF=1 |
| `CMPXCHG.LOCK [d],ECX` (ne) | `[d]` | unchanged | `EAX ← [d]` | ZF=0 |
| `XCHG [d],r32` | `[d]` | `r32_old` | `r32 ← old[d]` | unaffected |

## 5. `CALL` — direct, register-indirect, memory-indirect

| Form | Encoding | Example (VA / bytes) | Reference records produced |
|---|---|---|---|
| Direct relative | `E8 rel32` | `00401029 CALL 0x00402970` | `UNCONDITIONAL_CALL`, `is_call=true`; mirrored as `incoming_to_function_entry` at the callee |
| Register-indirect | `FF D0..D7` | `0040424e FFD6 CALL ESI` | `COMPUTED_CALL` → resolved EXTERNAL or internal VA; `is_call=true` |
| Memory operand | `FF 12..17` `[ + modRM ]` | `0040421e FF12 CALL dword ptr [EDX]` | same (`COMPUTED_CALL`) |
| Absolute memory (IAT) | `FF 15 disp32` | `00404221 FF1560725100 CALL dword ptr [0x00517260]` | **two records**: `COMPUTED_CALL` (is_call=true, resolved external) + `READ` of the IAT slot (`is_call=false`) |
| Tail via JMP | `E9 rel32` | 1,227 direct `JMP` into entries, logged `UNCONDITIONAL_CALL` `is_call=true` | semantics: tail call / thunk forward |
| Indirect terminator | `FF ..` ending function | `COMPUTED_CALL_TERMINATOR` (3) | tail-call terminator |

Distinguishing rule for analysts: the **type label is a Ghidra inference, not the opcode** — `UNCONDITIONAL_CALL` covers both `E8` and direct `JMP`-into-entry; only `is_call` and the bytes distinguish call from jump.

## 6. `JMP` — direct, register, memory

| Form | Encoding | Example | Type |
|---|---|---|---|
| Direct | `E9 rel32` | plain `JMP 0x…` examples: 4,436 records | `UNCONDITIONAL_JUMP` |
| Indirect register/memory | `FF /4` | `00516f3a E9A7DAFCFF JMP 0x004e49e6` is direct; indirect examples: `JMP dword ptr [EDX]` | `COMPUTED_JUMP` (720) |
| Import stub | `FF 25 disp32` | `004aec83.asm` `004aec83` `FF2528715100` `JMP dword ptr [0x00517128]` → IAT slot `0x00517128` = KERNEL32.DLL::CreateToolhelp32Snapshot | `INDIRECTION` (31) |

Jump tables / vtable dispatch both land in `COMPUTED_JUMP`; those targets are dataflow-resolved, rarely textually verifiable.

## 7. `REP MOVS` / `REP STOS` — string ops

| Form | Encoding | Example | Semantics |
|---|---|---|---|
| `REP MOVSD` | `F3 A5` | `004151cc F3A5 MOVSD.REP ES:EDI,ESI` | copy `ECX` dwords from `[ESI]` to `ES:[EDI]`, advancing both by 4 per iteration; `ECX ← ECX-1` each step until zero |
| `REP STOSB/W/D` | `F3 AA` `F3 AB` `66F3AB` | `004e57fa F3AB STOSD.REP ES:EDI` (eax pattern fill) | write `AL/AX/EAX` to `ES:[EDI]` `ECX` times |
| `MOVSD.REP` vs plain `MOVSD` | `F3 A5` vs `A5` | listing marks `.REP` explicitly | plain `A5` copies **one** dword |

Semantics depend on `ECX` (iteration count), `ESI`/`EDI` (pointers), `EAX` (fill value for STOS), `DF` (direction flag, normally clear after `CLD`), and the ES segment override for `STOS` (explicit in `ES:` operand). Copy direction is forward when `DF=0`. `REP MOVS` with `ECX=0` performs zero iterations. On modern CPUs these are microcoded fast-string ops; the atomicity of the whole operation is **not** guaranteed across CPUs — only single lines within it.

## 8. Quick triage checklist (for future phases)

1. Bytes first: `F0` ⇒ locked RMW — atomic scope only while the access is aligned and within a cache line.
2. Atomic operands are 32-bit dwords (`F00FC1` encodes XADD r/m32); none of the sampled locked sites use 64-bit `F0480FB…` forms.
3. `Stack[…]` destination ≠ shared state (e.g. §3 atomic local) — check the provenance of the base register before calling it a "shared counter".
4. `ffdff000` in `to` = FS/TEB artifact, never a heap object.
5. `XADD` with unknown accumulator ⇒ capture EAX at the site before reasoning about old/new.
