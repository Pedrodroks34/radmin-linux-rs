# Architecture and Calling Conventions

## Architecture

- **x86 (32-bit), little-endian** — confirmed from `language_id` = `x86:LE:32:default` and listings.
- **Image base** `0x00400000`.
- **Windows calling conventions** — compiler spec `windows`.

## General-purpose registers

EAX, EBX, ECX, EDX, ESI, EDI, EBP, ESP. No XMM register usage observed in the sampled listings (typical for C++ crypto/service code of this vintage; verify per-function).

## Stack frames

- `PUSH EBP; MOV EBP, ESP; SUB ESP, N; ... ; MOV ESP, EBP; POP EBP; RET [imm]`
- SEH exception handling via stack cookies (`DAT_00553250`) in most functions.

## Calling conventions (observed)

| Convention | Register args | Stack cleanup | Where used |
|---|---|---|---|
| `__cdecl` | No | Caller | C helpers |
| `__stdcall` | No | Callee (`ret imm`) | WinAPI-like |
| `__fastcall` | ECX, EDX | Callee (`ret`) | Internal helpers |
| `__thiscall` | ECX = `this` | Caller/callee varies | C++ methods |
| `unknown` | — | — | 23 functions, do not assume |

**Argument identification rule:** with `thiscall`, the first argument beyond `ECX` is `[EBP+8]`; with `stdcall`, all args are `[EBP+8+4n]`; with `fastcall`, ECX/EDX carry the first two.

## Atomic and synchronisation instructions observed

| Instruction | Semantics (x86) | Example |
|---|---|---|
| `XADD.LOCK [dst], EAX` | `dst_old ↔ EAX` with add: `EAX ← dst_old`, `dst ← dst + EAX_old` | `00401697 XADD.LOCK dword ptr [0x00598894],EAX` |
| `CMPXCHG [dst], ECX` | `dst == EAX ? (dst ← ECX, ZF=1) : (EAX ← dst, ZF=0)` | (present in codebase) |
| `XCHG [dst], EAX` | Atomic swap | `004037da XCHG dword ptr [EDI],ECX` |

**LOCK semantics are mandatory to document per site** — see `important_instructions.md`.

## Indirect calls

`CALL [EDX]`, `CALL [EAX+0x0C]`, etc. Reference type `COMPUTED_CALL` (5,075 occurrences). The target pointer is a value in memory or a register and is **not** a static address unless an explicit DATA reference resolves it.

## Data references vs calls

`reference_type:"DATA"` identifies a memory reference, not a call. Do not count DATA references to function addresses as callsites (see prior audit finding: DATA references accounted separately).

## Item checklist per instruction to document

1. Opcode bytes (present in listing column 2).
2. Operands and effective address expression.
3. Register sources/destinations.
4. Memory size (`dword ptr`, `word ptr`, `byte ptr`).
5. Flags affected.
6. Call target (direct VA or indirect expression).
