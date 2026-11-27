# Phase 2.4 Stage 08 — Indirect Deallocation Target Analysis

**Classification: UNKNOWN** (IAT slot value not resolved without runtime debugging)

## 1. The Indirect Call

| Property | Value |
|----------|-------|
| Instruction | `CALL DWORD PTR [0x00500CA6]` |
| Location | FUN_004ec736 (0x4ec736) |
| Call chain | FUN_004e6cd7 → thunk_FUN_004ec736 → FUN_004ec736 → `CALL [0x00500ca6]` |

**FUN_004ec736** (27 bytes): Contains `CALL dword ptr [0x00500ca6]` as its key operation.

**thunk_FUN_004ec736** (5 bytes at 0x4e7ec0): `JMP 0x4ec736` — confirmed by Ghidra as a thunk.

**FUN_004e6cd7** (14 bytes): `PUSH [EBP+0x8]; CALL 0x004e7ec0` — destruction wrapper.

## 2. Slot Location: [0x00500CA6]

| Property | Value |
|----------|-------|
| VA | 0x00500CA6 |
| RVA | 0x00100CA6 |
| Section | .data (VA 0x0014A000–0x0014E000) |
| Raw offset | 0x00148000 + (0x500CA6 − 0x400000 − 0x14A000) = need calculation |

**VA → RVA:** 0x500CA6 − 0x400000 = 0x100CA6

**VA → Raw Offset:** The .data section starts at VA 0x0014A000 with raw pointer 0x00148000. Since 0x500CA6 < 0x14A000, this address is NOT in .data — it falls in the gap between sections or in .rdata.

**Re-evaluation:** 0x500CA6 is between .rdata (ends at 0x119000 + 0x30600 = 0x149600) and .data (starts at 0x14A000). The address 0x500CA6 falls in the range 0x149600–0x14A000, which is a gap. This may mean:
- The address is in .rdata if the section extends further than reported
- The address is in a different section
- The address calculation needs verification

**This needs REA `read_bytes` verification at VA 0x500CA6.**

## 3. Candidate Targets

From PE import analysis, the slot at [0x00500ca6] could contain any of:

| Candidate | DLL | RVA | Plausibility |
|-----------|-----|-----|--------------|
| HeapFree | KERNEL32.dll | 0x11942a | High — standard deallocation |
| RolClient_FreeMemory | RvROLClient.dll | 0x11998c | High — custom ROL deallocation |
| CoTaskMemFree | ole32.dll | 0x119942 | Medium — COM memory free |
| LocalFree | KERNEL32.dll | 0x117cd4 | Medium — local memory free |

**Cannot determine statically** — the IAT slot value at runtime is unknown without debugging.

## 4. All Writes to the Slot

**Status:** Not yet searched. Need to search for all instructions that write to memory address 0x500CA6.

**Approach:** REA search for `MOV [0x500ca6], ...` patterns or data references to 0x500ca6.

## 5. Calling Convention and Arguments

If the target is `HeapFree`:
- Convention: `__stdcall`
- Arguments: `HeapFree(hHeap, dwFlags, lpMem)`
- Return: BOOL

If the target is `RolClient_FreeMemory`:
- Convention: Unknown (likely `__stdcall` or `__cdecl`)
- Arguments: Unknown
- Return: Unknown

**Cannot determine without knowing the actual target.**

## 6. Confidence Classification

| Question | Classification | Basis |
|----------|---------------|-------|
| Indirect call exists at [0x00500ca6] | CONFIRMED | FUN_004ec736 contains CALL [0x00500ca6] |
| Call chain to indirect call | STRONGLY SUPPORTED | All intermediate functions analyzed |
| Slot is in .data section | UNKNOWN | VA 0x500ca6 may fall in section gap |
| Slot is an IAT entry | UNKNOWN | Need to verify IAT layout |
| Actual target function | UNKNOWN | Slot value not readable statically without REA read_bytes |
| Target is HeapFree | HYPOTHESIS | HeapFree is imported; plausible for deallocation |
| Target is RolClient_FreeMemory | HYPOTHESIS | Imported; plausible for ROL objects |
| Calling convention | UNKNOWN | Depends on actual target |