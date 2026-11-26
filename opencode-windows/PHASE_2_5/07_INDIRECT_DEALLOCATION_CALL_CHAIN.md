# Phase 2.5 Stage 07 — Indirect Deallocation Call Chain

**Classification: STRONGLY SUPPORTED / PARTIALLY CORRECTED** — the chain `FUN_004e6cd7 → thunk → FUN_004ec736 → dealloc` is verified, but the final step is a **direct `CALL 0x00500CA6`** (not an indirect `CALL [0x00500ca6]`), and `0x00500CA6` is a function, not an IAT slot.

Cross-reference: `06_PE_LAYOUT_AND_00500CA6_CORRECTION.md`, `08_FUN_00473210_COMPLETE_ANALYSIS.md`, `14_DESTRUCTION_AND_DEALLOCATION_ANALYSIS.md`.

---

## 1. The Chain (verified disassembly)

### Step 1 — `FUN_004e6cd7` (destruction wrapper), VA `0x004E6CD7`, 14 bytes

Bytes: `55 8B EC FF 75 08 E8 DE 11 00 00 59 5D C3`

Decoded:
- `55` `PUSH EBP`
- `8B EC` `MOV EBP,ESP`
- `FF 75 08` `PUSH [EBP+8]` — push the node/this pointer argument
- `E8 DE 11 00 00` `CALL rel32 0x000011DE` → target = `0x4E6CDC + 5 + 0x11DE` = `0x4E6CE1 + 0x11DE` = `0x4E7EC0`
- `59` `POP ECX` (balance stack; the callee is `__cdecl` or cleans via `ADD ESP`... actually `POP ECX` here removes the pushed arg)
- `5D` `POP EBP`
- `C3` `RET`

**Behavior:** `FUN_004e6cd7(node)` pushes `node` and calls `0x4E7EC0` (thunk), then cleans the stack. This is a destruction wrapper that forwards `node` to the thunk.

Call site file offset: `0x000E60D7` (`.text`).

---

### Step 2 — Thunk `0x004E7EC0`, 5 bytes

Bytes: `E9 71 48 00 00`

Decoded: `E9 <rel32>` = `JMP rel32`. Rel32 = `0x00004871`. Next instruction at `0x4E7EC5`. Target = `0x4E7EC5 + 0x4871` = `0x4EC736`.

**Behavior:** Unconditional tail jump to `FUN_004ec736`. Confirmed thunk (5-byte `JMP`). File offset `0x000E72C0`.

---

### Step 3 — `FUN_004ec736`, VA `0x004EC736`, 27 bytes

Bytes: `8B FF 55 8B EC 51 FF 75 08 C7 45 FC 00 00 00 00 8B 45 FC E8 58 45 01 00 59 C9 C3`

Decoded:
- `8B FF` `MOV EDI,EDI` (hotpatch prologue)
- `55 8B EC` `PUSH EBP; MOV EBP,ESP`
- `51` `PUSH EAX`
- `FF 75 08` `PUSH [EBP+8]`
- `C7 45 FC 00 00 00 00` `MOV [EBP-4], 0` (local = 0)
- `8B 45 FC` `MOV EAX,[EBP-4]`
- `E8 58 45 01 00` `CALL rel32 0x00014558` → target = `0x4EC74E + 0x14558` = **`0x00500CA6`**
- `59` `POP ECX`
- `C9` `LEAVE`
- `C3` `RET`

**Behavior:** Calls function `0x00500CA6` directly (relative near call). Then cleans up and returns.

Call instruction VA: `0x004EC749`. File offset `0x000EBB49`. Target function `0x00500CA6` file offset `0x001000A6` (`.text`).

---

## 2. The Final Target: `0x00500CA6`

Per Report 06, `0x00500CA6` → RVA `0x00100CA6` → file offset `0x001000A6`, in `.text`. Bytes begin `8B FF 55 8B EC ...` = `MOV EDI,EDI / PUSH EBP / MOV EBP,ESP` — a function prologue.

So `FUN_004ec736` **directly calls function `0x00500CA6`**. There is **no indirect memory slot**, no IAT entry, and no unresolved pointer value. Phase 2.4's "CALL [0x00500ca6] indirect target unresolved" is corrected to "CALL 0x00500ca6 direct to function 0x00500ca6."

Function `0x00500CA6` (first 40 bytes): `8B FF 55 8B EC 83 7D 08 00 74 2D FF 75 08 6A 00 FF 35 E8 81 5A 00 FF 15 EC 92 51 00 85 C0 75 18 56 E8 E0 06 FF FF 8B F0 FF 15 80 92 51 00 50 E8 59 06 FF FF 59 89 06 5E 5D C3`

Internal references inside `0x00500CA6`:
- `FF 35 E8 81 5A 00` = `PUSH [0x005581E8]` — reads pointer from data VA `0x005581E8`.
- `FF 15 EC 92 51 00` = `CALL [0x005192EC]` — indirect call via IAT/data at `0x005192EC`.
- `FF 15 80 92 51 00` = `CALL [0x00519280]` — (same as GetLastError IAT used by `FUN_004731E0`).
- `E8 E0 06 FF FF` = `CALL 0x00500BA6` (direct).
- `E8 59 06 FF FF` = `CALL 0x00500B90` (direct).

So `0x00500CA6` is a real function performing memory operations (it reads `[0x005581E8]` and calls IAT functions). It is the **actual deallocation/free routine**, reached directly.

---

## 3. IAT / Data Addresses Referenced in the Chain

| VA | Kind | Instruction | Notes |
|----|------|-------------|-------|
| `0x00519280` | IAT/data | `CALL [0x00519280]` in `FUN_004731E0` and `0x00500CA6` | Likely `GetLastError`/`SetLastError` pair (Release uses `[0x00519280]`=GetLastError, `[0x00519260]`=SetLastError) |
| `0x00519260` | IAT/data | `CALL [0x00519260]` in `FUN_004731E0` | Likely SetLastError |
| `0x005192EC` | IAT/data | `CALL [0x005192EC]` inside `0x00500CA6` | Unresolved import |
| `0x005581E8` | data | `PUSH [0x005581E8]` inside `0x00500CA6` | Pointer global, likely an IAT thunk or function-pointer global |

`0x005581E8` → RVA `0x001581E8` → `.data` (RVA `0x0014A000`–`0x001A8218`) → file offset `0x00148000 + (0x1581E8 − 0x14A000)` = `0x00148000 + 0xE1E8` = `0x001561E8`. In `.data`, backed by raw file data.

---

## 4. Chain Summary Table

| # | Function | VA | Operation | Target | Type | Verified? |
|---|----------|-----|-----------|--------|------|-----------|
| 1 | `FUN_004e6cd7` | `0x004E6CD7` | `PUSH [EBP+8]; CALL 0x4E7EC0` | `0x004E7EC0` | destruction wrapper | PROVEN |
| 2 | thunk | `0x004E7EC0` | `JMP 0x4EC736` | `0x004EC736` | adjustment/tail thunk | PROVEN |
| 3 | `FUN_004ec736` | `0x004EC736` | `...; CALL 0x500CA6; ...` | `0x00500CA6` | deallocation routine | PROVEN |
| 4 | `0x00500CA6` | `0x00500CA6` | function body (frees memory) | — | final dealloc target | PROVEN (as function) |

**Corrected chain:**
```
Release (FUN_004731E0)
  └─ FUN_00473210 (cleanup: InterlockedExchange +0x20=0, +0x24=1)
       └─ 5 list-cleanup functions
            └─ per node: FUN_004e6cd7(node)
                 └─ thunk 0x4E7EC0 (JMP 0x4EC736)
                      └─ FUN_004ec736
                           └─ CALL 0x00500CA6  (DIRECT, not indirect)
                                └─ function 0x500CA6 frees memory
```

---

## 5. What Remains Unresolved

- The exact identity of `0x00500CA6` (which exported allocator/free function it corresponds to) is not statically determinable without symbols/PDB. It calls IAT at `0x005192EC` and `0x00519280`, reads data `0x005581E8`, and directly calls `0x00500BA6`/`0x00500B90`. It is plausibly `HeapFree` or `RolClient_FreeMemory`, but that is **HYPOTHESIS** — no import name is bound to `0x00500CA6` because `0x00500CA6` is not itself an IAT entry; it's a consumer of imports.
- Whether `0x00500CA6` frees the *object* or a *list node* is not fully determined, but the chain originates from the 5 list-cleanup functions (per-node destruction), so it most likely frees list nodes. The parent object's own free is not separately confirmed.
- Allocation site for the nodes/object remains UNKNOWN (no `HeapAlloc`/`RolClient_AllocMemory` call in any analyzed path).
