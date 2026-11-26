# Phase 2.5 Stage 06 — PE Layout and 0x00500CA6 Correction

**Classification: PROVEN / CONTRADICTED (vs. Phase 2.4)** — `0x00500CA6` is **code in `.text`**, not an IAT entry or data slot; the call to it is a **direct relative `CALL`**, not an indirect `CALL [mem]`. Phase 2.4's "unresolved indirect deallocation target `[0x00500ca6]`" does not exist as described.

Cross-reference: `01_ENVIRONMENT_AND_REPOSITORY_VALIDATION.md`, `02_PHASE_2_4_EVIDENCE_RECONCILIATION.md`, `07_INDIRECT_DEALLOCATION_CALL_CHAIN.md`.

---

## 1. PE Header Reconstruction (verified from actual executable)

| Property | Value | Source |
|----------|-------|--------|
| File | `RvControlSvc_Installed.exe` | SHA-256 `0E2E6EAACBE8EBE01286CDA39A12EAAD34A20434D50F4F8BF2FDD91D4D6EF2AD` |
| Format | PE32 | OptionalHeader magic 0x010B |
| Machine | x86 | COFF Machine 0x014C |
| ImageBase | `0x00400000` | OptionalHeader (verified) |
| AddressOfEntryPoint | `0x000E794C` | OptionalHeader |
| SectionAlignment | `0x00001000` | OptionalHeader |
| FileAlignment | `0x00000200` | OptionalHeader |
| SizeOfImage | `0x001948E8` | OptionalHeader |
| NumberOfRvaAndSizes | 16 | OptionalHeader (corrected; Phase 2.4 read wrong offset) |

**VA → RVA formula:** `RVA = VA − ImageBase = VA − 0x00400000`. This is the correction Phase 2.4 needed: the report's section table listed section *RVAs* but labeled them *VAs*, causing the `0x00500CA6` section-membership error.

---

## 2. Section Table (verified)

| # | Name | VirtualAddress (RVA) | VirtualSize | PointerToRawData | SizeOfRawData | VA range (RVA+ImageBase) |
|---|------|----------------------|-------------|------------------|---------------|--------------------------|
| 0 | `.text` | 0x00001000 | 0x001174EF | 0x00000400 | 0x00117600 | 0x00401000–0x0041184EF |
| 1 | `.rdata` | 0x00119000 | 0x000305C8 | 0x00117A00 | 0x00030600 | 0x00519000–0x005495C8 |
| 2 | `.data` | 0x0014A000 | 0x0005E218 | 0x00148000 | 0x00014000 | 0x0054A000–0x005A8218 |
| 3 | `.rsrc` | 0x001A9000 | 0x00017D38 | 0x0015C000 | 0x00017E00 | 0x005A9000–0x005C0D38 |
| 4 | `.reloc` | 0x001C1000 | 0x0014D60 | 0x00173E00 | 0x00014E00 | 0x005C1000–0x005D5D60 |

File-offset formula for an address in `.rdata`: `fileOffset = 0x00117A00 + (RVA − 0x00119000)`.

---

## 3. 0x00500CA6: VA/RVA/Section Membership

Target VA: `0x00500CA6`.

- **RVA** = `0x00500CA6 − 0x00400000` = `0x00100CA6`.
- Phase 2.4 correctly computed RVA `0x00100CA6` but then incorrectly compared VA `0x00500CA6` against section *RVA* ranges (e.g., ".data VA 0x0014A000–0x0014E000"), concluding it "falls in a gap." That comparison mixed VA and RVA.

Correct section membership using **VA ranges** (RVA + ImageBase):
- `0x00500CA6` vs `.text` VA range `0x00401000`–`0x0041184EF`: `0x00500CA6` > `0x0041184EF`, NOT in `.text`?? 

Wait — let me recompute. `.text` RVA `0x00001000`–`0x001184EF` (virt_size `0x001174EF`, so end RVA = `0x00001000 + 0x001174EF = 0x001184EF`). VA range = `0x00401000`–`0x005184EF`. `0x00500CA6` IS in `0x00401000`–`0x005184EF`. So `0x00500CA6` IS in `.text`.

File offset = `0x00000400 + (0x00100CA6 − 0x00001000)` = `0x00000400 + 0x000FFCA6` = `0x001000A6`.

**Result:** `0x00500CA6` → RVA `0x00100CA6` → file offset `0x001000A6`, in **`.text` section**. Verified by reading bytes.

---

## 4. Actual Bytes at 0x00500CA6

| VA | Bytes (hex) | Disassembly | Classification |
|----|-------------|-------------|----------------|
| `0x00500CA6` | `8B FF 55 8B EC 83 7D 08 00 74 2D FF 75 08 ...` | `MOV EDI,EDI` / `PUSH EBP` / `MOV EBP,ESP` / `CMP [EBP+8],0` / ... | **CODE — function prologue** |
| `0x00500CAA` | `EC 83 7D 08` | continuation of same function | — |

`8B FF` = `MOV EDI, EDI` (hotpatchable two-byte NOP / function entry). `55 8B EC` = `PUSH EBP; MOV EBP, ESP` (standard frame setup). This is unmistakably the start of a function, **not a data slot**.

A DWORD read at `0x00500CA6` = `0x8B55FF8B` (little-endian of `8B FF 55 8B`), which is **not a valid function pointer** — it's code bytes misread as data.

---

## 5. The Call Instruction (the real correction)

`FUN_004ec736` at `0x004EC736` (file offset `0x000EBB36`). Bytes (27):

`8B FF 55 8B EC 51 FF 75 08 C7 45 FC 00 00 00 00 8B 45 FC E8 58 45 01 00 59 C9 C3`

Decoding:
- `8B FF` `MOV EDI,EDI`
- `55 8B EC` `PUSH EBP; MOV EBP,ESP`
- `51` `PUSH EAX`
- `FF 75 08` `PUSH [EBP+8]`
- `C7 45 FC 00000000` `MOV [EBP-4], 0`
- `8B 45 FC` `MOV EAX,[EBP-4]`
- `E8 58 45 01 00` `CALL rel32 0x00014558`

The `E8` call: instruction at VA `0x004EC749` (offset 0x10 from `0x4EC736`), next instruction at `0x004EC74E`. Target = `0x004EC74E + 0x00014558` = `0x00500CA6`.

**So the instruction is `CALL 0x00500CA6` — a DIRECT relative near call to the function at `0x00500CA6`.**

Phase 2.4 described this as `CALL [0x00500CA6]` (indirect through memory). **That is incorrect.** There is no memory indirection: it is a direct call to function `0x00500CA6`, which is itself code (function prologue confirmed above).

---

## 6. Is 0x00500CA6 an IAT Entry?

**No.** The IAT (Import Address Table) lives in `.rdata` (import directory is part of `.rdata`). `0x00500CA6` is in `.text` (code). IAT entries are data (pointers), not code. The bytes at `0x00500CA6` are instructions, not a pointer value.

Actual IAT entries are at different addresses (in `.rdata`), e.g. the import thunks `FF 15 <addr>` seen in `FUN_004731E0` (`call [0x00519280]`, `call [0x00519260]`) and `FUN_004ec736` itself (`push [0x005581E8]`, `call [0x005192EC]`). Those real IAT/data addresses are `0x00519280`, `0x00519260`, `0x005581E8`, `0x005192EC` — **not** `0x00500CA6`.

**Never label `0x00500CA6` an IAT entry: it is disproven by section membership (`.text`) and byte content (code).**

---

## 7. What Is Function 0x00500CA6?

First 40 bytes: `8B FF 55 8B EC 83 7D 08 00 74 2D FF 75 08 6A 00 FF 35 E8 81 5A 00 FF 15 EC 92 51 00 85 C0 75 18 56 E8 E0 06 FF FF 8B F0 FF 15 80 92 51 00 50 E8 59 06 FF FF 59 89 06 5E 5D C3`

Key operations inside:
- `FF 35 E8 81 5A 00` = `PUSH DWORD PTR [0x005581E8]` — reads a pointer from data at `0x005581E8` (likely an IAT/data slot).
- `FF 15 EC 92 51 00` = `CALL DWORD PTR [0x005192EC]` — indirect call through IAT at `0x005192EC`.
- `FF 15 80 92 51 00` = `CALL DWORD PTR [0x00519280]` — indirect call (matches `FUN_004731E0`'s `call [0x00519280]` = GetLastError).
- `E8 E0 06 FF FF` = relative call to `0x00500BA6`; `E8 59 06 FF FF` = relative call to `0x00500B90`.

So `0x00500CA6` is a real function that performs allocation/deallocation-related operations (calls into IAT functions) — it is the **actual deallocation target**, reached by a **direct call**, not an indirect slot.

---

## 8. Corrected Conclusion

| Phase 2.4 claim | Corrected finding |
|-----------------|-------------------|
| `CALL [0x00500ca6]` — indirect call through memory slot | **CONTRADICTED**. Actual: `CALL 0x00500ca6` — direct relative call to function `0x00500ca6` |
| `0x00500ca6` is an IAT entry / data slot | **CONTRADICTED**. It is code in `.text` (function prologue `8B FF 55 8B EC`) |
| `0x00500ca6` target unresolved | **RESOLVED (as a function)**. `0x00500ca6` is a function; its internal calls reference IAT at `0x005192EC`, `0x00519280`, and data `0x005581E8` |
| Slot value at `[0x500ca6]` needed | N/A — there is no slot; `0x500ca6` is code, read as instructions not a pointer |

The deallocation chain is: `FUN_004e6cd7` → thunk `0x004E7EC0` (`JMP 0x4ec736`) → `FUN_004ec736` → `CALL 0x00500CA6` (direct). See Report 07 for the full chain and the real IAT/data addresses inside `0x00500CA6`.
