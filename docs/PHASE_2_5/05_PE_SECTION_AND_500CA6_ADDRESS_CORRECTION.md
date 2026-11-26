# Phase 2.5 Stage 05 — PE Section and 0x00500CA6 Address Correction

**Classification: VERIFIED** (all PE section data from REA `binary_overview`; all raw bytes from REA `read_bytes`)

## 1. Purpose

Correct the PE section and file-offset classification of `0x00500CA6` from Phase 2.4 Report 08, which incorrectly compared the absolute VA against section addresses and misclassified the section.

## 2. PE Section Table (from REA `binary_overview`)

| Section | Start VA | End VA | Length | ImageBase |
|---------|----------|--------|--------|-----------|
| Headers | 0x400000 | 0x400400 | 1024 | 0x400000 |
| .text | 0x401000 | 0x519000 | 1,146,880 | 0x400000 |
| .rdata | 0x519000 | 0x54A000 | 200,704 | 0x400000 |
| .data | 0x54A000 | 0x5A9000 | 389,120 | 0x400000 |
| .rsrc | 0x5A9000 | 0x5C1000 | 98,304 | 0x400000 |
| .reloc | 0x5C1000 | 0x5D6000 | 86,016 | 0x400000 |
| tdb | 0xFFDFF000 | 0xFFE00000 | 4,096 | 0x400000 |

**Key correction:** Phase 2.4 Report 03 listed different section boundaries (.text ended at 0x118600, .rdata at 0x149600, .data at 0x14A000). The REA `binary_overview` shows different boundaries. The REA data is authoritative as it reads directly from the PE headers.

## 3. VA → RVA → Section Classification for 0x00500CA6

| Step | Calculation | Result |
|------|-------------|--------|
| VA | — | 0x00500CA6 |
| RVA = VA − ImageBase | 0x500CA6 − 0x400000 | 0x00100CA6 |
| Section check | Is 0x500CA6 in .text (0x401000–0x519000)? | YES |
| Section check | Is 0x500CA6 in .rdata (0x519000–0x54A000)? | NO |
| Section check | Is 0x500CA6 in .data (0x54A000–0x5A9000)? | NO |

**Classification:** `0x00500CA6` is in the **.text** section, NOT in `.data` as Phase 2.4 Report 08 claimed.

## 4. Raw File Offset Calculation

For .text section:
- Section.VirtualAddress = 0x401000
- Section.PointerToRawData = 0x400 (from Phase 2.4 Report 18, verified)

```
FileOffset = PointerToRawData + (RVA − Section.VirtualAddress)
           = 0x400 + (0x100CA6 − 0x1000)
           = 0x400 + 0x0FFCA6
           = 0x1000A6
```

**Verification:** REA `read_bytes` at 0x500CA6 successfully returned 16 bytes, confirming the address is within mapped memory.

## 5. Raw Bytes at 0x00500CA6

| Address | Raw Bytes (hex) | Interpretation |
|---------|----------------|----------------|
| 0x500CA6 | 8B FF 55 8B EC 83 7D 08 00 74 2D FF 75 08 6A 00 | x86 function prologue |

**Instruction decode:**
- `8B FF` = `MOV EDI, EDI` (hotpatch NOP / function entry)
- `55` = `PUSH EBP`
- `8B EC` = `MOV EBP, ESP`
- `83 7D 08 00` = `CMP DWORD PTR [EBP+8], 0`
- `74 2D` = `JZ +0x2D`
- `FF 75 08` = `PUSH DWORD PTR [EBP+8]`
- `6A 00` = `PUSH 0`

**Conclusion:** The bytes at `0x00500CA6` are **code** (function prologue), NOT a function pointer or IAT slot.

## 6. Ghidra Function Analysis at 0x00500CA6

| Property | Value |
|----------|-------|
| Function name | `FID_conflict:_free` (Ghidra auto-named due to naming conflict) |
| Address | 0x00500CA6 |
| Size | 58 bytes |
| Convention | `__cdecl` |
| Signature | `void __cdecl FID_conflict:_free(void * _Memory)` |
| Basic blocks | 4 |
| Body range | 0x500CA6 – 0x500CDF |

**Interpretation:** Ghidra recognizes 0x500CA6 as a `free`-like deallocation function. The function name suggests it's the C runtime `free()` or a custom deallocator.

## 7. The CALL [0x00500CA6] Anomaly

The instruction `CALL DWORD PTR [0x00500CA6]` (raw bytes: `FF 15 A6 0C 50 00`) reads a 4-byte DWORD from address 0x500CA6 and uses it as a call target.

The DWORD at 0x500CA6 read as little-endian:
- Bytes: `8B FF 55 8B`
- Value: `0x8B55FF8B`

**This is NOT a valid code pointer.** It falls in the middle of instructions within the `free` function itself.

**Possible explanations (all unverified):**
1. **Ghidra misanalysis:** The CALL instruction may not actually target [0x500CA6]; the address may have been misresolved.
2. **Obfuscation:** The code at 0x500CA6 may be intentionally structured to mislead static analysis.
3. **Bound import / IAT thunk:** The address may be part of a bound import or import thunk that Ghidra has misclassified as a function.
4. **Runtime relocation:** The DWORD at 0x500CA6 may be patched at runtime by the loader, making the static value invalid.

**Required runtime validation:** Break at the `CALL [0x500CA6]` instruction in FUN_004ec736 and capture the actual resolved target.

## 8. Comparison with Phase 2.4 Report 08

| Aspect | Phase 2.4 Claim | Phase 2.5 Correction |
|--------|----------------|---------------------|
| Section containing 0x500CA6 | `.data` or gap | `.text` (confirmed by binary_overview) |
| Is it an IAT slot? | Hypothesized | NO — it's a function entry point |
| Bytes at address | Not inspected | Code (function prologue for `free`) |
| CALL target resolution | UNKNOWN | Still UNKNOWN (reads code bytes as pointer) |
| File offset | Not calculated | 0x1000A6 (computed, not yet verified against raw file) |

## 9. Confidence Classification

| Question | Classification | Basis |
|----------|---------------|-------|
| 0x500CA6 is in .text | CONFIRMED | REA binary_overview section table |
| 0x500CA6 contains code | CONFIRMED | REA read_bytes (function prologue) |
| 0x500CA6 is a `free` function | CONFIRMED | Ghidra function analysis |
| CALL [0x500CA6] reads valid pointer | REFUTED | DWORD value 0x8B55FF8B is not valid |
| CALL [0x500CA6] actual target | UNKNOWN | Requires runtime debugging |
| File offset 0x1000A6 | UNVERIFIED | Computed but not verified against raw file |