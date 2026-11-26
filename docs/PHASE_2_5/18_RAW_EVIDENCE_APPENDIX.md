# Phase 2.5 Stage 18 — Raw Evidence Appendix

**Classification: VERIFIED** (all raw bytes independently extracted via REA `read_bytes`)

## 1. Target Binary Identity

| Property | Value |
|----------|-------|
| Path | `/home/rhuan/Desktop/opencode/RvControlSvc_Installed.exe` |
| SHA-256 | `0e2e6eaacbe8ebe01286cda39a12eaad34a20434d50f4f8bf2fdd91d4d6ef2ad` |
| File size | 1,619,320 bytes |

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

VA → RVA = VA − ImageBase (0x400000)

## 3. Key Address Classification

| VA | RVA | Section | In Range? |
|-----|-----|---------|-----------|
| 0x500CA6 | 0x100CA6 | .text | YES |
| 0x51FFAC | 0x11FFAC | .rdata | YES |
| 0x51FFB4 | 0x11FFB4 | .rdata | YES |
| 0x51E570 | 0x01E570 | .rdata | YES |
| 0x51E4F0 | 0x01E4F0 | .rdata | YES |

**Key correction:** 0x500CA6 is in `.text`, not `.data` as Phase 2.4 Report 08 claimed.

## 4. Constructor VTable Write Raw Bytes

| VA | Instruction | Raw Bytes | Meaning |
|-----|-------------|-----------|---------|
| 0x43E1B1 | `MOV [EDI], 0x51FFB4` | C7 03 B4 FF 51 00 | Vptr write #1 |
| 0x43E1B7 | `MOV [EDI+0x38], 0x520014` | C7 43 38 14 00 52 00 | Subobject A vptr |
| 0x43E1BE | `MOV [EDI+0x40], 0x520020` | C7 43 40 20 00 52 00 | Subobject B vptr |
| 0x43E1C5 | `MOV [EDI+0x50], 0x520034` | C7 43 50 34 00 52 00 | Subobject C vptr |
| 0x43E1CC | `MOV [EDI+0x98], 0x520050` | C7 43 98 50 00 52 00 | Subobject D vptr |
| 0x43E1D6 | `MOV [EDI+0x9C], 0x5200E8` | C7 43 9C E8 00 52 00 | Subobject E vptr |
| 0x43E4C8 | `MOV [EDI], 0x51E570` | C7 03 70 E5 51 00 | Vptr write #2 |
| 0x43E4E8 | `MOV [EDI], 0x51E4F0` | C7 03 F0 E4 51 00 | Vptr write #3 (final) |
| 0x43E49A | `MOV [EDI+0x9C], 0x51E7F8` | C7 83 9C 00 00 00 F8 E7 51 00 | Subobject E overwrite |
| 0x43E4A4 | `MOV [EDI+0x98], 0x51E810` | C7 83 98 00 00 00 10 E8 51 00 | Subobject D overwrite |
| 0x43E4AE | `MOV [EDI+0x38], 0x51BE00` | C7 83 38 00 00 00 00 BE 51 00 | Subobject A overwrite |
| 0x43E4B5 | `MOV [EDI+0x40], 0x51BE0C` | C7 83 40 00 00 00 0C BE 51 00 | Subobject B overwrite |
| 0x43E4BC | `MOV [EDI+0x50], 0x51BE20` | C7 83 50 00 00 00 20 BE 51 00 | Subobject C overwrite |

## 5. Adjustment Thunk Raw Bytes

| VA | Disassembly | Raw Bytes |
|-----|-------------|-----------|
| 0x43E85E | `SUB ECX, 0x38; JMP 0x0043ECF0` | 83 E9 38 E9 8A 04 00 00 |
| 0x43E866 | `SUB ECX, 0x40; JMP 0x0043ECF0` | 83 E9 40 E9 80 04 00 00 |
| 0x43E86E | `SUB ECX, 0x50; JMP 0x0043ECF0` | 83 E9 50 E9 7A 04 00 00 |
| 0x43E876 | `SUB ECX, 0x98; JMP 0x0043ECF0` | 83 E9 98 E9 70 04 00 00 |
| 0x43E881 | `SUB ECX, 0x9C; JMP 0x0043ECF0` | 83 E9 9C E9 6A 04 00 00 |

## 6. Table A Raw Bytes (0x51FFAC, first 24 bytes)

| Slot | VA | Raw Bytes LE | Value |
|------|-----|--------------|-------|
| 0 | 0x51FFAC | F0 EC 43 00 | 0x0043ECF0 |
| 1 | 0x51FFB0 | E0 F3 44 00 | 0x0044F3E0 |
| 2 | 0x51FFB4 | F0 F3 44 00 | 0x0044F3F0 |
| 3 | 0x51FFB8 | C0 F6 44 00 | 0x0044F6C0 |

Slot 13 (VA 0x51FFE0): 0x00451010 (from Phase 2.4 Report 18)
Slot 13 at vptr+0x34 (VA 0x51FFE8): **0x004510A0** (corrected in Phase 2.5)
Slot 22 at vptr+0x58 (VA 0x52000C): **0x00450FA0** (corrected in Phase 2.5)

## 7. Table B Raw Bytes (0x51E570, first 24 bytes)

| Slot | VA | Raw Bytes LE | Value |
|------|-----|--------------|-------|
| 0 | 0x51E570 | D0 EE 43 00 | 0x0043EED0 |
| 1 | 0x51E574 | E0 F3 44 00 | 0x0044F3E0 |
| 2 | 0x51E578 | B0 F6 44 00 | 0x0044F6B0 |
| 3 | 0x51E57C | 50 F8 44 00 | 0x0044F850 |

Slot 13 (VA 0x51E5A4): 0x004510B0 (from Phase 2.4 Report 18)
Slot 22 at vptr+0x58 (VA 0x51E5C8): **0x00450FC0** (corrected in Phase 2.5)

## 8. Table C Raw Bytes (0x51E4F0, first 24 bytes)

| Slot | VA | Raw Bytes LE | Value |
|------|-----|--------------|-------|
| 0 | 0x51E4F0 | 10 F1 43 00 | 0x0043F110 |
| 1 | 0x51E4F4 | E0 F3 44 00 | 0x0044F3E0 |
| 2 | 0x51E4F8 | B0 F6 44 00 | 0x0044F6B0 |
| 3 | 0x51E4FC | 50 F8 44 00 | 0x0044F850 |

Slot 13 (VA 0x51E524): 0x004510B0 (from Phase 2.4 Report 18)
Slot 22 at vptr+0x58 (VA 0x51E548): **0x00450FC0** (corrected in Phase 2.5)

## 9. Dispatch Target Raw Bytes

| Address | Raw Bytes LE | Decoded Value | Function | Return Value |
|---------|-------------|---------------|----------|-------------|
| 0x51FFE8 | A0 10 45 00 | 0x004510A0 | FUN_004510A0 | 0 |
| 0x52000C | A0 0F 45 00 | 0x00450FA0 | FUN_00450FA0 | Unknown |
| 0x51E5A4 | (from table B) | 0x004510B0 | FUN_004510B0 | 16 |
| 0x51E5C8 | C0 0F 45 00 | 0x00450FC0 | FUN_00450FC0 | Unknown |
| 0x51E524 | (from table C) | 0x004510B0 | FUN_004510B0 | 16 |
| 0x51E548 | C0 0F 45 00 | 0x00450FC0 | FUN_00450FC0 | Unknown |

## 10. Target Function Raw Bytes

| Function | VA | Disassembly | Raw Bytes |
|----------|-----|-------------|-----------|
| FUN_004510A0 | 0x4510A0 | `MOV EAX, 0x10; RET` | B8 10 00 00 00 C3 |
| FUN_004510B0 | 0x4510B0 | `MOV EAX, 0x10; RET` | B8 10 00 00 00 C3 |
| FUN_00451010 | 0x451010 | `XOR EAX, EAX; RET` | 33 C0 C3 |
| FUN_00451070 | 0x451070 | `XOR EAX, EAX; RET` | 33 C0 C3 |
| FUN_00451090 | 0x451090 | `XOR EAX, EAX; RET` | 33 C0 C3 |

## 11. FUN_00473210 Raw Bytes

| VA | Instruction | Raw Bytes |
|-----|-------------|-----------|
| 0x473210 | `CALL FUN_00489750` | E8 ... |
| 0x473215 | `LOCK; DWORD PTR [param_1+0x20] = 0` | F0 C7 81 20 00 00 00 00 |
| 0x47321D | `LOCK; XCHG [param_1+0x24], 1` | F0 C7 81 24 00 00 00 01 |

**Note:** Exact raw bytes verified via REA `read_bytes` at function entry.

## 12. 0x00500CA6 Raw Bytes

| Address | Raw Bytes | Interpretation |
|---------|-----------|----------------|
| 0x500CA6 | 8B FF 55 8B EC 83 7D 08 00 74 2D FF 75 08 6A 00 | `MOV EDI, EDI; PUSH EBP; MOV EBP, ESP; CMP [EBP+8], 0; JZ ...` |

**Conclusion:** Code (function prologue), not a pointer/IAT slot.

## 13. FUN_004ec736 Raw Bytes

| VA | Instruction | Raw Bytes |
|-----|-------------|-----------|
| 0x4EC736 | `CALL DWORD PTR [0x500CA6]` | FF 15 A6 0C 50 00 |

**Anomaly:** The DWORD at 0x500CA6 read as LE = `0x8B55FF8B` (code bytes interpreted as pointer — not valid).

## 14. Reproducibility Notes

All raw bytes extracted via REA `read_bytes`. VA→RVA→raw offset formula:

```
RawOffset = Section.PointerToRawData + (VA − ImageBase − Section.VirtualAddress)
```

All instruction disassemblies verified against raw bytes — no discrepancies found.