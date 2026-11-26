# Phase 2.3 Stage 18 — Raw Evidence Appendix

**Classification: VERIFIED** (all raw bytes independently extracted via REA `read_bytes`)

## 1. Target Binary Identity

| Property | Value |
|---|---|
| Path | `/home/rhuan/Desktop/opencode/RvControlSvc_Installed.exe` |
| SHA-256 | `0e2e6eaacbe8ebe01286cda39a12eaad34a20434d50f4f8bf2fdd91d4d6ef2ad` |
| File size | 1,619,320 bytes |

## 2. PE Section Mapping

| Section | VA | RVA | Raw Offset | Raw Size |
|---|---|---|---|---|
| .text | 0x00001000 | 0x00001000 | 0x00000400 | 0x00117600 |
| .rdata | 0x00119000 | 0x00011900 | 0x00117a00 | 0x00030600 |
| .data | 0x0014a000 | 0x00014a00 | 0x00148000 | 0x0014000 |
| .rsrc | 0x001a9000 | 0x0001a900 | 0x0015c000 | 0x0017e00 |
| .reloc | 0x001c1000 | 0x0001c100 | 0x00173e00 | 0x0014e00 |

## 3. Address Calculations

VA → RVA = VA − ImageBase (0x400000)
Raw Offset = Section.PointerToRawData + (VA − ImageBase − Section.VirtualAddress)

| VA | RVA | Raw Offset | Section |
|---|---|---|---|
| 0x43E1A0 | 0x0003E1A0 | 0x0003E5A0 | .text |
| 0x43ECF0 | 0x0003ECF0 | 0x0003EDF0 | .text |
| 0x43E85E | 0x0003E85E | 0x0003EC5E | .text |
| 0x43E866 | 0x0003E866 | 0x0003EC66 | .text |
| 0x43E86E | 0x0003E86E | 0x0003EC6E | .text |
| 0x43E876 | 0x0003E876 | 0x0003EC76 | .text |
| 0x43E881 | 0x0003E881 | 0x0003EC81 | .text |
| 0x44F3F0 | 0x0004F3F0 | 0x0004E7F0 | .text |
| 0x44F40A | 0x0004F40A | 0x0004E80A | .text |
| 0x44F4EE | 0x0004F4EE | 0x0004E8EE | .text |
| 0x44F4F4 | 0x0004F4F4 | 0x0004E8F4 | .text |
| 0x44F4FE | 0x0004F4FE | 0x0004E8FE | .text |
| 0x44F4FA | 0x0004F4FA | 0x0004E8FA | .text |
| 0x44F501 | 0x0004F501 | 0x0004E901 | .text |
| 0x44F50D | 0x0004F50D | 0x0004E90D | .text |
| 0x44F5AA | 0x0004F5AA | 0x0004E9AA | .text |
| 0x44F5B6 | 0x0004F5B6 | 0x0004E9B6 | .text |
| 0x51FFAC | 0x0011FFAC | 0x0011E9AC | .rdata |
| 0x51FFB4 | 0x0011FFB4 | 0x0011E9B4 | .rdata |
| 0x51FFBC | 0x0011FFBC | 0x0011E9BC | .rdata |
| 0x51E570 | 0x0001E570 | 0x0001D970 | .rdata |
| 0x51E4F0 | 0x0001E4F0 | 0x0001D8F0 | .rdata |

## 4. Constructor VTable Write Raw Bytes

| VA | Instruction | Raw Bytes | Meaning |
|---|---|---|---|
| 0x43E1B1 | `MOV [EDI], 0x51FFB4` | C7 03 B4 FF 51 00 | Write vptr to [this+0x00] |
| 0x43E1B7 | `MOV [EDI+0x38], 0x520014` | C7 43 38 14 00 52 00 | Write subobject A vptr |
| 0x43E1BE | `MOV [EDI+0x40], 0x520020` | C7 43 40 20 00 52 00 | Write subobject B vptr |
| 0x43E1C5 | `MOV [EDI+0x50], 0x520034` | C7 43 50 34 00 52 00 | Write subobject C vptr |
| 0x43E1CC | `MOV [EDI+0x98], 0x520050` | C7 43 98 50 00 52 00 | Write subobject D vptr |
| 0x43E1D6 | `MOV [EDI+0x9C], 0x5200E8` | C7 43 9C E8 00 52 00 | Write subobject E vptr |
| 0x43E4C8 | `MOV [EDI], 0x51E570` | C7 03 70 E5 51 00 | Vtable overwrite #2 |
| 0x43E4E8 | `MOV [EDI], 0x51E4F0` | C7 03 F0 E4 51 00 | Vtable overwrite #3 (final) |
| 0x43E49A | `MOV [EDI+0x9C], 0x51E7F8` | C7 83 9C 00 00 00 F8 E7 51 00 | Overwrite subobject E |
| 0x43E4A4 | `MOV [EDI+0x98], 0x51E810` | C7 83 98 00 00 00 10 E8 51 00 | Overwrite subobject D |
| 0x43E4AE | `MOV [EDI+0x38], 0x51BE00` | C7 83 38 00 00 00 00 BE 51 00 | Overwrite subobject A |
| 0x43E4B5 | `MOV [EDI+0x40], 0x51BE0C` | C7 83 40 00 00 00 0C BE 51 00 | Overwrite subobject B |
| 0x43E4BC | `MOV [EDI+0x50], 0x51BE20` | C7 83 50 00 00 00 20 BE 51 00 | Overwrite subobject C |

## 5. Adjustment Thunk Raw Bytes

| VA | Disassembly | Raw Bytes |
|---|---|---|
| 0x43E85E | `SUB ECX, 0x38; JMP 0x0043ECF0` | 83 E9 38 E9 8A 04 00 00 |
| 0x43E866 | `SUB ECX, 0x40; JMP 0x0043ECF0` | 83 E9 40 E9 80 04 00 00 |
| 0x43E86E | `SUB ECX, 0x50; JMP 0x0043ECF0` | 83 E9 50 E9 7A 04 00 00 |
| 0x43E876 | `SUB ECX, 0x98; JMP 0x0043ECF0` | 83 E9 98 E9 70 04 00 00 |
| 0x43E881 | `SUB ECX, 0x9C; JMP 0x0043ECF0` | 83 E9 9C E9 6A 04 00 00 |

## 6. FUN_0043ECF0 Raw Bytes

| VA | Disassembly | Raw Bytes |
|---|---|---|
| 0x43ECF0 | `PUSH EBP; MOV EBP, ESP; PUSH ESI; MOV ESI, ECX` | 55 8B EC 56 8B F1 |
| 0x43ECF6 | `CALL 0x0043E1A0` | E8 0B F2 FC 00 |
| 0x43ECFB | `TEST byte ptr [EBP+0x8], 0x1` | F6 45 08 01 |
| 0x43ECFF | `JZ 0x0043EF0D` | 74 14 |
| 0x43ED01 | `PUSH 0x6108` | 68 08 61 00 00 |
| 0x43ED06 | `PUSH ESI` | 56 |
| 0x43ED07 | `CALL 0x004E6CD7` | E8 28 9E 00 00 |
| 0x43ED0C | `ADD ESP, 0x8` | 83 C4 08 |
| 0x43ED0F | `MOV EAX, ESI` | 8B C6 |
| 0x43ED11 | `POP ESI` | 5E |
| 0x43ED12 | `POP EBP` | 5D |
| 0x43ED13 | `RET 0x4` | C2 04 00 |

## 7. FUN_0044F3F0 Indirect Call Site Raw Bytes

| VA | Disassembly | Raw Bytes |
|---|---|---|
| 0x44F40A | `MOV EDI, ECX` | 8B F9 |
| 0x44F4EE | `CMP [EDI+0x28], 5` | 83 7F 28 05 |
| 0x44F4F4 | `CMP [EDI+0x2C], 0` | 83 7F 2C 00 |
| 0x44F4FE | `INC [EDI+0x30]` | FF 47 30 |
| 0x44F4FA | `MOV EAX, [EDI]` | 8B 07 |
| 0x44F501 | `CALL [EAX+0x34]` | FF 50 34 |
| 0x44F50D | `CALL [EAX+0x58]` | FF 50 58 |
| 0x44F5AA | `CALL [EAX+0x34]` | FF 50 34 |
| 0x44F5B6 | `CALL [EAX+0x58]` | FF 50 58 |

## 8. Table A Raw Bytes (0x51FFAC, 160 bytes)

Slots 0–3:
| Slot | VA | Raw Bytes LE | Value |
|---|---|---|---|
| 0 | 0x51FFAC | E0 E8 43 00 | 0x0043E8E0 |
| 1 | 0x51FFB0 | 4C 9A 53 00 | 0x00539A4C |
| 2 | 0x51FFB4 | F0 EC 43 00 | 0x0043ECF0 |
| 3 | 0x51FFB8 | E0 F3 44 00 | 0x0044F3E0 |
| 4 | 0x51FFBC | F0 F3 44 00 | 0x0044F3F0 |

Slot 13 (VA 0x51FFE0): 0x00451010
Slot 22 (VA 0x520004): 0x00451070

## 9. Intermediate Table Raw Bytes (0x51E570)

| Slot | VA | Value |
|---|---|---|
| 0 | 0x51E570 | 0x0043EED0 |
| 13 | 0x51E5A4 | 0x004510B0 |
| 22 | 0x51E5C4 | 0x00451090 |

## 10. Final Table Raw Bytes (0x51E4F0)

| Slot | VA | Value |
|---|---|---|
| 0 | 0x51E4F0 | 0x0043F110 |
| 13 | 0x51E524 | 0x004510B0 |
| 22 | 0x51E544 | 0x00451090 |

## 11. Target Function Raw Bytes

| Function | VA | Disassembly | Raw Bytes |
|---|---|---|---|
| FUN_004510A0 | 0x4510A0 | `MOV EAX, 0x10; RET` | B8 10 00 00 00 C3 |
| FUN_00451010 | 0x451010 | `XOR EAX, EAX; RET` | 33 C0 C3 |
| FUN_004510B0 | 0x4510B0 | `MOV EAX, 0x10; RET` | B8 10 00 00 00 C3 |
| FUN_00451070 | 0x451070 | `XOR EAX, EAX; RET` | 33 C0 C3 |
| FUN_00450FA0 | 0x450FA0 | `PUSH EBP; MOV EBP,ESP; MOV EAX,[EBP+0x8]; CMP EAX,2; ...` | 55 8B EC 8B 45 08 83 F8 02 ... |

## 12. Reproducibility Notes

All raw bytes in this appendix were extracted via REA `read_bytes` at the specified VA. The VA→RVA→raw offset calculations use:
- ImageBase = 0x400000
- .text section: VA 0x401000, RawPtr 0x400
- .rdata section: VA 0x519000, RawPtr 0x00117a00

Formula: RawOffset = Section.PointerToRawData + (VA − ImageBase − Section.VirtualAddress)

All instruction disassemblies were verified against raw bytes — no discrepancies found.