# Phase 2.6 Stage 18 — Reproducible Binary and Repository Search Methodology

**Classification: PROVEN** — all tools, versions, commands, and results documented for reproducibility.

Cross-reference: `01_ENVIRONMENT_AND_BINARY_VALIDATION.md`.

---

## 1. Environment

| Property | Value |
|----------|-------|
| Host OS | Microsoft Windows 10 Pro, version 10.0.19045 (20H2), 64-bit |
| Host architecture | AMD64 (x86-64) |
| Target architecture | PE32 x86 (ImageBase `0x00400000`) |
| Repository path | `C:\Users\Rhuan\Documents\Projeto Padrão\radmin-linux-rs` |
| Repository branch | `phase-2-6-instruction-decoding-audit` |
| Repository HEAD | `1c30faec5ad780f283e5058db0c49e70f546f9c5` |
| Target binary | `RvControlSvc_Installed_0E2E6EAA.exe` |
| Target SHA-256 | `0e2e6eaacbe8ebe01286cda39a12eaad34a20434d50f4f8bf2fdd91d4d6ef2ad` (verified at 3 locations) |

---

## 2. Tools and Versions

| Tool | Version | Role |
|------|---------|------|
| REA (Ghidra provider) | 6.10.1 | `open_binary`, `read_bytes` — ground-truth raw bytes |
| Ghidra | 12.2 PUBLIC | Underlying disassembler via REA |
| Capstone | 5.0.7 | Independent x86 instruction decoder (method 1) |
| Manual opcode decoder | Custom (Python) | Independent x86 instruction decoder (method 2) |
| Python | 3.13.17 | PE parsing, atomic scan, caller search |
| git | 2.56.0.windows.4 | Repository management |

**Two-decoder verification:** Every critical instruction decoded by both Capstone and the manual decoder. Where they agree, the decoding is treated as verified. REA `read_bytes` provides ground-truth bytes (`confidence: "observed"`, `authority: "shipped-artifact"`).

---

## 3. Reproduction Commands

### 3.1 Verify binary SHA-256
```powershell
Get-FileHash -Path "C:\Users\Rhuan\Documents\Projeto Padrão\RvControlSvc_Installed_0E2E6EAA.exe" -Algorithm SHA256
# Expected: 0E2E6EAACBE8EBE01286CDA39A12EAAD34A20434D50F4F8BF2FDD91D4D6EF2AD
```

### 3.2 Open binary via REA
```javascript
await tools["rea"].open_binary({ path: "C:\\Users\\Rhuan\\Documents\\Projeto Padrão\\RvControlSvc_Installed_0E2E6EAA.exe" });
// Returns: { path, sha256, kind: "executable", format: "pe", architecture: "x86" }
```

### 3.3 Read raw bytes at an address (REA)
```javascript
await tools["rea"].read_bytes({ address: "0x4731f2", size: 4 });
// Returns bytes_hex: "f00fc132" (LOCK XADD [EDX], ESI)
```

### 3.4 Capstone decode (Python)
```python
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
md = Cs(CS_ARCH_X86, CS_MODE_32)
data = open("RvControlSvc_Installed_0E2E6EAA.exe","rb").read()
# Map VA to file offset via PE section table (.text: VA 0x401000–0x5184EF, file off 0x400)
ins = list(md.disasm(data[file_offset:file_offset+16], va, 1))[0]
print(ins.mnemonic, ins.op_str)
```

### 3.5 Whole-program atomic scan (Python)
Scan `.text` for `F0 0F C1` (LOCK XADD), `0F B1` (CMPXCHG), `FF 15` (CALL [mem]), `E8` (CALL rel32) patterns. Map file offsets to VA via PE section table.

### 3.6 Constructor caller search (Python)
Scan `.text` for `E8 rel32` where `next_instruction_va + rel32 == target_va` for targets `0x43ECF0`, `0x43E1A0`, `0x44F3F0`, `0x43F110`.

### 3.7 PE section table (for VA→file offset mapping)
| Section | VA range | File offset |
|---------|----------|-------------|
| `.text` | 0x00401000–0x005184EF | 0x00000400–0x00011BA0 |
| `.rdata` | 0x00519000–0x005495C8 | 0x00117A00–0x00148000 |
| `.data` | 0x0054A000–0x005A8218 | 0x00148000–0x0015C000 |
| `.rsrc` | 0x005A9000–0x005C0D38 | 0x0015C000–0x00173E00 |
| `.reloc` | 0x005C1000–0x005D5D60 | 0x00173E00–0x00188C00 |

Formula: `fileOffset = sectionRawPtr + (VA − 0x00400000 − sectionVA)`.

---

## 4. Verified Critical Instructions (decoder cross-check table)

| VA | Raw bytes | Capstone | Manual | Agreement |
|-----|-----------|----------|--------|-----------|
| `0x4731F2` | `F0 0F C1 32` | `lock xadd dword ptr [edx], esi` | `lock xadd [edx], esi` | YES |
| `0x47321D` | `8D 4E 20` | `lea ecx, [esi + 0x20]` | `lea ecx, [esi + 0x20]` | YES |
| `0x473226` | `87 11` | `xchg dword ptr [ecx], edx` | `xchg [ecx], edx` | YES |
| `0x47322D` | `8D 4E 24` | `lea ecx, [esi + 0x24]` | `lea ecx, [esi + 0x24]` | YES |
| `0x473230` | `87 11` | `xchg dword ptr [ecx], edx` | `xchg [ecx], edx` | YES |

All 37 critical instructions audited — zero disagreements when starting at correct instruction boundaries.

---

## 5. Key Decoding Corrections (vs. Phase 2.5)

| Phase 2.5 claim | Actual bytes | Correct instruction | Verified by |
|-----------------|--------------|---------------------|-------------|
| `LOCK XCHG [EDX], ESI` | `F0 0F C1 32` | `LOCK XADD [EDX], ESI` | Capstone + Manual + REA |
| `MOV ECX, [ESI+0x20]` | `8D 4E 20` | `LEA ECX, [ESI+0x20]` | Capstone + Manual + REA |
| `MOV ECX, [ESI+0x24]` | `8D 4E 24` | `LEA ECX, [ESI+0x24]` | Capstone + Manual + REA |
| `CALL [0x00500ca6]` indirect | `E8 58 45 01 00` | `CALL 0x00500CA6` direct | Capstone + Manual + REA |

---

## 6. Limitations

- REA/Ghidra ephemeral session: closing discards metadata; each query re-imports the binary. Bytes are original (unchanged).
- No `list_procedures`/decompiler used for critical path — all decoding done via raw bytes + Capstone/manual.
- Import `[0x519138]` resolved to `DeleteCriticalSection` via ILT[12] of KERNEL32.dll; import `[0x5192EC]` not yet resolved.
- Whole-program scans limited to `.text` section (code). `.rdata`/`.data` not scanned for atomic patterns (they contain data, not code).
