# Phase 2.6 Stage 01 — Environment and Binary Validation

**Classification: PROVEN** — environment, repository, branch, binary identity, and PE architecture all verified against the actual machine and executable.

---

## 1. Actual Operating System and Architecture (Host)

The OpenCode execution environment is **Windows**, not Linux.

| Property | Value | Evidence |
|----------|-------|----------|
| Host OS | Microsoft Windows 10 Pro | `Get-ComputerInfo` OsName |
| Host OS version | 10.0.19045 (20H2) | `Get-ComputerInfo` OsVersion |
| Host OS architecture | 64-bit | `Get-ComputerInfo` OsArchitecture |
| Host processor | AMD64 (x86-64) | `$env:PROCESSOR_ARCHITECTURE` |

**Important:** The host is x64, but the **target executable is PE32 x86**. Host architecture ≠ target architecture. All analysis below targets the PE32 x86 executable.

---

## 2. Repository Identity and State

| Property | Value |
|----------|-------|
| Canonical repository URL | `https://github.com/Pedrodroks34/radmin-linux-rs.git` |
| Clone path | `C:\Users\Rhuan\Documents\Projeto Padrão\radmin-linux-rs` |
| Remote `origin` | `https://github.com/Pedrodroks34/radmin-linux-rs.git` (fetch and push) — verified via `git remote -v` |
| Current branch | `phase-2-6-instruction-decoding-audit` |
| Current HEAD | `1c30faec5ad780f283e5058db0c49e70f546f9c5` (Phase 2.5 commit) |
| Previous Phase 2.5 commit | `81f984af6068a520234638430ed537fd01376b7c` — verified present in history |
| Previous Phase 2.5 branch | `phase-2-5-static-forensics` — verified present in `git branch -a` |
| Working-tree status | CLEAN (no staged, unstaged, or untracked changes) |
| Phase 2.5 report directory | Now at `docs/PHASE_2_5/` (20 reports, moved from `opencode-windows/PHASE_2_5/`) |

Git safety restrictions observed: no `git reset --hard`, `git clean`, force push, or destructive cleanup. No Rust source files modified.

---

## 3. Target Binary Identity

Three copies of the binary exist on the machine; all three hash identically.

| Copy path | SHA-256 | Matches expected? |
|-----------|---------|-------------------|
| `C:\Users\Rhuan\Documents\Projeto Padrão\RvControlSvc_Installed_0E2E6EAA.exe` | `0E2E6EAACBE8EBE01286CDA39A12EAAD34A20434D50F4F8BF2FDD91D4D6EF2AD` | **YES** |
| `C:\Users\Rhuan\Desktop\RvControlSvc_Installed.exe` | `0E2E6EAACBE8EBE01286CDA39A12EAAD34A20434D50F4F8BF2FDD91D4D6EF2AD` | **YES** |
| `C:\Users\Rhuan\ghidra\ghidra_12.2_PUBLIC\Ghidra\RvControlSvc_Installed.exe` | `0E2E6EAACBE8EBE01286CDA39A12EAAD34A20434D50F4F8BF2FDD91D4D6EF2AD` | **YES** |

Expected SHA-256 (Section 1): `0e2e6eaacbe8ebe01286cda39a12eaad34a20434d50f4f8bf2fdd91d4d6ef2ad` — **MATCH** (case-insensitive).

---

## 4. PE Architecture (Target — Verified via REA/Ghidra and direct PE parse)

REA `open_binary` result confirms:
- Format: **PE**
- Architecture: **x86** (PE32, 32-bit)
- SHA-256: `0e2e6eaacbe8ebe01286cda39a12eaad34a20434d50f4f8bf2fdd91d4d6ef2ad`

Direct PE header parse confirms:
| Property | Value |
|----------|-------|
| Format | PE32 (magic 0x010B) |
| Machine | x86 (0x014C / 332) |
| ImageBase | 0x00400000 |
| AddressOfEntryPoint | 0x000E794C |
| SectionAlignment | 0x00001000 |
| FileAlignment | 0x00000200 |
| SizeOfImage | 0x001948E8 |
| NumberOfSections | 5 (`.text`, `.rdata`, `.data`, `.rsrc`, `.reloc`) |

---

## 5. Analysis Integration — REA/Ghidra Status

REA (Ghidra 12.2 provider) is **connected and functional**.

| Tool | Status | Used? |
|------|--------|-------|
| REA `open_binary` | FUNCTIONAL — binary opened, SHA-256 verified | Yes |
| REA `read_bytes` | FUNCTIONAL — reads raw bytes at any VA | Yes (all critical instructions) |
| REA `close_binary` | FUNCTIONAL | Yes |
| Ghidra version | 12.2 (via REA provider) | Yes |
| Capstone | 5.0.7 (Python, independent decoder) | Yes (cross-verification) |
| Manual opcode decoder | Custom (second independent method) | Yes (cross-verification) |
| REA `list_jeb_units` | NOT AVAILABLE (JEB MCP server not running) | No |
| pyghidra | Not installed in system Python | No |

**Two-decoder verification:** Every critical instruction in this phase is decoded by both Capstone 5.0.7 and a manual opcode decoder, with results cross-checked. Where they agree, the decoding is treated as verified.

---

## 6. Directory Convention

Because the actual execution environment is **Windows**, Phase 2.6 reports are created under `opencode-windows/PHASE_2_6/`.
