# Phase 2.5 Stage 01 — Environment and Repository Validation

**Classification: PROVEN** — all environment, repository, binary, and tool claims verified against the actual machine and the actual executable.

---

## 1. Actual Operating System and Architecture

The OpenCode execution environment is **Windows**, not Linux. The user's ChatGPT client OS is irrelevant; the machine running OpenCode is Windows.

| Property | Value | Evidence |
|----------|-------|----------|
| OS | Microsoft Windows 10 Pro | `Get-ComputerInfo` OsName |
| OS version | 10.0.19045 (2009 / 20H2) | `Get-ComputerInfo` OsVersion, WindowsVersion |
| OS architecture | 64-bit | `Get-ComputerInfo` OsArchitecture |
| Processor architecture | AMD64 (x86-64) | `$env:PROCESSOR_ARCHITECTURE` |
| Shell | PowerShell | Command interpreter in use |

**Directory convention applied:** Because the actual environment is **Windows**, Phase 2.5 reports are created under `opencode-windows/PHASE_2_5/` (not `opencode-linux/PHASE_2_5/`), per Section 1.1 of the phase mandate.

---

## 2. Repository Identity

| Property | Value |
|----------|-------|
| Canonical repository URL | `https://github.com/Pedrodroks34/radmin-linux-rs.git` |
| Clone path | `C:\Users\Rhuan\Documents\Projeto Padrão\radmin-linux-rs` |
| Remote `origin` | `https://github.com/Pedrodroks34/radmin-linux-rs.git` (fetch and push) — verified with `git remote -v` |
| Canonical owner account | `Pedrodroks34` |

An alternate clone `https://github.com/Pedrodroks34/radmin-vpn-linux-rs.git` was also probed in a temp scan directory; it contains identical content (same commit `92fafa0`, same branches). The canonical `radmin-linux-rs.git` clone is the one used for this phase. No other canonical clone exists on the machine.

---

## 3. Branch and Commit (Initial State)

Before any Phase 2.5 work, the repository was checked out to the expected Phase 2.4 commit.

| Property | Value |
|----------|-------|
| Base commit (initial SHA) | `6be002076beeb898a338c18c2eb1d263089c25ee` |
| Base commit subject | `docs: add Phase 2.4 runtime object lifecycle audit reports` |
| Expected Phase 2.4 commit present? | **YES** — `6be0020` exists in the canonical history |
| Expected Phase 2.4 branch present? | **YES** — `remotes/origin/phase-2-4-runtime-object-lifecycle-audit` |
| Default branch | `main` (tip `92fafa0`, which already contains a merged Phase 2.5) |
| Phase 2.5 merged into default? | **YES** — `main` contains merge `92fafa0` ("Merge pull request #13 ... phase-2-5-static-correction-runtime-readiness") |
| Working branch created for this phase | `phase-2-5-static-forensics` (based directly on `6be0020`) |
| Detached HEAD before branch | `6be0020` |

The phase branch is based on the canonical Phase 2.4 commit `6be0020`, **not** on `main` (which already contains a different Phase 2.5), so this phase represents independent verification rather than a re-tread of the merged work.

---

## 4. Working-Tree Preservation

- The clone was created with `git clone --no-checkout`, then `git checkout -f 6be0020` populated the worktree from the Phase 2.4 commit.
- No `git reset --hard`, `git clean -fd`, `git clean -fdx`, force-push, or broad deletion was used (all prohibited by Section 1.2).
- No pre-existing uncommitted user changes existed in this clone at checkout time (fresh clone).
- No Rust source files were modified at any point during this phase (verified in Section 11 of final validation).
- The Phase 2.4 reports under `opencode-linux/PHASE_2_4/` remain untouched in the tree.

---

## 5. Target Binary Identity and SHA-256

The target executable is `RvControlSvc_Installed.exe`. Three copies exist on the machine; all three hash identically.

| Copy path | SHA-256 | Matches expected? |
|-----------|---------|-------------------|
| `C:\Users\Rhuan\Desktop\RvControlSvc_Installed.exe` | `0E2E6EAACBE8EBE01286CDA39A12EAAD34A20434D50F4F8BF2FDD91D4D6EF2AD` | **YES** |
| `C:\Users\Rhuan\Documents\Projeto Padrão\RvControlSvc_Installed_0E2E6EAA.exe` | `0E2E6EAACBE8EBE01286CDA39A12EAAD34A20434D50F4F8BF2FDD91D4D6EF2AD` | **YES** |
| `C:\Users\Rhuan\ghidra\ghidra_12.2_PUBLIC\Ghidra\RvControlSvc_Installed.exe` | `0E2E6EAACBE8EBE01286CDA39A12EAAD34A20434D50F4F8BF2FDD91D4D6EF2AD` | **YES** |

Expected SHA-256 (Section 1): `0e2e6eaacbe8ebe01286cda39a12eaad34a20434d50f4f8bf2fdd91d4d6ef2ad` — **MATCH** (case-insensitive).

PE properties (verified by parsing the actual PE headers):

| Property | Value |
|----------|-------|
| File size | 1,619,320 bytes |
| Format | PE32 (magic 0x010B) |
| Machine | x86 (0x014C / 332) |
| ImageBase | 0x00400000 |
| AddressOfEntryPoint | 0x000E794C |
| SectionAlignment | 0x00001000 |
| FileAlignment | 0x00000200 |
| SizeOfImage | 0x001948E8 |
| NumberOfSections | 5 |

---

## 6. PE Section Table (verified from actual headers)

| # | Name | VirtualAddress (RVA) | VirtualSize | PointerToRawData | SizeOfRawData |
|---|------|----------------------|-------------|------------------|---------------|
| 0 | `.text` | 0x00001000 | 0x001174EF | 0x00000400 | 0x00117600 |
| 1 | `.rdata` | 0x00119000 | 0x000305C8 | 0x00117A00 | 0x00030600 |
| 2 | `.data` | 0x0014A000 | 0x0005E218 | 0x00148000 | 0x00014000 |
| 3 | `.rsrc` | 0x001A9000 | 0x00017D38 | 0x0015C000 | 0x00017E00 |
| 4 | `.reloc` | 0x001C1000 | 0x00014D60 | 0x00173E00 | 0x00014E00 |

Note: Section-header `VirtualAddress` fields are **RVAs**. VA = RVA + ImageBase (0x00400000). This distinction is central to the `0x00500CA6` correction (Report 06).

---

## 7. REA / Ghidra Availability

| Tool | Location | Status | Used? |
|------|----------|--------|-------|
| Ghidra 12.2 PUBLIC | `C:\Users\Rhuan\ghidra\ghidra_12.2_PUBLIC` | INSTALLED | Not launched (headless JEB MCP server not running) |
| pyghidra-mcp | `C:\Users\Rhuan\Documents\Projeto Padrão\pyghidra-mcp` | Source present; not installed in system Python | Not used |
| WinDbgX | `C:\Users\Users\Rhuan\AppData\Local\Microsoft\WindowsApps\WinDbgX.exe` | Store app present | Not used (static analysis sufficient) |
| REA MCP (JEB provider) | configured endpoint `http://127.0.0.1:8425/mcp` | NOT RUNNING (`capability_unavailable`) | Not used |
| Git | 2.56.0.windows.4 | FUNCTIONAL | Used |
| Python | 3.13.17 | FUNCTIONAL | Used for static PE/byte analysis |

**Analysis integration limitation:** The REA/JEB MCP provider is not running, and pyghidra is not installed in the system Python. Therefore no live Ghidra decompilation was performed. Static analysis was performed directly on the executable bytes using a Python PE parser (available equivalent), reading raw bytes at every claimed address. This is **more reliable** than decompiler interpretation because it reads the actual machine bytes, and every claimed pointer value below was independently re-read from the file.

Per Section 11: if Ghidra's current program is not the verified target binary, stop and load/select the correct program. No Ghidra program was loaded; all evidence is from the verified binary file `RvControlSvc_Installed.exe` (SHA-256 `0E2E6EA...`).

---

## 8. Evidence Location Conventions

All addresses in this phase are **virtual addresses (VA)** in the target process image (ImageBase 0x00400000) unless explicitly labelled RVA or file offset. Every pointer value reported as "verified" was read as 4 little-endian bytes at the corresponding VA, mapped through the PE section table to a file offset.
