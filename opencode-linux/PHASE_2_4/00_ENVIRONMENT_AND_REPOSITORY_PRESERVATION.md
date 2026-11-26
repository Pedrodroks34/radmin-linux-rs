# Phase 2.4 Stage 00 — Environment and Repository Preservation

**Classification: VERIFIED** (all environment facts directly observed)

## 1. Operating System

| Property | Value |
|----------|-------|
| OS | Linux |
| Distribution | Arch Linux (CachyOS) |
| Kernel | 7.3.5-2-cachyos |
| Architecture | x86_64 |
| User | rhuan |
| Working directory | /home/rhuan |

## 2. Canonical Repository

| Property | Value |
|----------|-------|
| URL | `https://github.com/Pedrodroks34/radmin-linux-rs.git` |
| Local path | `/home/rhuan/radmin-linux-rs/` |
| Remote `origin` | `https://github.com/Pedrodroks34/radmin-linux-rs.git` |
| Branch | `phase-2-4-runtime-object-lifecycle-audit` |
| Initial commit SHA | `90a1b2346e529dc4df1f216634098d5902238d2b` |
| Clone date | 2026-11-25 |

## 3. Repository State at Branch Creation

| Property | Value |
|----------|-------|
| Base branch | `main` (from `origin/main`) |
| Pre-existing modified tracked files | 0 (clean working tree at clone time) |
| Pre-existing untracked files | 0 (clean working tree at clone time) |
| Changes made by Phase 2.4 | Only new Markdown reports under `opencode-linux/PHASE_2_4/` |

## 4. Target Binary

| Property | Value |
|----------|-------|
| Path | `/home/rhuan/Desktop/opencode/RvControlSvc_Installed.exe` |
| SHA-256 | `0e2e6eaacbe8ebe01286cda39a12eaad34a20434d50f4f8bf2fdd91d4d6ef2ad` |
| Expected SHA-256 | `0e2e6eaacbe8ebe01286cda39a12eaad34a20434d50f4f8bf2fdd91d4d6ef2ad` |
| Match | YES |
| PE Format | PE32 |
| Architecture | x86 (32-bit) |
| ImageBase | 0x00400000 |
| SizeOfImage | 0x001D6000 |

Binary was NOT modified during Phase 2.4.

## 5. Analysis Environment

| Tool | Status |
|------|--------|
| REA MCP (Ghidra 12.2) | Connected and functional (verified in Phase 2.3) |
| Git | 2.56.1 |
| GitHub CLI (`gh`) | 2.106.0, authenticated as RhuanXDK |
| Java | Available (JAVA_HOME: /usr/lib/jvm/java-27-openjdk) |
| Windows debugger (WinDbg/x32dbg/x64dbg) | NOT available (Linux environment) |
| Live Windows VM | NOT available |
| Runtime debugging | NOT available — all Phase 2.4 analysis is static |

## 6. Phase 2.3 Reports Preserved

| Directory | File Count |
|-----------|------------|
| `opencode-linux/PHASE_2_3/` | 26 files (23 reports + 3 checkpoints) |

All Phase 2.3 reports were committed to the canonical repository on branch `phase-2-3-static-analysis-audit` and are present in the working tree.

## 7. Preservation Checklist

| Criterion | Status |
|-----------|--------|
| Canonical repository cloned | YES |
| Remote URL verified | YES |
| Branch created from `origin/main` | YES |
| Pre-existing changes preserved | YES (none existed at clone time) |
| Target binary unmodified | YES |
| No proprietary binaries committed | YES |
| No memory dumps committed | YES |
| No PCAP files committed | YES |
| No credentials committed | YES |

## 8. Workstream Limitations

- **No Windows runtime debugging available** — The environment is Linux only. No WinDbg, x32dbg, x64dbg, or Windows VM is configured.
- **All Phase 2.4 analysis is static** — REA/Ghidra static analysis only. Runtime-dependent questions (Q1, Q2, Q3, Q4, Q5, Q6 below) may remain BLOCKED unless static evidence is sufficient.
- **No process is running** — `RvControlSvc.exe` is not executing; no debugger can attach.