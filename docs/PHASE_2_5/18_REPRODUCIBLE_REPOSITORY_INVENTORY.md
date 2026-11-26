# Phase 2.5 Stage 18 — Reproducible Repository Inventory

**Classification: PROVEN** — all counts computed from the actual tracked Git tree at commit `6be0020` using `git ls-files` (not filesystem guesses). `.git` internals excluded. Counts use mutually exclusive, non-overlapping categories.

Cross-reference: `01_ENVIRONMENT_AND_REPOSITORY_VALIDATION.md`.

---

## 1. Commit Used

| Property | Value |
|----------|-------|
| Commit SHA | `6be002076beeb898a338c18c2eb1d263089c25ee` |
| Subject | `docs: add Phase 2.4 runtime object lifecycle audit reports` |
| Branch | `phase-2-5-static-forensics` (created from `6be0020`) |
| Repository | `https://github.com/Pedrodroks34/radmin-linux-rs.git` |
| Clone path | `C:\Users\Rhuan\Documents\Projeto Padrão\radmin-linux-rs` |

---

## 2. Tracked-File Counts (at commit `6be0020`, before adding Phase 2.5 reports)

All counts via `git ls-files` against the tracked tree. `.git` internals excluded.

| Metric | Count | Reproduction command |
|--------|-------|----------------------|
| Total tracked files | **164** | `git ls-files \| wc -l` |
| Total tracked Markdown (`.md`) | **112** | `git ls-files '*.md' \| wc -l` |
| Total tracked Rust source (`.rs`) | **32** | `git ls-files '*.rs' \| wc -l` |
| Tracked files under `src/` | 31 | `git ls-files 'src/*.rs' \| wc -l` |
| Tracked Rust source outside `src/` | 1 (`tests/integration_test.rs`) | `git ls-files '*.rs' \| grep -v '^src/' \| wc -l` |
| Untracked files (working tree, before commit) | **17** (Phase 2.5 reports 01–17) | `git ls-files --others --exclude-standard \| wc -l` |

---

## 3. Mutually Exclusive Directory Categories (tracked)

Categories do **not** overlap. Every tracked file appears in exactly one category below.

| Category | Path glob | File count | Markdown count | Non-MD count |
|----------|-----------|------------|----------------|--------------|
| Root files (no subdirectory) | `*` (depth 0) | 6 | 2 (`README.md`, `AGENTS.md`) | 4 (`Cargo.toml`, `Cargo.lock`, `LICENSE`, `.gitignore`) |
| GitHub workflow | `.github/workflows/rust.yml` | 1 | 0 | 1 |
| Top-level docs | `docs/*` | 79 | 64 | 15 (`.json`, `.md`-spec, etc.) |
| Phase 2.3 reports | `opencode-linux/PHASE_2_3/*` | 26 | 26 | 0 |
| Phase 2.4 reports | `opencode-linux/PHASE_2_4/*` | 20 | 20 | 0 |
| Rust source (`src/`) | `src/*.rs` | 31 | 0 | 31 |
| Tests | `tests/integration_test.rs` | 1 | 0 | 1 |
| **Total (tracked)** | | **164** | **112** | **52** |

**Cross-check:** 6 + 1 + 79 + 26 + 20 + 31 + 1 = **164** tracked files. Markdown: 2 + 64 + 26 + 20 = **112**. Non-MD: 4 + 1 + 15 + 0 + 0 + 31 + 1 = **52**. 112 + 52 = **164**. ✓

---

## 4. Phase 2.5 Reports (this phase) — to be added

| Directory | Planned count | Status at inventory time |
|-----------|---------------|--------------------------|
| `opencode-windows/PHASE_2_5/` | 20 | Reports 01–17 created (untracked); reports 18–20 being created |

After committing all 20 Phase 2.5 reports:
- New total tracked files: **164 + 20 = 184**
- New total Markdown: **112 + 20 = 132**
- New untracked count: **0** (after commit)

---

## 5. Why Historical Totals Differed (Section 14 of mandate)

Phase 2.4 reported contradictory totals (2 root files, 57 documents, 13 files under `docs/reverse-engineering/round-02`, 26 Phase 2.3 reports, 20 Phase 2.4 reports, 89 reviewed files, 92 total files). These do not reconcile because:
- Categories overlapped (e.g., "documents" may include Markdown under multiple directories).
- `docs/reverse-engineering/round-02` contains 13 files, but the broader `docs/` tree contains 79 files — different scopes were summed as if they were the same universe.
- Some counts were taken at different commits (e.g., before Phase 2.3/2.4 reports were moved from `docs/` to `opencode-linux/`).
- "Reviewed files" and "total files" mixed tracked and possibly untracked/ignored files.

This inventory uses a single commit (`6be0020`), mutually exclusive categories, and `git ls-files` so every count is reproducible and non-overlapping.

---

## 6. Reproduction Commands

Run from the repository root (`C:\Users\Rhuan\Documents\Projeto Padrão\radmin-linux-rs`) on commit `6be0020`:

```bash
# Total tracked files
git ls-files | wc -l                     # 164

# Total tracked Markdown
git ls-files '*.md' | wc -l               # 112

# Total tracked Rust source
git ls-files '*.rs' | wc -l               # 32

# Directory categories (mutually exclusive)
git ls-files '*'        | grep -v '/' | wc -l           # root files: 6
git ls-files '.github/*' | wc -l                    # github workflow: 1
git ls-files 'docs/*'   | wc -l                     # docs: 79
git ls-files 'docs/*.md' | wc -l                    # docs markdown: 64
git ls-files 'opencode-linux/PHASE_2_3/*' | wc -l   # P2.3: 26
git ls-files 'opencode-linux/PHASE_2_4/*' | wc -l   # P2.4: 20
git ls-files 'src/*.rs' | wc -l                     # src Rust: 31
git ls-files 'tests/*.rs' | wc -l                   # tests: 1

# Untracked (working tree)
git ls-files --others --exclude-standard | wc -l    # 17 before commit (reports 01-17)

# Category sum check
# 6 + 1 + 79 + 26 + 20 + 31 + 1 = 164
# 2 + 64 + 26 + 20 = 112 markdown
```

On Windows (PowerShell), replace `wc -l` with `Measure-Object -Line | Select-Object -ExpandProperty Lines`, and `grep -v '/'` with `Where-Object { $_ -notmatch '/' }`.
