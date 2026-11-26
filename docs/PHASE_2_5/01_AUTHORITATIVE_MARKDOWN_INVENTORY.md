# Phase 2.5 Stage 01 — Authoritative Markdown Inventory

**Classification: VERIFIED** (all counts from `git ls-files` against commit `6be002076beeb898a338c18c2eb1d263089c25ee`)

## 1. Purpose

Resolve the Markdown file count discrepancy between Phase 2.4 reports:
- Report 01 claimed 92 Markdown files.
- Report 19 claimed 89 reviewed Markdown files.
- Category totals in Report 01 appeared to add to 118, not 92.

This report uses `git ls-files` against the actual commit to produce authoritative counts.

## 2. Inventory Method

Command used:
```
git ls-files '*.md' | grep -v '^\.git/'
```

Executed against commit `6be002076beeb898a338c18c2eb1d263089c25ee` on branch `phase-2-4-runtime-object-lifecycle-audit`.

No file is counted twice. No untracked or uncommitted files are included unless explicitly noted.

## 3. Authoritative Counts by Directory

| Directory | Tracked `.md` Files |
|-----------|--------------------|
| Root (`/`) | 2 (AGENTS.md, README.md) |
| `docs/` | 57 |
| `docs/reverse-engineering/round-02/` | 13 |
| `opencode-linux/PHASE_2_3/` | 26 |
| `opencode-linux/PHASE_2_4/` | 20 |
| **Total tracked** | **118** |

## 4. Discrepancy Resolution

| Source | Claimed Count | Actual Count | Resolution |
|--------|--------------|--------------|------------|
| Phase 2.4 Report 01 | 92 | 118 | Report 01 undercounted — it omitted some categories and used non-overlapping groupings that didn't match the actual tree |
| Phase 2.4 Report 19 | 89 | 118 | Report 19 undercounted — similar omission of categories |
| Report 01 category sum | 118 | 118 | The category sum in Report 01 was correct (118) but the headline claim of 92 was wrong |

**Root cause:** The Phase 2.4 reports claimed 92/89 but the actual git tree contains 118 tracked `.md` files. The 92 figure appears to have excluded `opencode-linux/PHASE_2_4/` (20 files) and possibly some `docs/` subdirectories. 118 - 20 (PHASE_2_4) - 26 (PHASE_2_3) = 72 files in root/docs/round-02, which matches: 2 + 57 + 13 = 72.

## 5. Untracked Markdown Files

At branch creation time, the working tree was clean (0 untracked files). After Phase 2.5 reports are created, they will appear as untracked until committed.

## 6. Commit SHA Used for Inventory

`6be002076beeb898a338c18c2eb1d263089c25ee`

## 7. Full File Listing

### Root (2 files)
- `AGENTS.md`
- `README.md`

### docs/ (57 files)
`CONTROL_HANDSHAKE_SPEC.md`, `CONTROL_PROTOCOL.md`, `CRYPTO_AES_CONSUMER_TRACE.md`, `CRYPTO_AES_KEY_INSTALLATION_TRACE.md`, `CRYPTO_AES_KEY_SPLIT_TRACE.md`, `CRYPTO_CONTROL_KEY_LIFECYCLE.md`, `CRYPTOGRAPHIC_OVERVIEW.md`, `CRYPTO_KEY_LIFECYCLE_GAP_ANALYSIS.md`, `CRYPTO_MD5_ANALYSIS.md`, `CRYPTO_PHASE_10_10_RECONCILIATION.md`, `CRYPTO_PHASE_10_11_RECONSTRUCTION.md`, `CRYPTO_PHASE_10_12_BLOCKER_RESOLUTION.md`, `CRYPTO_PHASE_10_13_DYNAMIC_ANALYSIS_PLAN.md`, `CRYPTO_PHASE_10_13_P0_BLOCKER_RESOLUTION.md`, `CRYPTO_PHASE_10_14_IDENTITY_REMEDIATION_AND_PASSWORD_INVESTIGATION.md`, `CRYPTO_PHASE_10_15_STATIC_PASSWORD_ENCODING_RECONSTRUCTION.md`, `CRYPTO_PHASE_10_16_RSA_AND_SRP_PROOF_RECONSTRUCTION.md`, `CRYPTO_PHASE_10_17_M1_REMEDIATION_AND_RSA_CALLER_TRACE.md`, `CRYPTO_PHASE_10_18_M2_BYTE_LEVEL_AND_RSA_DATA_FLOW.md`, `CRYPTO_PHASE_10_19_M2_BIGNUM_AND_RSA_IAT_AUDIT.md`, `CRYPTO_PHASE_10_20_DYNAMIC_ANALYSIS_READINESS.md`, `CRYPTO_PHASE_10_3_10_5_CONSOLIDATED_REPORT.md`, `CRYPTO_PHASE_10_3_10_5_OPEN_QUESTIONS.md`, `CRYPTO_PHASE_10_5_COMPATIBILITY_AUDIT.md`, `CRYPTO_PHASE_10_5_REMEDIATION.md`, `CRYPTO_PHASE_10_5_VALIDATION.md`, `CRYPTO_RSA_ANALYSIS.md`, `CRYPTO_RSA_KEY_PROVENANCE.md`, `CRYPTO_RSESSION_ANALYSIS.md`, `CRYPTO_RSESSION_KEY_LIFECYCLE.md`, `CRYPTO_RUST_GAP_ANALYSIS.md`, `CRYPTO_SRP_ANALYSIS.md`, `CRYPTO_SRP_DISPATCH_AND_DATA_FLOW_AUDIT.md`, `CRYPTO_SRP_EFFECTIVE_IMPLEMENTATION.md`, `CRYPTO_SRP_INTEGER_SERIALIZATION_AUDIT.md`, `CRYPTO_SRP_PASSWORD_ENCODING.md`, `CRYPTO_SRP_SCRAMBLING_VERIFICATION.md`, `CRYPTO_SYMMETRIC_ENCRYPTION.md`, `CRYPTO_UNRESOLVED_QUESTIONS.md`, `KEY_EXCHANGE_ANALYSIS.md`, `PCAP_FLOW_MAP.md`, `PCAP_FORENSICS_DEEP_DIVE.md`, `PCAP_FORENSICS_REPORT.md`, `PCAP_IMPLEMENTATION_READINESS.md`, `PCAP_MESSAGE_CATALOG.md`, `PCAP_PREVIOUS_REPORT_CORRECTIONS.md`, `PCAP_THIRD_ROUND_AUDIT.md`, `PHASE_3_CONTROL_MESSAGE_CATALOG.md`, `PROTOCOL_SPEC.md`, `REFERENCE_PROJECT_ANALYSIS.md`, `REVERSE_ENGINEERING.md`

### docs/reverse-engineering/round-02/ (13 files)
`01-handshake.md`, `02-cryptography.md`, `03-tlv-catalog.md`, `04-authentication-networks.md`, `05-tcp-relay.md`, `06-p2p-nat.md`, `07-teredo.md`, `08-windows-ipc.md`, `09-ndis-driver.md`, `10-architecture.md`, `EVIDENCE_INDEX.md`, `IMPLEMENTATION_READINESS.md`, `UNRESOLVED_QUESTIONS.md`

### opencode-linux/PHASE_2_3/ (26 files)
23 reports (00-23) + 3 checkpoints (CHECKPOINT_00, CHECKPOINT_01, CHECKPOINT_02)

### opencode-linux/PHASE_2_4/ (20 files)
20 reports (00-19)