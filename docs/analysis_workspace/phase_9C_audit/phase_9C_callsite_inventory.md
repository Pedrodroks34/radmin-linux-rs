# Phase 9C — Callsite Inventory (rebuilt from scratch)

**Method.** Every callsite record in `references.jsonl` targeting the three functions was collected via `xref.py callers` (i.e., any `UNCONDITIONAL_CALL` / `COMPUTED_CALL` / `COMPUTED_CALL_TERMINATOR` record whose `to` equals the target, regardless of `direction`), then verified against the instruction line at the same VA in `ghidra_export/listing/<caller-file>.asm`. Every site is logged exactly once. Every instruction is a direct `CALL 0x…` (`E8 rel32`). No `JMP`-tail, no computed call, no terminator appears among these 38 sites.

Legend: `caller` = `from_function`; `refs` = the single matching `references.jsonl` record (all present); `bytes` = raw opcode bytes from the listing; `reach.` = revalidated reachability classification (see `phase_9C_blocked_path_revalidation.md`). "Incoming/outgoing" indicates which side of the edge Ghidra logged; both appear for this export (see count reconciliation).

## 1. `FUN_0041e220` — 15 callsites / 14 unique callers

Listing confirm: all are `E8 xx xx xx xx  CALL 0x0041e220`. Reference records: 10 × `outgoing_from_function`, 5 × `incoming_to_function_entry`; each callsite logged exactly once.

| # | Caller | Callsite | Bytes | Target (E8-rel resolved) | refs record | Reachability (Phase 9C) |
|---|--------|----------|-------|--------------------------|-------------|------------------------|
| 1 | FUN_00419e20 | 00419e9b | `E880430000` | 0041e220 ✓ | outgoing | BLOCKED UNDER EXPLICIT ASSUMPTIONS (via FUN_00422f20 gate) |
| 2 | FUN_0041a6d0 | 0041a739 | `E8E23A0000` | 0041e220 ✓ | outgoing | BLOCKED UNDER EXPLICIT ASSUMPTIONS (via FUN_004230c0 gate) |
| 3 | FUN_0041a6d0 | 0041a768 | `E8B33A0000` | 0041e220 ✓ | outgoing | BLOCKED UNDER EXPLICIT ASSUMPTIONS (same gate) |
| 4 | FUN_0041ae30 | 0041b05a | `E8C1310000` | 0041e220 ✓ | outgoing | CONDITIONAL |
| 5 | FUN_0041b090 | 0041b125 | `E8F6300000` | 0041e220 ✓ | outgoing | CONDITIONAL |
| 6 | FUN_0041b140 | 0041b1cc | `E84F300000` | 0041e220 ✓ | outgoing | CONDITIONAL |
| 7 | FUN_0041b2f0 | 0041b370 | `E8AB2E0000` | 0041e220 ✓ | outgoing | CONDITIONAL |
| 8 | FUN_0041bb40 | 0041bd36 | `E8E5240000` | 0041e220 ✓ | outgoing | CONDITIONAL |
| 9 | FUN_0041bd70 | 0041c03a | `E8E1210000` | 0041e220 ✓ | outgoing | CONDITIONAL |
| 10 | FUN_0041df70 | 0041e025 | `E8F6010000` | 0041e220 ✓ | outgoing | CONDITIONAL |
| 11 | FUN_0041f710 | 0041f80e | `E80DEAFFFF` | 0041e220 ✓ | incoming | CONDITIONAL |
| 12 | FUN_0041fa80 | 0041fc6e | `E8ADE5FFFF` | 0041e220 ✓ | incoming | CONDITIONAL |
| 13 | FUN_00420b80 | 00420c7b | `E8A0D5FFFF` | 0041e220 ✓ | incoming | UNKNOWN (0 incoming refs) |
| 14 | FUN_0041f110 | 0041f3b1 | `E86AEEFFFF` | 0041e220 ✓ | incoming | UNKNOWN (0 incoming refs) |
| 15 | FUN_0041f450 | 0041f6dd | `E83EEBFFFF` | 0041e220 ✓ | incoming | CONDITIONAL |

- Unique callers: **14** — `FUN_0041a6d0` (×2, sites #2, #3) + 13 others.
- Callers with zero incoming `is_call=true` references: `FUN_00420b80`, `FUN_0041f110` (both UNKNOWN).
- Prior-report comparison: **matches 15/14** (Phase 8W/8X inventories).

## 2. `FUN_0041e280` — 22 callsites / 21 unique callers

Listing confirm: all are `E8 xx xx xx xx  CALL 0x0041e280`. Reference records: 13 × `outgoing_from_function`, 9 × `incoming_to_function_entry`; each callsite logged exactly once.

| # | Caller | Callsite | Bytes | Target | refs record | Reachability (Phase 9C) |
|---|--------|----------|-------|--------|-------------|------------------------|
| 1 | FUN_00419b30 | 00419bce | `E8AD460000` | 0041e280 ✓ | outgoing | CONDITIONAL |
| 2 | FUN_0041a640 | 0041a6b2 | `E8C93B0000` | 0041e280 ✓ | outgoing | CONDITIONAL |
| 3 | FUN_0041a6d0 | 0041a7f1 | `E88A3A0000` | 0041e280 ✓ | outgoing | BLOCKED UNDER EXPLICIT ASSUMPTIONS (via FUN_004230c0 gate) |
| 4 | FUN_0041aa40 | 0041aaee | `E88D370000` | 0041e280 ✓ | outgoing | CONDITIONAL |
| 5 | FUN_0041b1e0 | 0041b2a1 | `E8DA2F0000` | 0041e280 ✓ | outgoing | CONDITIONAL |
| 6 | FUN_0041c300 | 0041c3fd | `E87E1E0000` | 0041e280 ✓ | outgoing | CONDITIONAL |
| 7 | FUN_0041c870 | 0041c8df | `E89C190000` | 0041e280 ✓ | outgoing | CONDITIONAL |
| 8 | FUN_0041d380 | 0041d438 | `E8430E0000` | 0041e280 ✓ | outgoing | CONDITIONAL |
| 9 | FUN_0041d380 | 0041d468 | `E8130E0000` | 0041e280 ✓ | outgoing | CONDITIONAL |
| 10 | FUN_0041d6e0 | 0041d757 | `E8240B0000` | 0041e280 ✓ | outgoing | CONDITIONAL |
| 11 | FUN_0041d770 | 0041d87e | `E8FD090000` | 0041e280 ✓ | outgoing | CONDITIONAL |
| 12 | FUN_0041de60 | 0041dec2 | `E8B9030000` | 0041e280 ✓ | outgoing | CONDITIONAL |
| 13 | FUN_0041e1f0 | 0041e20d | `E86E000000` | 0041e280 ✓ | outgoing | CONDITIONAL (wrapper; 3 known callers of the wrapper: FUN_0041ae30@0041b043, FUN_0041bb40@0041bc76, FUN_0041bd70@0041bed2) |
| 14 | FUN_0041e360 | 0041e457 | `E824FEFFFF` | 0041e280 ✓ | incoming | CONDITIONAL |
| 15 | FUN_0041f450 | 0041f67e | `E8FDEBFFFF` | 0041e280 ✓ | incoming | CONDITIONAL |
| 16 | FUN_00422840 | 004229d9 | `E8A2B8FFFF` | 0041e280 ✓ | incoming | CONDITIONAL |
| 17 | FUN_00422e00 | 00422ed0 | `E8ABB3FFFF` | 0041e280 ✓ | incoming | CONDITIONAL |
| 18 | FUN_004230c0 | 00423239 | `E842B0FFFF` | 0041e280 ✓ | incoming | BLOCKED UNDER EXPLICIT ASSUMPTIONS (same gate) |
| 19 | FUN_00423980 | 00423ad2 | `E8A9A7FFFF` | 0041e280 ✓ | incoming | CONDITIONAL |
| 20 | FUN_004240f0 | 0042411c | `E85FA1FFFF` | 0041e280 ✓ | incoming | CONDITIONAL |
| 21 | FUN_0042f810 | 0042f889 | `E8F2E9FEFF` | 0041e280 ✓ | incoming | CONDITIONAL |
| 22 | FUN_00430510 | 0043057d | `E8FEDCFEFF` | 0041e280 ✓ | incoming | CONDITIONAL |

- Unique callers: **21** — `FUN_0041d380` (×2) + 19 others.
- Prior-report comparison: **Phase 8X (22/21) CONFIRMED**; **`relatorio_parte8R_caller_table.md` §5.1 ("22 distinct caller functions, no function calls it twice") is WRONG** — corrected here.
- Wrapper note: `FUN_0041e1f0` (#13, is the wrapper) is called from exactly 3 sites (`0041b043`, `0041bc76`, `0041bed2`), all `UNCONDITIONAL_CALL`, verified.

## 3. `FUN_00416650` — 1 callsite / 1 unique caller

| # | Caller | Callsite | Bytes | Target | refs record |
|---|--------|----------|-------|--------|-------------|
| 1 | FUN_00415300 | 00415585 | `E8C6100000` | 00416650 ✓ | outgoing |

- Wrapper note: `FUN_00416650` calls `FUN_0041e1f0`? No — verified: no outgoing refs to `FUN_0041e1f0` in its listing; its indirect chain is `CALL [EDX+0x0C]` (see `phase_9C_16650_pointer_chain.md`).
- Wrapper note 2: `FUN_00415300`'s callsite passes a freshly allocated Wait-ish object (see listing `00415300.asm:00415585` context).

## 4. Aggregate counts

| Target | Sites | Unique callers | Caller twice |
|---|---|---|---|
| FUN_0041e220 | 15 | 14 | FUN_0041a6d0 (2) |
| FUN_0041e280 | 22 | 21 | FUN_0041d380 (2) |
| FUN_00416650 | 1 | 1 | — |

All three inventories re-verified directly from raw `grep` on `references.jsonl` (independent of `xref.py`): `grep -E '"to":"0041e220".*(UNCONDITIONAL_CALL|COMPUTED_CALL|COMPUTED_CALL_TERMINATOR)"' | wc -l` → 15; same for e280 → 22; 16650 → 1.
