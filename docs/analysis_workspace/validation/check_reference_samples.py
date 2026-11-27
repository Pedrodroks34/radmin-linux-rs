import json
import os
import re
from collections import Counter, defaultdict

ROOT = "/home/pedrodroks/Downloads/radmin"
LISTING = os.path.join(ROOT, "ghidra_export", "listing")
REF_JSONL = os.path.join(ROOT, "ghidra_export", "references.jsonl")
OUT_TXT = "/home/pedrodroks/Downloads/radmin/analysis_workspace/validation/reference_check_output.txt"
OUT_MISMATCH = "/home/pedrodroks/Downloads/radmin/analysis_workspace/validation/reference_check_mismatches.txt"

LINE_RE = re.compile(r"^([0-9A-Fa-f]{8})\s{2,}([0-9A-F]+(?:\s+[0-9A-F]+)*)\s{2,}(\S.*)$")

va_to_line = {}
bad_lines = 0
with os.scandir(LISTING) as it:
    for entry in it:
        if not entry.name.endswith(".asm"):
            continue
        with open(entry.path, errors="ignore") as fh:
            for line in fh:
                m = LINE_RE.match(line.rstrip("\n"))
                if not m:
                    bad_lines += 1
                    continue
                rest = m.group(3)
                parts = rest.split(None, 1)
                mnemonic = parts[0]
                operands = parts[1] if len(parts) > 1 else ""
                va_to_line[int(m.group(1), 16)] = (mnemonic.upper(), operands.strip())

cond_mnemonics = {
    "JZ", "JNZ", "JE", "JNE", "JA", "JAE", "JB", "JBE", "JG", "JGE", "JL", "JLE",
    "JC", "JNC", "JS", "JNS", "JO", "JNO", "JP", "JNP", "JPE", "JPO", "JECXZ",
    "LOOP", "LOOPE", "LOOPZ", "LOOPNE", "LOOPNZ",
}

type_mnemonic = defaultdict(Counter)
type_to_style = defaultdict(Counter)
mismatch_samples = []
counters = Counter()
total = 0

def add_mismatch(kind, rec, detail):
    counters[f"mismatch_{kind}"] += 1
    if len(mismatch_samples) < 60:
        mismatch_samples.append(
            f"{kind}: {rec['direction']} {rec['from']}->{rec['to']} type={rec['reference_type']} is_call={rec['is_call']} | {detail}"
        )

def contains_va(haystack, va_hex):
    return va_hex.lstrip("0") in haystack.lower()

with open(REF_JSONL) as fh:
    for line in fh:
        total += 1
        rec = json.loads(line)
        rt = rec["reference_type"]
        to = rec["to"]
        frm = rec["from"]
        is_call = rec["is_call"]

        va = None
        try:
            va = int(frm, 16)
        except (TypeError, ValueError):
            counters["from_not_hex"] += 1

        if re.fullmatch(r"Stack\[-?0x[0-9A-Fa-f]+\]", to):
            to_style = "stack"
        elif re.fullmatch(r"[0-9A-Fa-f]{8}", to):
            to_style = "hex32"
        else:
            to_style = "other"

        if rec["direction"] == "incoming_to_function_entry":
            if rec.get("from_function") is not None:
                counters["incoming_with_from_function_set"] += 1
            if rec.get("to_function") is None:
                counters["incoming_to_null_function"] += 1
        elif rec["direction"] == "outgoing_from_function":
            if rec.get("from_function") is None:
                counters["outgoing_from_function_null"] += 1
        else:
            counters[f"unknown_direction_{rec['direction']}"] += 1

        info = va_to_line.get(va) if va is not None else None
        if info is None:
            counters[f"no_listing_line_{rt}"] += 1
            continue

        mnemonic, operands = info
        type_mnemonic[rt][mnemonic] += 1
        type_to_style[rt][to_style] += 1
        m = mnemonic
        ops = operands.lower()

        if rt == "UNCONDITIONAL_CALL":
            direct_va = re.fullmatch(r"0x[0-9a-fA-F]{8}", operands)
            if m == "CALL" and direct_va:
                counters["uncond_call_direct"] += 1
            elif m == "JMP" and direct_va:
                counters["uncond_call_tail_jmp"] += 1
            else:
                add_mismatch("uncond_call", rec, f"mnemonic={m} operands={operands}")
            if not is_call:
                add_mismatch("uncond_call_iscall", rec, "is_call=false")
        elif rt == "COMPUTED_CALL":
            direct_va = re.fullmatch(r"0x[0-9a-fA-F]{8}", operands)
            if m == "CALL" and not direct_va:
                counters["computed_call_ok"] += 1
            elif m == "CALL":
                counters["computed_call_direct_typed"] += 1
                add_mismatch("computed_call_direct", rec, f"mnemonic={m} operands={operands}")
            else:
                add_mismatch("computed_call", rec, f"mnemonic={m} operands={operands}")
            if not is_call:
                add_mismatch("computed_call_iscall", rec, "is_call=false")
        elif rt == "COMPUTED_CALL_TERMINATOR":
            ok = m == "CALL" and "[" in operands
            counters["computed_call_term_ok" if ok else "mismatch_computed_call_term"] += 1
            if not ok:
                add_mismatch("computed_call_term", rec, f"mnemonic={m} operands={operands}")
        elif rt == "UNCONDITIONAL_JUMP":
            ok = m == "JMP" and "[" not in operands
            counters["uncond_jmp_ok" if ok else "mismatch_uncond_jmp"] += 1
            if not ok:
                add_mismatch("uncond_jmp", rec, f"mnemonic={m} operands={operands}")
        elif rt == "COMPUTED_JUMP":
            ok = m == "JMP" and "[" in operands
            counters["computed_jmp_ok" if ok else "mismatch_computed_jmp"] += 1
            if not ok:
                add_mismatch("computed_jmp", rec, f"mnemonic={m} operands={operands}")
        elif rt == "CONDITIONAL_JUMP":
            ok = m in cond_mnemonics
            counters["cond_jump_ok" if ok else "mismatch_cond_jump"] += 1
            if not ok:
                add_mismatch("cond_jump", rec, f"mnemonic={m} operands={operands}")
        else:
            if to_style == "hex32":
                if "FS:" in operands.upper():
                    counters[f"data_ref_fs_segment_{rt}"] += 1
                elif contains_va(ops, to):
                    counters[f"data_ref_textual_ok_{rt}"] += 1
                else:
                    counters[f"data_ref_dataflow_{rt}"] += 1
                    add_mismatch(f"dataflow_{rt}", rec, f"to={to} mnemonic={m} operands={operands}")
            elif to_style == "stack":
                if "EBP" in operands.upper() or "ESP" in operands.upper():
                    counters[f"data_ref_textual_ok_{rt}"] += 1
                else:
                    counters[f"stack_dataflow_{rt}"] += 1
                    add_mismatch(f"stackdataflow_{rt}", rec, f"to={to} mnemonic={m} operands={operands}")
            else:
                counters[f"data_ref_uncheckable_{rt}"] += 1

with open(OUT_TXT, "w") as fh:
    fh.write(f"total reference records checked: {total}\n")
    fh.write(f"listing lines indexed: {len(va_to_line)}\n")
    fh.write(f"unparseable listing lines: {bad_lines}\n\nCounters:\n")
    for k, v in sorted(counters.items()):
        fh.write(f"  {k}: {v}\n")
    fh.write("\nMnemonics observed per reference_type:\n")
    for rt in sorted(type_mnemonic):
        fh.write(f"  {rt} ({sum(type_mnemonic[rt].values())}):\n")
        for mn, c in type_mnemonic[rt].most_common():
            fh.write(f"    {mn}: {c}\n")
    fh.write("\n'to' value styles per reference_type:\n")
    for rt in sorted(type_to_style):
        fh.write(f"  {rt}: {dict(type_to_style[rt])}\n")

with open(OUT_MISMATCH, "w") as fh:
    fh.write("\n".join(mismatch_samples) + ("\n" if mismatch_samples else "NO MISMATCHES\n"))

print(open(OUT_TXT).read())
print("=== mismatch samples ===")
print(open(OUT_MISMATCH).read())
