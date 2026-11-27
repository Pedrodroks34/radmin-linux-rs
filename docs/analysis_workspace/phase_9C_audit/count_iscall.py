import json
import os
import re
from collections import Counter

ROOT = "/home/pedrodroks/Downloads/radmin"
REF = ROOT + "/ghidra_export/references.jsonl"
LISTING = ROOT + "/ghidra_export/listing"

LINE_RE = re.compile(r"^([0-9A-Fa-f]{8})\s{2,}([0-9A-F]+(?:\s+[0-9A-F]+)*)\s{2,}(\S.*)$")
asm_vas = set()
with os.scandir(LISTING) as it:
    for entry in it:
        if entry.name.endswith(".asm"):
            with open(entry.path, errors="ignore") as fh:
                for line in fh:
                    m = LINE_RE.match(line.rstrip("\n"))
                    if m:
                        asm_vas.add(int(m.group(1), 16))

c_uncond_by_dir = Counter()
c_uncond_line_status = Counter()
c_uncond_direct_kind = Counter()
c_uncond_tail_jmp_by_dir = Counter()
c_uncond_direct_call_by_dir = Counter()
c_comp_term_dir = Counter()
c_comp_call_line_status = Counter()
c_comp_call_target_kind = Counter()
c_iscall_direction = Counter()
c_iscall_from_null = Counter()
total = 0

with open(REF) as fh:
    for line in fh:
        rec = json.loads(line)
        if not rec["is_call"]:
            continue
        total += 1
        rt = rec["reference_type"]
        d = rec["direction"]
        to = rec["to"]
        va = int(rec["from"], 16) if re.fullmatch(r"[0-9a-fA-F]{8}", rec["from"]) else None
        has_line = va in asm_vas if va is not None else False

        c_iscall_direction[d] += 1
        if rec.get("from_function") is None:
            c_iscall_from_null[rt] += 1

        if rt == "UNCONDITIONAL_CALL":
            c_uncond_by_dir[d] += 1
            if not has_line:
                c_uncond_line_status[d] += 1
            else:
                pass
        elif rt == "COMPUTED_CALL":
            c_comp_call_line_status["with_line" if has_line else "no_line"] += 1
            if to.startswith("EXTERNAL:"):
                c_comp_call_target_kind["EXTERNAL_import"] += 1
            elif re.fullmatch(r"[0-9a-f]{8}", to):
                c_comp_call_target_kind["hex32_internal"] += 1
            else:
                c_comp_call_target_kind["other"] += 1
        elif rt == "COMPUTED_CALL_TERMINATOR":
            c_comp_term_dir[d] += 1

print("is_call=true total:", total)
print("by direction:", dict(c_iscall_direction))
print("UNCONDITIONAL_CALL by direction:", dict(c_uncond_by_dir))
print("UNCONDITIONAL_CALL with NO listing line (by direction):", dict(c_uncond_line_status))
print("COMPUTED_CALL line status:", dict(c_comp_call_line_status))
print("COMPUTED_CALL target kinds (all):", dict(c_comp_call_target_kind))
print("COMPUTED_CALL_TERMINATOR by direction:", dict(c_comp_term_dir))
print("is_call=true records with from_function=null, by type:", dict(c_iscall_from_null))
