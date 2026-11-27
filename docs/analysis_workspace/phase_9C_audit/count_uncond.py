import json
import os
import re
from collections import Counter

ROOT = "/home/pedrodroks/Downloads/radmin"
REF = ROOT + "/ghidra_export/references.jsonl"
LISTING = ROOT + "/ghidra_export/listing"

LINE_RE = re.compile(r"^([0-9A-Fa-f]{8})\s{2,}([0-9A-F]+(?:\s+[0-9A-F]+)*)\s{2,}(\S.*)$")
va_to_line = {}
with os.scandir(LISTING) as it:
    for entry in it:
        if entry.name.endswith(".asm"):
            with open(entry.path, errors="ignore") as fh:
                for line in fh:
                    m = LINE_RE.match(line.rstrip("\n"))
                    if m:
                        rest = m.group(3)
                        parts = rest.split(None, 1)
                        va_to_line[int(m.group(1), 16)] = (parts[0].upper(), parts[1] if len(parts) > 1 else "")

kind_dir = Counter()
kind_total = Counter()
with open(REF) as fh:
    for line in fh:
        rec = json.loads(line)
        if rec["reference_type"] != "UNCONDITIONAL_CALL":
            continue
        va = rec["from"]
        try:
            iva = int(va, 16)
        except ValueError:
            kind_total["from_not_hex"] += 1
            continue
        info = va_to_line.get(iva)
        if info is None:
            kind_total["no_line"] += 1
            kind_dir[f"no_line|{rec['direction']}"] += 1
            continue
        m, ops = info
        is_direct_hex = re.fullmatch(r"0x[0-9a-fA-F]{8}", ops) is not None
        if m == "CALL":
            kind = "E8_direct_call"
        elif m == "JMP" and is_direct_hex:
            kind = "E9_tail_jmp"
        elif m == "JMP":
            kind = "JMP_other"
        else:
            kind = f"OTHER_{m}"
        kind_total[kind] += 1
        kind_dir[f"{kind}|{rec['direction']}"] += 1

print("UNCONDITIONAL_CALL by instruction kind:", dict(kind_total))
print()
for k, v in sorted(kind_dir.items()):
    print(" ", k, v)
