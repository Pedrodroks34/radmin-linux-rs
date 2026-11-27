import json
import re

REF = "/home/pedrodroks/Downloads/radmin/ghidra_export/references.jsonl"
PETSV = "/home/pedrodroks/Downloads/radmin/analysis_workspace/validation/import_iat_map.txt"

pe = {}
with open(PETSV) as fh:
    for line in fh:
        m = re.match(r"^([0-9a-f]{8})\s+([^\s]+)", line.strip())
        if m:
            pe[m.group(1)] = m.group(2)

ind = []
with open(REF) as fh:
    for line in fh:
        r = json.loads(line)
        if r["reference_type"] == "INDIRECTION":
            ff = r.get("from_function") or ""
            if ".DLL::" in ff:
                ind.append((r["from"], r["to"], ff))

print(f"INDIRECTION stubs with DLL:: name: {len(ind)}")
mismatch = 0
for frm, slot, ff in ind:
    slot_norm = slot.lstrip("0").zfill(8)
    names = {pe.get(slot_norm), pe.get(slot_norm.lstrip("0"))}
    pe_name = pe.get(slot_norm) or pe.get(slot.lstrip("0"))
    ok = pe_name == ff
    status = "MATCH" if ok else "MISMATCH"
    if not ok:
        mismatch += 1
    print(f"  thunk@{frm}  IAT={slot_norm}  export-name={ff}  pe-name={pe_name}  [{status}]")

print()
print("mismatches:", mismatch)
