import json
import sys

FUNC = "/home/pedrodroks/Downloads/radmin/ghidra_export/functions.jsonl"
bodies = []
with open(FUNC) as fh:
    for line in fh:
        if not line.strip():
            continue
        f = json.loads(line)
        try:
            bodies.append((int(f["body_min"], 16), int(f["body_max"], 16), f["entry"], f["name"]))
        except Exception:
            pass
bodies.sort()

def find(va):
    lo, hi = 0, len(bodies) - 1
    res = []
    while lo <= hi:
        mid = (lo + hi) // 2
        bmin, bmax, entry, name = bodies[mid]
        if va < bmin:
            hi = mid - 1
        elif va > bmax:
            lo = mid + 1
        else:
            res.append((entry, name))
            lo = mid + 1
            continue
    return res

for arg in sys.argv[1:]:
    va = int(arg, 16)
    owners = find(va)
    print(f"{va:08x} -> {', '.join(f'{e} ({n})' for e, n in owners) if owners else 'NOT INSIDE ANY EXPORTED FUNCTION'}")
