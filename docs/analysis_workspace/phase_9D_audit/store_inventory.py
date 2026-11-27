import re
import sys
from collections import Counter

LISTING = "/home/pedrodroks/Downloads/radmin/ghidra_export/listing"
STORE_RE = re.compile(r"^([0-9A-Fa-f]{8})\s+[0-9A-F]+\s+(MOV|MOVUPS|MOVQ|MOVAPD|MOVLPD|XCHG|AND|OR|ADD|SUB|XADD)\s+(.*)$")

for fn in sys.argv[1:]:
    path = f"{LISTING}/{fn}.asm"
    offs = Counter()
    stores = []
    with open(path) as fh:
        for line in fh:
            m = STORE_RE.match(line.rstrip())
            if not m:
                continue
            va, mn, ops = m.groups()
            dm = re.search(r"\[(?:EAX|ECX|EDX|EBX|ESI|EDI|EBP) ?\+ (0x[0-9a-f]+)\]", ops)
            if dm:
                offs[(dm.group(1), mn)] += 1
                if re.match(r"^(MOV|XCHG|MOVUPS)\s+(dword|xmmword) ptr \[(?:EAX|ECX|EDX|EBX|ESI|EDI)", ops) or ops.strip().startswith(("MOV ", "XCHG ")):
                    stores.append((va, mn, ops.strip()))
    print(f"### {fn} stores: {len(stores)}")
    for off, n in sorted(offs.items(), key=lambda kv: int(kv[0][0], 16)):
        print(f"  {off[0]:>6}  {off[1]:<8} x{n}")
