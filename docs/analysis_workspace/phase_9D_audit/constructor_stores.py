import re
import sys
from collections import Counter

LISTING = "/home/pedrodroks/Downloads/radmin/ghidra_export/listing/00421410.asm"
STORE_RE = re.compile(r"^([0-9a-f]{8})\s+[0-9A-F]+\s+(MOV|MOVUPS|MOVQ|MOVAPD|MOVLPD|PUSH)\s+(.*)$")

offs = Counter()
stores = []
with open(LISTING) as fh:
    for line in fh:
        m = STORE_RE.match(line.rstrip())
        if not m:
            continue
        va, mnemonic, operands = m.groups()
        dm = re.search(r"\[(?:EAX|ECX|EDX|EBX|ESI|EDI|EBP) ?\+ (0x[0-9a-f]+)\]", operands)
        if dm:
            offs[(dm.group(1), mnemonic)] += 1
            stores.append((va, mnemonic, operands.strip()))
print("stores to [reg + off] in FUN_00421410:", len(stores))
for (off, mn), c in sorted(offs.items(), key=lambda kv: int(kv[0][0], 16)):
    print(f"  {off:>6}  {mn:<8} x{c}")
print()
print("all constructor stores:")
for va, mn, ops in stores:
    print(f"  {va}  {mn:<8} {ops}")
