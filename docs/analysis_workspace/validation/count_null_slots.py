slots = sorted(int(l.strip(), 16) for l in open("/home/pedrodroks/Downloads/radmin/analysis_workspace/validation/iat_slots.txt"))
start, end = 0x00517000, 0x0051753C
have = set(slots)
missing = [f"{v:08x}" for v in range(start, end, 4) if v not in have]
print("directory slots:", (end - start) // 4)
print("decoded:", len(slots))
print("unused/null slots:", len(missing), missing)
