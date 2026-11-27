import struct

PATH = "/home/pedrodroks/Downloads/radmin/claude-handoff/binaries/radmin_ext/RvControlSvc.exe"
IMAGE_BASE = 0x00400000

sections = []
with open(PATH, "rb") as fh:
    data = fh.read()

e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
coff_off = e_lfanew + 4
num_sections = struct.unpack_from("<H", data, coff_off + 2)[0]
size_opt = struct.unpack_from("<H", data, coff_off + 16)[0]
sec_off = coff_off + 20 + size_opt
for i in range(num_sections):
    name = data[sec_off:sec_off + 8].split(b"\0")[0].decode()
    vsize, vaddr, rawsize, rawoff = struct.unpack_from("<IIII", data, sec_off + 8)
    sections.append((name, IMAGE_BASE + vaddr, vaddr, vsize, rawoff, rawsize))
    sec_off += 40

def read_va(va, n):
    for name, va_base, rva, vsize, rawoff, rawsize in sections:
        if va_base <= va < va_base + max(vsize, rawsize):
            off = rawoff + (va - va_base)
            return data[off:off + n]
    raise ValueError(f"va {va:#x} not mapped")

for base in (0x00519dac, 0x0051b254, 0x00521710, 0x0051a9d0, 0x00515830, 0x0055bf80, 0x0055bf84):
    raw = read_va(base, 0x40)
    print(f"VA {base:#010x}:")
    for i in range(0, len(raw), 16):
        chunk = raw[i:i + 16]
        dwords = struct.unpack("<4I", chunk) if len(chunk) == 16 else struct.unpack("<I", chunk[:4])
        print(f"   {base + i:#010x}  " + "  ".join(f"{d:08x}" for d in dwords))
    print()
