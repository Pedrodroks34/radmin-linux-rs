import struct

PATH = "/home/pedrodroks/Downloads/radmin/claude-handoff/binaries/radmin_ext/RvControlSvc.exe"
IMAGE_BASE = 0x00400000

with open(PATH, "rb") as fh:
    data = fh.read()

e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
coff_off = e_lfanew + 4
num_sections = struct.unpack_from("<H", data, coff_off + 2)[0]
size_opt = struct.unpack_from("<H", data, coff_off + 16)[0]
sec_off = coff_off + 20 + size_opt
sections = []
for i in range(num_sections):
    name = data[sec_off:sec_off + 8].split(b"\0")[0].decode()
    vsize, vaddr, rawsize, rawoff = struct.unpack_from("<IIII", data, sec_off + 8)
    sections.append((name, IMAGE_BASE + vaddr, vsize, rawoff, rawsize))
    sec_off += 40

def read_va(va, n):
    for name, va_base, vsize, rawoff, rawsize in sections:
        if va_base <= va < va_base + max(vsize, rawsize):
            return data[rawoff + (va - va_base): rawoff + (va - va_base) + n]
    return b""

for va in [0x0051753c, 0x00517538, 0x0051727c, 0x00517510]:
    raw = read_va(va, 8)
    d = struct.unpack_from("<II", raw, 0)
    print(f"{va:#010x}: {d[0]:08x} {d[1]:08x}")
