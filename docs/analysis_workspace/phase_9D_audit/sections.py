import struct
import sys

PATH = "/home/pedrodroks/Downloads/radmin/claude-handoff/binaries/radmin_ext/RvControlSvc.exe"

with open(PATH, "rb") as fh:
    data = fh.read()

e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
coff_off = e_lfanew + 4
num_sections = struct.unpack_from("<H", data, coff_off + 2)[0]
size_opt = struct.unpack_from("<H", data, coff_off + 16)[0]
sec_off = coff_off + 20 + size_opt

print("sections:")
for i in range(num_sections):
    name = data[sec_off:sec_off + 8].split(b"\0")[0].decode()
    vsize, vaddr, rawsize, rawoff = struct.unpack_from("<IIII", data, sec_off + 8)
    chars = struct.unpack_from("<I", data, sec_off + 36)[0]
    print(f"  {name:8} vsize={vsize:#010x} va={vaddr:#010x} rawsize={rawsize:#010x} rawoff={rawoff:#010x} chars={chars:#010x}")
    sec_off += 40

target = int(sys.argv[1], 16)
base = 0x00400000
print()
print(f"query {target:#010x}")
for i in range(num_sections):
    pass
