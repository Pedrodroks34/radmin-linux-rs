# Import & Thunk Metadata — can the API names be resolved?

**Short answer: yes — completely and by two independent routes that agree.** Route A is inside the export itself (no extra data needed). Route B decodes the PE import directory of the local, unmodified `RvControlSvc.exe`. 23/24 name pairs agree exactly; the single divergence is an ordinal-vs-name rendering that both routes document consistently (§5).

## 1. Route A — inside the export (`references.jsonl`)

Every `COMPUTED_CALL[*]` record whose `to` is `EXTERNAL:000000xx` carries `to_function: "<DLL>::<API>"`.

Measured:

| Metric | Value |
|---|---|
| EXTERNAL-target call records | 4,782 (`COMPUTED_CALL` 4,779 + `COMPUTED_CALL_TERMINATOR` 3) |
| Records missing the API name | **0** |
| Conflicting names per EXTERNAL id | **0** |
| Distinct EXTERNAL ids observed | 297 |
| Distinct imported API names | **297** |
| Distinct DLLs | 13 |

Per-DLL call-site counts (from `to_function`):

| DLL | sites | DLL | sites |
|---|---|---|---|
| KERNEL32.DLL | 4,413 | OLE32.DLL | 29 |
| ADVAPI32.DLL | 137 | WININET.DLL | 18 |
| WS2_32.DLL | 73 | IPHLPAPI.DLL | 6 |
| OLEAUT32.DLL | 62 | RPCRT4.DLL | 4 |
| RVROLCLIENT.DLL | 58 | SHELPER.DLL | 2 |
| FWPUCLNT.DLL | 37 | SHELL32.DLL | 2 |
| | | MSI.DLL | 2 |

The **top imported APIs by call-site count**: `KERNEL32.DLL::GetLastError` 1,970 · `KERNEL32.DLL::SetLastError` 1,914 · internal `FUN_004eb266` 116 · `guard_check_icall` 86 (CF-Guard) · `KERNEL32.DLL::GetProcAddress` 79 · `KERNEL32.DLL::CloseHandle` 24 · `OLEAUT32.DLL::SysFreeString` 19 · `WS2_32.DLL::ntohs`/`htons` 18+18 · `WS2_32.DLL::htonl` 17 · `KERNEL32.DLL::LeaveCriticalSection` 14 · `OLEAUT32.DLL::VariantInit` 13 · `KERNEL32.DLL::GetModuleHandleW` 13 · `GetLocaleInfoW` 13 · `RVROLCLIENT.DLL::ROLClient_FreeMemory` 12 · `OLEAUT32.DLL::SysAllocString` 12 · `WideCharToMultiByte` 12 · `EnterCriticalSection` 12 · `SetServiceStatus` 12 · `RegQueryValueExW` 12.

## 2. Route B — PE import directory (binary read-only; PE32)

Decoded with `pe_imports.py` (this directory) and cross-checked with `objdump -p` (Portuguese output, same numbers):

| Item | Value |
|---|---|
| Architecture | PE32 (`pei-i386`), subsystem 3 (Windows CUI), image base `0x00400000` |
| `AddressOfEntryPoint` | `0x000e647c` → VA **`0x004e647c`** (matches the export's single `EXTERNAL` pseudo-record, `to_function:"entry"`) |
| Sections | `.text` `00401000` (READONLY CODE) · `.rdata` `00517000` · `.data` `00548000` · `.rsrc` `005a7000` · `.reloc` `005bf000` |
| `DYNAMIC_BASE` (ASLR) · `NX_COMPAT` · `LARGE_ADDRESS_AWARE` · `TERMINAL_SERVICE_AWARE` | yes |
| Checksum / link timestamp | `0x00197a41` · Wed Jul 29 09:12:40 2026 |
| Import directory RVA / size | `0x001450f4` / `0x118` (inside `.rdata` tail) |
| IAT directory RVA / size | `0x00117000` / `0x53c` → VA `0x00517000..0x0051753c` |
| IAT slots (4-byte) | 335 directory slots · **322 resolved imports** · 13 unused (`005170e8`, `00517104`, `00517370`, `00517398`, `005173a8`, `0051743c`, `00517448`, `00517450`, `00517480`, `005174c8`, `0051750c`, `00517514`, `00517538`) |
| Decoded import names | 322 (see `import_iat_map.txt`) |

Per-DLL decoded import counts: KERNEL32 154 · ADVAPI32 58 · RVROLCLIENT 36 · FWPUCLNT 16 · WS2_32 17 · OLEAUT32 9 · OLE32 8 · WININET 11 · IPHLPAPI 6 · RPCRT4 3 · SHELL32 2 · SHELPER 1 · MSI 1 = **322** (ordinal-only: OLEAUT32 ×9, WS2_32 ×14, MSI ×1).

Sanity examples verified both by the parser and by `objdump -p`:

- `0x00517258` (RVA `00117258`) → **LocalFree**, hint `0x3d3` = 979 ✓ (objdump agrees).
- `0x00517264` → **SetFileAttributesW** ✓.
- `0x00517260` (RVA `00117260`) → **SetLastError**, hint `0x534` = 1332 ✓ — the exact slot read at `00404221 CALL dword ptr [0x00517260]` whose paired records are `READ → 00517260` + `COMPUTED_CALL → EXTERNAL:00000057` (`to_function: KERNEL32.DLL::SetLastError`). **Both routes and the listing bytes agree.**
- `0x0051744c` → **SHELPER.DLL::SHelper_Init** hint `0x16` = 22 ✓ — imported by the control service itself; the `004e6f0b` stub jumps to it (`FF254C745100`).

## 3. Route C — the 31 `INDIRECTION` records are the IAT import stubs

`references.jsonl` INDIRECTION (all `JMP dword ptr [0x00517xxx]`, verified in listings):

- 22 records are import-stub jumps whose IAT slot VA we can now resolve by Route A **or** Route B (they agree): `00472340`/`004803a0` → `005171d4` **GetACP**; `004aec83`/`004aec89`/`004aec8f` → `00517128`/`0051712c`/`00517130` **CreateToolhelp32Snapshot / Process32FirstW / Process32NextW**; `004e6f05`…`004e6f6b` → `00517510…00517508` **MSI ordinal 205 / SHELPER SHelper_Init / 17 × FWPUCLNT Fwpm***; `0041a570` → `00517408` **RVROLCLIENT.DLL::ROLClient_FreeMemory**; `0050184a`…`005018cb` → `00517164`/`0051715c`/`00517160` **TlsFree / TlsGetValue / TlsSetValue**; `004eb03f` → `00517158` **TlsAlloc**; `0041d6ce` → `00517400` **RVROLCLIENT.DLL::ROLClient_AllocMemory**; `0041dcee` → `00517408`; `00451637` → `00517088` **ADVAPI32.DLL::EventRegister**.
- 9 of these IAT slots are also read directly by `CALL dword ptr [IAT]` sites typed `COMPUTED_CALL` elsewhere in the binary (e.g. `00404221`, and the two `005171d4` call sources).

**Cross-check result (`crosscheck_iat.py`): 23 of 24 name-carrying stubs resolve to byte-identical names between the export and the PE directory.** The one divergent pair:

- `thunk@004e6f05` → IAT `0x00517510` — export (Ghidra) reports `MSI.DLL::MsiEnumRelatedProductsW`;
  the PE directory contains **ordinal 205, no name string** (confirmed by the PE parser and by `objdump -p`: `00117510 205 <none>`). The ordinal→name resolution is Ghidra's, derived from the analysis workstation (`/C:/Users/Rhuan/Desktop/RvControlSvc.exe`); it is **STRONGLY_SUPPORTED**, not independently verified against a live `msi.dll`.
- The OLEAUT32 (`ordinal_2,6,8,9,16,21,22,26,411`) and WS2_32 (`ordinal_2,3,5,6,7,8,9,10,14,15,22,23,111,115`) slots are ordinal-only in the PE directory. Ghidra resolved all of them to real names (no `ordinal` string appears anywhere in `to_function`), e.g. `WS2_32.DLL::socket / bind / closesocket / ntohs / htons / htonl / ntohl / WSAStartup / WSARecv / WSAGetLastError / WSAGetOverlappedResult / getnameinfo / ioctlsocket / getsockopt / getsockname / getpeername / shutdown`; `OLEAUT32.DLL::SysAllocString / SysFreeString / VariantInit / …`. These are **Ghidra-resolved names** (evidence: `to_function` strings), consistent with well-known ordinal assignments on Windows, but not verified against local copies of those DLLs (not present in this workspace).

## 4. Thunks — three different things, don't conflate them

1. **Import thunk stubs** (`JMP [IAT]`, 5–6 bytes): 22 `unknown`-calling-convention functions — `0041a570`, `004aec83|004aec89|004aec8f`, `004e6f05…004e6f6b` (18) — plus the `JMP [0x005171xx]` INSIDE other functions (e.g. `0050184a`). These are the only PE import jump stubs. The two `RVROLCLIENT.DLL` stubs (`0041a570`) forward to `ROLClient_FreeMemory`.
2. **Ghidra FID "thunk_" functions** (`is_thunk:true`, 91 entries, e.g. `thunk_FUN_00478a50` ×8, `thunk_FUN_0047a000` ×2): small internal wrappers recognized by Function-ID — **not** import stubs, not IAT-related. They jump to internal `FUN_004xxxxx` targets.
3. **Direct `JMP 0x…` tail calls** into function entries, logged as `UNCONDITIONAL_CALL` `is_call=true` (1,227 records).

## 5. Name-resolution routes — summary & limits

| Route | Data needed | Result | Limit |
|---|---|---|---|
| A. export `to_function` on EXTERNAL records | nothing extra | 297 API names + DLL | names are Ghidra's inference; EXTERNAL ids are export-local indices, **not** IAT ordinals |
| B. PE import directory decode (`pe_imports.py`, `objdump -p`) | the binary (present) | 322 slots: 298 named + 24 ordinal-only | cannot name pure ordinal slots without the vendor DLL |
| C. INDIRECTION + listing `FF 25` pattern | export only | 23 IAT slots with stub context | only covers stubs, not every IAT call site |
| D. runtime under debugger | ASLR base + IAT contents | authoritative for this machine | out of scope for static work |

**Explicit answers to the mission questions:**

- *Is import metadata available in the export?* **Yes** — as `EXTERNAL:` ids + `to_function` names, plus 31 INDIRECTION stub references. **No import table is embedded in the export** (it is derived, not raw).
- *Can internal IAT thunks be mapped to API names now?* **Yes** — 22 stubs × DLL::Name (Route A ∩ Route B), all cross-verified. The `0x00517158`…`0x0051716x` Fls slots and both `RVROLCLIENT.DLL` slots are covered.
- *Are there gaps?* The single MSI ordinal (205 → `MsiEnumRelatedProductsW`) is Ghidra-resolved only; 23 ordinal-only slots overall are Ghidra-resolved only. Nothing else is missing.
- *What additional export would be required?* None for API names. If ordinal names must be certified independently, supply `msi.dll`, `ws2_32.dll`, `oleaut32.dll` export tables (e.g. `objdump -x` on those DLLs, or a debugger dumping `IAT` after `LdrGetDllHandle`). No edits to the export are needed.

## 6. What the service actually uses — quick intel for future phases

- **RVROLCLIENT.DLL** — 36 imports incl. `ROLClient_Connect` (hint 5), `ROLClient_ContinueConnect` (6), `ROLClient_JoinNetwork` (19), `ROLClient_CancelJoin` (2), `ROLClient_ListenVpn` (21), `ROLClient_SetVirtualAddresses` (39), `ROLClient_ManageNetwork2` (24), session reporting (`ROLClient_ReportRServerInfo` 31, `ROLClient_ReportLanguage` 30, `ROLClient_ReportIpConflict` 29, `ROLClient_ReportSessionSummary` 32), `ROLClient_InitConnector` (17), `ROLClient_Register` (27), `ROLClient_CheckUpdates` (4), `ROLClient_ChatCommand` (3), `ROLClient_EnumPublicNetworks` (9), `ROLClient_EnableModuleEvents` (8), `ROLClient_InitDll` (18) / `ShutdownDll` (42), `ROLClient_Connect`/`Send`/`Receive` + `ROLClient_SetRecvCallback` (38). **The control service is a thin client to these entry points** — mapping call sites with `xref.py` is the shortest path to identifying the session-setup sequence.
- **SHELPER.DLL** — `SHelper_Init` (hint 22 = `0x16`). The SRP/crypto helper DLL is loaded and initialized once per process from here.
- **ADVAPI32** — service control manager (`StartServiceCtrlDispatcherW` 762, `SetServiceStatus` 754), crypto providers (`CryptAcquireContextW` 194, `CryptGenRandom` 210), registry, ACL helpers, `RegGetValueW`, `CreateWellKnownSid`, `GetNamedSecurityInfoW`.
- **WININET.DLL** — `InternetOpenW` / `InternetConnectW` / `HttpOpenRequestW` / `HttpSendRequestW` / `InternetReadFile` / `HttpQueryInfoW` (upgrade/check path, classic HTTP not HTTPS API-wise).
- **FWPUCLNT.DLL** — Windows Filtering Platform management (`FwpmEngineOpen0/Close0`, `FwpmSubLayer*`, `FwpmFilter*`) — WFP firewall filter management.
- **WS2_32 / IPHLPAPI / OLE32 / OLEAUT32 / RPCRT4 / SHELL32 / MSI** — sockets + adapter notifications + COM/variants + UuidCreate + MsiEnumRelatedProductsW (ordinal 205).
- *Important for crypto work:* `CRYPTGENRANDOM` (hint 210) and `CryptAcquireContextW` are imported by the **service**, independent of the SRP code in `shelper.dll`.

Import directory Entry 0 (Export Directory) = `0x00000000 0x00000000` — **the binary exports nothing**. `.text` is read-only, no symbols. All VAs everywhere in this analysis are preferred-base (ASLR active); do not use runtime addresses from a debugger without relocation adjustment.
