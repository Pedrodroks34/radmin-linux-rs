# Phase 2.7 — New Binary Hash and Version Inventory

## 1. Summary
**No new binaries identified** in post-connection capture. All modules match baseline inventory (Report 02).

## 2. Baseline Hash Reference (from Report 02)

| Binary | SHA-256 | Version | Status |
|--------|---------|---------|--------|
| RvControlSvc.exe | 0E2E6EAACBE8EBE01286CDA39A12EAAD34A20434D50F4F8BF2FDD91D4D6EF2AD | 2.1.4952.2 | ✅ Verified post-restart |
| RvRvpnGui.exe | A9B093C68288AA8B8282FEBA37A254DDF45D8BEABFC9F575CF8B07620825739E | 2.1.4952.2 | ✅ Verified unchanged |
| RvROLClient.dll | 018EECAB36CFD80BD307A385294702C4418B81A26ACF63484451F3D7CA8038A9 | 2.1.4952.2 | ✅ Loaded pre-connection |
| RvDownloader.dll | 882B5ABEB4896AC42652682B1693E5AD20AFEEEF989169E96A17C086C42A31F2 | 2.1.4952.2 | ✅ Loaded pre-connection |
| RvRolUpdater.dll | 0FE7F1B441A6869A2304D8EF6470D1A138AAAED69ED8DC394A888539E1842DCD | 2.1.4952.2 | ✅ Loaded pre-connection |
| RvUESClient.dll | DF732E2A0815BC377D035B9F590C528400DC079AF4FC7F733A03884527743C5F | 2.1.4952.2 | ✅ Loaded pre-connection |
| Shelper.dll | D89DAF6BCD5CAFA3C7F6173F835CCF045BAF8E7134F868819DB6FD7615959AC4 | 4.0.0.4 | ✅ Loaded pre-connection |
| RvFwHelper.exe | DBA18C5D039C2AF7031540156F6129AD61D707B434053EB36CDF499BE1065EE8 | 2.1.4952.2 | ❌ Not spawned |
| drvinst.exe | EADC3524E28AC20F879DFABFB901C96F5ED0BDE09DC09C202C505BC4CE0354B2 | 2.1.4952.2 | ❌ Not spawned |
| RvGuiStarter.exe | 2891A6DC87498AC85483E4C3E7FE51E0126483584D731B036E9F1C39A92703BE | 2.1.4952.2 | ❌ Not spawned |

## 3. Post-Connection Verification
- **RvControlSvc.exe (PID 5476)**: Same file, same hash (service restart uses same binary)
- **RvRvpnGui.exe (PID 1232)**: Same file, same hash (unchanged)
- **All Radmin DLLs**: Same hashes, same load addresses (ASLR consistent)
- **Third-party DLLs**: OpenSSL, libcurl, Qt, ICU — all same versions/hashes

## 4. New Binary Template (N/A — None Found)

| Binary | SHA-256 | Version | Path | Classification | First Seen |
|--------|---------|---------|------|----------------|------------|
| *(none)* | — | — | — | — | — |

## 5. Conclusion
The VPN connection establishment **does not load any new executable modules**. All required binaries (RvROLClient.dll, libcrypto-3.dll, libssl-3.dll, libcurl.dll, etc.) are already loaded in the service process before connection. The service restart reuses the exact same binaries.

---
*Report generated: 2026-11-26 03:35 UTC*
*Evidence classification: Computed (SHA-256 from Report 02), Tool-reported (EnumModules2 post-connection)*