# Official WinDivert dependency

Pinned release: WinDivert2.2.2-A, x64.
Source: https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip
Upstream: https://github.com/basil00/WinDivert

| File | SHA256 |
|---|---|
| Official ZIP | 63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15 |
| x64/WinDivert.dll | c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2 |
| x64/WinDivert64.sys | 8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2 |

These pins were computed from the official GitHub release downloaded over verified
HTTPS during this work. They are recorded source pins, not invented upstream
published checksum claims. fetch-windivert.ps1 checks the ZIP before extraction,
checks both extracted files, requires Windows trust of the SYS signature, and
refuses to overwrite an existing dependency directory. Installer and runtime
loader recheck file hashes; runtime uses an absolute protected directory and
constrained DLL search.

The official DLL has no Authenticode certificate table. The official SYS has an
embedded certificate table. Requiring DLL Authenticode was a real startup blocker
in the previous source. Runtime now checks SYS Authenticode and both SHA256 pins.
Cloud verified archive/file hashes and PE structure, not the Windows trust chain.
Windows signature/capture behavior remains a required runtime check.

No ZIP, DLL, SYS or other third-party binary blob is committed. Downloaded files
stay in ignored local dependency/state directories. Review upstream licensing
before redistributing binaries outside your local test installation.
