# Referenced implementations and runtime dependency

Flowseal/zapret-discord-youtube and bol-van/zapret were studied at revisions recorded in docs/FLOWSEAL_ZAPRET_ANALYSIS.md. Independent Go implementation; no upstream fake files, full list snapshots, batch scripts, executable or packet-processing code is vendored. Their MIT notices are retained under licenses/.

Existing WinDivert 2.2.2 is dynamically loaded, unmodified, not relicensed by this project. Select LGPLv3 for distribution; include COPYING.LESSER, COPYING and the corresponding source link with binary artifacts. Users may replace the DLL with a compatible build. Sources and build instructions: https://github.com/basil00/WinDivert/tree/v2.2.2 . Do not distribute modified library/driver without fulfilling corresponding source obligations. Kernel-driver signing constraints still apply.

DIRECT+ v2 independently implements bounded fake/split/disorder concepts and manually curates small Discord/YouTube domain subsets after review of Flowseal eb16c1419057e36b8a36fbe7c959483450e6ac8b and zapret c4d0b1990129dce2b28095277173ee0d7702d304. Existing Flowseal/bol-van MIT copyright and license notices in licenses/ accompany distributions. No upstream fake templates, winws binary or C packet implementation is bundled. See docs/DIRECT_PLUS_V2.md.

LOCAL catalog review (2026-10-23): Flowseal1.10.4/176f56dc3f11ce5915c26abcdde903f93d835b64,
zapret c4d0b1990129dce2b28095277173ee0d7702d304, zapret2
4a33055448ce5f4e7acc704e1fbe0d8a8a6aa08d and zapretgui
34c3bf9a775f30fdc14fdb2ceefdca1fe9991e8d. zapretgui MIT found at docs/LICENSE;
its copyright notice and zapret2 MIT are retained in licenses/. Inventory contains
parameters/provenance from all22 Flowseal general*.bat files, not scripts, binary
fakes or upstream packet-processing code. Own TLS1.3 fake and packet adaptations
are not claimed bit-for-bit equivalents. Unsupported catalog modes are explicitly
non-executable; no arbitrary shell/Lua/Python from a catalog is executed.
