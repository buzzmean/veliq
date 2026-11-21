# VELIQ: branding and existing-install compatibility

VELIQ is the user-facing product name. Desktop title, tray, messages, notifications,
WPF dialogs, Windows service display name, published GUI and artifact labels use
VELIQ. The theme uses black, white and neutral greys, including keyboard focus and
disabled controls. Approved source SVG assets from 2dfdb48 are imported; the WPF header uses the
approved symbol. The existing ICO resource remains until a validated Windows
export. Inventory and exact scope: BRAND_INVENTORY.md.

## Compatibility contract

| Surface | Preserved identity |
| --- | --- |
| Windows SCM **name**, service binary | `neexitlag`, `neexitlag-service.exe` |
| Service data/keys/profiles/driver | `%ProgramData%\neexitlag` |
| GUI preferences/recovery/policy journals | `%LOCALAPPDATA%\NeExitLag` |
| IPC, health marker, PAC hosts, recovery protocol | Existing names and payloads |
| Single-instance mutex/activation pipe | Existing SID-scoped names |
| HKCU Run value | `NeExitLag` (compatible, same per-user toggle) |
| Go module, .NET namespaces/project paths | Existing identifiers |
| Server paths/users/DB/certificates/tickets/ALPN | Existing identifiers, no migration |

The GUI assembly/product and primary executable are `VELIQ.exe`. The publish
wrapper also emits a byte-identical `NeExitLag.exe` entry point, so existing
shortcuts/autostart still launch the new application. Both use the same mutex and
activation pipe: running one while the other is open activates the existing GUI.
The Windows running-app picker excludes both executable names. Release artifacts
use VELIQ labels and also publish legacy download-name aliases with the identical
bytes and manifests, preserving existing pinned update-vps/download automation.
The updater therefore needs no server or credential migration.

## Windows update

Exit only the VELIQ GUI through its tray **Exit** item before replacing the
service/helper image. Keep Chrome and Edge open; never close/restart them for branding. In elevated PowerShell, pull the expected
reviewed commit, run `build-e2e.ps1`, `build-desktop.ps1`, then `update-service.ps1`.
The updater retains persistent binary/ACL backups and changes only the SCM display
name to `VELIQ Routing Service`; its SCM name, path, identity and state are kept.
A failed binary update restores the previous binary/ACL/display name.

As the ordinary installation owner run:

```powershell
.\tools\windows\install-desktop.ps1
```

This per-user GUI installer is idempotent, backs up existing GUI binaries, uses
atomic replacement and verifies hashes. It creates a VELIQ Start menu shortcut
and replaces a legacy shortcut only when it belongs to the same installation.
Foreign shortcuts/autostart are not overwritten. It never provisions a device,
modifies Chrome policy, opens credentials, resets profiles or touches the VPS.
An enabled compatible HKCU Run entry is retargeted without enabling a disabled one.
Old GUI preferences and Chrome recovery journals remain in their original paths.

Start **VELIQ** normally, activate Chrome AUTO if needed, then optionally run the
short `acceptance-chrome-sites.ps1 -RestartService` helper. Automated fixtures are
not proof of Telegram/other public website reachability on a particular ISP.

## Verification

Native Windows CI checks the published VELIQ title, tray lifecycle, Russian
resources, keyboard/focus/disabled monochrome controls and single-instance
activation. It launches the compatibility alias against the primary executable.
Per-user installer regression installs twice, compares legacy/new binary hashes,
checks shortcut replacement and collision protection, and verifies pre-existing
preferences/recovery/profile/identity fixtures remain byte-identical. Existing
service reinstall tests retain hashes/ACL checks and assert the preserved SCM
name together with the new display name.
