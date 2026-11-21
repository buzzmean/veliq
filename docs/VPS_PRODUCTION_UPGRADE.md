# Existing VPS: reviewed production upgrade, PR #8

This procedure is for the existing VPS **2.56.177.4**, not installation or
provisioning. Creating these tools and running CI does **not** authorize a live
upgrade. Obtain separate deployment authorization before `Preflight`, `Apply`,
`Status` or `Rollback`: those modes contact the VPS. `Prepare` downloads and
verifies artifacts locally and performs **no SSH/SCP**.

## Audit and compatibility

* `install.sh` / `install-backend.sh` are bootstrap tools. Do not run them against
  this installation. `update.sh` only updates relay and discards its temporary
  backup: it is not this production procedure.
* The existing Control Plane unit carries `-seed-*` bootstrap arguments. Repeating
  them during maintenance can overwrite relay metadata. The upgrader adds a
  compatible **seed-free ExecStart drop-in**; original units are backed up unchanged.
* Migration `001_initial.sql` is idempotent and additive (including the partial
  revoked-device index). No schema/table/key/identity is deleted. CP startup runs
  it and, with the explicit upgrade-only `-publish-config-on-start` flag, publishes
  a complete signed snapshot immediately. Publication failure prevents readiness;
  the upgrade is not committed.
* Relay supports `neexitlag/2` and `neexitlag/3`. `/2` clients can authenticate, but
  need the newer Windows build for same-session lease renewal. Production lease
  remains **30 minutes**. Renewal does not require an application reconnect.
* New signed configurations may reach **1 MiB**. Older consumers may accept only
  64 KiB; the earlier CP also truncated devices at 1000. **Upgrade every signed
  configuration consumer (Windows clients and relays) before enabling larger CP
  publication.** Windows GUI version alone is not sufficient evidence.
* There is no trustworthy fleet-version inventory API today. Therefore an explicit
  reviewed inventory attestation, matching the full target commit and checked
  within 24 hours, is mandatory. This is an operator statement, not automatic
  remote version detection. For disconnected machines, update before allowing
  them back onto this CP. Do not fabricate the attestation to bypass the gate.

Current VPS health, DB version, disk space, installed binary versions, SSH access
and actual unit layout are **unknown until authorized preflight**. CI's loopback
fixture proves implementation behavior, not Internet performance or VPS readiness.

## Prerequisites and one Windows block

Use an operator Windows account with GitHub CLI (`gh auth login` already done),
OpenSSH client, an **already configured SSH key/agent**, and an independently
verified host key in `~/.ssh/known_hosts`. BatchMode and strict host verification
are mandatory: no password prompts, password copying, SSH key scanning or root
passwords. The existing deployment uses root SSH; the tool does not change SSH
configuration or create access keys. If key access is unavailable, prepare it
through your normal administrative process before granting deployment permission.

Retain the existing private enrolled Windows test bundle:
`windows/device/{identity.json,device.pem}`, `windows/trust/{trust.json,ca.pem,cp-ca.pem}`
and `windows/echo.token`. The tool neither enrolls a replacement device nor sends
these credentials to the VPS. The existing HMAC-authenticated echo service must
already accept **TCP and UDP 40000**. These ports, UDP4433 and TCP8443 must already
be reachable; the upgrader does not change firewalls or start/reconfigure echo.

After reviewing your inventory, create a local JSON file with this schema:

```json
{
  "validated_commit": "FULL_40_CHARACTER_TARGET_HEAD",
  "checked_at": "UTC_ISO8601_TIME_OF_ACTUAL_INVENTORY_REVIEW",
  "all_config_consumers_support_1mib": true,
  "inventory_reference": "Your inventory or change record identifying every consumer"
}
```

The block below is the **future deployment command**. Fill `Target` with the
reported full HEAD and `ReleaseRun` with its successful **Relay release and route
test** run ID. Keep `Mode='Prepare'` until separate deployment authorization;
then set `Mode='Apply'`. The same block performs preflight, backup, upgrade, real
protocol proof and commit. Run from the existing repository; it rejects the wrong
checkout and does not switch branches or discard working changes.

```powershell
$ErrorActionPreference = 'Stop'
$Target = 'FULL_40_CHARACTER_TARGET_HEAD'
$ReleaseRun = 'SUCCESSFUL_RELEASE_WORKFLOW_RUN_ID'
$Mode = 'Prepare' # ONLY change to Apply after separate deployment authorization

git fetch origin codex/direct-plus-flowseal
if ($LASTEXITCODE -ne 0) { throw 'git fetch failed' }
git pull --ff-only origin codex/direct-plus-flowseal
if ($LASTEXITCODE -ne 0) { throw 'git pull failed; preserve local work' }
if ((git branch --show-current).Trim() -cne 'codex/direct-plus-flowseal' -or
    (git rev-parse HEAD).Trim() -cne $Target) { throw 'Wrong branch or exact HEAD' }
git diff --quiet -- tools/windows/update-vps.ps1
if ($LASTEXITCODE -ne 0) { throw 'Upgrade tool locally modified' }
& .\tools\windows\update-vps.ps1 -Mode $Mode -ExpectedCommit $Target `
    -RunId $ReleaseRun -HostAddress '2.56.177.4' `
    -CompatibilityFile '.\.e2e\fleet-compatibility.json' `
    -DeviceDirectory '.\.e2e\bundle\windows\device' `
    -TrustDirectory '.\.e2e\bundle\windows\trust' `
    -EchoTokenFile '.\.e2e\bundle\windows\echo.token'
```

`Prepare` does not require the inventory or private device files. It verifies the
successful official workflow's repository/name/full head SHA and artifact hashes.
`Preflight` additionally stages **public candidate binaries/scripts and the
inventory statement only** and checks the server without stopping services.
`Apply` runs all gates and commits only after the real Windows proof succeeds.
Workflow artifacts expire according to GitHub retention; rebuild from the exact
clean commit if absent, and use that successful workflow run ID. No Go/.NET needed
for this test client.

## Transaction and preflight details

The remote root-only Python entry point is `deploy/vps/production-upgrade.py`.
It accepts only the audited existing local PostgreSQL/systemd layout and Linux
amd64, no arbitrary shell commands or test-root CLI override. Unknown unit flags,
custom drop-ins, extended ACLs or symlinked configuration require review rather
than silently weakening permissions. Existing root ownership and service-group
readability are checked, with no chmod/chown of `/etc/neexitlag`.

Preflight verifies required **preinstalled** commands, service users/units/PIDs,
running-vs-installed binary hashes, credential-file presence/access, TLS certificate
validity for at least 24h, local PostgreSQL 14–17, matching pg_dump major, expected
schema, no idle transaction, initial authenticated HTTPS health and loopback relay
metrics, existing echo health plus TCP/UDP40000 listeners, config size/device counts, and conservative free space on each relevant
filesystem (minimum 1 GiB, scaled to DB and binary size). Dependencies, ports and
custom layouts are not automatically repaired. Certificate expiry is a separate
operational prerequisite; this tool does not rotate credentials.

1. Exclusive host transaction lock, root-private unpredictable staging, exact SHA
   and SHA256 manifest validation, explicit fleet compatibility gate.
2. Permanent backup directory `/var/backups/neexitlag-upgrades/<UTC-ID>/`, mode0700:
   old binaries, original units + configuration archive (ACL/xattr preserved),
   custom-format DB dump, cluster globals, stopped-relay state archive, hashes,
   transaction state and root-only private command log. Backup files and directory
   entries are fsynced before binary replacement. **No automatic deletion.**
   Secret contents and raw journal/DB stderr are never emitted to the operator
   console or uploaded to Actions. Store a separately secured off-host copy via
   your backup policy; this procedure does not exfiltrate credentials.
3. Independent systemd **10-minute rollback watchdog**, plus persistent boot
   recovery required/ordered before CP and relay. Disconnecting Windows does not
   leave an unverified candidate silently committed.
4. Stop CP to quiesce its DB writes, dump/validate DB; stop relay and back up replay
   state; atomic same-filesystem relay replacement, version validation, relay
   startup/health. Then atomically replace CP, add seed-free publication override,
   run additive migrations/start CP, compare **all** DB revoked IDs to publication
   and wait for the relay to persist that exact verified signed snapshot (its
   existing 30-second configuration polling cadence; 45-second bounded gate).
5. Check identity/config hashes **and owner/mode** remain unchanged. Keep pending
   until independent protocol evidence and live relay metrics are verified.
6. Windows probe uses existing device proof to get fresh one-shot tickets. It
   proves mTLS rejection without a client certificate; invalid/replayed tickets
   rejected; authenticated `/2` compatibility and `/3`; real HMAC TCP+UDP replies
   with VPS egress; **two immediate authenticated renewals of the normal 30-minute
   lease**, keeping the same QUIC connection, TCP stream and UDP mapping. Identical
   receipt retry does not extend authorization twice; ticket reuse with another
   sequence is rejected. Counters and all three deadlines must advance.
7. Commit revalidates proof, binaries, config identity and publication, and requires
   post-upgrade metrics deltas (renewals≥2, TCP≥1, UDP≥3). It durably commits before
   disarming the watchdog. Failed proof/health invokes rollback immediately.

An upgrade restart **interrupts existing relay connections once**; use a maintenance
window. This tool does not promise zero-downtime binary replacement. Subsequent
healthy `/3` sessions renew without the historical 30-minute socket interruption.
Immediate renewal proof validates the installed production protocol without
changing its lease duration; existing accelerated expiry/outage/revocation CI
continues to cover deadline behavior. No 30–65 minute human test is required.

## Rollback and failure handling

The tool prints a backup ID and retains Windows logs under
`.e2e/vps-upgrade/logs-*/`. Recover status or request rollback using the same target
and release run arguments (these two modes work even after artifacts expire):

```powershell
.\tools\windows\update-vps.ps1 -Mode Status -ExpectedCommit $Target -RunId $ReleaseRun -BackupId 'EXACT_PRINTED_BACKUP_ID'
.\tools\windows\update-vps.ps1 -Mode Rollback -ExpectedCommit $Target -RunId $ReleaseRun -BackupId 'EXACT_PRINTED_BACKUP_ID'
```

Automatic rollback restores verified old binaries and a seed-free compatible unit
command, then checks health. It **never restores an old DB, replay cache or signed
cache**: that could resurrect revoked devices or allow replayed tickets. Backups
are durable recovery/forensic material. Restoring a DB is a separate offline,
security-reviewed recovery into a new database; never overwrite live security
state merely to make old binaries start.

**Incompatible downgrade is deliberately refused**: if old capabilities cannot
handle the current document size or complete revocations (>1000 devices), CP and
relay remain stopped in `maintenance-compatibility`, retaining current DB/replay
state. Boot recovery dependencies prevent these services from starting after a
failed guard. Recover forward with reviewed compatible binaries; no automatic
truncation, old snapshot publication, credential rotation or DIRECT fallback.
This is an availability risk when upgrading a legacy installation with large
state. Audit that risk before authorization; an automatic healthy downgrade cannot
be guaranteed where the old software is security-incompatible.

A pending reboot triggers file recovery before application services, without
waiting for units ordered after recovery. A committed transaction is never undone
by a late watchdog. Multiple runs refuse an unresolved earlier transaction.

## Validation and limits

`test_production_upgrade.py` runs OS-adapter fault injection in temporary roots:
rollback at DB/relay/CP stages, fixed security state, legacy incompatibility,
5000 devices/1500 revoked, truncated/oversized publication, corrupt bundle, stale
inventory/metrics, boot ordering, strict same-flow proof and permanent hashes.
`vps-upgrade-tests.ps1` runs real redirected Windows processes in PS5.1 and PS7.
Go tests exercise actual QUIC/mTLS/echo, renewal/replay and `/2` compatibility.
The **Isolated production upgrade** Actions workflow also runs real systemd,
PostgreSQL, binary replacement, a restored dump in a **separate test DB**, 5000
revocations producing >64 KiB, real TCP/UDP/two renewals, and injected installed
binary failure with rollback, entirely inside a disposable GitHub-hosted VM.

The fixture is **not the VPS** and supplies no Internet/production PASS. Real host
layout, known-host identity, package availability, backup space and fleet inventory
remain deployment preconditions. No change to firewall, `/etc/neexitlag`, device
identity, routing policies or production lease is part of this upgrade.
