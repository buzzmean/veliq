#!/usr/bin/env python3
"""Bounded operator workflow for an explicitly prepared relay and control plane."""
import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

PHASES = ("prepare", "cohort", "stage", "probe", "canary", "active", "drain", "rollback")
NODE_ID = re.compile(r"[A-Za-z0-9_-]{1,48}\Z")
PROFILE_HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}\Z")
USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
IDENTITY_REF = re.compile(r"[A-Z][A-Z0-9_]{1,63}\Z")
PIN = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
FIXED_HELPER = "/opt/neexitlag/libexec/relay-fleet-agent.py"
MAX_REPLY = 65536
MAX_ARTIFACT = 32 * 1024 * 1024
RESOURCE_KEYS = {"sessions", "flows", "packets_per_second", "bits_per_second", "opens_per_second"}


class FleetError(RuntimeError):
    pass


def require(ok, code):
    if not ok:
        raise FleetError(code)


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def load_object(path, limit=MAX_REPLY):
    with Path(path).open("rb") as stream:
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, "DOCUMENT_TOO_LARGE")
    value = json.loads(raw)
    require(isinstance(value, dict), "DOCUMENT_MUST_BE_OBJECT")
    return value


def digest_file(path, size_limit=MAX_ARTIFACT):
    h = hashlib.sha256()
    size = 0
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            size += len(block)
            require(size <= size_limit, "ARTIFACT_TOO_LARGE")
            h.update(block)
    return size, h.hexdigest()


def endpoint(value):
    host, sep, port = value.rpartition(":")
    require(bool(sep) and port.isdecimal() and 0 < int(port) <= 65535, "INVALID_ENDPOINT")
    require(host != "", "INVALID_ENDPOINT")
    address = ipaddress.ip_address(host[1:-1] if host.startswith("[") and host.endswith("]") else host)
    require(host == (f"[{address}]" if address.version == 6 else str(address)), "INVALID_ENDPOINT")
    require(not address.is_unspecified and not address.is_multicast and "%" not in host, "INVALID_ENDPOINT")
    return address, int(port)


def validate_profile(profile):
    require(set(profile) == {"host", "port", "user", "known_hosts", "host_pin", "identity_ref"}, "SSH_PROFILE_FIELDS")
    require(PROFILE_HOST.fullmatch(profile["host"]) and USER.fullmatch(profile["user"]) and profile["user"] != "root", "SSH_PROFILE_SCOPE")
    require(type(profile["port"]) is int and 0 < profile["port"] <= 65535, "SSH_PROFILE_PORT")
    require(PIN.fullmatch(profile["host_pin"]) and IDENTITY_REF.fullmatch(profile["identity_ref"]), "SSH_PROFILE_TRUST")
    require(Path(profile["known_hosts"]).is_absolute(), "SSH_PIN_PATH_REQUIRED")


def validate_plan(plan):
    keys = {"schema", "operation_id", "node_id", "address", "source_commit", "artifact_sha256", "artifact_bytes",
            "probe_target", "probe_device_ref", "canary_device_ref", "pilot_devices", "limits", "cp", "relay"}
    require(set(plan) == keys and plan["schema"] == 1, "PLAN_SCHEMA")
    require(NODE_ID.fullmatch(plan["operation_id"]) and NODE_ID.fullmatch(plan["node_id"])
            and plan["node_id"].lower() not in {"direct", "cp-fleet-config"}, "PLAN_IDS")
    require(re.fullmatch(r"[0-9a-f]{40}", plan["source_commit"]) and HEX.fullmatch(plan["artifact_sha256"]), "PLAN_ARTIFACT_HASH")
    require(type(plan["artifact_bytes"]) is int and 0 < plan["artifact_bytes"] <= MAX_ARTIFACT, "PLAN_ARTIFACT_SIZE")
    endpoint(plan["address"])
    _, port = endpoint(plan["probe_target"])
    require(port != 53, "PLAN_PROBE_TARGET")
    devices = plan["pilot_devices"]
    require(isinstance(devices, list) and 1 <= len(devices) <= 10 and all(isinstance(x, str) and NODE_ID.fullmatch(x) for x in devices)
            and len(set(devices)) == len(devices) and plan["canary_device_ref"] in devices
            and plan["probe_device_ref"] not in devices and NODE_ID.fullmatch(plan["probe_device_ref"]), "PLAN_COHORT")
    require(set(plan["limits"]) == RESOURCE_KEYS and all(type(x) is int and x > 0 for x in plan["limits"].values()), "PLAN_LIMITS")
    require(plan["limits"]["sessions"] <= 128 and plan["limits"]["flows"] <= 8192, "PLAN_HARD_LIMITS")
    cp, relay = plan["cp"], plan["relay"]
    validate_profile(cp)
    validate_profile(relay)
    require((cp["host"], cp["port"]) != (relay["host"], relay["port"])
            and cp["host_pin"] != relay["host_pin"] and cp["identity_ref"] != relay["identity_ref"]
            and os.path.normcase(os.path.normpath(cp["known_hosts"])) != os.path.normcase(os.path.normpath(relay["known_hosts"])),
            "SSH_PROFILES_MUST_BE_INDEPENDENT")


def verify_known_host(profile):
    path = Path(profile["known_hosts"])
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 8192, "PIN_FILE_UNAVAILABLE")
    token = profile["host"] if profile["port"] == 22 else "[%s]:%d" % (profile["host"], profile["port"])
    matches = []
    for line in path.read_text(encoding="ascii").splitlines():
        fields = line.split()
        if not fields or fields[0].startswith("#"):
            continue
        require(len(fields) == 3 and fields[0] == token and fields[1] == "ssh-ed25519", "PIN_FILE_SCOPE")
        blob = base64.b64decode(fields[2], validate=True)
        require(len(blob) > 4, "PIN_KEY_FORMAT")
        length = struct.unpack(">I", blob[:4])[0]
        require(blob[4:4 + length] == b"ssh-ed25519" and len(blob) == 4 + length + 4 + 32
                and struct.unpack(">I", blob[4 + length:8 + length])[0] == 32, "PIN_KEY_FORMAT")
        matches.append("SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("="))
    require(matches == [profile["host_pin"]], "SSH_HOST_KEY_MISMATCH")


class SSHAdapter:
    """Fixed helper and dedicated, previously provisioned SSH identities."""
    def __init__(self, plan, run=subprocess.run):
        self.profiles = {role: plan[role] for role in ("cp", "relay")}
        self.run = run
        self.identities = {}
        for role, profile in self.profiles.items():
            verify_known_host(profile)
            identity = Path(os.environ[profile["identity_ref"]])
            require(identity.is_absolute() and identity.is_file() and not identity.is_symlink(), "SSH_IDENTITY_UNAVAILABLE")
            self.identities[role] = identity
        require(not self.identities["cp"].samefile(self.identities["relay"]), "SSH_IDENTITY_REUSED")

    def call(self, role, args):
        profile = self.profiles[role]
        verify_known_host(profile)
        known = str(Path(profile["known_hosts"]).resolve())
        require(not any(x in known for x in '"\r\n'), "SSH_PIN_PATH_INVALID")
        cmd = ["ssh", "-T", "-F", "none", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
               "-o", "IdentitiesOnly=yes", "-o", "UpdateHostKeys=no", "-o", "ClearAllForwardings=yes",
               "-o", "ForwardAgent=no", "-o", "ControlMaster=no", "-o", "PasswordAuthentication=no",
               "-o", "ConnectTimeout=8", "-o", 'UserKnownHostsFile="' + known.replace("\\", "/") + '"',
               "-o", "GlobalKnownHostsFile=" + ("NUL" if os.name == "nt" else "/dev/null"),
               "-i", str(self.identities[role]), "-p", str(profile["port"]), profile["user"] + "@" + profile["host"],
               "python3", "-I", FIXED_HELPER, role]
        try:
            result = self.run(cmd, input=json_bytes(args), capture_output=True, timeout=30, check=False)
            require(result.returncode == 0 and len(result.stdout) <= MAX_REPLY, "SSH_OPERATION_FAILED")
            value = json.loads(result.stdout)
            require(isinstance(value, dict), "SSH_RESULT_INVALID")
            return value
        except (OSError, ValueError, subprocess.TimeoutExpired):
            raise FleetError("SSH_OPERATION_UNAVAILABLE") from None


class Journal:
    def __init__(self, directory, plan):
        self.path = Path(directory)
        require(self.path.is_dir() and not self.path.is_symlink(), "VERIFIED_JOURNAL_DIRECTORY_REQUIRED")
        self.operation = plan["operation_id"]
        self.scope = hashlib.sha256(json_bytes(plan)).hexdigest()

    def read(self, stage, kind):
        path = self.path / (self.operation + "-" + stage + "-" + kind + ".json")
        if not path.exists():
            return None
        doc = load_object(path)
        require(doc.get("scope") == self.scope and doc.get("stage") == stage, "JOURNAL_SCOPE_MISMATCH")
        if kind == "result":
            payload = json_bytes(doc["result"])
            require((doc.get("result_bytes"), doc.get("result_sha256")) == (len(payload), hashlib.sha256(payload).hexdigest()), "JOURNAL_READBACK_MISMATCH")
        return doc

    def write(self, stage, kind, value):
        path = self.path / (self.operation + "-" + stage + "-" + kind + ".json")
        doc = {"scope": self.scope, "stage": stage, "utc": datetime.now(timezone.utc).isoformat(), **value}
        raw = json_bytes(doc)
        # Link an already synced temporary into the final name without replacing
        # an existing receipt. Each operation uses owner-specific external storage.
        with tempfile.NamedTemporaryFile(prefix=path.name + "-", suffix=".pending", dir=self.path, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        finally:
            temporary.unlink()
        require(path.read_bytes() == raw, "JOURNAL_READBACK_MISMATCH")
        return doc

    def result(self, stage, payload):
        encoded = json_bytes(payload)
        return self.write(stage, "result", {"result": payload, "result_bytes": len(encoded),
                                            "result_sha256": hashlib.sha256(encoded).hexdigest()})


class Operator:
    def __init__(self, plan, adapter, journal):
        validate_plan(plan)
        self.plan, self.adapter, self.journal = plan, adapter, journal

    def prerequisite(self, phase):
        done = self.journal.read(phase, "result")
        require(done is not None, "PREREQUISITE_NOT_VERIFIED")
        return done["result"]

    def observe(self):
        return self.adapter.call("cp", {"action": "inspect", "relay_id": self.plan["node_id"]})

    def matches_node(self, observed):
        return observed.get("relay_id") == self.plan["node_id"] and all(
            observed.get(key) == self.plan[key] for key in ("address", "source_commit", "artifact_sha256", "artifact_bytes")
        )

    def undo_enrollment(self, snapshot):
        starting = self.journal.read("cohort", "intent")
        if not starting or starting["before_cohort_enabled"]:
            return False
        completed = self.journal.read("cohort", "result")
        if completed is None and snapshot["cohort_enabled"]:
            # Re-read this exact operation after a lost reply. A conflicting
            # activation has a different receipt and will fail the CAS.
            completed = self.apply("cohort")
        return completed is not None

    def apply(self, stage):
        require(stage in PHASES, "UNKNOWN_PHASE")
        done = self.journal.read(stage, "result")
        if done:
            return done
        p = self.plan
        prior = {"stage": "prepare", "probe": "stage", "canary": "probe", "active": "canary",
                 "drain": "stage", "rollback": "stage"}
        if stage == "rollback" and self.journal.read("stage", "result") is None:
            require(self.journal.read("stage", "intent") is not None, "STAGE_INTENT_UNAVAILABLE")
            seen = self.observe()
            require(self.matches_node(seen), "NODE_PRECONDITION_UNVERIFIED")
            prerequisite = {"relay_id": p["node_id"], "phase": seen.get("phase"), "stage_ack": "pending"}
        else:
            prerequisite = self.prerequisite(prior[stage]) if stage in prior else None
        if stage == "canary":
            self.prerequisite("cohort")
        intent = self.journal.read(stage, "intent")
        if intent is None:
            snapshot = {}
            if stage not in {"prepare", "probe"}:
                snapshot = self.adapter.call("cp", {"action": "inspect"})
                require(type(snapshot.get("registry_version")) is int and snapshot["registry_version"] > 0, "CP_VERSION_UNAVAILABLE")
                require(type(snapshot.get("cohort_enabled")) is bool, "CP_COHORT_UNAVAILABLE")
            rollback_legacy = stage == "rollback" and self.undo_enrollment(snapshot)
            intent = self.journal.write(stage, "intent", {"operation_id": p["operation_id"] + "-" + stage,
                                        "before_version": snapshot.get("registry_version"),
                                        "before_cohort_enabled": snapshot.get("cohort_enabled"),
                                        "rollback_legacy": rollback_legacy, "previous": prerequisite})
        request = {"action": "prepare", "relay_id": p["node_id"], "address": p["address"],
                   "source_commit": p["source_commit"], "artifact_bytes": p["artifact_bytes"],
                   "artifact_sha256": p["artifact_sha256"], "probe_target": p["probe_target"]}
        if stage == "prepare":
            ready = self.adapter.call("relay", request)
            require(ready.get("ready") is True and ready.get("artifact_sha256") == p["artifact_sha256"]
                    and ready.get("source_commit") == p["source_commit"], "NODE_PREPARE_UNVERIFIED")
            return self.journal.result(stage, {"artifact_sha256": ready["artifact_sha256"], "source_commit": ready["source_commit"]})
        if stage == "probe":
            request["action"] = "probe"
            proof = self.adapter.call("relay", request)
            require(proof.get("pass") is True and proof.get("relay_id") == p["node_id"]
                    and proof.get("probe_target") == p["probe_target"] and HEX.fullmatch(proof.get("proof_sha256", "")), "STAGED_PROBE_UNVERIFIED")
            evidence = {key: proof[key] for key in ("pass", "relay_id", "address", "probe_target", "proof")}
            require(evidence["address"] == p["address"] and evidence["proof"] == "verified_mtls_audience_authenticated_udp_echo"
                    and hashlib.sha256(json_bytes(evidence)).hexdigest() == proof["proof_sha256"], "PROBE_READBACK_MISMATCH")
            return self.journal.result(stage, {"proof_sha256": proof["proof_sha256"], "verified_echo": evidence})
        mutation = {"operation_id": intent["operation_id"], "expected_version": intent["before_version"]}
        phase = "drain" if stage == "rollback" else "staged" if stage == "stage" else stage
        if stage == "cohort":
            mutation["cohort"] = {"enabled": True, "devices": p["pilot_devices"]}
        elif intent["rollback_legacy"]:
            mutation["cohort"] = {"enabled": False, "devices": []}
        else:
            node = {"relay_id": p["node_id"], "address": p["address"], "limits": p["limits"], "phase": phase,
                    "source_commit": p["source_commit"], "artifact_sha256": p["artifact_sha256"], "artifact_bytes": p["artifact_bytes"]}
            if stage == "stage":
                ready = self.adapter.call("relay", request)
                require(ready.get("ready") is True and ready.get("artifact_sha256") == prerequisite["artifact_sha256"]
                        and HEX.fullmatch(ready.get("heartbeat_sha256", "")), "NODE_STAGE_UNVERIFIED")
                node.update(probe_device_ref=p["probe_device_ref"], probe_target=p["probe_target"],
                            heartbeat_sha256=ready["heartbeat_sha256"])
            if stage == "canary":
                node.update(canary_device_ref=p["canary_device_ref"], proof_sha256=prerequisite["proof_sha256"])
            mutation["node"] = node
        receipt = self.adapter.call("cp", {"action": "mutate", "mutation": mutation})
        version = receipt.get("registry_version")
        require(type(version) is int and version > intent["before_version"], "SIGNED_PUBLICATION_UNVERIFIED")
        if stage != "cohort":
            observed = self.observe()
            require(self.matches_node(observed) and observed.get("phase") == phase and type(observed.get("applied_version")) is int
                    and observed["applied_version"] >= version, "NODE_POLICY_ACK_PENDING")
        cohort_enabled = None
        if stage == "cohort" or intent["rollback_legacy"]:
            live = self.adapter.call("cp", {"action": "inspect"})
            cohort_enabled = stage == "cohort"
            require(live.get("cohort_enabled") is cohort_enabled and live.get("registry_version", 0) >= version,
                    "COHORT_POLICY_READBACK_PENDING")
        return self.journal.result(stage, {"registry_version": version, "phase": phase, "relay_id": p["node_id"],
                                           "cohort_enabled": cohort_enabled})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True)
    parser.add_argument("--phase", choices=PHASES, required=True)
    parser.add_argument("--journal")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    try:
        plan = load_object(args.plan)
        validate_plan(plan)
        if not args.execute:
            print(json_bytes({"mode": "dry-run", "phase": args.phase, "node": plan["node_id"], "ssh": False}).decode(), end="")
            return 0
        require(args.journal, "VERIFIED_JOURNAL_DIRECTORY_REQUIRED")
        result = Operator(plan, SSHAdapter(plan), Journal(args.journal, plan)).apply(args.phase)
        print(json_bytes(result["result"]).decode(), end="")
        return 0
    except FleetError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except (KeyError, TypeError, ValueError, OSError):
        print("FLEET_INPUT_OR_RUNTIME_UNAVAILABLE", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
