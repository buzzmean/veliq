import base64
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

DEPLOY = Path(__file__).resolve().parents[2] / "deploy" / "vps"


def load(name):
    spec = importlib.util.spec_from_file_location(name, DEPLOY / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


stage = load("relay-fleet-stage")
agent = load("relay-fleet-agent")


class FixtureAdapter:
    def __init__(self):
        self.version = 9
        self.receipts = {}
        self.attempts = []
        self.node = {}
        self.cohort_enabled = False
        self.ready = True
        self.echo = True
        self.ack = True
        self.lose_changed_reply = False

    def call(self, role, args):
        action = args["action"]
        if role == "relay" and action == "prepare":
            return {"ready": self.ready, "artifact_sha256": args["artifact_sha256"],
                    "source_commit": args["source_commit"], "heartbeat_sha256": "1" * 64}
        if role == "relay" and action == "probe":
            reply = {"pass": self.echo, "relay_id": args["relay_id"], "address": args["address"],
                     "probe_target": args["probe_target"], "proof": "verified_mtls_audience_authenticated_udp_echo"}
            return {**reply, "proof_sha256": hashlib.sha256(stage.json_bytes(reply)).hexdigest()}
        if role == "cp" and action == "inspect":
            if "relay_id" in args:
                return {**self.node, "applied_version": self.version if self.ack else self.version - 1}
            return {"registry_version": self.version, "cohort_enabled": self.cohort_enabled}
        if role != "cp" or action != "mutate":
            raise AssertionError("unexpected fixture request")
        change = args["mutation"]
        self.attempts.append(stage.json_bytes(change))
        operation = change["operation_id"]
        if operation in self.receipts:
            before, version = self.receipts[operation]
            if before != change:
                raise AssertionError("idempotency key reused with different payload")
            return {"registry_version": version}
        if change["expected_version"] != self.version:
            raise AssertionError("unexpected version")
        self.version += 1
        if "node" in change:
            node = change["node"]
            self.node = {k: node[k] for k in ("relay_id", "address", "phase", "source_commit", "artifact_sha256", "artifact_bytes")}
        if "cohort" in change:
            self.cohort_enabled = change["cohort"]["enabled"]
            if not self.cohort_enabled:
                self.node["phase"] = "drain"
        self.receipts[operation] = (change, self.version)
        if self.lose_changed_reply:
            self.lose_changed_reply = False
            raise stage.FleetError("FIXTURE_REPLY_LOST")
        return {"registry_version": self.version}


class FleetStageTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.env = {}
        self.plan = {"schema": 1, "operation_id": "fixture", "node_id": "isolated-b",
                     "address": "127.0.0.1:4433", "source_commit": "a" * 40,
                     "artifact_sha256": "b" * 64, "artifact_bytes": 7, "probe_target": "127.0.0.1:4400",
                     "probe_device_ref": "probe-only", "canary_device_ref": "pc-fixture",
                     "pilot_devices": ["pc-fixture"], "limits": dict.fromkeys(stage.RESOURCE_KEYS, 20),
                     "cp": self.profile("cp", 10), "relay": self.profile("relay", 11)}
        self.io = FixtureAdapter()
        self.journal = stage.Journal(self.root, self.plan)
        self.operator = stage.Operator(self.plan, self.io, self.journal)

    def profile(self, name, seed):
        host = name + ".fixture.invalid"
        key = b"ssh-ed25519"
        raw_key = struct.pack(">I", len(key)) + key + struct.pack(">I", 32) + bytes([seed]) * 32
        hostfile = self.root / (name + "-hosts")
        hostfile.write_text(host + " ssh-ed25519 " + base64.b64encode(raw_key).decode() + "\n", encoding="ascii")
        identity = self.root / (name + "-unused")
        identity.write_text("fixture only; never supplied to a real SSH process", encoding="ascii")
        reference = "FLEET_TEST_" + name.upper()
        self.env[reference] = str(identity)
        digest = base64.b64encode(hashlib.sha256(raw_key).digest()).decode().rstrip("=")
        return {"host": host, "port": 22, "user": "fleet", "known_hosts": str(hostfile),
                "host_pin": "SHA256:" + digest, "identity_ref": reference}

    def test_dry_run_creates_no_journal_and_never_constructs_ssh(self):
        planfile = self.root / "plan.json"
        planfile.write_bytes(stage.json_bytes(self.plan))
        stdout = io.StringIO()
        with patch.object(sys, "argv", ["stage", "--plan", str(planfile), "--phase", "stage"]), \
             patch.object(stage, "SSHAdapter", side_effect=AssertionError("SSH in dry run")), redirect_stdout(stdout):
            self.assertEqual(stage.main(), 0)
        self.assertEqual(json.loads(stdout.getvalue()), {"mode": "dry-run", "phase": "stage", "node": "isolated-b", "ssh": False})
        self.assertFalse(list(self.root.glob("fixture-*.json")))

    def test_prepare_stage_probe_cohort_canary_active_rollback(self):
        for phase in ("prepare", "stage", "probe", "cohort", "canary", "active", "rollback"):
            doc = self.operator.apply(phase)
            self.assertEqual(doc, self.journal.read(phase, "result"))
            data = stage.json_bytes(doc["result"])
            self.assertEqual((len(data), hashlib.sha256(data).hexdigest()), (doc["result_bytes"], doc["result_sha256"]))
        self.assertEqual(self.io.node["phase"], "drain")
        self.assertEqual(self.io.version, 14)
        self.assertEqual(self.operator.apply("rollback"), self.journal.read("rollback", "result"))
        self.assertEqual(len(self.io.attempts), 5)
        self.assertFalse(self.io.cohort_enabled)
        self.assertEqual(json.loads(self.io.attempts[-1])["cohort"], {"enabled": False, "devices": []})
        self.assertNotIn(str(self.root), "".join(p.read_text() for p in self.root.glob("fixture-*.json")))

    def test_rollback_only_drains_node_for_preexisting_fleet(self):
        self.io.cohort_enabled = True
        for phase in ("prepare", "stage", "probe", "cohort", "canary", "rollback"):
            self.operator.apply(phase)
        self.assertTrue(self.io.cohort_enabled)
        mutation = json.loads(self.io.attempts[-1])
        self.assertEqual(mutation["node"]["phase"], "drain")
        self.assertNotIn("cohort", mutation)

    def test_retry_keeps_cas_and_id_after_committed_reply_is_lost(self):
        self.operator.apply("prepare")
        self.io.lose_changed_reply = True
        with self.assertRaisesRegex(stage.FleetError, "FIXTURE_REPLY_LOST"):
            self.operator.apply("stage")
        self.assertEqual(self.io.node["phase"], "staged")
        self.assertIsNone(self.journal.read("stage", "result"))
        self.assertEqual(self.operator.apply("stage")["result"]["registry_version"], 10)
        self.assertEqual(self.io.attempts[0], self.io.attempts[1])
        self.assertEqual(self.io.version, 10)

    def test_rollback_recovers_cohort_receipt_lost_after_publication(self):
        self.operator.apply("prepare")
        self.operator.apply("stage")
        self.operator.apply("probe")
        self.io.lose_changed_reply = True
        with self.assertRaisesRegex(stage.FleetError, "FIXTURE_REPLY_LOST"):
            self.operator.apply("cohort")
        self.assertTrue(self.io.cohort_enabled)
        self.assertIsNone(self.journal.read("cohort", "result"))
        self.operator.apply("rollback")
        self.assertEqual(self.io.attempts[-3], self.io.attempts[-2])
        self.assertFalse(self.io.cohort_enabled)
        self.assertEqual(self.io.node["phase"], "drain")

    def test_stage_journal_requires_exact_artifact_readback(self):
        self.operator.apply("prepare")
        self.io.ack = False
        with self.assertRaisesRegex(stage.FleetError, "NODE_POLICY_ACK_PENDING"):
            self.operator.apply("stage")
        self.io.ack = True
        self.io.node["artifact_sha256"] = "c" * 64
        with self.assertRaisesRegex(stage.FleetError, "NODE_POLICY_ACK_PENDING"):
            self.operator.apply("stage")
        self.assertIsNone(self.journal.read("stage", "result"))

    def test_probe_failure_and_missing_cohort_prevent_canary(self):
        self.operator.apply("prepare")
        self.operator.apply("stage")
        self.io.echo = False
        with self.assertRaisesRegex(stage.FleetError, "STAGED_PROBE_UNVERIFIED"):
            self.operator.apply("probe")
        with self.assertRaisesRegex(stage.FleetError, "PREREQUISITE_NOT_VERIFIED"):
            self.operator.apply("canary")
        self.io.echo = True
        self.operator.apply("probe")
        with self.assertRaisesRegex(stage.FleetError, "PREREQUISITE_NOT_VERIFIED"):
            self.operator.apply("canary")
        self.assertEqual(self.io.node["phase"], "staged")

    def test_rollback_can_drain_a_committed_unacknowledged_stage(self):
        self.operator.apply("prepare")
        self.io.ack = False
        with self.assertRaisesRegex(stage.FleetError, "NODE_POLICY_ACK_PENDING"):
            self.operator.apply("stage")
        self.assertIsNone(self.journal.read("stage", "result"))
        self.io.ack = True
        result = self.operator.apply("rollback")["result"]
        self.assertEqual((result["registry_version"], result["phase"]), (11, "drain"))

    def test_known_host_and_identity_scope_fail_before_ssh(self):
        runner = Mock(side_effect=AssertionError("a real SSH call would be unsafe"))
        with patch.dict("os.environ", self.env):
            stage.SSHAdapter(self.plan, run=runner)
            hostfile = Path(self.plan["relay"]["known_hosts"])
            hostfile.write_bytes(Path(self.plan["cp"]["known_hosts"]).read_bytes())
            with self.assertRaisesRegex(stage.FleetError, "PIN_FILE_SCOPE"):
                stage.SSHAdapter(self.plan, run=runner)
        self.plan["relay"]["identity_ref"] = self.plan["cp"]["identity_ref"]
        with self.assertRaisesRegex(stage.FleetError, "SSH_PROFILES_MUST_BE_INDEPENDENT"):
            stage.validate_plan(self.plan)
        runner.assert_not_called()

    def test_prepare_does_not_accept_a_substituted_artifact(self):
        shipped = self.root / "relay-artifact"
        shipped.write_bytes(b"changed")
        args = {k: self.plan["node_id"] if k == "relay_id" else self.plan[k] for k in
                ("relay_id", "address", "source_commit", "artifact_bytes", "artifact_sha256", "probe_target")}
        config = {**args, "artifact_file": str(shipped)}
        args["action"] = "prepare"
        runner = Mock()
        with self.assertRaisesRegex(agent.stage.FleetError, "NODE_ARTIFACT_MISMATCH"):
            agent.local_relay(config, args, runner)
        runner.assert_not_called()

    def test_relay_env_accepts_only_supported_fleet_modes(self):
        validate = load("validate-env").validate
        source = (DEPLOY / "example.env").read_text().replace("REPLACE_TARGET_IPV4", "198.51.100.25")
        env_file = self.root / "relay.env"
        for mode in ("0", "1", "observe"):
            env_file.write_text(source.replace("RELAY_FLEET_ADMISSION=0", "RELAY_FLEET_ADMISSION=" + mode))
            self.assertEqual(validate(env_file)["RELAY_FLEET_ADMISSION"], mode)
        env_file.write_text(source.replace("RELAY_FLEET_ADMISSION=0", "RELAY_FLEET_ADMISSION=invalid"))
        with self.assertRaisesRegex(ValueError, "invalid fleet admission mode"):
            validate(env_file)

    def test_relay_start_applies_only_the_selected_fleet_mode(self):
        bash = os.environ.get("VELIQ_TEST_BASH") or shutil.which("bash")
        if not bash:
            self.skipTest("GNU Bash is required for the wrapper fixture")
        wrapper = (DEPLOY / "relay-start.sh").read_text()
        executable = "exec /opt/neexitlag/bin/relay"
        self.assertEqual(wrapper.count(executable), 1)
        stub = "fixture_relay() { printf '%s\\n' \"$@\"; }\n"
        body = stub + wrapper.replace(executable, "fixture_relay")
        env = {**os.environ, "RELAY_DESTINATION_POLICY": "public-only", "RELAY_ALLOW_CIDRS": "", "BASH_ENV": "", "ENV": ""}
        for mode, expected in (("0", None), ("1", "-fleet-admission"), ("observe", "-fleet-observe-only"), ("invalid", None)):
            env["RELAY_FLEET_ADMISSION"] = mode
            run = subprocess.run([bash, "--noprofile", "--norc", "-s"], input=body, text=True, env=env,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
            self.assertEqual(run.returncode, int(mode == "invalid"), run.stderr)
            args = run.stdout.splitlines()
            self.assertEqual("-fleet-admission" in args, expected == "-fleet-admission")
            self.assertEqual("-fleet-observe-only" in args, expected == "-fleet-observe-only")
            if mode != "invalid":
                self.assertIn("-ticket-keys", args)
                self.assertIn("-heartbeat-token-file", args)

    def test_tampered_result_rejected_before_next_phase(self):
        self.operator.apply("prepare")
        receipt = self.root / "fixture-prepare-result.json"
        corrupted = stage.load_object(receipt)
        corrupted["result"]["source_commit"] = "d" * 40
        receipt.write_bytes(stage.json_bytes(corrupted))
        with self.assertRaisesRegex(stage.FleetError, "JOURNAL_READBACK_MISMATCH"):
            self.operator.apply("stage")
        self.assertFalse(self.io.attempts)


if __name__ == "__main__":
    unittest.main()
