#!/usr/bin/env python3
"""Fixed scoped SSH helper for a prepared host. No installation or key issuance."""
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
from urllib.parse import urlencode, urlsplit


spec = importlib.util.spec_from_file_location("fleet_stage", Path(__file__).with_name("relay-fleet-stage.py"))
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


def trusted_file(name, limit, secret=False):
    p = Path(name)
    stage.require(p.is_absolute() and p.is_file() and not p.is_symlink() and p.stat().st_size <= limit, "AGENT_FILE_UNAVAILABLE")
    if secret:
        stage.require((p.stat().st_mode & 0o077) == 0, "AGENT_PRIVATE_FILE_MODE")
    return p


def registry_request(config, args):
    url = urlsplit(config["cp_url"])
    stage.require(url.scheme == "https" and url.hostname and url.username is None and url.path in {"", "/"}
                  and not url.query and not url.fragment, "CP_URL_UNTRUSTED")
    ca = trusted_file(config["ca_file"], stage.MAX_REPLY)
    token = trusted_file(config["registry_token_file"], 256, True).read_text(encoding="ascii").strip()
    stage.require(len(token) >= 24 and token.isascii() and token.isprintable() and not any(c.isspace() for c in token), "CP_TOKEN_UNAVAILABLE")
    context = ssl.create_default_context(cafile=str(ca))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    client = http.client.HTTPSConnection(url.hostname, url.port or 443, context=context, timeout=8)
    path = "/api/v1/fleet/registry"
    headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
    try:
        if args.get("action") == "inspect":
            if "relay_id" in args:
                stage.require(stage.NODE_ID.fullmatch(args["relay_id"]), "NODE_ID_INVALID")
                path += "?" + urlencode({"node": args["relay_id"]})
            client.request("GET", path, headers=headers)
        else:
            stage.require(args.get("action") == "mutate" and set(args) == {"action", "mutation"}, "CP_ACTION_INVALID")
            client.request("POST", path, body=stage.json_bytes(args["mutation"]), headers=headers)
        reply = client.getresponse()
        body = reply.read(stage.MAX_REPLY + 1)
        stage.require(reply.status == 200 and len(body) <= stage.MAX_REPLY, "CP_REGISTRY_REJECTED")
        data = json.loads(body)
        stage.require(isinstance(data, dict), "CP_RESULT_INVALID")
        permitted = {"registry_version", "cohort_enabled", "relay_id", "address", "phase", "applied_version", "observed_at", "load",
                     "source_commit", "artifact_sha256", "artifact_bytes"}
        return {k: data[k] for k in permitted if k in data}
    finally:
        client.close()


def local_relay(config, args, runner=subprocess.run):
    require = stage.require
    expected = {"action", "relay_id", "address", "source_commit", "artifact_bytes", "artifact_sha256", "probe_target"}
    require(set(args) == expected and args["action"] in {"prepare", "probe"}, "NODE_ACTION_INVALID")
    for k in ("relay_id", "address", "source_commit", "probe_target"):
        require(args[k] == config[k], "NODE_SCOPE_MISMATCH")
    require(stage.NODE_ID.fullmatch(args["relay_id"]) and stage.HEX.fullmatch(args["artifact_sha256"]), "NODE_REQUEST_INVALID")
    artifact = trusted_file(config["artifact_file"], stage.MAX_ARTIFACT)
    require(stage.digest_file(artifact) == (args["artifact_bytes"], args["artifact_sha256"]), "NODE_ARTIFACT_MISMATCH")
    release = stage.load_object(trusted_file(config["artifact_manifest"], stage.MAX_REPLY))
    require(release == {"role": "relay", "source_commit": args["source_commit"], "sha256": args["artifact_sha256"],
                        "bytes": args["artifact_bytes"]}, "NODE_PROVENANCE_MISMATCH")
    leaf = trusted_file(config["public_leaf_file"], stage.MAX_REPLY).read_text(encoding="ascii")
    leaf_hex = hashlib.sha256(ssl.PEM_cert_to_DER_cert(leaf)).hexdigest()
    require(leaf_hex == config["public_leaf_sha256"], "NODE_LEAF_PIN_MISMATCH")
    trusted_file(config["node_key_file"], stage.MAX_REPLY, True)
    secret = trusted_file(config["heartbeat_file"], 256, True).read_bytes().strip()
    require(len(secret) == 32, "NODE_HEARTBEAT_SCOPE")
    if args["action"] == "prepare":
        return {"ready": True, "source_commit": args["source_commit"], "artifact_sha256": args["artifact_sha256"],
                "heartbeat_sha256": hashlib.sha256(secret).hexdigest()}
    runner_path = trusted_file(config["probe_binary"], stage.MAX_ARTIFACT)
    require(stage.digest_file(runner_path)[1] == config["probe_binary_sha256"], "PROBE_BINARY_PIN_MISMATCH")
    manifest = trusted_file(config["probe_manifest"], stage.MAX_REPLY, True)
    proc = runner([str(runner_path), "-mode", "fleet-staged", "-relay-id", args["relay_id"],
                   "-address", args["address"], "-probe-target", args["probe_target"],
                   "-manifest", str(manifest), "-timeout", "15"], capture_output=True, check=False, timeout=20)
    require(proc.returncode == 0 and len(proc.stdout) <= stage.MAX_REPLY, "STAGED_PROBE_FAILED")
    evidence = json.loads(proc.stdout)
    expected_proof = {"pass": True, "relay_id": args["relay_id"], "address": args["address"],
                      "probe_target": args["probe_target"], "proof": "verified_mtls_audience_authenticated_udp_echo"}
    require(evidence == expected_proof, "STAGED_PROBE_RESULT_MISMATCH")
    return {**evidence, "proof_sha256": hashlib.sha256(stage.json_bytes(evidence)).hexdigest()}


def main():
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in {"cp", "relay"}:
            return 2
        role = sys.argv[1]
        raw = sys.stdin.buffer.read(stage.MAX_REPLY + 1)
        stage.require(len(raw) <= stage.MAX_REPLY, "REQUEST_TOO_LARGE")
        request = json.loads(raw)
        stage.require(isinstance(request, dict), "REQUEST_INVALID")
        conf_path = trusted_file("/etc/neexitlag/fleet-agent-" + role + ".json", stage.MAX_REPLY, True)
        config = stage.load_object(conf_path)
        reply = registry_request(config, request) if role == "cp" else local_relay(config, request)
        sys.stdout.buffer.write(stage.json_bytes(reply))
        return 0
    except (OSError, ValueError, KeyError, TypeError, stage.FleetError, subprocess.TimeoutExpired, http.client.HTTPException):
        print("FLEET_AGENT_REQUEST_FAILED", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
