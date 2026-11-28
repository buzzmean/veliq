"""Run every package/test with race and a bounded per-process deadline.

Control-plane tests have many independent PostgreSQL fixtures. Partition their
top-level names, not assertions or subtests, so a growing package cannot exhaust
its cumulative deadline just before a short final test. Every listed test must
actually start; there are no exclusions, retries or larger individual budgets.
"""
import collections
import json
import os
from pathlib import Path
import re
import subprocess
import sys

CP = "github.com/buzzmean/veliq/services/control-plane"


def partition(names):
    names = sorted(names)
    if len(names) < 2 or len(set(names)) != len(names):
        raise ValueError("INVALID_OR_DUPLICATE_TEST_PLAN")
    shards = [names[::2], names[1::2]]
    if set(shards[0]) & set(shards[1]) or set().union(*map(set, shards)) != set(names):
        raise ValueError("TEST_PLAN_COVERAGE_INVALID")
    return shards


def check_coverage(planned, observed, failed, code):
    if code != 0 or failed:
        raise RuntimeError("GO_RACE_FAILED")
    if planned is not None and set(planned) != set(observed):
        raise RuntimeError("GO_TEST_PLAN_NOT_EXECUTED: missing=" + repr(sorted(set(planned) - set(observed))) +
                           " unexpected=" + repr(sorted(set(observed) - set(planned))))


def run(packages, names=None):
    command = ["go", "test", "-race", "-count=1", "-json", "-timeout", "120s"]
    if names is not None:
        command += ["-run", "^(?:" + "|".join(re.escape(name) for name in names) + ")$"]
    command += packages
    observed, failed = set(), False
    counts = collections.Counter()
    tail = collections.deque(maxlen=35)
    child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8")
    for line in child.stdout:
        tail.append(line.rstrip())
        try:
            event = json.loads(line)
        except ValueError:
            continue
        test, action = event.get("Test"), event.get("Action")
        if test and action == "run" and "/" not in test:
            observed.add(test)
        if test and action in ("pass", "skip", "fail"):
            counts[action] += 1
        if action == "fail":
            failed = True
    code = child.wait()
    try:
        check_coverage(names, observed, failed, code)
    except RuntimeError:
        print("\n".join(tail), file=sys.stderr)
        raise
    result = {"packages": packages, "planned_top_level": len(names) if names is not None else None,
              "observed_top_level": len(observed), "test_results_including_subtests": dict(counts),
              "race": True, "timeout_seconds": 120, "cache": False, "result": "PASS"}
    print(json.dumps(result), flush=True)
    return result


def main():
    if not os.environ.get("VELIQ_TEST_DATABASE_URL"):
        raise RuntimeError("REAL_ISOLATED_CP_DATABASE_REQUIRED")
    packages = subprocess.check_output(["go", "list", "./..."], text=True).splitlines()
    if CP not in packages or len(packages) != len(set(packages)):
        raise RuntimeError("CONTROL_PLANE_PACKAGE_NOT_LISTED")
    listed = subprocess.check_output(["go", "test", "-list", ".", CP], text=True)
    names = [line for line in listed.splitlines() if re.fullmatch(r"(?:Test|Example|Fuzz)\w*", line)]
    shards = partition(names)
    out = Path(".e2e/go-race-shards.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    plan = {"packages": packages, "control_plane_shards": shards, "per_process_timeout_seconds": 120,
            "all_listed_CP_tests_required": True, "source": os.environ.get("GITHUB_SHA", "local"), "results": []}
    out.write_text(json.dumps(plan, indent=2) + "\n")
    plan["results"].append(run([package for package in packages if package != CP]))
    for shard in shards:
        plan["results"].append(run([CP], shard))
    plan["result"] = "PASS"
    out.write_text(json.dumps(plan, indent=2) + "\n")


if __name__ == "__main__":
    main()
