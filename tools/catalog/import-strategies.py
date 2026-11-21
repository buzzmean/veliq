#!/usr/bin/env python3
"""Offline parameter inventory, never execute source scripts or read fake files."""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess


def revision(root):
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def extract(path, source, rev):
    text = path.read_text(encoding="utf-8-sig", errors="strict").replace("^\n", " ")
    rules = []
    for block in re.split(r"--new\b", text):
        matches = re.findall(r'--([a-z0-9-]+)(?:=("[^"\r\n]*"|[^\s]+))?', block)
        options = {}
        for key, value in matches:
            if key.startswith("dpi-desync") or key in ("filter-tcp", "filter-udp", "filter-l7", "hostlist-domains", "hostlist", "ip-id"):
                options.setdefault(key, []).append(value.strip('"'))
        if "dpi-desync" not in options:
            continue
        tcp, udp = options.get("filter-tcp", [""])[0], options.get("filter-udp", [""])[0]
        applies = [name for name, ports in (("tcp80", tcp), ("tcp443", tcp), ("quic443", udp)) if name.removeprefix("tcp").removeprefix("quic") in ports.split(",")]
        if not applies:
            continue
        raw = json.dumps(options, sort_keys=True, separators=(",", ":"))
        rules.append(dict(id=source + "-" + hashlib.sha256((path.name + raw).encode()).hexdigest()[:12], source=source, revision=rev, file=path.name, applies=applies, options=options))
    return rules


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--flowseal", type=pathlib.Path, required=True)
    p.add_argument("--zapret", type=pathlib.Path, required=True)
    p.add_argument("--zapret2", type=pathlib.Path, required=True)
    p.add_argument("--zapretgui", type=pathlib.Path, required=True)
    p.add_argument("--output", type=pathlib.Path, required=True)
    a = p.parse_args()
    sources = []
    for name, root in (("flowseal", a.flowseal), ("zapret", a.zapret), ("zapret2", a.zapret2), ("zapretgui", a.zapretgui)):
        sources.append(dict(id=name, revision=revision(root), license="MIT", url="https://github.com/" + {"flowseal": "Flowseal/zapret-discord-youtube", "zapret": "bol-van/zapret", "zapret2": "bol-van/zapret2", "zapretgui": "zapret-discordyoutube/zapretgui"}[name]))
    rules = []
    files = sorted(a.flowseal.glob("general*.bat"))
    if len(files) < 10:
        raise ValueError("FLOWSEAL_GENERAL_INVENTORY_INCOMPLETE")
    for path in files:
        rules += extract(path, "flowseal", sources[0]["revision"])
    # These are concepts/parameters, not copied shell/Python/Lua implementation.
    for source, source_file, variants in [
        ("zapret", "blockcheck.sh", ["multisplit", "multidisorder", "fake,multisplit", "fake,fakedsplit", "fake,fakeddisorder", "hostfakesplit"]),
        ("zapret2", "blockcheck2.d/standard", ["fake,multisplit", "fake,fakedsplit", "fake,hostfakesplit", "quic-fake"]),
        ("zapretgui", "src/presets/builtin/winws1", ["fake,multisplit", "fake,multidisorder"]),
    ]:
        rev = next(s["revision"] for s in sources if s["id"] == source)
        for mode in variants:
            rules.append(dict(id=source+"-"+mode.replace(",","-"),source=source,revision=rev,file=source_file,applies=["quic443" if mode=="quic-fake" else "tcp443"], options={"dpi-desync":[mode],"dpi-desync-split-pos":["1,midsld"],"dpi-desync-fooling":["badseq"],"dpi-desync-repeats":["6"]}))
    document = dict(version=1, reviewed="2026-10-23", flowseal_release="1.10.4", flowseal_files=[p.name for p in files], sources=sources, rules=rules)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(document,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print("parameter inventory: files=%d rules=%d; no binaries/templates copied" % (len(files),len(rules)))


if __name__ == "__main__":
    main()
