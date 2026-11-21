"""Parameter inventory is data: do not execute any imported BAT/command."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("local_catalog_import", ROOT / "tools/catalog/import-strategies.py")
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class LocalCatalogTests(unittest.TestCase):
    def test_release_inventory_has_every_general_and_provenance(self):
        c = json.loads((ROOT / "core/localstrategy/catalog.json").read_text())
        self.assertEqual(c["flowseal_release"], "1.10.4")
        self.assertEqual(len(c["flowseal_files"]), 22)
        self.assertEqual(len(c["flowseal_files"]), len(set(c["flowseal_files"])))
        self.assertEqual({s["id"] for s in c["sources"]}, {"flowseal", "zapret", "zapret2", "zapretgui"})
        for name in c["flowseal_files"]:
            self.assertTrue(any(r["file"] == name for r in c["rules"]))
        for source in c["sources"]:
            self.assertEqual(source["license"], "MIT")
            self.assertEqual(len(source["revision"]), 40)

    def test_caret_crlf_and_shell_text_are_only_parsed_not_executed(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "general.bat"
            p.write_bytes(b'@echo off\r\ndel important\r\n--filter-tcp=443 ^\r\n--dpi-desync=fake,multidisorder --dpi-desync-repeats=11 --dpi-desync-fake-tls="%BIN%fake.bin" --new ^\r\n--filter-udp=443 --dpi-desync=fake\r\n')
            rules = MOD.extract(p, "flowseal", "a" * 40)
            self.assertEqual(len(rules), 2)
            self.assertEqual(rules[0]["applies"], ["tcp443"])
            self.assertEqual(rules[1]["applies"], ["quic443"])
            self.assertEqual(rules[0]["options"]["dpi-desync-repeats"], ["11"])
            self.assertEqual(list(Path(temp).iterdir()), [p])
