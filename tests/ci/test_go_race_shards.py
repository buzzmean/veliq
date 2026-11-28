import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("go_race_shards", Path(__file__).resolve().parents[2] / "tools/ci/go_race_shards.py")
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)


class RaceShardContract(unittest.TestCase):
    def test_every_test_example_and_seed_is_in_exactly_one_shard(self):
        names = ["TestPayment", "TestPostgres5000", "TestActivation", "ExampleAccount", "FuzzInput", "Test", "Example", "Fuzz"]
        shards = ci.partition(names)
        self.assertEqual(sorted(sum(shards, [])), sorted(names))
        self.assertFalse(set(shards[0]) & set(shards[1]))
        self.assertEqual(shards, ci.partition(list(reversed(names))))

    def test_duplicate_and_empty_plan_are_errors(self):
        for names in ([], ["TestOnly"], ["TestSame", "TestSame"]):
            with self.subTest(names=names), self.assertRaises(ValueError):
                ci.partition(names)

    def test_unstarted_planned_case_cannot_be_pass(self):
        with self.assertRaisesRegex(RuntimeError, "NOT_EXECUTED"):
            ci.check_coverage(["TestOne", "TestTwo"], {"TestOne"}, False, 0)

    def test_unplanned_case_or_failure_cannot_be_pass(self):
        with self.assertRaisesRegex(RuntimeError, "NOT_EXECUTED"):
            ci.check_coverage(["TestOne"], {"TestOne", "TestOther"}, False, 0)
        for failed, code in [(True, 0), (False, 1), (True, 1)]:
            with self.subTest(failed=failed, code=code), self.assertRaisesRegex(RuntimeError, "GO_RACE_FAILED"):
                ci.check_coverage(["TestOne"], {"TestOne"}, failed, code)

    def test_complete_successful_plan_is_accepted(self):
        ci.check_coverage(["TestOne", "TestTwo"], {"TestTwo", "TestOne"}, False, 0)


if __name__ == "__main__":
    unittest.main()
