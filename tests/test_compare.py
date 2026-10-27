import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import aranya
from report import compare
from registry import store
from test_pipeline import make_fetch


class ClassifyTest(unittest.TestCase):
    def test_agree(self):
        self.assertEqual(compare.classify({"15169": {"a", "b", "c"}}), "agree")

    def test_spread(self):
        self.assertEqual(compare.classify({"x": {"a"}, "y": {"a"}}), "spread")

    def test_disagree(self):
        self.assertEqual(compare.classify({"x": {"a"}, "y": {"b"}}), "disagree")

    def test_spread_is_displayed_as_set(self):
        self.assertEqual(compare.verdict_label("spread"), "set")
        self.assertEqual(compare.verdict_label("disagree"), "disagree")


class CompareTest(unittest.TestCase):
    def test_comparison_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = store.open_store(str(Path(tmp) / "t.db"))
            aranya.run_all(conn, "8.8.8.8", fetch=make_fetch())
            rows = compare.summarize(conn, "8.8.8.8")
            conn.close()

        by_key = {(row["topic"], row["key"]): row for row in rows}
        self.assertEqual(by_key[("ownership", "asn")]["verdict"], "agree")
        self.assertEqual(by_key[("location", "claim")]["verdict"], "disagree")
        self.assertIn(("identity", "hostname"), by_key)


if __name__ == "__main__":
    unittest.main()
