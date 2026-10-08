import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import aggregate
import store


def seed(conn, rows):
    for ip, source, topic, key, value in rows:
        store.save_observation(conn, ip, source, source, "reported", topic, key, value)


class AggregateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = store.open_store(str(Path(self.tmp.name) / "t.db"))
        seed(self.conn, [
            ("8.8.8.8", "a", "ownership", "asn", "15169"),
            ("8.8.8.8", "b", "ownership", "asn", "15169"),
            ("8.8.8.8", "a", "location", "claim", {"city": "Mountain View", "country": "US"}),
            ("8.8.8.8", "b", "location", "claim", {"city": "Denver", "country": "US"}),
            ("8.8.8.8", "c", "location", "claim", {"latitude": 37.75, "longitude": -97.82}),
            ("1.1.1.1", "a", "ownership", "asn", "13335"),
            ("1.1.1.1", "b", "ownership", "asn", "15169"),
        ])

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def test_claim_label_location(self):
        self.assertEqual(
            aggregate.claim_label("location", "claim", {"city": "Ashburn", "country": "US"}),
            "Ashburn, US",
        )
        self.assertEqual(
            aggregate.claim_label("location", "claim", {"latitude": 37.75, "longitude": -97.82}),
            "37.75,-97.82",
        )

    def test_agreeing_asn(self):
        rows = {(s["topic"], s["key"]): s for s in aggregate.cell_summaries(self.conn, "8.8.8.8")}
        asn = rows[("ownership", "asn")]
        self.assertEqual(asn["verdict"], "agree")
        self.assertEqual(asn["consensus"], "15169")
        self.assertEqual(asn["backers"], ["a", "b"])

    def test_contested_location(self):
        rows = {(s["topic"], s["key"]): s for s in aggregate.cell_summaries(self.conn, "8.8.8.8")}
        claim = rows[("location", "claim")]
        self.assertEqual(claim["verdict"], "disagree")
        self.assertEqual(len(claim["labels"]), 3)

    def test_enumeration_flag(self):
        seed(self.conn, [
            ("9.9.9.9", "n", "facility", "facility", {"city": f"c{i}"})
            for i in range(5)
        ])
        rows = {(s["topic"], s["key"]): s for s in aggregate.cell_summaries(self.conn, "9.9.9.9")}
        self.assertTrue(rows[("facility", "facility")]["enumeration"])

    def test_overview(self):
        verdicts = aggregate.overview(self.conn, ["8.8.8.8", "1.1.1.1"])
        self.assertEqual(verdicts[("8.8.8.8", "ownership", "asn")], "agree")
        self.assertEqual(verdicts[("1.1.1.1", "ownership", "asn")], "disagree")

    def test_profile(self):
        profile = {row["source"]: row for row in aggregate.agreement_profile(self.conn, ["8.8.8.8"])}
        self.assertEqual(profile["a"]["cells"], 2)
        self.assertEqual(profile["a"]["agree"], 1)
        self.assertEqual(profile["a"]["dissent"], 1)


if __name__ == "__main__":
    unittest.main()
