import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import analyze
from registry import store


class AnalyzeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = store.open_store(str(Path(self.tmp.name) / "t.db"))
        rows = [
            ("8.8.8.8", "a", "ownership", "asn", "15169"),
            ("8.8.8.8", "b", "ownership", "asn", "15169"),
            ("8.8.8.8", "a", "location", "claim", {"city": "Amsterdam", "country": "NL"}),
            ("8.8.8.8", "b", "location", "claim", {"city": "Denver", "country": "US"}),
            ("9.9.9.9", "a", "ownership", "asn", "64500"),
            ("9.9.9.9", "a", "location", "claim", {"latitude": 1.0, "longitude": 2.0}),
            ("9.9.9.9", "a", "location", "claim", {"latitude": 3.0, "longitude": 4.0}),
            ("9.9.9.9", "a", "location", "claim", {"latitude": 5.0, "longitude": 6.0}),
            ("9.9.9.9", "a", "location", "claim", {"latitude": 7.0, "longitude": 8.0}),
            ("9.9.9.9", "a", "location", "claim", {"latitude": 9.0, "longitude": 10.0}),
            ("9.9.9.9", "a", "location", "claim", {"latitude": 11.0, "longitude": 12.0}),
        ]
        for ip, source, topic, key, value in rows:
            store.save_observation(self.conn, ip, source, source, "reported", topic, key, value)

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def test_verdicts(self):
        data = analyze.stats(self.conn)
        self.assertEqual(data["claims"], 4)
        self.assertEqual(data["verdicts"]["agree"], 1)
        self.assertEqual(data["verdicts"]["disagree"], 1)
        self.assertEqual(data["verdicts"]["spread"], 1)
        self.assertEqual(data["verdicts"]["single"], 1)

    def test_top_disagreement(self):
        data = analyze.stats(self.conn)
        top = data["disagreements"][0]
        self.assertEqual((top["topic"], top["key"]), ("location", "claim"))
        self.assertEqual(top["cells"], 2)
        self.assertEqual(top["contested"], 2)
        self.assertEqual(top["rate"], 1.0)

    def test_anycast_detection(self):
        data = analyze.stats(self.conn)
        self.assertEqual(data["anycast"][0]["ip"], "9.9.9.9")
        self.assertEqual(data["anycast"][0]["values"], 6)

    def test_scoped_to_ip(self):
        data = analyze.stats(self.conn, ["8.8.8.8"])
        self.assertEqual(data["claims"], 2)
        self.assertEqual(data["anycast"], [])

    def test_normalize_reduces_disagreement(self):
        store.save_observation(self.conn, "4.4.4.4", "a", "A", "reported", "ownership", "asn", "AS15169")
        store.save_observation(self.conn, "4.4.4.4", "b", "B", "reported", "ownership", "asn", "15169")
        raw = analyze.stats(self.conn, ["4.4.4.4"])
        norm = analyze.stats(self.conn, ["4.4.4.4"], normalize=True)
        self.assertEqual(raw["verdicts"].get("disagree"), 1)
        self.assertEqual(norm["verdicts"].get("agree"), 1)


if __name__ == "__main__":
    unittest.main()
