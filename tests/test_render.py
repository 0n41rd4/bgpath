import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from report import labels, render
from registry import store


class RenderTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = store.open_store(str(Path(self.tmp.name) / "t.db"))
        store.save_observation(self.conn, "8.8.8.8", "a", "a", "reported", "ownership", "asn", "15169")
        store.save_observation(self.conn, "8.8.8.8", "b", "b", "reported", "ownership", "asn", "15169")
        store.save_observation(
            self.conn, "8.8.8.8", "a", "a", "reported", "location", "claim",
            {"city": "Mountain View", "country": "US"},
        )
        store.save_observation(
            self.conn, "8.8.8.8", "b", "b", "reported", "location", "claim",
            {"city": "Denver", "country": "US"},
        )
        store.save_observation(
            self.conn, "8.8.8.8", "c", "c", "reported", "identity", "hostname", "dns.google",
        )
        store.save_observation(
            self.conn, "8.8.8.8", "routeviews.prefix", "RouteViews", "observed-passive",
            "routing", "routeviews",
            {"prefix": "8.8.8.0/24", "collectors": ["amsix.ams"], "as_paths": ["2119 15169"]},
        )
        store.save_observation(self.conn, "1.1.1.1", "c", "c", "reported", "ownership", "asn", "13335")
        store.save_observation(
            self.conn, "1.1.1.1", "c", "c", "reported", "identity", "hostname", "one.one.one.one",
        )

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def test_claim_labels_are_human_readable_and_unique(self):
        self.assertEqual(labels.claim_name("ownership", "asn"), "ASN")
        self.assertEqual(labels.claim_name("ownership", "name"), "AS Network name")
        self.assertEqual(labels.claim_name("directory", "website"), "AS Website")
        self.assertEqual(labels.claim_name("identity", "hostname"), "Hostname")
        self.assertIn("advertising this IP", labels.claim_description("ownership", "asn"))
        self.assertEqual(labels.claim_group("directory", "website"), "as")
        self.assertEqual(labels.claim_group("routing", "ris"), "routes")
        self.assertLess(labels.claim_priority("ownership", "asn"), labels.claim_priority("latency", "probe"))
        values = [labels.claim_name(topic, key) for topic, key in labels.CLAIM_LABELS]
        self.assertEqual(len(values), len(set(values)))

    def test_single_ip_report_is_human_readable(self):
        text = "\n".join(render.report_view(self.conn, ["8.8.8.8"], color=False))
        self.assertIn("AS15169", text)
        self.assertIn("Location", text)
        self.assertIn("RouteViews", text)
        self.assertEqual(text.count("Hostname"), 1)
        self.assertIn("contested", text)
        self.assertNotIn("ownership.", text)
        self.assertNotIn("location.", text)
        self.assertNotIn("facility.facility", text)

    def test_single_ip_report_colour(self):
        text = "\n".join(render.report_view(self.conn, ["8.8.8.8"], color=True))
        self.assertNotEqual(text, "\n".join(render.report_view(self.conn, ["8.8.8.8"], color=False)))

    def test_multi_ip_report(self):
        text = "\n".join(render.report_view(self.conn, ["8.8.8.8", "1.1.1.1"], color=False))
        self.assertIn("8.8.8.8", text)
        self.assertIn("1.1.1.1", text)
        self.assertIn("contested", text)
        self.assertIn("IP(s)", text)
        self.assertNotIn("ownership.", text)

    def test_summary_view(self):
        text = "\n".join(render.summary_view(self.conn, "8.8.8.8", color=False))
        self.assertIn("AS15169", text)
        self.assertNotIn("ownership.", text)

    def test_entities_view(self):
        text = "\n".join(render.entities_view(self.conn, "8.8.8.8", color=False))
        self.assertIn("asn", text)
        self.assertIn("15169", text)


if __name__ == "__main__":
    unittest.main()
