import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from registry import store

from report import asn as report_asn


def _seed(conn, ip, topic, key, value, source="src"):
    store.save_observation(conn, ip, source, source, "reported", topic, key, value)


class RoutingSummaryTest(unittest.TestCase):
    def test_routing_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = store.open_store(os.path.join(tmp, "a.db"))
            _seed(conn, "8.8.8.8", "ownership", "asn", "3356")
            _seed(conn, "8.8.8.8", "routing", "announced-count", 1075, "ripestat.announced-prefixes")
            _seed(
                conn, "8.8.8.8", "routing", "ris",
                {"rrc": "RRC03", "location": "Amsterdam, NL", "paths": ["12956 3356", "2914 3356"],
                 "next_hops": ["213.140.36.189", "4.68.71.1"]},
                "ris.looking-glass",
            )
            _seed(
                conn, "8.8.8.8", "routing", "routeviews",
                {"collectors": ["amsix.ams", "linx.lon"], "as_paths": ["12956 3356"]},
                "routeviews.prefix",
            )
            _seed(
                conn, "8.8.8.8", "routing", "bgproutes",
                {"as_path": "553 12956 3356", "vp_label": "VP AS-X", "ixp_name": "AMS-IX", "vp_country": "NL"},
                "bgproutes.prefix",
            )
            summary = report_asn.routing_summary(conn, "8.8.8.8")
            conn.close()

        self.assertEqual(summary["origin_asn"], "3356")
        self.assertEqual(summary["announced"], 1075)
        self.assertEqual(summary["upstream_as"], "12956")
        self.assertEqual(summary["next_hops"][0], "213.140.36.189")
        self.assertTrue(any(o["source"] == "bgproutes.io" and o["location"] == "AMS-IX" for o in summary["observers"]))
        self.assertTrue(any(o["source"] == "RIPE RIS" and o["location"] == "RRC03 Amsterdam, NL" for o in summary["observers"]))


if __name__ == "__main__":
    unittest.main()
