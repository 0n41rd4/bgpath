import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from registry import store


class StoreTest(unittest.TestCase):
    def test_save_fetch_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = store.open_store(str(Path(tmp) / "t.db"))
            fetch_id = store.save_fetch(conn, "src", "http://example", 200, "{}", None)
            row = conn.execute("SELECT id, source, status, body FROM fetches").fetchone()
            conn.close()
        self.assertEqual(fetch_id, row[0])
        self.assertEqual(row[1:], ("src", 200, "{}"))

    def test_save_observation_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = store.open_store(str(Path(tmp) / "t.db"))
            fetch_id = store.save_fetch(conn, "src", "http://example", 200, "{}", None)
            store.save_observation(
                conn, "8.8.8.8", "src", "up", "reported", "ownership", "asn", "15169", fetch_id
            )
            row = conn.execute(
                "SELECT ip, source, upstream, evidence_class, topic, key, value, fetch_id FROM observations"
            ).fetchone()
            conn.close()
        self.assertEqual(row[0], "8.8.8.8")
        self.assertEqual(row[1], "src")
        self.assertEqual(row[2], "up")
        self.assertEqual(row[3], "reported")
        self.assertEqual(row[4], "ownership")
        self.assertEqual(row[5], "asn")
        self.assertEqual(json.loads(row[6]), "15169")
        self.assertEqual(row[7], fetch_id)

    def test_views_exist(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = store.open_store(str(Path(tmp) / "t.db"))
            views = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='view'")}
            conn.close()
        self.assertTrue({"v_observations", "v_locations", "v_latency"} <= views)

    def test_v_locations_extracts_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = store.open_store(str(Path(tmp) / "t.db"))
            loc = {"city": "Ashburn", "country": "US", "latitude": 39.04, "longitude": -77.49}
            store.save_observation(conn, "8.8.8.8", "src", "up", "reported", "location", "claim", loc)
            row = conn.execute(
                "SELECT city, country, latitude, longitude FROM v_locations WHERE ip = '8.8.8.8'"
            ).fetchone()
            conn.close()
        self.assertEqual(row, ("Ashburn", "US", 39.04, -77.49))


if __name__ == "__main__":
    unittest.main()
