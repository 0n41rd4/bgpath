import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import aranya

FIXTURE = Path(__file__).parent / "fixtures" / "ripestat_network_info.json"


class ParseTest(unittest.TestCase):
    def test_network_info(self):
        result = aranya.parse_network_info(FIXTURE.read_text())
        self.assertEqual(result["prefix"], "8.8.8.0/24")
        self.assertEqual(result["asns"], ["15169"])

    def test_empty_data(self):
        result = aranya.parse_network_info('{"data": {}}')
        self.assertIsNone(result["prefix"])
        self.assertEqual(result["asns"], [])

    def test_non_dict_payload(self):
        result = aranya.parse_network_info("[1, 2, 3]")
        self.assertIsNone(result["prefix"])
        self.assertEqual(result["asns"], [])


class StoreTest(unittest.TestCase):
    def test_save_fetch_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = aranya.open_store(str(Path(tmp) / "t.db"))
            aranya.save_fetch(conn, aranya.SOURCE, "http://example", 200, "{}", None)
            row = conn.execute("SELECT source, status, body FROM fetches").fetchone()
            conn.close()
        self.assertEqual(row, (aranya.SOURCE, 200, "{}"))


if __name__ == "__main__":
    unittest.main()
