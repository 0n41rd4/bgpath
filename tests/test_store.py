import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import store


class StoreTest(unittest.TestCase):
    def test_save_fetch_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = store.open_store(str(Path(tmp) / "t.db"))
            store.save_fetch(conn, "src", "http://example", 200, "{}", None)
            row = conn.execute("SELECT source, status, body FROM fetches").fetchone()
            conn.close()
        self.assertEqual(row, ("src", 200, "{}"))


if __name__ == "__main__":
    unittest.main()
