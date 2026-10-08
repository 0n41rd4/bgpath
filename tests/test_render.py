import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import render
import store


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

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def test_claim_view_plain(self):
        text = "\n".join(render.claim_view(self.conn, "8.8.8.8", color=False))
        self.assertIn("ownership.asn", text)
        self.assertIn("agree", text)
        self.assertIn("Mountain View, US", text)
        self.assertNotIn("\033[", text)

    def test_claim_view_colour(self):
        text = "\n".join(render.claim_view(self.conn, "8.8.8.8", color=True))
        self.assertIn("\033[", text)

    def test_overview_view(self):
        text = "\n".join(render.overview_view(self.conn, ["8.8.8.8"], color=False))
        self.assertIn("overview:", text)
        self.assertIn("legend:", text)
        self.assertIn("own.asn", text)

    def test_profile_view(self):
        text = "\n".join(render.profile_view(self.conn, ["8.8.8.8"], color=False))
        self.assertIn("agreement profile:", text)
        self.assertIn("cells", text)


if __name__ == "__main__":
    unittest.main()
