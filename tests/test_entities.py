import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from report import entities
from registry import store


class CanonicalTest(unittest.TestCase):
    def test_asn(self):
        self.assertEqual(entities.asn("AS15169"), 15169)
        self.assertEqual(entities.asn("15169"), 15169)
        self.assertEqual(entities.asn(15169), 15169)
        self.assertIsNone(entities.asn("GOOGL"))

    def test_country(self):
        self.assertEqual(entities.country("United States"), "US")
        self.assertEqual(entities.country("us"), "US")
        self.assertEqual(entities.country("US"), "US")
        self.assertEqual(entities.country("Germany"), "DE")

    def test_prefix_and_range(self):
        self.assertEqual(entities.prefix("8.8.8.0/24"), "8.8.8.0/24")
        self.assertEqual(entities.prefix("8.8.8.5/24"), "8.8.8.0/24")
        self.assertIsNone(entities.prefix("13312-15359"))
        self.assertEqual(entities.range_canon("8.8.8.0 - 8.8.8.255"), "8.8.8.0-8.8.8.255")

    def test_org(self):
        self.assertEqual(entities.org("GOOGLE - Google LLC"), "GOOGLE")
        self.assertEqual(entities.org("AS15169 Google LLC"), "GOOGLE")
        self.assertEqual(entities.org("Cloudflare, Inc."), "CLOUDFLARE")

class ResolveTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = store.open_store(str(Path(self.tmp.name) / "t.db"))
        rows = [
            ("ipinfo", "ownership", "asn", "15169"),
            ("ipinfo", "ownership", "org", "AS15169 Google LLC"),
            ("maxmind.asn", "ownership", "asn", "15169"),
            ("maxmind.asn", "ownership", "org", "Google LLC"),
            ("rdap", "ownership", "name", "GOGL"),
            ("rdap", "country", "country", "United States"),
            ("rdap", "ownership", "range", "8.8.8.0-8.8.8.255"),
            ("cymru.origin", "ownership", "prefix", "8.8.8.0/24"),
        ]
        for source, topic, key, value in rows:
            store.save_observation(self.conn, "8.8.8.8", source, source, "reported", topic, key, value)

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def test_resolve_entity(self):
        entity = entities.resolve(self.conn, "8.8.8.8")
        self.assertEqual([record["asn"] for record in entity["asn"]], [15169])
        self.assertEqual(entity["country"], ["US"])
        self.assertEqual(entity["prefix"], ["8.8.8.0/24"])
        self.assertEqual(entity["range"], ["8.8.8.0-8.8.8.255"])
        aliases = entity["aliases"]["15169"]
        self.assertEqual(sorted(entities.org(a) for a in aliases), ["GOOGLE", "GOOGLE"])
        self.assertEqual(entity["unlinked"], ["GOGL"])

if __name__ == "__main__":
    unittest.main()
