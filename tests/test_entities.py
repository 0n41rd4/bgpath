import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import aggregate
import entities
import store


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
        self.assertTrue(entities.same_name("GOOGLE - Google LLC", "Google LLC"))
        self.assertFalse(entities.same_name("Google LLC", "GOGL"))

    def test_canonical_dispatch(self):
        self.assertEqual(entities.canonical("ownership", "asn", "AS15169"), 15169)
        self.assertEqual(entities.canonical("country", "country", "United States"), "US")
        self.assertEqual(entities.canonical("ownership", "name", "Google LLC"), "GOOGLE")

    def test_canonical_keeps_unparseable(self):
        self.assertEqual(entities.canonical("ownership", "asn", "GOOGL"), "GOOGL")
        self.assertEqual(entities.canonical("ownership", "range", "n/a"), "n/a")
        self.assertEqual(entities.canonical("ownership", "asn", None), None)


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

    def test_canonical_reduces_false_disagreement(self):
        raw = {(s["topic"], s["key"]): s["verdict"] for s in aggregate.cell_summaries(self.conn, "8.8.8.8")}
        canon = {(s["topic"], s["key"]): s["verdict"] for s in aggregate.canonical_cell_summaries(self.conn, "8.8.8.8")}
        self.assertEqual(raw[("ownership", "asn")], "agree")
        self.assertEqual(canon[("ownership", "asn")], "agree")
        self.assertEqual(canon[("country", "country")], "single")

    def test_canonical_merges_asn_forms(self):
        store.save_observation(self.conn, "8.8.8.8", "other", "Other", "reported", "ownership", "asn", "AS15169")
        canon = {(s["topic"], s["key"]): s for s in aggregate.canonical_cell_summaries(self.conn, "8.8.8.8")}
        self.assertEqual(canon[("ownership", "asn")]["consensus"], "15169")
        self.assertEqual(canon[("ownership", "asn")]["n_sources"], 3)

    def test_unparseable_asn_not_collapsed(self):
        store.save_observation(self.conn, "8.8.8.8", "x", "X", "reported", "ownership", "asn", "GOOGL")
        store.save_observation(self.conn, "8.8.8.8", "y", "Y", "reported", "ownership", "asn", "FOO")
        canon = {(s["topic"], s["key"]): s for s in aggregate.canonical_cell_summaries(self.conn, "8.8.8.8")}
        self.assertEqual(canon[("ownership", "asn")]["verdict"], "disagree")


if __name__ == "__main__":
    unittest.main()
