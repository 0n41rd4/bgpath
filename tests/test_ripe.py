import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from registry import ripe

FIXTURES = Path(__file__).parent / "fixtures" / "ripe"


def load(name: str) -> str:
    return (FIXTURES / name).read_text()


class RipestatTest(unittest.TestCase):
    def test_network_info(self):
        r = ripe.network_info(load("network-info.json"))
        self.assertEqual(r["prefix"], "8.8.8.0/24")
        self.assertEqual(r["asns"], ["15169"])

    def test_geoloc(self):
        r = ripe.geoloc(load("geoloc.json"))
        self.assertTrue(r["locations"])
        first = r["locations"][0]
        self.assertEqual(first["country"], "US")
        self.assertIn("latitude", first)

    def test_as_overview(self):
        r = ripe.as_overview(load("as-overview.json"))
        self.assertEqual(r["asn"], "15169")
        self.assertEqual(r["holder"], "GOOGLE - Google LLC")
        self.assertTrue(r["announced"])

    def test_asn_neighbours(self):
        r = ripe.asn_neighbours(load("asn-neighbours.json"))
        self.assertEqual(r["asn"], "15169")
        self.assertGreater(len(r["neighbours"]), 0)
        self.assertIn("unique", r["neighbour_counts"])

    def test_looking_glass(self):
        r = ripe.looking_glass(load("looking-glass.json"))
        self.assertEqual(r["rrcs"][0]["rrc"], "RRC01")
        self.assertEqual(r["rrcs"][0]["peers"][0]["as_path"], "15692 2914 15169")
        self.assertEqual(r["rrcs"][0]["peers"][0]["prefix"], "8.8.8.0/24")


class IpmapTest(unittest.TestCase):
    def test_ipmap(self):
        r = ripe.ipmap(load("ipmap.json"))
        self.assertTrue(r["locations"])
        first = r["locations"][0]
        self.assertIn("city", first)
        self.assertIn("score", first)


class ToleranceTest(unittest.TestCase):
    def test_non_dict_payload(self):
        self.assertEqual(ripe.network_info("[1, 2]"), {"prefix": None, "asns": []})
        self.assertEqual(ripe.ipmap("[1, 2]"), {"locations": []})

    def test_bad_json(self):
        with self.assertRaises(json.JSONDecodeError):
            ripe.network_info("not json")


if __name__ == "__main__":
    unittest.main()
