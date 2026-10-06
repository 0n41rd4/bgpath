import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import parsers

FIXTURES = Path(__file__).parent / "fixtures" / "others"


def load(name: str) -> str:
    return (FIXTURES / name).read_text()


class NonRipeParserTest(unittest.TestCase):
    def test_rdns(self):
        self.assertEqual(parsers.rdns("dns.google"), {"hostname": "dns.google"})

    def test_cymru(self):
        r = parsers.cymru(load("cymru.json"))
        self.assertEqual(r["records"][0]["asn"], "15169")
        self.assertEqual(r["records"][0]["prefix"], "8.8.8.0/24")

    def test_rdap(self):
        r = parsers.rdap(load("rdap.json"))
        self.assertEqual(r["handle"], "NET-8-8-8-0-2")
        self.assertEqual(r["range"], "8.8.8.0-8.8.8.255")

    def test_internetdb(self):
        r = parsers.internetdb(load("internetdb.json"))
        self.assertEqual(r["hostnames"], ["dns.google", "cas.emarketer.com"])
        self.assertIn(53, r["ports"])

    def test_globalping(self):
        r = parsers.globalping(load("globalping.json"))
        self.assertTrue(r["results"])
        first = r["results"][0]
        self.assertIn("min_rtt", first)
        self.assertIn("country", first)

    def test_peeringdb_net(self):
        r = parsers.peeringdb_net(load("peeringdb_net.json"))
        self.assertEqual(r["net_id"], 433)
        self.assertEqual(r["name"], "Google LLC")

    def test_peeringdb_netfac(self):
        r = parsers.peeringdb_netfac(load("peeringdb_netfac.json"))
        self.assertTrue(r["facilities"])
        self.assertIn("city", r["facilities"][0])

    def test_peeringdb_netixlan(self):
        r = parsers.peeringdb_netixlan(load("peeringdb_netixlan.json"))
        self.assertTrue(r["ix"])
        self.assertIn("ipaddr4", r["ix"][0])

    def test_crtsh(self):
        r = parsers.crtsh(load("crtsh.json"))
        self.assertTrue(r["certificates"])
        self.assertEqual(r["certificates"][0]["common_name"], "dns.google")


class ToleranceTest(unittest.TestCase):
    def test_non_dict(self):
        self.assertIsNone(parsers.rdap("[1, 2]")["handle"])
        self.assertEqual(parsers.crtsh("{}"), {"certificates": []})

    def test_bad_json(self):
        with self.assertRaises(json.JSONDecodeError):
            parsers.rdap("not json")


if __name__ == "__main__":
    unittest.main()
