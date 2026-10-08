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

    def test_ipinfo(self):
        r = parsers.ipinfo(load("ipinfo.json"))
        self.assertEqual(r["org"], "AS15169 Google LLC")
        self.assertEqual(r["hostname"], "dns.google")
        self.assertEqual(r["latitude"], 38.0088)
        self.assertEqual(r["asn"], "15169")
        self.assertIs(r["anycast"], True)

    def test_shodan(self):
        r = parsers.shodan(load("shodan.json"))
        self.assertEqual(r["hostnames"], ["dns.google"])
        self.assertIn(53, r["ports"])
        self.assertEqual(r["country"], "United States")

    def test_mmdb(self):
        r = parsers.mmdb(load("mmdb.json"))
        self.assertEqual(r["country"], "US")
        self.assertEqual(r["city"], "Mountain View")
        self.assertEqual(r["latitude"], 37.4056)

    def test_mmdb_asn(self):
        r = parsers.mmdb_asn(load("mmdb_asn.json"))
        self.assertEqual(r["asn"], "15169")
        self.assertEqual(r["org"], "Google LLC")

    def test_ipwhois(self):
        r = parsers.ipwhois(load("ipwhois.json"))
        self.assertEqual(r["asn"], "15169")
        self.assertEqual(r["org"], "Google LLC")
        self.assertEqual(r["country"], "US")
        self.assertEqual(r["city"], "San Jose")

    def test_ipguide(self):
        r = parsers.ipguide(load("ipguide.json"))
        self.assertEqual(r["asn"], "15169")
        self.assertEqual(r["prefix"], "8.8.8.0/24")
        self.assertEqual(r["name"], "Google LLC")
        self.assertEqual(r["country"], "US")

    def test_routeviews_prefix(self):
        r = parsers.routeviews_prefix(load("routeviews_prefix.json"))
        prefixes = [route["prefix"] for route in r["routes"]]
        self.assertEqual(prefixes, ["8.8.8.0/24", "8.0.0.0/12", "0.0.0.0/0"])
        best = r["routes"][0]
        self.assertEqual(best["origin_asn"], 15169)
        self.assertEqual(best["rpki_state"], "valid")
        self.assertTrue(best["as_paths"])

    def test_atlas_ping(self):
        r = parsers.atlas_ping(load("atlas.json"))
        self.assertTrue(r["results"])
        first = r["results"][0]
        self.assertIsInstance(first["prb_id"], int)
        self.assertIsInstance(first["avg_rtt"], float)

    def test_irr(self):
        r = parsers.irr(load("irr.txt"))
        self.assertTrue(r["objects"])
        first = r["objects"][0]
        self.assertEqual(first["prefix"], "8.8.8.0/24")
        self.assertEqual(first["origin"], "AS15169")


class ToleranceTest(unittest.TestCase):
    def test_non_dict(self):
        self.assertIsNone(parsers.rdap("[1, 2]")["handle"])
        self.assertEqual(parsers.crtsh("{}"), {"certificates": []})

    def test_bad_json(self):
        with self.assertRaises(json.JSONDecodeError):
            parsers.rdap("not json")


if __name__ == "__main__":
    unittest.main()
