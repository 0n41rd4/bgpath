import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from source import asn as asn_mod


class AsnTest(unittest.TestCase):
    def test_announced_prefixes_merges_and_sorts(self):
        ripestat = [{"prefix": "4.0.0.0/9", "first_seen": "t1", "last_seen": "t2", "source": "RIPEstat"}]
        with mock.patch.object(asn_mod, "_announced_ripestat", return_value=ripestat), mock.patch.object(
            asn_mod.bgp, "prefixes_for_asn", return_value=["4.0.0.0/9", "171.75.0.0/16"]
        ):
            prefixes = asn_mod.announced_prefixes("3356")
        self.assertEqual([p["prefix"] for p in prefixes], ["171.75.0.0/16", "4.0.0.0/9"])

    def test_contains_prefix(self):
        with mock.patch.object(asn_mod, "announced_prefixes", return_value=[{"prefix": "4.0.0.0/9"}]):
            self.assertTrue(asn_mod.contains_prefix("3356", "4.2.2.2/24"))
            self.assertTrue(asn_mod.contains_prefix("3356", "4.0.0.0/9"))
            self.assertFalse(asn_mod.contains_prefix("3356", "1.1.1.0/24"))

    def test_announcement_locations(self):
        def fake_fetch(adapter_id, ip, context=None, refresh=False):
            if adapter_id == "routeviews.prefix":
                return {"routes": [{"prefix": "4.0.0.0/9", "origin_asn": "3356", "collectors": ["amsix.ams", "linx.lon"]}]}
            if adapter_id == "ris.looking-glass":
                return {"rrcs": [{"rrc": "RRC00", "location": "Amsterdam, NL", "peers": [{"as_path": "12956 3356", "prefix": "4.0.0.0/9"}]}]}
            if adapter_id == "bgproutes.prefix":
                return {"routes": [{"prefix": "4.0.0.0/9", "as_path": "553 12956 3356", "ixp_name": "AMS-IX", "vp_country": "NL", "org_name": "AS-X", "vp_label": "AS-X"}]}
            raise KeyError(adapter_id)

        with mock.patch.object(asn_mod.query, "fetch_parsed", side_effect=fake_fetch), mock.patch.object(
            asn_mod.query, "peeringdb_net", return_value=None
        ):
            locations = asn_mod.announcement_locations("3356", "4.0.0.0/9")
        self.assertEqual({o["source"] for o in locations["observers"]}, {"RouteViews", "RIPE RIS", "bgproutes.io"})
        self.assertTrue(any(o["location"] == "AMS-IX" for o in locations["observers"]))


if __name__ == "__main__":
    unittest.main()
