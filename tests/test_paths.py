import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import paths.enrich as enrich
import paths.probe as probe
import paths.store as store

try:
    import paths.graph as graphlib

    HAVE_NX = graphlib.nx is not None
except Exception:
    graphlib = None
    HAVE_NX = False

FIXTURE = Path(__file__).parent / "fixtures" / "paths" / "dublin_8.8.8.8.json"
SCAMPER_FIXTURE = Path(__file__).parent / "fixtures" / "paths" / "scamper_8.8.8.8.json"


def hops():
    return probe.parse_dublin(json.loads(FIXTURE.read_text()))


def scamper_hops():
    traces = [json.loads(line) for line in SCAMPER_FIXTURE.read_text().splitlines() if line.strip()]
    return probe.parse_scamper([obj for obj in traces if obj.get("type") == "trace"])


class ScamperTest(unittest.TestCase):
    def test_flows(self):
        self.assertEqual(sorted({hop["flow_id"] for hop in scamper_hops()}), [40001, 40002])

    def test_fields(self):
        hop = next(h for h in scamper_hops() if h["ttl"] == 1)
        self.assertEqual(hop["src_ip"], "192.168.1.254")
        self.assertEqual((hop["icmp_type"], hop["icmp_code"]), (11, 0))
        self.assertIsNotNone(hop["rtt_ms"])

    def test_last_hop(self):
        hop = next(h for h in scamper_hops() if h["is_last"])
        self.assertEqual(hop["src_ip"], "8.8.8.8")
        self.assertEqual((hop["icmp_type"], hop["icmp_code"]), (3, 3))

    def test_gap_preserved(self):
        ttls = sorted(h["ttl"] for h in scamper_hops() if h["flow_id"] == 40001)
        self.assertIn(2, [b - a for a, b in zip(ttls, ttls[1:])])


class ProbeTest(unittest.TestCase):
    def test_flows(self):
        self.assertEqual(sorted({hop["flow_id"] for hop in hops()}), [33434, 33435, 33436])

    def test_unanswered_ttls_kept(self):
        unanswered = [hop for hop in hops() if hop["flow_id"] == 33434 and hop["ttl"] in (3, 4)]
        self.assertEqual(len(unanswered), 2)
        self.assertTrue(all(hop["src_ip"] is None for hop in unanswered))

    def test_icmp_type_code_swap(self):
        hop = next(h for h in hops() if h["flow_id"] == 33434 and h["ttl"] == 1)
        self.assertEqual((hop["icmp_type"], hop["icmp_code"]), (11, 0))

    def test_last_hop(self):
        hop = next(h for h in hops() if h["flow_id"] == 33434 and h["is_last"])
        self.assertEqual(hop["src_ip"], "8.8.8.8")
        self.assertEqual((hop["icmp_type"], hop["icmp_code"]), (3, 3))


@unittest.skipUnless(HAVE_NX, "networkx not installed")
class GraphTest(unittest.TestCase):
    def setUp(self):
        self.graph = graphlib.interface_graph(hops())

    def test_nodes_and_edges(self):
        self.assertIn("8.8.8.8", self.graph)
        self.assertGreater(self.graph.number_of_edges(), 0)

    def test_ecmp_fanout(self):
        self.assertIn("72.14.194.218", graphlib.ecmp_nodes(self.graph))

    def test_gap_edge(self):
        self.assertTrue(self.graph["190.215.80.1"]["190.196.124.214"]["gap"])

    def test_persist_and_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = store.open_store(os.path.join(tmp, "p.db"))
            graphlib.persist(conn, "r1", self.graph)
            counts = store.graph_counts(conn, "r1")
            self.assertEqual(counts["edges"]["interface"]["distinct"], self.graph.number_of_edges())
            conn.close()


@unittest.skipUnless(HAVE_NX, "networkx not installed")
class EnrichTest(unittest.TestCase):
    def test_expand_offline(self):
        def fake(adapter_id, ip="", context=None):
            if adapter_id == "cymru.origin":
                return {"records": [{"asn": "15169", "prefix": "8.8.8.0/24", "country": "US"}]}
            if adapter_id == "ripestat.asn-neighbours":
                return {"neighbours": [{"asn": 3356, "type": "left", "power": 9}, {"asn": 174, "type": "left", "power": 8}]}
            if adapter_id == "peeringdb.net":
                return {"net_id": 433}
            if adapter_id == "peeringdb.netfac":
                return {"facilities": [{"name": "Equinix Ashburn", "city": "Ashburn", "country": "US"}]}
            if adapter_id == "peeringdb.netixlan":
                return {"ix": [{"name": "DE-CIX", "ix_id": 31}]}
            raise KeyError(adapter_id)

        original = enrich.fetch_parsed
        enrich.fetch_parsed = fake
        try:
            with tempfile.TemporaryDirectory() as tmp:
                conn = store.open_store(os.path.join(tmp, "p.db"))
                graph = graphlib.interface_graph(hops())
                stats = enrich.expand(conn, "r1", graph, budget=1)
                counts = store.graph_counts(conn, "r1")
                conn.close()
        finally:
            enrich.fetch_parsed = original

        self.assertEqual(stats["origin_edges"], 1)
        self.assertIn("15169", stats["asns"])
        self.assertEqual(stats["as_edges"], 2)
        self.assertEqual(stats["facilities"], 1)
        self.assertEqual(stats["ixps"], 1)
        self.assertEqual(counts["edges"]["as"]["distinct"], 2)


if __name__ == "__main__":
    unittest.main()
