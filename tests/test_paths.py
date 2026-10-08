import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import bgp
import parsers
import paths.alias as alias
import paths.enrich as enrich
import paths.export as paths_export
import paths.probe as probe
import paths.store as store
import query

try:
    import paths.graph as graphlib

    HAVE_NX = graphlib.nx is not None
except Exception:
    graphlib = None
    HAVE_NX = False

FIXTURE = Path(__file__).parent / "fixtures" / "paths" / "dublin_8.8.8.8.json"
SCAMPER_FIXTURE = Path(__file__).parent / "fixtures" / "paths" / "scamper_8.8.8.8.json"
ANNOUNCE_FIXTURE = Path(__file__).parent / "fixtures" / "others" / "routeviews_announcements.json"


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
    def _patch(self):
        saved = {}

        def swap(module, name, value):
            saved[(module, name)] = getattr(module, name)
            setattr(module, name, value)

        swap(query, "asn_of", lambda ip: {"asn": "15169", "prefix": "8.8.8.0/24", "source": "cymru.origin"})
        swap(query, "neighbours", lambda asn: [{"asn": 3356, "type": "left", "power": 9}, {"asn": 174, "type": "left", "power": 8}])
        swap(query, "peeringdb_net", lambda asn: 433)
        swap(query, "facilities", lambda net_id: [{"name": "Equinix Ashburn", "city": "Ashburn", "country": "US"}])
        swap(query, "ixps", lambda net_id: [{"name": "DE-CIX", "ix_id": 31}])
        swap(query, "fetch_parsed", lambda aid, ip="", context=None: {"routes": [{"prefix": "8.8.8.0/24", "origin_asn": 15169}]} if aid == "routeviews.prefix" else {})
        swap(bgp, "announcements", lambda prefix: [{"prefix": prefix, "origin_asn": 15169, "announcements": [
            {"peer_asn": 3356, "peer_addr": "80.249.209.192", "collector": "amsix.ams", "as_path": "3356 15169", "timestamp": "t"},
            {"peer_asn": 174, "peer_addr": "80.249.209.192", "collector": "route-views.linx", "as_path": "174 15169", "timestamp": "t"},
        ]}])
        swap(bgp, "collector", lambda name: {"name": name, "ipv4": "80.249.213.84", "lat": 52.36, "lng": 4.89, "country": "NL"})
        swap(alias, "default_resolver", lambda ip: None)
        return saved

    def _restore(self, saved):
        for (module, name), value in saved.items():
            setattr(module, name, value)

    def test_expand_offline(self):
        saved = self._patch()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                conn = store.open_store(os.path.join(tmp, "p.db"))
                graph = graphlib.interface_graph(hops())
                stats = enrich.expand(conn, "r1", graph, budget=1)
                counts = store.graph_counts(conn, "r1")
                conn.close()
        finally:
            self._restore(saved)

        self.assertEqual(stats["origin_edges"], 1)
        self.assertEqual(stats["as_edges"], 2)
        self.assertEqual(stats["facilities"], 1)
        self.assertEqual(stats["ixps"], 1)
        self.assertEqual(stats["sessions"]["sessions"], 2)
        self.assertEqual(stats["sessions"]["collectors"], 2)
        self.assertEqual(stats["aliased"]["80.249.209.192"], ["AS174", "AS3356"])
        self.assertEqual(counts["edges"]["session"]["distinct"], 2)


class BgpTest(unittest.TestCase):
    def setUp(self):
        self.routes = parsers.routeviews_announcements(ANNOUNCE_FIXTURE.read_text())["routes"]

    def test_sessions(self):
        facts = bgp.sessions(self.routes, cap=2)
        self.assertEqual(len(facts), 2)
        self.assertEqual(facts[0]["speaker_ip"], "80.249.209.192")
        self.assertEqual(facts[0]["speaker_asn"], 2119)
        self.assertEqual(facts[0]["as_path"], "2119 15169")

    def test_speaker_asns(self):
        self.assertEqual(bgp.speaker_asns(self.routes)["80.249.209.192"], {"2119"})

    def test_owns(self):
        self.assertTrue(bgp.owns("2119", "80.249.209.192", prefixes=["80.249.0.0/16"]))
        self.assertFalse(bgp.owns("2119", "80.249.209.192", prefixes=["1.0.0.0/8"]))


class AliasTest(unittest.TestCase):
    def test_router_token_strips_interface(self):
        self.assertEqual(alias.router_token("ae5.cr2.scl1.example.net"), ("cr2", "scl1.example.net"))
        self.assertEqual(alias.router_token("reverso.190.215.80.example.net"), ("reverso", "190.215.80.example.net"))
        self.assertIsNone(alias.router_token("localhost"))

    def test_rdns_pairs_and_clusters(self):
        rdns = {
            "10.0.0.1": "ae1.cr2.scl1.example.net",
            "10.0.0.2": "ae2.cr2.scl1.example.net",
            "10.0.0.3": "ae1.cr3.scl1.example.net",
        }
        clusters = alias.clusters(alias.rdns_pairs(rdns))
        self.assertEqual(clusters, [["10.0.0.1", "10.0.0.2"]])

    def test_machine_key_stable(self):
        self.assertEqual(alias.machine_key(["b", "a"]), alias.machine_key(["a", "b"]))


class ExportTest(unittest.TestCase):
    def test_build_and_render(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = store.open_store(os.path.join(tmp, "p.db"))
            store.save_run(conn, {"run_id": "r1", "target": "8.8.8.8", "src_ip": "1.2.3.4", "tool": "scamper", "started_at": "t"})
            store.add_node(conn, "interface", "8.8.8.8")
            store.add_node(conn, "as", "AS15169", {"asn": "15169"})
            store.add_edge(conn, "r1", "origin", "8.8.8.8", "AS15169", attrs={"source_url": "https://stat.ripe.net/8.8.8.8"})
            data = paths_export.build(conn, "r1")
            html = paths_export.render_html(conn, "r1")
            conn.close()

        self.assertEqual(len(data["nodes"]), 2)
        self.assertEqual(len(data["edges"]), 1)
        self.assertTrue(all("x" in node and "y" in node for node in data["nodes"]))
        self.assertEqual(data["edges"][0]["source_url"], "https://stat.ripe.net/8.8.8.8")
        self.assertNotIn("/*__PATHS_DATA__*/", html)
        self.assertIn("AS15169", html)


if __name__ == "__main__":
    unittest.main()
