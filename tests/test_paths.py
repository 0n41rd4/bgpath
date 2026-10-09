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
import paths.analysis as analysis
import paths.enrich as enrich
import paths.export as paths_export
import paths.ingest as ingest
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
VOYAGE_FIXTURE = Path(__file__).parent / "fixtures" / "paths" / "voyage_flat_8.8.8.8.jsonl"
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


def voyage_hops():
    return probe.parse_voyage(VOYAGE_FIXTURE.read_text())


class VoyageTest(unittest.TestCase):
    def test_flows_and_protocol(self):
        hops = voyage_hops()
        self.assertEqual(sorted({hop["flow_id"] for hop in hops}), [24000, 24001])
        self.assertEqual(hops[0]["protocol"], "icmp")
        self.assertEqual(hops[0]["tool"], "voyage")

    def test_rtt_and_reply(self):
        hop = next(h for h in voyage_hops() if h["flow_id"] == 24000 and h["ttl"] == 1)
        self.assertEqual(hop["src_ip"], "192.168.1.254")
        self.assertAlmostEqual(hop["rtt_ms"], 0.5)
        self.assertEqual(hop["reply_ttl"], 254)

    @unittest.skipUnless(HAVE_NX, "networkx not installed")
    def test_multipath_fan(self):
        graph = graphlib.interface_graph(voyage_hops())
        successors = set(graph.successors("192.168.1.254"))
        self.assertEqual(successors, {"10.0.0.1", "10.0.0.2"})
        self.assertEqual(set(graph.predecessors("8.8.8.8")), {"10.0.0.1", "10.0.0.2"})
        self.assertIn("192.168.1.254", graphlib.ecmp_nodes(graph))


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


class AnalysisTest(unittest.TestCase):
    def test_ttl_trust_confidence(self):
        hops = [
            {"flow_id": 1, "ttl": 1, "src_ip": "a", "reply_ttl": 254, "rtt_ms": 1.0},
            {"flow_id": 2, "ttl": 1, "src_ip": "a", "reply_ttl": 254, "rtt_ms": 1.2},
            {"flow_id": 1, "ttl": 2, "src_ip": "b", "reply_ttl": 63, "rtt_ms": 2.0},
            {"flow_id": 1, "ttl": 3, "src_ip": "c", "reply_ttl": 63, "rtt_ms": 3.0},
            {"flow_id": 2, "ttl": 3, "src_ip": "c", "reply_ttl": 63, "rtt_ms": 3.1},
            {"flow_id": 1, "ttl": 4, "src_ip": "d", "reply_ttl": 64, "rtt_ms": 4.0},
            {"flow_id": 2, "ttl": 5, "src_ip": "d", "reply_ttl": 64, "rtt_ms": 5.0},
        ]
        trust = analysis.ttl_trust(hops)
        self.assertEqual(trust["a"]["flows"], 2)
        self.assertEqual(trust["a"]["return_hops"], 1)
        self.assertEqual(trust["d"]["ttls"], [4, 5])
        self.assertEqual(analysis.ttl_confidence(trust["a"], False)[0], "high")
        self.assertEqual(analysis.ttl_confidence(trust["b"], False)[0], "medium")
        self.assertEqual(analysis.ttl_confidence(trust["d"], False)[0], "low")
        self.assertEqual(analysis.ttl_confidence(trust["a"], True)[0], "medium")

    def test_same_place_and_facility(self):
        santiago = {"city": "Santiago", "country": "CL", "latitude": -33.45, "longitude": -70.66}
        miami = {"city": "Miami", "country": "US", "latitude": 25.76, "longitude": -80.19}
        self.assertTrue(analysis.same_place(santiago, dict(santiago))[0])
        self.assertFalse(analysis.same_place(santiago, miami)[0])
        self.assertTrue(analysis.facility_matches_place({"city": "Santiago", "country": "CL"}, santiago))
        self.assertFalse(analysis.facility_matches_place({"city": "Miami", "country": "US"}, santiago))


class IngestTest(unittest.TestCase):
    def test_parse_mtr(self):
        payload = {"report": {"hubs": [
            {"count": 1, "host": "192.168.1.1", "Avg": 0.5},
            {"count": 2, "host": "???", "Avg": 0.0},
            {"count": 3, "host": "8.8.8.8", "Avg": 5.0},
        ]}}
        hops = ingest.parse_mtr(payload)
        self.assertEqual([h["ttl"] for h in hops], [1, 2, 3])
        self.assertEqual(hops[0]["src_ip"], "192.168.1.1")
        self.assertIsNone(hops[1]["src_ip"])
        self.assertEqual(hops[0]["tool"], "mtr")
        self.assertEqual(hops[0]["protocol"], "icmp")

    def test_ingest_voyage_dispatch(self):
        hops = ingest.ingest_hops(str(VOYAGE_FIXTURE), "voyage")
        self.assertEqual(len(hops), 6)
        self.assertEqual(hops[0]["tool"], "voyage")

    def test_parse_traceroute(self):
        text = "traceroute to 8.8.8.8\n 1  _gateway (192.168.1.1)  0.532 ms  0.4 ms\n 2  * * *\n 3  8.8.8.8  5.1 ms\n"
        hops = ingest.parse_traceroute(text, protocol="udp")
        self.assertEqual([h["ttl"] for h in hops], [1, 2, 3])
        self.assertEqual(hops[0]["src_ip"], "192.168.1.1")
        self.assertEqual(hops[0]["name"], "_gateway")
        self.assertAlmostEqual(hops[0]["rtt_ms"], 0.532)
        self.assertIsNone(hops[1]["src_ip"])
        self.assertEqual(hops[2]["src_ip"], "8.8.8.8")

    @unittest.skipUnless(HAVE_NX, "networkx not installed")
    def test_provenance_merges(self):
        hops = [
            {"flow_id": 1, "ttl": 1, "src_ip": "a", "rtt_ms": 1.0, "protocol": "udp", "tool": "scamper"},
            {"flow_id": 1, "ttl": 2, "src_ip": "b", "rtt_ms": 2.0, "protocol": "udp", "tool": "scamper"},
            {"flow_id": 2, "ttl": 1, "src_ip": "a", "rtt_ms": 1.0, "protocol": "icmp", "tool": "mtr"},
            {"flow_id": 2, "ttl": 2, "src_ip": "b", "rtt_ms": 2.0, "protocol": "icmp", "tool": "mtr"},
        ]
        graph = graphlib.interface_graph(hops)
        data = graph["a"]["b"]
        self.assertEqual(data["protocols"], {"udp", "icmp"})
        self.assertEqual(data["tools"], {"scamper", "mtr"})
        self.assertEqual(data["count"], 2)


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
            store.save_hops(conn, "r1", [
                {"flow_id": 1, "ttl": 1, "src_ip": "1.2.3.4", "rtt_ms": 1.0, "icmp_type": 11, "icmp_code": 0, "is_last": False},
                {"flow_id": 1, "ttl": 2, "src_ip": "8.8.8.8", "rtt_ms": 5.0, "icmp_type": 3, "icmp_code": 3, "is_last": True},
            ])
            store.add_node(conn, "interface", "8.8.8.8")
            store.add_node(conn, "as", "AS15169", {"asn": "15169"})
            store.add_edge(conn, "r1", "interface", "1.2.3.4", "8.8.8.8", ttl=2, rtt_ms=5.0)
            store.add_edge(conn, "r1", "origin", "8.8.8.8", "AS15169", attrs={"source_url": "https://stat.ripe.net/8.8.8.8"})
            data = paths_export.build(conn, "r1")
            html = paths_export.render_html(conn, "r1")
            conn.close()

        self.assertEqual(len(data["hops"]), 2)
        self.assertEqual(len(data["edges"]), 1)
        self.assertTrue(all("x" in hop and "y" in hop for hop in data["hops"]))
        self.assertEqual([c["label"] for c in data["containers"]], ["AS15169"])
        self.assertNotIn("/*__PATHS_DATA__*/", html)
        self.assertIn("AS15169", html)

    def test_geo_suspected_facility(self):
        santiago = {"city": "Santiago", "country": "CL", "latitude": -33.45, "longitude": -70.66, "source": "ripestat.geoloc"}
        with tempfile.TemporaryDirectory() as tmp:
            conn = store.open_store(os.path.join(tmp, "p.db"))
            store.save_run(conn, {"run_id": "r1", "target": "2.2.2.2", "src_ip": "10.0.0.1", "tool": "scamper", "started_at": "t"})
            store.save_hops(conn, "r1", [
                {"flow_id": 1, "ttl": 1, "src_ip": "10.0.0.1", "rtt_ms": 1.0, "icmp_type": 11, "icmp_code": 0, "is_last": False, "reply_ttl": 254},
                {"flow_id": 1, "ttl": 2, "src_ip": "2.2.2.2", "rtt_ms": 5.0, "icmp_type": 3, "icmp_code": 3, "is_last": True, "reply_ttl": 63},
            ])
            store.add_node(conn, "interface", "10.0.0.1", {"geo": santiago})
            store.add_node(conn, "interface", "2.2.2.2", {"geo": dict(santiago)})
            store.add_node(conn, "as", "AS1", {"asn": "1", "name": "GTD"})
            store.add_node(conn, "as", "AS2", {"asn": "2"})
            store.add_node(conn, "facility", "FAC:SCL", {"name": "Ascenty SCL01", "city": "Santiago", "country": "CL"})
            store.add_edge(conn, "r1", "interface", "10.0.0.1", "2.2.2.2", ttl=2, rtt_ms=5.0)
            store.add_edge(conn, "r1", "origin", "10.0.0.1", "AS1")
            store.add_edge(conn, "r1", "origin", "2.2.2.2", "AS2")
            store.add_edge(conn, "r1", "facility", "AS1", "FAC:SCL")
            data = paths_export.build(conn, "r1")
            conn.close()

        edge = data["edges"][0]
        self.assertTrue(edge["handoff"]["geo"]["match"])
        self.assertEqual([f["name"] for f in edge["handoff"]["facilities"]], ["Ascenty SCL01"])
        self.assertEqual(edge["handoff"]["facilities"][0]["method"], "geo")
        hop = next(h for h in data["hops"] if h["id"] == "2.2.2.2")
        self.assertEqual(hop["ttl_confidence"], "medium")

    def test_handoff_intersection_and_ixp_port(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = store.open_store(os.path.join(tmp, "p.db"))
            store.save_run(conn, {"run_id": "r1", "target": "2.2.2.2", "src_ip": "10.0.0.1", "tool": "scamper", "started_at": "t"})
            store.save_hops(conn, "r1", [
                {"flow_id": 1, "ttl": 1, "src_ip": "10.0.0.1", "rtt_ms": 1.0, "icmp_type": 11, "icmp_code": 0, "is_last": False},
                {"flow_id": 1, "ttl": 2, "src_ip": "2.2.2.2", "rtt_ms": 5.0, "icmp_type": 3, "icmp_code": 3, "is_last": True},
            ])
            store.add_node(conn, "as", "AS1", {"asn": "1"})
            store.add_node(conn, "as", "AS2", {"asn": "2"})
            store.add_node(conn, "ix", "IX:10", {"name": "IX-A", "ix_id": 10})
            store.add_node(conn, "ix", "IX:20", {"name": "IX-B", "ix_id": 20})
            store.add_node(conn, "facility", "FAC:F1", {"name": "Equinix X", "city": "Ashburn"})
            store.add_edge(conn, "r1", "interface", "10.0.0.1", "2.2.2.2", ttl=2, rtt_ms=5.0)
            store.add_edge(conn, "r1", "origin", "10.0.0.1", "AS1")
            store.add_edge(conn, "r1", "origin", "2.2.2.2", "AS2")
            store.add_edge(conn, "r1", "ix", "AS1", "IX:10", attrs={"ipaddr4": "10.0.0.1"})
            store.add_edge(conn, "r1", "ix", "AS2", "IX:10")
            store.add_edge(conn, "r1", "ix", "AS1", "IX:20")
            store.add_edge(conn, "r1", "facility", "AS1", "FAC:F1")
            store.add_edge(conn, "r1", "facility", "AS2", "FAC:F1")
            data = paths_export.build(conn, "r1")
            conn.close()

        edge = data["edges"][0]
        self.assertEqual([x["name"] for x in edge["handoff"]["ixps"]], ["IX-A"])
        self.assertEqual([f["name"] for f in edge["handoff"]["facilities"]], ["Equinix X"])
        hop = next(h for h in data["hops"] if h["id"] == "10.0.0.1")
        self.assertEqual(hop["ix"]["name"], "IX-A")
        as1 = next(c for c in data["containers"] if c["label"] == "AS1")
        self.assertEqual(as1["info"]["total_ixps"], 2)
        self.assertEqual([x["name"] for x in as1["info"]["ixps"]], ["IX-A"])


if __name__ == "__main__":
    unittest.main()
