import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from source import bgp, query, topology

import paths.analysis as analysis
import paths.enrich as enrich
import paths.export as paths_export
import paths.ingest as ingest
import paths.probe as probe
import paths.store as store
import paths.__main__ as paths_cli

try:
    import paths.graph as graphlib

    HAVE_NX = graphlib.nx is not None
except Exception:
    graphlib = None
    HAVE_NX = False

FIXTURE = Path(__file__).parent / "fixtures" / "paths" / "dublin_8.8.8.8.json"
SCAMPER_FIXTURE = Path(__file__).parent / "fixtures" / "paths" / "scamper_8.8.8.8.json"
VOYAGE_FIXTURE = Path(__file__).parent / "fixtures" / "paths" / "voyage_flat_8.8.8.8.jsonl"

TARGET = "41.222.2.1"


def hops():
    return probe.parse_dublin(json.loads(FIXTURE.read_text()))


def scamper_hops():
    traces = [json.loads(line) for line in SCAMPER_FIXTURE.read_text().splitlines() if line.strip()]
    return probe.parse_scamper([obj for obj in traces if obj.get("type") == "trace"])


def voyage_hops():
    return probe.parse_voyage(VOYAGE_FIXTURE.read_text())


class PingTest(unittest.TestCase):
    def test_parse_ok(self):
        text = (
            "PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.\n"
            "64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=14.1 ms\n"
            "--- 8.8.8.8 ping statistics ---\n"
            "1 packets transmitted, 1 received, 0% packet loss, time 0ms\n"
            "rtt min/avg/max/mdev = 14.063/14.123/14.183/0.048 ms\n"
        )
        result = probe.parse_ping_output(text, 0)
        self.assertTrue(result["reachable"])
        self.assertEqual(result["loss_percent"], 0.0)
        self.assertEqual(result["rtt_min_ms"], 14.063)
        self.assertEqual(result["rtt_avg_ms"], 14.123)

    def test_parse_unreachable(self):
        text = "--- 8.8.8.8 ping statistics ---\n3 packets transmitted, 0 received, 100% packet loss, time 0ms\n"
        result = probe.parse_ping_output(text, 1)
        self.assertFalse(result["reachable"])
        self.assertEqual(result["loss_percent"], 100.0)

    def test_parse_fractional_loss(self):
        text = "3 packets transmitted, 2 received, 33.3333% packet loss, time 2003ms\n"
        result = probe.parse_ping_output(text, 0)
        self.assertTrue(result["reachable"])
        self.assertAlmostEqual(result["loss_percent"], 33.3333)


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


class VoyageTest(unittest.TestCase):
    def test_flows_and_protocol(self):
        parsed = voyage_hops()
        self.assertEqual(sorted({hop["flow_id"] for hop in parsed}), [24000, 24001])
        self.assertEqual(parsed[0]["protocol"], "icmp")
        self.assertEqual(parsed[0]["tool"], "voyage")

    @unittest.skipUnless(HAVE_NX, "networkx not installed")
    def test_multipath_fan(self):
        graph = graphlib.interface_graph(voyage_hops())
        self.assertEqual(set(graph.successors("192.168.1.254")), {"10.0.0.1", "10.0.0.2"})


class ProbeTest(unittest.TestCase):
    def test_flows(self):
        self.assertEqual(sorted({hop["flow_id"] for hop in hops()}), [33434, 33435, 33436])

    def test_unanswered_ttls_kept(self):
        unanswered = [hop for hop in hops() if hop["flow_id"] == 33434 and hop["ttl"] in (3, 4)]
        self.assertEqual(len(unanswered), 2)
        self.assertTrue(all(hop["src_ip"] is None for hop in unanswered))


@unittest.skipUnless(HAVE_NX, "networkx not installed")
class GraphTest(unittest.TestCase):
    def setUp(self):
        self.graph = graphlib.interface_graph(hops())

    def test_nodes_and_edges(self):
        self.assertIn("8.8.8.8", self.graph)
        self.assertGreater(self.graph.number_of_edges(), 0)

    def test_repeated_ttl_replies_do_not_cross_product(self):
        graph = graphlib.interface_graph([
            {"flow_id": 1, "ttl": 1, "src_ip": "10.0.0.1", "rtt_ms": 1.0},
            {"flow_id": 1, "ttl": 1, "src_ip": "10.0.0.2", "rtt_ms": 2.0},
            {"flow_id": 1, "ttl": 2, "src_ip": "10.0.1.1", "rtt_ms": 3.0},
            {"flow_id": 1, "ttl": 2, "src_ip": "10.0.1.2", "rtt_ms": 4.0},
        ])
        self.assertEqual(list(graph.edges), [("10.0.0.1", "10.0.1.1")])

    def test_ecmp_fanout(self):
        self.assertIn("72.14.194.218", graphlib.ecmp_nodes(self.graph))

    def test_vantage_origin_skips_private(self):
        graph = graphlib.interface_graph(
            [
                {"flow_id": 1, "ttl": 1, "src_ip": "192.168.1.1", "rtt_ms": 1.0},
                {"flow_id": 1, "ttl": 3, "src_ip": "93.184.216.34", "rtt_ms": 10.0},
                {"flow_id": 1, "ttl": 4, "src_ip": "1.1.1.1", "rtt_ms": 20.0},
            ],
            vantage="8.8.8.8",
        )
        self.assertNotIn("192.168.1.1", graph)
        self.assertIn("8.8.8.8", graph)
        self.assertTrue(graph.has_edge("8.8.8.8", "93.184.216.34"))
        self.assertFalse(graph.has_edge("192.168.1.1", "93.184.216.34"))

    def test_gap_edge_stays_within_flow(self):
        self.assertTrue(self.graph["190.215.80.1"]["190.196.124.214"]["gap"])
        self.assertTrue(self.graph.has_edge("192.168.1.254", "190.215.80.1"))


@unittest.skipUnless(HAVE_NX, "networkx not installed")
class EnrichTest(unittest.TestCase):
    def _hops(self):
        return [
            {"flow_id": 1, "ttl": 1, "src_ip": "10.0.0.1", "rtt_ms": 1.0, "protocol": "udp", "tool": "scamper"},
            {"flow_id": 1, "ttl": 2, "src_ip": "10.0.0.2", "rtt_ms": 2.0, "protocol": "udp", "tool": "scamper"},
        ]

    def _patch(self):
        saved = {}

        def swap(module, name, value):
            saved[(module, name)] = getattr(module, name)
            setattr(module, name, value)

        swap(query, "asn_of", lambda ip: {"asn": "1" if ip == "10.0.0.1" else "2", "source": "cymru.origin"})
        swap(query, "as_name", lambda asn: {"1": "AS One", "2": "AS Two"}.get(asn))
        swap(query, "geo", lambda ip: None)
        swap(topology, "neighbour_map", lambda asn: {})
        swap(topology, "target_paths", lambda ip, prefix=None, with_bgproutes=True: [])
        swap(query, "peeringdb_net", lambda asn: {"1": 100, "2": 200}.get(asn))
        swap(
            query,
            "facilities",
            lambda net_id: [{"fac_id": 1, "name": "Equinix X", "city": "Ashburn", "country": "US"}],
        )
        swap(query, "ixps", lambda net_id: [{"ix_id": 10, "name": "IX-A"}])
        swap(bgp, "owns", lambda asn, ip, prefixes=None: asn == 1)
        return saved

    def _restore(self, saved):
        for (module, name), value in saved.items():
            setattr(module, name, value)

    def test_expand_annotates_handoff(self):
        saved = self._patch()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                conn = store.open_store(os.path.join(tmp, "p.db"))
                graph = graphlib.interface_graph(self._hops())
                stats = enrich.expand(conn, "r1", graph, TARGET)
                row = conn.execute(
                    "SELECT attrs FROM edges WHERE run_id = 'r1' AND layer = 'interface' "
                    "AND src = '10.0.0.1' AND dst = '10.0.0.2'"
                ).fetchone()
                conn.close()
        finally:
            self._restore(saved)

        self.assertEqual(stats["handoffs"], 1)
        self.assertEqual(stats["asns"], ["1", "2"])
        handoff = json.loads(row[0])["handoff"]
        self.assertEqual(handoff["from_as"], "1")
        self.assertEqual([f["name"] for f in handoff["facilities"]], ["Equinix X"])
        self.assertEqual([x["name"] for x in handoff["ixps"]], ["IX-A"])
        self.assertTrue(handoff["announces_dest"])

    def test_expand_marks_confirmed_peering(self):
        saved = self._patch()
        try:
            with mock.patch.object(
                query, "asn_of",
                lambda ip: {"asn": "1" if ip == "10.0.0.1" else "2", "country": "ES", "source": "cymru.origin"},
            ), mock.patch.object(query, "geo", lambda ip: None), mock.patch.object(
                topology, "neighbour_map",
                lambda asn: {"1": {"2": {"type": "left", "power": 100}}, "2": {"1": {"type": "left", "power": 100}}}.get(asn, {}),
            ), mock.patch.object(
                topology, "target_paths",
                lambda ip, prefix=None, with_bgproutes=True: [
                    {"source": "bgproutes.io", "as_path": "1 2", "detail": "VP AS9999", "vp_label": "VP AS9999"},
                ],
            ):
                with tempfile.TemporaryDirectory() as tmp:
                    conn = store.open_store(os.path.join(tmp, "p.db"))
                    graph = graphlib.interface_graph(self._hops())
                    enrich.expand(conn, "r1", graph, "10.0.0.2")
                    row = conn.execute(
                        "SELECT attrs FROM edges WHERE run_id = 'r1' AND src = '10.0.0.1' AND dst = '10.0.0.2'"
                    ).fetchone()
                    conn.close()
        finally:
            self._restore(saved)

        handoff = json.loads(row[0])["handoff"]
        self.assertTrue(handoff["confirmed"])
        self.assertEqual(handoff["adjacency"][0]["source"], "bgproutes.io")
        self.assertTrue(handoff["neighbours"])
        self.assertTrue(handoff["geo"]["match"])


class RetryTest(unittest.TestCase):
    def test_retry_only_when_cap_was_hit(self):
        capped = [{"ttl": 32, "src_ip": "10.0.0.1"}]
        self.assertTrue(paths_cli._should_retry_ttl(capped, TARGET, 32))
        self.assertFalse(paths_cli._should_retry_ttl(capped, TARGET, 64))
        self.assertFalse(paths_cli._should_retry_ttl([{"ttl": 20, "src_ip": "10.0.0.1"}], TARGET, 32))
        self.assertFalse(paths_cli._should_retry_ttl([{"ttl": 32, "src_ip": TARGET}], TARGET, 32))
        self.assertFalse(paths_cli._should_retry_ttl(
            [{"ttl": 9, "src_ip": "10.0.0.1"}, {"ttl": 32, "src_ip": None}], TARGET, 32
        ))

    def test_run_target_retries_once_with_longer_ttl(self):
        first = (
            "t0",
            [{"flow_id": 0, "ttl": 32, "src_ip": "10.0.0.1", "is_last": False}],
            {"tool": "traceroute", "max_ttl": 32},
        )
        second = (
            "t1",
            [
                {"flow_id": 0, "ttl": 32, "src_ip": "10.0.0.1", "is_last": False},
                {"flow_id": 0, "ttl": 33, "src_ip": TARGET, "is_last": True},
            ],
            {"tool": "traceroute", "max_ttl": 64},
        )
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "p.db")
            with mock.patch.object(probe, "capture_ping", return_value={"reachable": True, "rtt_avg_ms": 1.0, "loss_percent": 0}),                  mock.patch.object(paths_cli, "get_public_ip", return_value=None),                  mock.patch.object(paths_cli, "_capture_tool", side_effect=[first, second]) as capture:
                with contextlib.redirect_stdout(io.StringIO()):
                    code = paths_cli.run_target(
                        TARGET, tools=["traceroute"], db=db, do_enrich=False, text=True, do_dest=False
                    )
            self.assertEqual(code, 0)
            self.assertEqual(capture.call_count, 2)
            self.assertEqual(capture.call_args_list[1].args[3], 64)
            conn = store.open_store(db)
            meta = json.loads(conn.execute("SELECT meta FROM runs").fetchone()[0])
            conn.close()
        self.assertEqual(meta["max_ttl"], 64)
        self.assertEqual(meta["retry_ttl"], 64)


class PublicIpTest(unittest.TestCase):
    def test_get_public_ip(self):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return b"1.2.3.4\n"

        with mock.patch("urllib.request.urlopen", return_value=Response()):
            self.assertEqual(paths_cli.get_public_ip(), "1.2.3.4")

    def test_get_public_ip_falls_through_to_none(self):
        with mock.patch("urllib.request.urlopen", side_effect=OSError("no network")):
            self.assertIsNone(paths_cli.get_public_ip())


class BgpTest(unittest.TestCase):
    def test_owns(self):
        self.assertTrue(bgp.owns("2119", "80.249.209.192", prefixes=["80.249.0.0/16"]))
        self.assertFalse(bgp.owns("2119", "80.249.209.192", prefixes=["1.0.0.0/8"]))


class AnalysisTest(unittest.TestCase):
    def test_reachability(self):
        blocked = [
            {"flow_id": 1, "ttl": 1, "src_ip": "10.0.0.1", "icmp_type": 11, "icmp_code": 0},
            {"flow_id": 1, "ttl": 2, "src_ip": "192.0.2.9", "icmp_type": 3, "icmp_code": 13},
        ]
        result = analysis.reachability(blocked, TARGET)
        self.assertFalse(result["reached"])
        self.assertEqual(result["last_hop"], "192.0.2.9")
        self.assertEqual(result["error"], "!X")
        reached = analysis.reachability(
            blocked + [{"flow_id": 1, "ttl": 3, "src_ip": TARGET, "icmp_type": 3, "icmp_code": 3}],
            TARGET,
        )
        self.assertTrue(reached["reached"])


class IngestTest(unittest.TestCase):
    def test_parse_mtr(self):
        payload = {"report": {"hubs": [
            {"count": 1, "host": "192.168.1.1", "Avg": 0.5},
            {"count": 2, "host": "???", "Avg": 0.0},
            {"count": 3, "host": "8.8.8.8", "Avg": 5.0},
        ]}}
        parsed = ingest.parse_mtr(payload)
        self.assertEqual([h["ttl"] for h in parsed], [1, 2, 3])
        self.assertEqual(parsed[0]["src_ip"], "192.168.1.1")
        self.assertIsNone(parsed[1]["src_ip"])

    def test_parse_mtr_ignores_100pct_loss_hub(self):
        payload = {"report": {"mtr": {"dst": "8.8.8.8"}, "hubs": [
            {"count": 1, "host": "8.8.8.8", "Loss%": 100.0, "Avg": 0.0},
        ]}}
        parsed = ingest.parse_mtr(payload, target="8.8.8.8")
        self.assertIsNone(parsed[0]["src_ip"])
        self.assertFalse(parsed[0]["is_last"])

    def test_parse_traceroute(self):
        text = " 1  _gateway (192.168.1.1)  0.532 ms\n 2  * * *\n 3  8.8.8.8  5.1 ms\n"
        parsed = ingest.parse_traceroute(text, protocol="udp")
        self.assertEqual([h["ttl"] for h in parsed], [1, 2, 3])
        self.assertEqual(parsed[2]["src_ip"], "8.8.8.8")

    def test_ingest_voyage_dispatch(self):
        parsed = ingest.ingest_hops(str(VOYAGE_FIXTURE), "voyage")
        self.assertEqual(len(parsed), 6)
        self.assertEqual(parsed[0]["tool"], "voyage")


class ExportTest(unittest.TestCase):
    def _seed(self, conn, run_id, hops, meta=None, edges=None, nodes=None):
        store.save_run(
            conn,
            {"run_id": run_id, "target": TARGET, "src_ip": "10.0.0.1", "tool": "scamper",
             "started_at": "t", "meta": meta or {}},
        )
        store.save_hops(conn, run_id, hops)
        for src, dst, ttl in edges or []:
            store.add_edge(conn, run_id, "interface", src, dst, ttl=ttl)
        for ip, attrs in (nodes or {}).items():
            store.set_node_attrs(conn, "interface", ip, attrs)

    def test_failed_trace_hangs(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = store.open_store(os.path.join(tmp, "p.db"))
            self._seed(
                conn,
                "r1",
                [
                    {"flow_id": 0, "ttl": 1, "src_ip": "10.0.0.1", "icmp_type": 11, "icmp_code": 0, "is_last": False},
                    {"flow_id": 0, "ttl": 2, "src_ip": "192.0.2.9", "icmp_type": 3, "icmp_code": 13, "is_last": False},
                ],
                meta={"ping": {"reachable": False, "loss_percent": 100.0}},
                edges=[("10.0.0.1", "192.0.2.9", 2)],
            )
            data = paths_export.build(conn, "r1")
            conn.close()

        self.assertFalse(data["reachability"]["reached"])
        self.assertFalse(data["ping"]["reachable"])
        self.assertNotIn(TARGET, [hop["id"] for hop in data["hops"]])
        self.assertNotIn(TARGET, [edge["target"] for edge in data["edges"]])

    def test_inter_as_link_carries_handoff(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = store.open_store(os.path.join(tmp, "p.db"))
            self._seed(
                conn,
                "r2",
                [
                    {"flow_id": 0, "ttl": 1, "src_ip": "10.0.0.1", "icmp_type": 11, "icmp_code": 0, "is_last": False},
                    {"flow_id": 0, "ttl": 2, "src_ip": TARGET, "icmp_type": 3, "icmp_code": 3, "is_last": True},
                ],
                meta={"ping": {"reachable": True, "rtt_avg_ms": 5.0}},
                edges=[("10.0.0.1", TARGET, 2)],
                nodes={"10.0.0.1": {"asn": "1", "as_name": "AS One"}, TARGET: {"asn": "2"}},
            )
            store.set_edge_attrs(
                conn, "r2", "interface", "10.0.0.1", TARGET,
                {"handoff": {"from_as": "1", "to_as": "2",
                             "facilities": [{"name": "Equinix X", "city": "Ashburn"}],
                             "ixps": [{"name": "IX-A"}], "announces_dest": True}},
            )
            data = paths_export.build(conn, "r2")
            html = paths_export.render_html(conn, ["r2"])
            conn.close()

        edge = data["edges"][0]
        self.assertTrue(edge["handoff"]["announces_dest"])
        self.assertEqual([f["name"] for f in edge["handoff"]["facilities"]], ["Equinix X"])
        self.assertNotIn("/*__PATHS_DATA__*/", html)
        self.assertIn("Equinix X", html)

    @unittest.skipUnless(HAVE_NX, "networkx not installed")
    def test_vantage_positioned_at_ttl_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = store.open_store(os.path.join(tmp, "p.db"))
            store.save_run(
                conn,
                {"run_id": "r1", "target": TARGET, "src_ip": "8.8.8.8", "tool": "scamper", "started_at": "t", "meta": {}},
            )
            store.save_hops(
                conn,
                "r1",
                [
                    {"flow_id": 0, "ttl": 1, "src_ip": "192.168.1.1", "is_last": False},
                    {"flow_id": 0, "ttl": 3, "src_ip": "93.184.216.34", "is_last": True},
                ],
            )
            graph = graphlib.interface_graph(store.load_hops(conn, "r1"), vantage="8.8.8.8")
            graphlib.persist(conn, "r1", graph)
            data = paths_export.build(conn, "r1")
            conn.close()
        ttl_by_id = {hop["id"]: hop["ttl"] for hop in data["hops"]}
        self.assertEqual(ttl_by_id["8.8.8.8"], 0)
        self.assertIn("93.184.216.34", ttl_by_id)
        self.assertNotIn("192.168.1.1", ttl_by_id)

    def test_build_hides_off_path_nodes(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = store.open_store(os.path.join(tmp, "p.db"))
            self._seed(
                conn,
                "r1",
                [
                    {"flow_id": 1, "ttl": 1, "src_ip": "10.0.0.1", "is_last": False},
                    {"flow_id": 1, "ttl": 2, "src_ip": "10.0.0.2", "is_last": True},
                    {"flow_id": 1, "ttl": 2, "src_ip": "10.0.0.3", "is_last": False},
                ],
                edges=[("10.0.0.1", "10.0.0.2", 2)],
            )
            data = paths_export.build(conn, "r1")
            conn.close()
        self.assertEqual({hop["id"] for hop in data["hops"]}, {"10.0.0.1", "10.0.0.2"})
        self.assertEqual({hop["src_ip"] for hop in data["raw"]}, {"10.0.0.1", "10.0.0.2", "10.0.0.3"})

    def test_build_exposes_semi_raw_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = store.open_store(os.path.join(tmp, "p.db"))
            self._seed(
                conn,
                "r1",
                [
                    {"flow_id": 1, "ttl": 1, "src_ip": "10.0.0.1", "rtt_ms": 1.5, "is_last": False},
                    {"flow_id": 1, "ttl": 2, "src_ip": None, "rtt_ms": None, "is_last": False},
                ],
                meta={"protocols": ["icmp"], "max_ttl": 32},
            )
            data = paths_export.build(conn, "r1")
            conn.close()
        self.assertEqual(len(data["raw"]), 2)
        self.assertEqual(data["raw"][0]["rtt_ms"], 1.5)
        self.assertIsNone(data["raw"][1]["src_ip"])
        self.assertEqual(data["run"]["meta"]["max_ttl"], 32)

    def test_one_graph_per_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = store.open_store(os.path.join(tmp, "p.db"))
            self._seed(conn, "r1", [{"flow_id": 0, "ttl": 1, "src_ip": "10.0.0.1", "is_last": False}], edges=[], meta={"tool": "scamper"})
            self._seed(conn, "r2", [{"flow_id": 0, "ttl": 1, "src_ip": "10.0.0.1", "is_last": False}], edges=[], meta={"tool": "dublin"})
            data = paths_export.build_graphs(conn, ["r1", "r2"])
            conn.close()

        self.assertEqual(len(data["graphs"]), 2)
        self.assertEqual(data["target"], TARGET)


if __name__ == "__main__":
    unittest.main()

class ClearTest(unittest.TestCase):
    def _seed(self, conn, run_id, target, hop_ip, fetch_ip):
        store.save_run(
            conn,
            {"run_id": run_id, "target": target, "tool": "scamper", "started_at": "t", "meta": {}},
        )
        store.save_hops(conn, run_id, [{"flow_id": 0, "ttl": 1, "src_ip": hop_ip, "is_last": True}])
        store.add_edge(conn, run_id, "interface", hop_ip, hop_ip, ttl=1)
        store.set_node_attrs(conn, "interface", hop_ip, {})
        conn.execute(
            "INSERT INTO fetches (ip, source, url, status, body, error, fetched_at) "
            "VALUES (?, 'test', 'http://example', 200, '{}', NULL, 't')",
            (fetch_ip,),
        )
        conn.commit()

    def test_clear_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = store.open_store(os.path.join(tmp, "p.db"))
            self._seed(conn, "r1", "1.1.1.1", "10.0.0.1", "10.0.0.1")
            self._seed(conn, "r2", "2.2.2.2", "10.0.0.2", "10.0.0.2")
            counts = store.clear(conn, "1.1.1.1")
            remaining_runs = {row[0] for row in conn.execute("SELECT run_id FROM runs")}
            remaining_nodes = {row[0] for row in conn.execute("SELECT key FROM nodes")}
            remaining_fetches = {row[0] for row in conn.execute("SELECT ip FROM fetches")}
            conn.close()
        self.assertEqual(counts, {"runs": 1, "hops": 1, "edges": 1, "nodes": 1, "fetches": 1})
        self.assertEqual(remaining_runs, {"r2"})
        self.assertEqual(remaining_nodes, {"10.0.0.2"})
        self.assertEqual(remaining_fetches, {"10.0.0.2"})

    def test_clear_all(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = store.open_store(os.path.join(tmp, "p.db"))
            self._seed(conn, "r1", "1.1.1.1", "10.0.0.1", "10.0.0.1")
            self._seed(conn, "r2", "2.2.2.2", "10.0.0.2", "10.0.0.2")
            counts = store.clear(conn)
            totals = {
                "runs": conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0],
                "hops": conn.execute("SELECT COUNT(*) FROM hops").fetchone()[0],
                "edges": conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0],
                "nodes": conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0],
                "fetches": conn.execute("SELECT COUNT(*) FROM fetches").fetchone()[0],
            }
            conn.close()
        self.assertEqual(counts, {"runs": 2, "hops": 2, "edges": 2, "nodes": 2, "fetches": 2})
        self.assertEqual(set(totals.values()), {0})

    def test_cli_clear_all_and_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "p.db")
            conn = store.open_store(db)
            self._seed(conn, "r1", "1.1.1.1", "10.0.0.1", "10.0.0.1")
            self._seed(conn, "r2", "2.2.2.2", "10.0.0.2", "10.0.0.2")
            conn.close()
            with mock.patch.object(paths_cli.sources, "load_env"):
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    self.assertEqual(paths_cli.run_path(["--db", db, "--clear", "1.1.1.1"]), 0)
                self.assertIn("cleared 1 runs", out.getvalue())
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    self.assertEqual(paths_cli.run_path(["--db", db, "--clear"]), 0)
                self.assertIn("(all)", out.getvalue())
