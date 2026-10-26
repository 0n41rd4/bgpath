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

import aranya
from registry import sources, store

RIPE = Path(__file__).parent / "fixtures" / "ripe"
OTHERS = Path(__file__).parent / "fixtures" / "others"

OPTIONAL = {
    "ipinfo", "shodan.host", "maxmind.geolite2", "maxmind.asn", "dbip.lite",
    "peeringdb.fac", "peeringdb.ixpfx",
}
NO_MMDB = {"MAXMIND_DB": "/nonexistent", "MAXMIND_ASN_DB": "/nonexistent", "DBIP_DB": "/nonexistent"}


def make_fetch():
    def fetch(url):
        if "network-info" in url:
            body = (RIPE / "network-info.json").read_text()
        elif "geoloc" in url:
            body = (RIPE / "geoloc.json").read_text()
        elif "as-overview" in url:
            body = (RIPE / "as-overview.json").read_text()
        elif "asn-neighbours" in url:
            body = (RIPE / "asn-neighbours.json").read_text()
        elif "ipmap.ripe.net" in url:
            body = (RIPE / "ipmap.json").read_text()
        elif "cymru" in url:
            body = (OTHERS / "cymru.json").read_text()
        elif "api.routeviews.org" in url:
            body = (OTHERS / "routeviews_prefix.json").read_text()
        elif "looking-glass" in url:
            body = (RIPE / "looking-glass.json").read_text()
        elif "atlas.ripe.net" in url:
            body = (OTHERS / "atlas.json").read_text()
        elif url.startswith("IRR "):
            body = (OTHERS / "irr.txt").read_text()
        elif "rdap" in url:
            body = (OTHERS / "rdap.json").read_text()
        elif "ipwho.is" in url:
            body = (OTHERS / "ipwhois.json").read_text()
        elif "ip.guide" in url:
            body = (OTHERS / "ipguide.json").read_text()
        elif url.startswith("PTR "):
            body = "dns.google"
        elif "internetdb" in url:
            body = (OTHERS / "internetdb.json").read_text()
        elif "ipinfo.io" in url:
            body = (OTHERS / "ipinfo.json").read_text()
        elif "api.shodan.io" in url:
            body = (OTHERS / "shodan.json").read_text()
        elif "globalping" in url:
            body = (OTHERS / "globalping.json").read_text()
        elif "netfac" in url:
            body = (OTHERS / "peeringdb_netfac.json").read_text()
        elif "netixlan" in url:
            body = (OTHERS / "peeringdb_netixlan.json").read_text()
        elif "peeringdb.com/api/fac" in url:
            body = (OTHERS / "peeringdb_fac.json").read_text()
        elif "peeringdb.com/api/ixpfx" in url:
            body = (OTHERS / "peeringdb_ixpfx.json").read_text()
        elif "peeringdb.com/api/net" in url:
            body = (OTHERS / "peeringdb_net.json").read_text()
        elif "crt.sh" in url:
            body = (OTHERS / "crtsh.json").read_text()
        else:
            return None, None, f"unmapped url: {url}"
        return 200, body, None

    return fetch


class PipelineTest(unittest.TestCase):
    def test_full_pipeline_offline(self):
        with mock.patch.dict(os.environ, {**NO_MMDB, "IPINFO_TOKEN": "", "SHODAN_API_KEY": ""}):
            with tempfile.TemporaryDirectory() as tmp:
                conn = store.open_store(str(Path(tmp) / "t.db"))
                statuses, parsed = aranya.run_all(conn, "8.8.8.8", fetch=make_fetch())
                conn.close()

        for source_id, status in statuses.items():
            if source_id in OPTIONAL:
                self.assertTrue(status.startswith("skipped"), f"{source_id}: {status}")
            else:
                self.assertEqual(status, "ok", f"{source_id}: {status}")
        self.assertEqual(statuses["peeringdb.fac[1]"], "ok")
        self.assertEqual(statuses["peeringdb.ixpfx[128]"], "ok")

        self.assertEqual(parsed["ripestat.network-info"]["asns"], ["15169"])
        self.assertEqual(parsed["peeringdb.net"]["net_id"], 433)
        self.assertEqual(parsed["rdns.ptr"]["hostname"], "dns.google")
        self.assertEqual(parsed["routeviews.prefix"]["routes"][0]["origin_asn"], 15169)
        self.assertEqual(parsed["ris.looking-glass"]["rrcs"][0]["rrc"], "RRC01")
        self.assertEqual(parsed["atlas.ping"]["results"][0]["prb_id"], 1002934)
        self.assertEqual(parsed["irr.origin"]["objects"][0]["origin"], "AS15169")

    def test_optional_sources_configured(self):
        env = {"IPINFO_TOKEN": "test-token", "SHODAN_API_KEY": "test-key", **NO_MMDB}
        with mock.patch.dict(os.environ, env):
            with tempfile.TemporaryDirectory() as tmp:
                conn = store.open_store(str(Path(tmp) / "t.db"))
                statuses, _ = aranya.run_all(conn, "8.8.8.8", fetch=make_fetch())
                urls = [
                    r[0]
                    for r in conn.execute(
                        "SELECT url FROM fetches WHERE source IN ('ipinfo', 'shodan.host')"
                    )
                ]
                conn.close()

        self.assertEqual(statuses["ipinfo"], "ok")
        self.assertEqual(statuses["shodan.host"], "ok")
        for url in urls:
            self.assertNotIn("test-token", url)
            self.assertNotIn("test-key", url)

    def test_redact_url(self):
        redacted = sources.redact_url("https://ipinfo.io/8.8.8.8/json?token=sekrit&other=1")
        self.assertNotIn("sekrit", redacted)
        self.assertIn("other=1", redacted)
        self.assertEqual(sources.redact_url("PTR 8.8.8.8"), "PTR 8.8.8.8")

    def test_observations_written_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = store.open_store(str(Path(tmp) / "t.db"))
            aranya.run_all(conn, "8.8.8.8", fetch=make_fetch())
            asns = conn.execute(
                "SELECT value FROM observations WHERE topic = 'ownership' AND key = 'asn'"
            ).fetchall()
            locations = conn.execute(
                "SELECT COUNT(*) FROM v_locations WHERE ip = '8.8.8.8'"
            ).fetchone()
            untraced = conn.execute(
                "SELECT COUNT(*) FROM observations WHERE fetch_id IS NULL"
            ).fetchone()
            ris = conn.execute(
                "SELECT COUNT(*) FROM observations WHERE source = 'ris.looking-glass' AND key = 'ris'"
            ).fetchone()
            facs = conn.execute(
                "SELECT COUNT(*) FROM observations WHERE source = 'peeringdb.fac'"
            ).fetchone()
            ixs = conn.execute(
                "SELECT COUNT(*) FROM observations WHERE source = 'peeringdb.ixpfx'"
            ).fetchone()
            conn.close()

        self.assertTrue(asns)
        self.assertGreater(locations[0], 0)
        self.assertEqual(untraced[0], 0)
        self.assertGreater(ris[0], 0)
        self.assertGreater(facs[0], 0)
        self.assertGreater(ixs[0], 0)

    def test_verbose_progress(self):
        stream = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stderr(stream):
            conn = store.open_store(str(Path(tmp) / "t.db"))
            aranya.run_all(conn, "8.8.8.8", fetch=make_fetch(), verbose=True)
            conn.close()
        output = stream.getvalue()
        self.assertIn("fetching", output)
        self.assertIn("ripestat.network-info", output)

    def test_rerun_replaces_observations(self):
        with mock.patch.dict(os.environ, {**NO_MMDB, "IPINFO_TOKEN": "", "SHODAN_API_KEY": ""}):
            with tempfile.TemporaryDirectory() as tmp:
                conn = store.open_store(str(Path(tmp) / "t.db"))
                aranya.run_all(conn, "8.8.8.8", fetch=make_fetch())
                first = conn.execute(
                    "SELECT COUNT(*) FROM observations WHERE ip = '8.8.8.8'"
                ).fetchone()[0]
                aranya.run_all(conn, "8.8.8.8", fetch=make_fetch())
                second = conn.execute(
                    "SELECT COUNT(*) FROM observations WHERE ip = '8.8.8.8'"
                ).fetchone()[0]
                conn.close()
        self.assertGreater(first, 0)
        self.assertEqual(first, second)

    def test_warnings_include_missing_credentials(self):
        with mock.patch.dict(os.environ, {"IPINFO_TOKEN": "", "SHODAN_API_KEY": "", "MAXMIND_LICENSE_KEY": ""}):
            items = sources.warnings()
        self.assertTrue(any("IPINFO_TOKEN" in item for item in items))
        self.assertTrue(any("SHODAN_API_KEY" in item for item in items))

    def test_update_dbs_dispatches(self):
        with mock.patch.object(sources, "load_env"), mock.patch.object(
            aranya, "_update_dbs", return_value=0
        ) as update:
            self.assertEqual(aranya.main(["--update-dbs"]), 0)
            update.assert_called_once()

    def test_default_db_uses_xdg(self):
        with mock.patch.dict(os.environ, {"XDG_DATA_HOME": "/tmp/xdg"}):
            self.assertEqual(aranya._default_db(), "/tmp/xdg/aranya/aranya.db")

    def test_clear_ip_dispatches(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "t.db")
            conn = store.open_store(path)
            store.save_observation(conn, "1.1.1.1", "src", "up", "reported", "t", "k", 1)
            store.save_observation(conn, "2.2.2.2", "src", "up", "reported", "t", "k", 2)
            conn.close()
            with mock.patch.object(sources, "load_env"):
                self.assertEqual(aranya.main(["--db", path, "--clear-ip", "1.1.1.1"]), 0)
            conn = store.open_store(path)
            ips = {row[0] for row in conn.execute("SELECT DISTINCT ip FROM observations")}
            conn.close()
        self.assertEqual(ips, {"2.2.2.2"})

    def test_load_env_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "env"
            path.write_text("export ARANYA_TEST_A=bar\nARANYA_TEST_B='qux'\n")
            with mock.patch.dict(os.environ, {"ARANYA_TEST_A": "keep"}, clear=False):
                sources.load_env(str(path))
                self.assertEqual(os.environ["ARANYA_TEST_A"], "keep")
                self.assertEqual(os.environ["ARANYA_TEST_B"], "qux")

    def test_mmdb_default_path(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DBIP_DB", None)
            os.environ.pop("ARANYA_DATA", None)
            path = sources._db_path("DBIP_DB", "dbip-city-lite.mmdb")
            self.assertTrue(path.endswith(os.path.join("data", "dbip-city-lite.mmdb")))

    def test_dump_last_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "dumps"
            aranya._link_last(str(root), "20260101T000000Z")
            link = root / "last"
            self.assertTrue(link.is_symlink())
            self.assertEqual(os.readlink(link), "20260101T000000Z")
            aranya._link_last(str(root), "20260102T000000Z")
            self.assertEqual(os.readlink(link), "20260102T000000Z")

    def test_dump_source_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = store.open_store(str(Path(tmp) / "t.db"))
            dump = Path(tmp) / "dump" / "8.8.8.8"
            aranya.run_all(conn, "8.8.8.8", fetch=make_fetch(), dump_dir=str(dump))
            conn.close()
            self.assertTrue((dump / "ripestat.network-info" / "output.txt").exists())
            raw = json.loads((dump / "ripestat.network-info" / "raw_output.json").read_text())
            self.assertIn("asns", raw["data"])
            self.assertEqual(
                json.loads((dump / "rdns.ptr" / "raw_output.json").read_text()),
                {"raw": "dns.google"},
            )
            routeviews = json.loads((dump / "routeviews.prefix" / "raw_output.json").read_text())
            self.assertIn("reporting_peers", routeviews[0])
            meta = json.loads((dump / "ripestat.network-info" / "output.json").read_text())
            self.assertEqual(meta["status"], 200)
            self.assertIn("asns", meta["parsed"])
            status = (dump / "_status.txt").read_text()
            self.assertIn("source\tstatus\tfolder", status)
            self.assertIn("ripestat.network-info\t", status)
            self.assertIn("ripestat.network-info/", status)

    def test_dump_as_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = store.open_store(str(Path(tmp) / "t.db"))
            dump = Path(tmp) / "dump" / "8.8.8.8"
            aranya.run_all(conn, "8.8.8.8", fetch=make_fetch(), dump_dir=str(dump))
            conn.close()
            self.assertTrue((dump / "AS15169" / "peeringdb.net" / "output.txt").exists())
            self.assertTrue((dump / "AS15169" / "ripestat.as-overview" / "output.txt").exists())
            self.assertTrue((dump / "AS15169" / "atlas.probes" / "output.txt").exists())
            self.assertTrue((dump / "AS15169" / "peeringdb.fac" / "1" / "output.txt").exists())
            self.assertTrue((dump / "AS15169" / "peeringdb.ixpfx" / "128" / "output.txt").exists())
            self.assertFalse((dump / "peeringdb.net").exists())
            status = (dump / "_status.txt").read_text()
            self.assertIn("AS15169/peeringdb.net", status)
            self.assertIn("AS15169/peeringdb.fac/1", status)
            self.assertIn("\trouteviews.prefix/", status)

    def test_followups_dedupe(self):
        facilities = {"facilities": [{"fac_id": 1}, {"fac_id": 1}, {"fac_id": 2}]}
        ixlans = {"ix": [{"ixlan_id": 7}, {"ixlan_id": 7}, {"ixlan_id": 8}]}
        self.assertEqual(len(sources._followup_facilities(facilities, {})), 2)
        self.assertEqual(len(sources._followup_ixlans(ixlans, {})), 2)

    def test_main_prints_followup_statuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "t.db")
            statuses = {"peeringdb.fac[1]": "ok", "routeviews.prefix": "ok"}
            with mock.patch.object(aranya, "run_all", return_value=(statuses, {})):
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    self.assertEqual(aranya.main(["--db", path, "8.8.8.8"]), 0)
        self.assertIn("peeringdb.fac[1]", out.getvalue())

    def test_missing_dependencies_skip(self):
        def failing_fetch(url):
            return None, None, "offline failure"

        with tempfile.TemporaryDirectory() as tmp:
            conn = store.open_store(str(Path(tmp) / "t.db"))
            statuses, _ = aranya.run_all(conn, "8.8.8.8", fetch=failing_fetch)
            conn.close()

        self.assertEqual(statuses["ripestat.network-info"], "error (offline failure)")
        self.assertTrue(statuses["ripestat.as-overview"].startswith("skipped"))
        self.assertTrue(statuses["peeringdb.net"].startswith("skipped"))
        self.assertTrue(statuses["crtsh"].startswith("skipped"))


if __name__ == "__main__":
    unittest.main()
