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
        with tempfile.TemporaryDirectory() as tmp:
            conn = store.open_store(str(Path(tmp) / "t.db"))
            statuses, parsed = aranya.run_all(conn, "8.8.8.8", fetch=make_fetch())
            conn.close()

        for source_id, status in statuses.items():
            if source_id in OPTIONAL:
                self.assertTrue(status.startswith("skipped"), f"{source_id}: {status}")
            else:
                self.assertEqual(status, "ok", f"{source_id}: {status}")

        self.assertEqual(parsed["ripestat.network-info"]["asns"], ["15169"])
        self.assertEqual(parsed["peeringdb.net"]["net_id"], 433)
        self.assertEqual(parsed["rdns.ptr"]["hostname"], "dns.google")
        self.assertEqual(parsed["routeviews.prefix"]["routes"][0]["origin_asn"], 15169)
        self.assertEqual(parsed["atlas.ping"]["results"][0]["prb_id"], 1002934)
        self.assertEqual(parsed["irr.origin"]["objects"][0]["origin"], "AS15169")

    def test_optional_sources_configured(self):
        env = {"IPINFO_TOKEN": "test-token", "SHODAN_API_KEY": "test-key"}
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
            conn.close()

        self.assertTrue(asns)
        self.assertGreater(locations[0], 0)
        self.assertEqual(untraced[0], 0)

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
