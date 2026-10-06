import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import aranya
import store

RIPE = Path(__file__).parent / "fixtures" / "ripe"
OTHERS = Path(__file__).parent / "fixtures" / "others"


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
        elif "rdap" in url:
            body = (OTHERS / "rdap.json").read_text()
        elif url.startswith("PTR "):
            body = "dns.google"
        elif "internetdb" in url:
            body = (OTHERS / "internetdb.json").read_text()
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
            self.assertEqual(status, "ok", f"{source_id}: {status}")

        self.assertEqual(parsed["ripestat.network-info"]["asns"], ["15169"])
        self.assertEqual(parsed["peeringdb.net"]["net_id"], 433)
        self.assertEqual(parsed["rdns.ptr"]["hostname"], "dns.google")

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
