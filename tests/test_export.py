import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import export
import store

HOSTILE = "<img src=x onerror=alert(1)>"


class ExportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = store.open_store(str(Path(self.tmp.name) / "t.db"))
        self.conn.execute(
            "INSERT INTO observations (ip, source, upstream, evidence_class, topic, key, value, observed_at)"
            " VALUES ('8.8.8.8','a','Alpha','reported','ownership','asn','\"15169\"','2024-01-01')"
        )
        self.conn.execute(
            "INSERT INTO observations (ip, source, upstream, evidence_class, topic, key, value, observed_at)"
            " VALUES ('8.8.8.8','b','Beta','reported','ownership','asn','\"15169\"','2024-01-01')"
        )
        self.conn.execute(
            "INSERT INTO observations (ip, source, upstream, evidence_class, topic, key, value, observed_at)"
            " VALUES ('8.8.8.8','c','Gamma','reported','identity','hostname',?,'2024-01-01')",
            (json.dumps(HOSTILE),),
        )
        store.save_fetch(self.conn, "a", "http://a", 200, "{}", None, "8.8.8.8")
        store.save_fetch(self.conn, "b", "http://b", 200, "{}", None, "8.8.8.8")
        store.save_fetch(self.conn, "d", "d", None, None, "skipped (missing asn)", "8.8.8.8")
        store.save_fetch(self.conn, "e", "http://e", 500, None, None, "8.8.8.8")
        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def test_schema_and_verdict(self):
        obj = export.build(self.conn)
        self.assertEqual(obj["schema_version"], export.SCHEMA_VERSION)
        claims = {(c["ip"], c["topic"], c["key"]): c for c in obj["claims"]}
        asn = claims[("8.8.8.8", "ownership", "asn")]
        self.assertEqual(asn["verdict"], "agree")
        self.assertEqual(asn["n_sources"], 2)
        self.assertEqual(asn["n_upstreams"], 2)
        host = claims[("8.8.8.8", "identity", "hostname")]
        self.assertEqual(host["verdict"], "single")

    def test_states_include_failure(self):
        obj = export.build(self.conn)
        states = {(s["topic"], s["key"], s["source"]): s["state"] for s in obj["states"]}
        self.assertEqual(states[("ownership", "asn", "a")], "agree")
        self.assertEqual(states[("ownership", "asn", "d")], "skipped")
        self.assertEqual(states[("ownership", "asn", "e")], "error")
        self.assertEqual(states[("ownership", "asn", "c")], "no_data")
        self.assertEqual(states[("identity", "hostname", "c")], "single")

    def test_deterministic(self):
        self.assertEqual(export.to_json(export.build(self.conn)), export.to_json(export.build(self.conn)))

    def test_json_is_parseable(self):
        obj = json.loads(export.to_json(export.build(self.conn, with_observations=True)))
        hostile = [o for o in obj["observations"] if o["topic"] == "identity"]
        self.assertEqual(hostile[0]["value"], HOSTILE)

    def test_html_escapes_hostile_and_has_no_external_resources(self):
        html = export.render_html(export.build(self.conn, with_observations=True))
        self.assertIn("\\u003cimg", html)
        self.assertNotIn("<img", html)
        self.assertNotIn("<script src", html)
        self.assertNotIn("<link", html)
        self.assertNotIn('src="http', html)
        self.assertNotIn('href="http', html)
        self.assertNotIn("@import", html)

    def test_template_has_no_external_resources(self):
        text = Path(export.TEMPLATE).read_text(encoding="utf-8")
        self.assertIsNone(re.search(r'src\s*=\s*"https?:', text))
        self.assertIsNone(re.search(r'href\s*=\s*"https?:', text))
        self.assertNotIn("@import", text)
        self.assertNotIn("url(http", text)


if __name__ == "__main__":
    unittest.main()
