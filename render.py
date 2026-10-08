"""Terminal rendering of the observation views.

Pure presentation: consumes views.py (read-only rows) and aggregate.py
(consensus/cross-IP), and prints compact ANSI tables. Disable colour with
--no-color or NO_COLOR.
"""

from __future__ import annotations

import aggregate
import analyze
import entities
import views

GLYPHS = ["●", "◆", "▲", "■", "★", "▼", "◈", "⬟"]
CLAIM_COLORS = [96, 95, 93, 92, 94, 91]
VERDICT_COLOR = {"agree": 32, "single": 90, "spread": 33, "disagree": 31}
VERDICT_GLYPH = {"agree": ".", "single": "o", "spread": "+", "disagree": "#"}
ABSENT_COLOR = 90

TOPIC_TAG = {
    "ownership": "own", "location": "loc", "routing": "rtg", "identity": "idn",
    "neighbours": "nbr", "directory": "dir", "facility": "fac", "ix": "ix",
    "latency": "lat", "names": "nam", "country": "cty",
}
KEY_TAG = {
    "asn": "asn", "org": "org", "name": "nam", "prefix": "pre", "holder": "hld",
    "handle": "hnd", "range": "rng", "block": "blk", "status": "sts", "claim": "clm",
    "announced": "ann", "anycast": "any", "hostname": "hst", "ports": "prt",
    "vulns": "vln", "list": "lst", "counts": "cnt", "net_id": "net",
    "info_type": "typ", "website": "web", "facility": "fac", "ixlan": "ixl",
    "probe": "prb", "certificate": "crt", "country": "cty",
}


class Paint:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, text: str, code: int | None) -> str:
        if self.enabled and code:
            return f"\033[{code}m{text}\033[0m"
        return text


def key_tag(topic: str, key: str) -> str:
    return f"{TOPIC_TAG.get(topic, topic[:3])}.{KEY_TAG.get(key, key[:3])}"


def claim_view(conn, ip: str, color: bool = True, cap: int = 6, normalized: bool = False) -> list[str]:
    summaries = aggregate.cell_summaries(conn, ip, normalize=normalized)
    if not summaries:
        return [f"{ip}: no observations"]
    paint = Paint(color)
    width = max(len(f"{s['topic']}.{s['key']}") for s in summaries)
    tag = "   [normalized]" if normalized else ""
    lines = [f"{ip}  —  {len(summaries)} claim(s){tag}   (* = reports a set)\n"]
    for summary in summaries:
        multi = set(summary["multi"])
        listed = [entry for entry in summary["labels"] if any(s not in multi for s in entry["sources"])]
        verdict = summary["verdict"]
        mark = paint(aggregate.VERDICT_MARK[verdict], VERDICT_COLOR[verdict])
        head = f"{summary['topic']}.{summary['key']:<{width}}"
        lines.append(
            f"{head}  [{mark}] {verdict:<10} "
            f"{summary['n_sources']} source(s), {summary['n_upstreams']} upstream(s)"
        )
        for index, entry in enumerate(listed[:cap]):
            glyph = paint(GLYPHS[index % len(GLYPHS)], CLAIM_COLORS[index % len(CLAIM_COLORS)])
            names = ", ".join(
                f"{src}*" if src in multi else src for src in entry["sources"]
            )
            lines.append(f"    {glyph} {entry['label']:<34} {names}")
        if len(listed) > cap:
            lines.append(f"      + {len(listed) - cap} more value(s)")
        for source in summary["multi"]:
            labels = summary["source_labels"][source]
            sample = ", ".join(labels[:3])
            glyph = paint("~", 33)
            lines.append(
                f"    {glyph} {source + '*':<34} {len(labels)} values: {sample}{'…' if len(labels) > 3 else ''}"
            )
        lines.append("")
    return lines


def overview_view(conn, ips: list[str], color: bool = True, normalize: bool = False) -> list[str]:
    verdicts = aggregate.overview(conn, ips, normalize=normalize)
    keys = [key for key in views.keys(conn, ips) if any((ip, *key) in verdicts for ip in ips)]
    paint = Paint(color)
    tags = [key_tag(topic, key) for topic, key in keys]
    width = max(len(tag) for tag in tags)
    ipw = max(len(ip) for ip in ips)
    lines = ["overview:  per-IP agreement per claim", ""]
    lines.append(f"{' ' * ipw}  " + " ".join(f"{tag:>{width}}" for tag in tags))
    for ip in ips:
        row = []
        for topic, key in keys:
            verdict = verdicts.get((ip, topic, key))
            if verdict is None:
                row.append(paint("·", ABSENT_COLOR).rjust(width))
            else:
                row.append(f"{paint(VERDICT_GLYPH[verdict], VERDICT_COLOR[verdict]):>{width}}")
        lines.append(f"{ip:>{ipw}}  " + " ".join(row))
    legend = "  ".join(
        f"{paint(VERDICT_GLYPH[v], VERDICT_COLOR[v])} {v}"
        for v in ("agree", "single", "spread", "disagree")
    )
    lines.append("")
    lines.append(f"legend: {legend}   {paint('·', ABSENT_COLOR)} absent")
    return lines


def profile_view(conn, ips: list[str], color: bool = True, normalize: bool = False) -> list[str]:
    rows = aggregate.agreement_profile(conn, ips, normalize=normalize)
    paint = Paint(color)
    namew = max(len(row["source"]) for row in rows)
    lines = ["", "agreement profile:  conformity, not accuracy", ""]
    lines.append(f"{'source':<{namew}}  cells  agree  dissent  multi  single")
    for row in rows:
        agree = paint(str(row["agree"]).rjust(5), 32)
        dissent = paint(str(row["dissent"]).rjust(8), 31)
        multi = paint(str(row["multi"]).rjust(6), 33)
        single = paint(str(row["single"]).rjust(7), 90)
        lines.append(
            f"{row['source']:<{namew}}  {row['cells']:>5}  {agree}  {dissent}  {multi}  {single}"
        )
    return lines


def entities_view(conn, ip: str, color: bool = True) -> list[str]:
    entity = entities.resolve(conn, ip)
    lines = [f"{ip}  entity"]
    asns = ", ".join(str(record["asn"]) for record in entity["asn"]) or "-"
    lines.append(f"  asn      {asns}")
    for record in entity["asn"]:
        lines.append(f"           AS{record['asn']}  <- {', '.join(record['sources'])}")
    lines.append(f"  country  {', '.join(entity['country']) or '-'}")
    lines.append(f"  prefix   {', '.join(entity['prefix']) or '-'}")
    lines.append(f"  range    {', '.join(entity['range']) or '-'}")
    for number, raws in entity["aliases"].items():
        groups: dict[str, list[str]] = {}
        for raw in raws:
            groups.setdefault(entities.org(raw), []).append(raw)
        lines.append(f"  aliases of AS{number}:")
        for canonical, variants in sorted(groups.items()):
            mark = "=" if len(variants) > 1 else " "
            lines.append(f"    [{mark}] {canonical:<24} <- {', '.join(variants)}")
    if entity["unlinked"]:
        lines.append(f"  unlinked names: {', '.join(entity['unlinked'])}")
    return lines


def stats_view(conn, ips: list[str] | None = None, color: bool = True, normalize: bool = False) -> list[str]:
    data = analyze.stats(conn, ips, normalize=normalize)
    paint = Paint(color)
    lines = [f"analysis  ·  {len(data['ips'])} ip(s)  ·  {data['claims']} claim-cells", ""]
    lines.append("verdicts:")
    for verdict in ("disagree", "spread", "agree", "single"):
        count = data["verdicts"].get(verdict, 0)
        if count:
            lines.append(f"  {paint(f'{verdict:<10}', VERDICT_COLOR[verdict])} {count}")
    lines.append("")
    lines.append("most contested claims:")
    lines.append(f"  {'topic.key':<26} {'cells':>5} {'contested':>9} {'rate':>6}")
    for row in data["disagreements"][:15]:
        if not row["contested"]:
            continue
        lines.append(
            f"  {row['topic'] + '.' + row['key']:<26} {row['cells']:>5} {row['contested']:>9} "
            f"{row['rate']:>6.0%}"
        )
    lines.append("")
    lines.append("anycast-like (one source reports many location claims):")
    for row in data["anycast"][:10]:
        lines.append(f"  {row['ip']:<16} {row['source']:<22} {row['values']} values")
    lines.append("")
    lines.append("sources (conformity, not accuracy):")
    lines.append(f"  {'source':<24} {'cells':>5} {'agree':>6} {'dissent':>7} {'multi':>6} {'single':>6}")
    for row in data["sources"]:
        lines.append(
            f"  {row['source']:<24} {row['cells']:>5} {row['agree']:>6} {row['dissent']:>7} "
            f"{row['multi']:>6} {row['single']:>6}"
        )
    return lines
