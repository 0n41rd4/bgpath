"""Terminal rendering of the observation views.

Pure presentation: consumes views.py (read-only rows) and aggregate.py
(consensus/cross-IP), and prints compact ANSI tables. Disable colour with
--no-color or NO_COLOR.
"""

from __future__ import annotations

import aggregate
import views

GLYPHS = ["●", "◆", "▲", "■", "★", "▼", "◈", "⬟"]
CLAIM_COLORS = [96, 95, 93, 92, 94, 91]
VERDICT_COLOR = {"agree": 32, "spread": 33, "disagree": 31}
VERDICT_GLYPH = {"agree": ".", "spread": "+", "disagree": "#"}
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


def claim_view(conn, ip: str, color: bool = True, cap: int = 6) -> list[str]:
    summaries = aggregate.cell_summaries(conn, ip)
    if not summaries:
        return [f"{ip}: no observations"]
    paint = Paint(color)
    width = max(len(f"{s['topic']}.{s['key']}") for s in summaries)
    lines = [f"{ip}  —  {len(summaries)} claim(s)   (* = source reports a set)\n"]
    for summary in summaries:
        multi = summary["multi"]
        listed = []
        for label, backing in summary["labels"]:
            singles = [src for src in sorted(backing) if src not in multi]
            if singles:
                listed.append((label, singles, [src for src in sorted(backing) if src in multi]))
        listed.sort(key=lambda item: (-len(item[1]), item[0]))

        verdict = "spread" if summary["enumeration"] else summary["verdict"]
        status = "enumerated" if summary["enumeration"] else summary["verdict"]
        mark = paint(aggregate.VERDICT_MARK[verdict], VERDICT_COLOR[verdict])
        head = f"{summary['topic']}.{summary['key']:<{width}}"
        lines.append(f"{head}  [{mark}] {status:<10} {len(summary['sources'])} source(s)")

        for index, (label, singles, multis) in enumerate(listed[:cap]):
            glyph = paint(GLYPHS[index % len(GLYPHS)], CLAIM_COLORS[index % len(CLAIM_COLORS)])
            names = ", ".join(singles + [f"{src}*" for src in multis])
            lines.append(f"    {glyph} {label:<34} {names}")
        if len(listed) > cap:
            lines.append(f"      + {len(listed) - cap} more value(s)")

        for source in sorted(multi):
            count = summary["counts"][source]
            sample = ", ".join(summary["source_labels"][source][:3])
            glyph = paint("~", 33)
            lines.append(
                f"    {glyph} {source + '*':<34} {count} values: {sample}{'…' if count > 3 else ''}"
            )
        lines.append("")
    return lines


def overview_view(conn, ips: list[str], color: bool = True) -> list[str]:
    verdicts = aggregate.overview(conn, ips)
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
                glyph = paint(VERDICT_GLYPH[verdict], VERDICT_COLOR[verdict])
                row.append(f"{glyph:>{width}}")
        lines.append(f"{ip:>{ipw}}  " + " ".join(row))
    legend = "  ".join(
        f"{paint(VERDICT_GLYPH[v], VERDICT_COLOR[v])} {v}" for v in ("agree", "spread", "disagree")
    )
    lines.append("")
    lines.append(f"legend: {legend}   {paint('·', ABSENT_COLOR)} absent")
    return lines


def profile_view(conn, ips: list[str], color: bool = True) -> list[str]:
    rows = aggregate.profile(conn, ips)
    paint = Paint(color)
    namew = max(len(row["source"]) for row in rows)
    lines = ["", f"source profile:  agreement with each cell's consensus", ""]
    lines.append(f"{'source':<{namew}}  cells  agree  dissent  multi")
    for row in rows:
        agree = paint(str(row["agree"]).rjust(5), 32)
        dissent = paint(str(row["dissent"]).rjust(8), 31)
        multi = paint(str(row["multi"]).rjust(6), 33)
        lines.append(
            f"{row['source']:<{namew}}  {row['cells']:>5}  {agree}  {dissent}  {multi}"
        )
    return lines
