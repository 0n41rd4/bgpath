"""Normalization: turn a raw body into parsed data and observations.

This is a separate step from fetching/storing so that observations can later
be (re)built from the raw store alone when a parser changes, without ever
touching the raw responses.
"""

from __future__ import annotations


def normalize(adapter: dict, ip: str, body: str) -> tuple[dict, list[dict]]:
    parsed = adapter["parse"](body)
    return parsed, adapter["observations"](ip, parsed)
