"""Entity normalization.

Canonicalise observation values so that sources describing the same thing in
different words are not counted as disagreements, and resolve an IP's
ownership entity (ASN + the name aliases linked to it).

Nothing here writes; it is pure transformation over observation values.
"""

from __future__ import annotations

import ipaddress
import json
import re

LEGAL_SUFFIXES = {
    "LLC", "INC", "LTD", "LIMITED", "CORP", "CORPORATION", "CO", "GMBH", "AG",
    "BV", "NV", "SA", "SAS", "SARL", "SRL", "SPA", "PLC", "PTY", "OY", "AB",
    "AS", "SE", "KK", "PTE", "SL", "SLU", "UG", "EOOD", "OOO", "OAO", "PAO",
}

COUNTRY_NAMES = {
    "UNITED STATES": "US", "UNITED STATES OF AMERICA": "US", "USA": "US",
    "UNITED KINGDOM": "GB", "GREAT BRITAIN": "GB", "UK": "GB",
    "RUSSIAN FEDERATION": "RU", "SOUTH KOREA": "KR", "KOREA": "KR",
    "KOREA, REPUBLIC OF": "KR", "NORTH KOREA": "KP", "CZECH REPUBLIC": "CZ",
    "CZECHIA": "CZ", "VIET NAM": "VN", "VIETNAM": "VN", "TAIWAN": "TW",
    "HONG KONG": "HK", "HONG KONG SAR CHINA": "HK", "UAE": "AE",
    "UNITED ARAB EMIRATES": "AE", "IRAN": "IR", "IRAN, ISLAMIC REPUBLIC OF": "IR",
    "SYRIA": "SY", "BOLIVIA": "BO", "VENEZUELA": "VE", "MOLDOVA": "MD",
    "TANZANIA": "TZ", "BRUNEI": "BN", "LAOS": "LA", "MACEDONIA": "MK",
    "NORTH MACEDONIA": "MK", "GERMANY": "DE", "FRANCE": "FR", "NETHERLANDS": "NL",
    "SPAIN": "ES", "ITALY": "IT", "POLAND": "PL", "SWEDEN": "SE",
    "SWITZERLAND": "CH", "AUSTRIA": "AT", "BELGIUM": "BE", "IRELAND": "IE",
    "JAPAN": "JP", "CHINA": "CN", "INDIA": "IN", "BRAZIL": "BR",
    "CANADA": "CA", "AUSTRALIA": "AU", "SINGAPORE": "SG", "SOUTH AFRICA": "ZA",
}


def asn(value) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    match = re.search(r"\d+", str(value or ""))
    return int(match.group()) if match else None


def country(value) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if len(text) == 2 and text.isalpha():
        return text.upper()
    return COUNTRY_NAMES.get(text.upper(), text.upper())


def prefix(value) -> str | None:
    if value is None:
        return None
    match = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$", str(value).strip())
    if not match:
        return None
    try:
        net = ipaddress.ip_network(f"{match.group(1)}/{match.group(2)}", strict=False)
    except ValueError:
        return None
    return str(net)


def range_canon(value) -> str | None:
    if value is None:
        return None
    match = re.match(
        r"^(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})$", str(value).strip()
    )
    if not match:
        return None
    try:
        lo = int(ipaddress.IPv4Address(match.group(1)))
        hi = int(ipaddress.IPv4Address(match.group(2)))
    except ValueError:
        return None
    return f"{match.group(1)}-{match.group(2)}" if lo <= hi else None


def org(value) -> str:
    text = re.sub(r"\bAS\s*\d+\b", " ", str(value or ""), flags=re.I)
    tokens = [
        token for token in re.findall(r"[A-Z0-9]+", text.upper())
        if token not in LEGAL_SUFFIXES
    ]
    deduped: list[str] = []
    for token in tokens:
        if token not in deduped:
            deduped.append(token)
    return " ".join(deduped) if deduped else str(value or "").upper()




def resolve(conn, ip: str) -> dict:
    asns: dict[int, set[str]] = {}
    countries: set[str] = set()
    prefixes: set[str] = set()
    ranges: set[str] = set()
    names: list[tuple[str, str]] = []
    per_source: dict[str, dict] = {}

    for source, topic, key, value in conn.execute(
        "SELECT source, topic, key, value FROM observations WHERE ip = ? ORDER BY source, topic, key",
        (ip,),
    ):
        parsed = json.loads(value)
        entry = per_source.setdefault(source, {})
        if (topic, key) == ("ownership", "asn"):
            number = asn(parsed)
            if number is not None:
                asns.setdefault(number, set()).add(source)
                entry["asn"] = number
        elif (topic, key) == ("country", "country"):
            code = country(parsed)
            if code:
                countries.add(code)
        elif (topic, key) == ("ownership", "prefix"):
            normalized = prefix(parsed)
            if normalized:
                prefixes.add(normalized)
        elif (topic, key) == ("ownership", "range"):
            normalized = range_canon(parsed)
            if normalized:
                ranges.add(normalized)
        elif (topic, key) in (("ownership", "name"), ("ownership", "org"), ("ownership", "holder")):
            names.append((source, str(parsed)))

    aliases: dict[int, set[str]] = {}
    unlinked: set[str] = set()
    for source, raw in names:
        anchor = per_source.get(source, {}).get("asn")
        if anchor is not None:
            aliases.setdefault(anchor, set()).add(raw)
        else:
            unlinked.add(raw)

    known = {org(raw): number for number, raws in aliases.items() for raw in raws}
    still_unlinked = set()
    for raw in unlinked:
        match = known.get(org(raw))
        if match is not None:
            aliases[match].add(raw)
        else:
            still_unlinked.add(raw)

    return {
        "ip": ip,
        "asn": [{"asn": number, "sources": sorted(sources)} for number, sources in sorted(asns.items())],
        "country": sorted(countries),
        "prefix": sorted(prefixes),
        "range": sorted(ranges),
        "aliases": {str(number): sorted(values) for number, values in sorted(aliases.items())},
        "unlinked": sorted(still_unlinked),
    }
