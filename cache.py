"""Small disk cache for source analysis, so repeated test runs do not re-hit
rate-limited APIs.

Controlled by environment:
  PATHS_CACHE      cache dir, or "off" to disable (default ~/.cache/aranya/paths)
  PATHS_CACHE_TTL  seconds before an entry is stale (default 86400; 0 = never)
"""

from __future__ import annotations

import hashlib
import json
import os
import time


def _dir() -> str:
    return os.environ.get("PATHS_CACHE") or os.path.join(os.path.expanduser("~"), ".cache", "aranya", "paths")


def enabled() -> bool:
    return _dir().lower() not in ("off", "0", "none", "")


def make(*parts) -> str:
    return hashlib.sha1("|".join(str(part) for part in parts).encode()).hexdigest()


def _path(key: str) -> str:
    return os.path.join(_dir(), key[:2], key + ".json")


def get(key: str):
    if not enabled():
        return None
    try:
        with open(_path(key)) as handle:
            blob = json.load(handle)
        ttl = float(os.environ.get("PATHS_CACHE_TTL", "86400"))
        if ttl and time.time() - blob.get("t", 0) > ttl:
            return None
        return blob.get("v")
    except Exception:
        return None


def put(key: str, value) -> None:
    if not enabled():
        return
    try:
        path = _path(key)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as handle:
            json.dump({"t": time.time(), "v": value}, handle)
    except Exception:
        pass
