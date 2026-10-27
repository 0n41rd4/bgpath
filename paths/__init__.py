"""aranya.paths — ping + traceroute and a per-tool topological graph.

Measurement (`probe.py`, `ingest.py`), graph construction (`graph.py`),
persistence (`store.py`), source enrichment (`enrich.py`) and rendering
(`export.py`) live here; source queries reuse aranya's `source` layer.
"""

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
