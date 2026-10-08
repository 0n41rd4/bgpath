"""aranya.paths - path & topology exploration sub-project.

Measurement and graph layers live here; source enrichment reuses aranya's
adapters (sources/parsers/observe). The graph is kept topological: nodes and
edges are routers/interfaces/ASes/IXPs/facilities, and every geographic claim
is an annotation, never a coordinate baked into the topology.
"""

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
