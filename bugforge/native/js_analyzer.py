"""Legacy re-export of gungnir.native.js_analyzer.

Deprecated: import from ``gungnir.native.js_analyzer`` instead.
Kept so JS secret/route patterns (P1) cannot diverge from gungnir.
"""
from __future__ import annotations

from gungnir.native.js_analyzer import (  # noqa: F401
    API_ROUTE_PATTERNS,
    PARAM_PATTERNS,
    SECRET_PATTERNS,
    analyze_js,
    normalize_url,
)

__all__ = [
    "API_ROUTE_PATTERNS",
    "PARAM_PATTERNS",
    "SECRET_PATTERNS",
    "analyze_js",
    "normalize_url",
]
