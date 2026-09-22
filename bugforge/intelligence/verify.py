"""Legacy re-export of gungnir.intelligence.verify.

Deprecated: import from ``gungnir.intelligence.verify`` instead.
Kept so ``from bugforge.intelligence.verify import verify_criticals`` cannot
diverge from the P2 honest verification engine (evidence XSS, statuses, scope).
"""
from __future__ import annotations

from gungnir.intelligence.verify import (  # noqa: F401
    STATUS_CONFIRMED,
    STATUS_NOT_REPRODUCED,
    STATUS_SKIPPED,
    STATUS_UNVERIFIED,
    verify_criticals,
    _fetch,
    _fetch_headers,
    _fetch_status,
    _retest,
    _resolve_scope_allows,
    _set_status,
)

__all__ = [
    "STATUS_CONFIRMED",
    "STATUS_NOT_REPRODUCED",
    "STATUS_SKIPPED",
    "STATUS_UNVERIFIED",
    "verify_criticals",
]
