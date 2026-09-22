"""Legacy re-export of gungnir.vulns.secrets.

Deprecated: import from ``gungnir.vulns.secrets`` instead.
Kept so secret-scan regexes and ``SecretScanner`` cannot diverge from gungnir (P0/P1).
"""
from __future__ import annotations

from gungnir.vulns.secrets import (  # noqa: F401
    SECRET_PATTERNS,
    SecretMatch,
    SecretScanner,
)

__all__ = [
    "SECRET_PATTERNS",
    "SecretMatch",
    "SecretScanner",
]
