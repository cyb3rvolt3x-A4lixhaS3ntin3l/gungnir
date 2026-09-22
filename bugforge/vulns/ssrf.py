"""Legacy re-export of gungnir.vulns.ssrf.

Deprecated: import from ``gungnir.vulns.ssrf`` instead.
Kept so SSRF helpers/payloads cannot diverge from gungnir (P0/P1).
"""
from __future__ import annotations

from gungnir.vulns.ssrf import (  # noqa: F401
    BYPASS_ENCODINGS,
    CLOUD_METADATA,
    INTERNAL_PORT_SCAN_DEFAULT,
    INTERNAL_TARGETS,
    SsrfHelper,
    SsrfPayload,
    _is_private_ip,
)

__all__ = [
    "BYPASS_ENCODINGS",
    "CLOUD_METADATA",
    "INTERNAL_PORT_SCAN_DEFAULT",
    "INTERNAL_TARGETS",
    "SsrfHelper",
    "SsrfPayload",
]
