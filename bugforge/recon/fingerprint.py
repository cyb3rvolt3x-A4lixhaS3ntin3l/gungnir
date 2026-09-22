"""Legacy re-export of gungnir.recon.fingerprint.

Deprecated: import from ``gungnir.recon.fingerprint`` instead.
Kept so tech fingerprinting (P1) cannot diverge from gungnir.
"""
from __future__ import annotations

from gungnir.recon.fingerprint import (  # noqa: F401
    BODY_SIGNS,
    HEADER_SIGNS,
    FingerprintResult,
    TechFingerprinter,
    TechMatch,
)

__all__ = [
    "BODY_SIGNS",
    "HEADER_SIGNS",
    "FingerprintResult",
    "TechFingerprinter",
    "TechMatch",
]
