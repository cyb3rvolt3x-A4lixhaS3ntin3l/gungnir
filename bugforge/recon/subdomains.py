"""Legacy re-export of gungnir.recon.subdomains.

Deprecated: import from ``gungnir.recon.subdomains`` instead.
Kept so subdomain enumeration (P1) cannot diverge from gungnir.
"""
from __future__ import annotations

from gungnir.recon.subdomains import (  # noqa: F401
    Subdomain,
    SubdomainEnum,
)

__all__ = [
    "Subdomain",
    "SubdomainEnum",
]
