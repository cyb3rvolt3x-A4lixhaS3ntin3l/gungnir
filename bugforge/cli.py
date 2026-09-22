"""Legacy re-export of gungnir.cli.

Deprecated: prefer ``gungnir.cli`` / ``python -m gungnir``.
Kept so ``from bugforge.cli import main`` cannot diverge from the shipped CLI.
"""
from __future__ import annotations

from gungnir.cli import main

__all__ = ["main"]
