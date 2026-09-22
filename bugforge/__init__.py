"""BugForge — legacy compatibility package alias for GUNGNIR.

Deprecated: prefer importing and running ``gungnir``. This twin package is kept
as a thin compatibility surface so old ``bugforge`` imports and ``python -m
bugforge`` cannot silently diverge from the hardened gungnir verify/CLI path.
"""
from gungnir import __version__ as __version__  # noqa: F401 — stay in lockstep
