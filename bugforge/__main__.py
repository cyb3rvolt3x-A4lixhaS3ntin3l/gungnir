"""BugForge — legacy compatibility entry point for GUNGNIR.

Deprecated: prefer ``python -m gungnir`` or the ``gungnir`` console script.
This module exists so remote CI and old invocations of ``python -m bugforge``
keep working without diverging from the gungnir CLI.
"""
from __future__ import annotations

import sys

from gungnir.cli import main

if __name__ == "__main__":
    sys.exit(main())
