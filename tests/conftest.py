"""
conftest.py — pytest configuration.

Sets MAILSHIELD_CONFIG before any project module is imported so that
config.py's module-level `settings = load()` finds a valid file.
"""

import os
from pathlib import Path

# Point to the bundled default config so tests run without a real installation
_DEFAULT_CONF = str(Path(__file__).parent.parent / "core" / "config" / "mailshield.conf")
os.environ.setdefault("MAILSHIELD_CONFIG", _DEFAULT_CONF)
