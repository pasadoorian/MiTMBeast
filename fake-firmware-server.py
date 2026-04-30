#!/usr/bin/env python3
"""Fake firmware server — backwards-compat shim.

The implementation now lives in ``mitmbeast.core.fakefw``. This script
remains as the entry point that the bash mitm.sh wrappers and any
external automation invoke, and now uses a threaded HTTP/HTTPS server
(was single-threaded in v1.0).

Run ``python fake-firmware-server.py --help`` for usage.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Allow running directly from the repo without installing the package
SRC = Path(__file__).resolve().parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mitmbeast.core.fakefw import main

if __name__ == "__main__":
    main()
