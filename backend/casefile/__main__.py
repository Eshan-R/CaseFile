"""Entry point for python -m casefile."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure backend directory is in sys.path when invoked directly
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.cli import app  # noqa: E402

if __name__ == "__main__":
    app()

