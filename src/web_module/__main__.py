"""`python -m web_module` — the only entry point."""

from __future__ import annotations

from .server import main

if __name__ == "__main__":
    raise SystemExit(main())
