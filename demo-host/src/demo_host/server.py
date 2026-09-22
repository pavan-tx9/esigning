"""The ASGI application uvicorn loads: ``demo_host.server:app``."""

from __future__ import annotations

from demo_host.app import create_app

app = create_app()
