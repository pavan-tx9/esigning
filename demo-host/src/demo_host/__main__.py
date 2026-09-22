"""``python -m demo_host`` -- run the stand-in EHR.

``DEMO_HOST_PORT`` (default 8100) and ``DEMO_HOST_BIND`` (default 127.0.0.1) decide where.
"""

from __future__ import annotations

import os

import uvicorn


def main() -> None:
    uvicorn.run(
        "demo_host.server:app",
        host=os.environ.get("DEMO_HOST_BIND", "127.0.0.1"),
        port=int(os.environ.get("DEMO_HOST_PORT", "8100")),
        server_header=False,
        log_level=os.environ.get("DEMO_LOG_LEVEL", "info"),
    )


if __name__ == "__main__":
    main()
