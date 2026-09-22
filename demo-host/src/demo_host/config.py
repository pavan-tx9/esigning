"""Where the demo host finds the signing service, and the one password it pretends to check.

Everything comes from the environment, because ``make demo`` registers a fresh host with
``esign hosts create`` and passes the credentials it printed. Nothing is stored in the repository:
the API key and the webhook secret are shown once by that command and live only in the shell that
started the demo.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

__all__ = ["Config", "load_config"]


@dataclass(frozen=True)
class Config:
    #: The e-signing service's HTTP API (server to server, Host API key).
    api_url: str
    #: Where the browser loads the signing UI from. Same origin as the API in this setup.
    ui_url: str
    #: ``esk_...``, printed once by ``esign hosts create``.
    api_key: str
    #: Identifies this host to ``/sign?host=...`` so the service can send the right CSP.
    host_id: str
    #: Hex secret, printed once by ``esign hosts create``. Empty means "refuse every webhook".
    webhook_secret: bytes
    #: This app's own public origin. It has to match the host's registered allowed origin.
    public_url: str
    #: The demo's single shared password. A real EHR would not have one of these.
    password: str

    @property
    def signing_ui_src(self) -> str:
        return f"{self.ui_url.rstrip('/')}/sign?host={self.host_id}"


def _secret(name: str) -> bytes:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return b""
    try:
        return bytes.fromhex(raw)
    except ValueError:
        return raw.encode("utf-8")


def load_config() -> Config:
    api_url = os.environ.get("DEMO_ESIGN_API_URL", "http://localhost:8000").rstrip("/")
    return Config(
        api_url=api_url,
        ui_url=os.environ.get("DEMO_ESIGN_UI_URL", api_url).rstrip("/"),
        api_key=os.environ.get("DEMO_ESIGN_API_KEY", ""),
        host_id=os.environ.get("DEMO_ESIGN_HOST_ID", ""),
        webhook_secret=_secret("DEMO_ESIGN_WEBHOOK_SECRET"),
        public_url=os.environ.get("DEMO_PUBLIC_URL", "http://localhost:8100").rstrip("/"),
        password=os.environ.get("DEMO_PASSWORD", "demo1234"),
    )
