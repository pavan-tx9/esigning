"""Serving the built signing UI at ``/sign`` (SPEC section 9, "Embedding protocol").

The UI is loaded in an iframe as ``/sign?host=<host id>``. The host id is not a secret and says
nothing about a patient; it is what lets this response carry the two things the embedding rules
need *before* any token exists:

* ``Content-Security-Policy: frame-ancestors <that host's allowed origins>`` -- the browser refuses
  to render the UI inside any other page;
* ``<meta name="esign-allowed-origins">`` with the same list -- the UI accepts ``esign:init`` (and
  therefore a token) only from those origins.

An unknown, disabled or missing host gets ``frame-ancestors 'none'`` and an empty list: the UI then
cannot be embedded and trusts nobody. The token itself never appears in a URL.
"""

from __future__ import annotations

import html
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from esign.api.context import runtime_of
from esign.api.errors import error_response
from esign.api.middleware import ui_csp
from esign.identity import embedding_origins

__all__ = ["install_ui"]


def _origins_for(request: Request) -> tuple[str, ...]:
    raw = request.query_params.get("host", "")
    try:
        host_id = UUID(raw)
    except ValueError:
        return ()
    rt = runtime_of(request)
    with rt.transaction() as db:
        return embedding_origins(db, host_id) or ()


def install_ui(app: FastAPI, dist: Path) -> bool:
    """Mount the UI when ``frontend/dist`` exists. Returns whether it did."""
    index = dist / "index.html"
    if not index.is_file():
        return False
    router = APIRouter(include_in_schema=False)

    @router.get("/sign")
    @router.get("/sign/")
    def sign_ui(request: Request) -> HTMLResponse:
        origins = _origins_for(request)
        try:
            page = index.read_text(encoding="utf-8")
        except OSError:
            return HTMLResponse(error_response(503, "ui_unavailable").body, status_code=503)
        meta = f'<meta name="esign-allowed-origins" content="{html.escape(" ".join(origins), quote=True)}">'
        page = page.replace("<head>", f"<head>\n    {meta}", 1) if "<head>" in page else meta + page
        return HTMLResponse(page, headers={"Content-Security-Policy": ui_csp(origins), "Cache-Control": "no-store"})

    app.include_router(router)
    assets = dist / "assets"
    if assets.is_dir():
        # The Vite build references /assets/... from the root. Hashed filenames, no PHI: cacheable.
        app.mount("/assets", StaticFiles(directory=assets), name="ui-assets")
    return True
