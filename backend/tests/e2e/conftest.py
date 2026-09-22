"""End-to-end fixtures: the real HTTP app over real modules.

Nothing here is faked. The app is ``create_app`` over ``build_runtime``: Postgres as the restricted
``esign_app`` role, the ``fs`` blob store, the local key backend with a generated dev PKI, and the
in-process RFC 3161 authority that PKI provides. Requests go through Starlette's ``TestClient``, so
routing, middleware, error handling and the per-request transaction are all the production code.

``Ehr`` plays the host: it holds the API key, uploads and publishes templates over the API, and
drives a signer through the UI's calls with the session token. Commits are real, so every test
ends by emptying the database (``db_factory``'s teardown).
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from esign.api import create_app
from esign.clock import FixedClock
from esign.config import Settings
from esign.contracts import Sealer
from esign.identity import create_host, rotate_webhook_secret, seed_default_consent
from esign.runtime import Runtime, build_runtime
from esign.sealing import generate_dev_pki
from tests.conftest import FROZEN_NOW
from tests.documents.helpers import handwriting_png

TEMPLATES_DIR = Path(__file__).resolve().parents[3] / "templates"

#: Values a real envelope carries that must never leave the database and the PDF.
PATIENT_NAME = "Marguerite Okonkwo-Vasquez"
WITNESS_NAME = "Bartholomew Featherstonehaugh"
CLINICIAN_NAME = "Dr Quincy Ravensworth"
PREFILL = {
    "patient_name": PATIENT_NAME,
    "date_of_birth": "1971-04-02",
    "procedure_name": "Left knee arthroscopy",
    "procedure_description": "Keyhole examination and repair of the left knee joint.",
    "known_risks": "Bleeding, infection, stiffness, deep vein thrombosis.",
}

Sessions = Callable[[], AbstractContextManager[Session]]


@pytest.fixture(scope="session")
def e2e_pki(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One dev PKI for the whole run: four RSA keys per test would dominate it."""
    directory = tmp_path_factory.mktemp("e2e-dev-pki")
    generate_dev_pki(directory, FixedClock(FROZEN_NOW))
    return directory


@pytest.fixture
def e2e_settings(settings: Settings, e2e_pki: Path, tmp_path: Path) -> Settings:
    return settings.model_copy(
        update={
            "dev_pki_dir": e2e_pki,
            "trust_roots_path": e2e_pki / "trust-roots.pem",
            "seal_profile": "PAdES-B-LT",
            "seal_key_backend": "local",
            "tsa_url": "",  # the in-process authority from the dev PKI
            "frontend_dist_dir": tmp_path / "no-ui-built",
            "log_level": "INFO",
        }
    )


@dataclass
class Signer:
    """One signer's browser: a session token and the calls the UI makes with it."""

    client: TestClient
    token: str
    session_id: str
    signer_id: str

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    def get(self, path: str) -> httpx.Response:
        response: httpx.Response = self.client.get(f"/v1/signing{path}", headers=self.headers)
        return response

    def post(self, path: str, body: dict[str, Any], **headers: str) -> httpx.Response:
        response: httpx.Response = self.client.post(
            f"/v1/signing{path}", json=body, headers={**self.headers, **headers}
        )
        return response

    def session(self) -> dict[str, Any]:
        response = self.get("/session")
        assert response.status_code == 200, response.text
        payload: dict[str, Any] = response.json()
        return payload

    def review_and_consent(self) -> dict[str, Any]:
        """Fetch the document, display every page, accept the disclosure -- what the UI does."""
        payload = self.session()
        document = self.get("/document")
        assert document.status_code == 200, document.text
        assert document.headers["cache-control"] == "no-store"
        assert document.content.startswith(b"%PDF")
        viewed = self.post("/viewed", {"pages_viewed": payload["envelope"]["page_count"]})
        assert viewed.status_code == 200, viewed.text
        consent = self.post("/consent", {"consent_version": payload["consent"]["version"], "accepted": True})
        assert consent.status_code == 200, consent.text
        return payload

    def captures(self, payload: dict[str, Any], *, kind: str = "drawn") -> list[dict[str, Any]]:
        """One capture per field this signer owns, in the wire shapes of SPEC section 9."""
        image = base64.b64encode(handwriting_png()).decode("ascii")
        out: list[dict[str, Any]] = []
        for item in payload["fields"]:
            if item["type"] == "date_signed":
                continue  # the server fills these from Clock; a client that sends one is refused
            if item["type"] == "checkbox":
                out.append({"field_id": item["id"], "checked": True})
            elif item["type"] == "text":
                out.append({"field_id": item["id"], "text_value": "Noted"})
            elif item["type"] == "initials":
                out.append({"field_id": item["id"], "kind": "typed", "typed_text": "MO"})
            elif kind == "drawn":
                out.append({"field_id": item["id"], "kind": "drawn", "image_png_base64": image})
            elif kind == "typed":
                out.append({"field_id": item["id"], "kind": "typed", "typed_text": payload["signer"]["display_name"]})
            else:
                out.append({"field_id": item["id"], "kind": "click"})
        return out

    def sign(self, payload: dict[str, Any], *, key: str, kind: str = "drawn") -> httpx.Response:
        body = {"intent_confirmed": True, "captures": self.captures(payload, kind=kind)}
        return self.post("/sign", body, **{"Idempotency-Key": key})


@dataclass
class Ehr:
    """The host: an API key, and the server-to-server calls an EHR backend makes."""

    client: TestClient
    rt: Runtime
    clock: FixedClock
    host_id: str
    api_key: str
    webhook_secret: bytes | None = None
    deliveries: list[tuple[str, bytes, dict[str, str]]] = field(default_factory=list)

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key}"}

    def get(self, path: str) -> httpx.Response:
        response: httpx.Response = self.client.get(f"/v1{path}", headers=self.headers)
        return response

    def post(self, path: str, body: dict[str, Any] | None = None, **headers: str) -> httpx.Response:
        response: httpx.Response = self.client.post(f"/v1{path}", json=body, headers={**self.headers, **headers})
        return response

    # -- templates -----------------------------------------------------------

    def publish_template(self, key: str) -> None:
        """Upload a sample template over the API and publish version 1."""
        definitions = (TEMPLATES_DIR / f"{key}.json").read_text(encoding="utf-8")
        with (TEMPLATES_DIR / f"{key}.pdf").open("rb") as pdf:
            created = self.client.post(
                "/v1/templates",
                headers=self.headers,
                files={"pdf": (f"{key}.pdf", pdf, "application/pdf")},
                data={"definitions": definitions},
            )
        assert created.status_code == 201, created.text
        published = self.post(f"/templates/{key}/versions/1/publish")
        assert published.status_code == 200, published.text

    # -- envelopes -----------------------------------------------------------

    def envelope_body(self, template_key: str, **overrides: Any) -> dict[str, Any]:
        signers = {
            "patient": {
                "role_key": "patient",
                "host_user_id": "pt-100482",
                "display_name": PATIENT_NAME,
                "capacity": "self",
            },
            "witness": {
                "role_key": "witness",
                "host_user_id": "staff-2207",
                "display_name": WITNESS_NAME,
                "capacity": "witness",
            },
            "clinician": {
                "role_key": "clinician",
                "host_user_id": "dr-0311",
                "display_name": CLINICIAN_NAME,
                "capacity": "clinician",
            },
        }
        definitions = json.loads((TEMPLATES_DIR / f"{template_key}.json").read_text(encoding="utf-8"))
        roles = [r["key"] for r in definitions["signer_roles"]]
        prefill_keys = [p["key"] for p in definitions["prefill_fields"]]
        prefill = {k: PREFILL.get(k, "2026-03 notice") for k in prefill_keys}
        if "treatment_summary" in prefill:
            prefill["treatment_summary"] = "Routine physiotherapy for the left knee."
        body: dict[str, Any] = {
            "template_key": template_key,
            "patient_ref": "chart-77120",
            "host_document_ref": "doc-5531",
            "signing_order": "sequential",
            "signers": [signers[r] for r in roles],
            "prefill": prefill,
        }
        body.update(overrides)
        return body

    def create_envelope(self, template_key: str, **overrides: Any) -> dict[str, Any]:
        response = self.post("/envelopes", self.envelope_body(template_key, **overrides))
        assert response.status_code == 201, response.text
        payload: dict[str, Any] = response.json()
        return payload

    def envelope(self, envelope_id: str) -> dict[str, Any]:
        response = self.get(f"/envelopes/{envelope_id}")
        assert response.status_code == 200, response.text
        payload: dict[str, Any] = response.json()
        return payload

    def signer_id(self, envelope: dict[str, Any], role_key: str) -> str:
        return next(str(s["id"]) for s in envelope["signers"] if s["role_key"] == role_key)

    def open_session_response(
        self, envelope: dict[str, Any], role_key: str, *, method: str = "password", kiosk: dict[str, str] | None = None
    ) -> httpx.Response:
        body: dict[str, Any] = {
            "auth": {"method": method, "auth_time": (self.clock.now() - timedelta(minutes=2)).isoformat()}
        }
        if kiosk is not None:
            body["kiosk"] = kiosk
        return self.post(f"/envelopes/{envelope['id']}/signers/{self.signer_id(envelope, role_key)}/sessions", body)

    def open_session(self, envelope: dict[str, Any], role_key: str, **kwargs: Any) -> Signer:
        response = self.open_session_response(envelope, role_key, **kwargs)
        assert response.status_code == 201, response.text
        payload = response.json()
        return Signer(
            client=self.client,
            token=payload["token"],
            session_id=payload["session_id"],
            signer_id=self.signer_id(envelope, role_key),
        )

    def reauth(self, signer: Signer, *, method: str = "password+mfa") -> httpx.Response:
        return self.post(
            f"/sessions/{signer.session_id}/reauth", {"method": method, "auth_time": self.clock.now().isoformat()}
        )

    def audit(self, envelope_id: str) -> list[dict[str, Any]]:
        response = self.get(f"/envelopes/{envelope_id}/audit")
        assert response.status_code == 200, response.text
        events: list[dict[str, Any]] = response.json()["events"]
        return events

    def audit_types(self, envelope_id: str) -> list[str]:
        return [str(e["event_type"]) for e in self.audit(envelope_id)]

    def verification(self, envelope_id: str) -> dict[str, Any]:
        response = self.get(f"/envelopes/{envelope_id}/verification")
        assert response.status_code == 200, response.text
        payload: dict[str, Any] = response.json()
        return payload

    def sign_everyone(self, envelope: dict[str, Any], roles: tuple[str, ...]) -> None:
        for index, role_key in enumerate(roles):
            signer = self.open_session(
                envelope, role_key, method="password+mfa" if role_key == "clinician" else "password"
            )
            payload = signer.review_and_consent()
            if payload["signer"]["requires_reauth"]:
                assert self.reauth(signer).status_code == 200
            signed = signer.sign(payload, key=f"sign-{envelope['id']}-{index}")
            assert signed.status_code == 200, signed.text

    # -- webhooks ------------------------------------------------------------

    def receive(self, url: str, body: bytes, headers: dict[str, str]) -> int:
        """A ``Sender`` standing in for the network: the host's webhook endpoint, recording
        exactly what arrived."""
        self.deliveries.append((url, body, headers))
        return 204


@dataclass
class World:
    client: TestClient
    rt: Runtime
    clock: FixedClock
    sessions: Sessions
    settings: Settings

    def host(self, name: str = "Riverside EHR", *, webhook: bool = False) -> Ehr:
        with self.rt.transaction() as db:
            key, host = create_host(
                db,
                name,
                ("https://ehr.example",),
                "https://ehr.example/hooks/esign" if webhook else None,
                clock=self.clock,
            )
            secret = rotate_webhook_secret(db, host.id) if webhook else None
        return Ehr(
            client=self.client, rt=self.rt, clock=self.clock, host_id=str(host.id), api_key=key, webhook_secret=secret
        )


def build_world(
    settings: Settings, clock: FixedClock, engine: Engine, sessions: Sessions, *, sealer: Sealer | None = None
) -> World:
    rt = build_runtime(settings, clock=clock, engine=engine, sealer=sealer)
    with rt.transaction() as db:
        seed_default_consent(db)
    client = TestClient(create_app(runtime=rt), raise_server_exceptions=False)
    return World(client=client, rt=rt, clock=clock, sessions=sessions, settings=settings)


@pytest.fixture
def world(e2e_settings: Settings, clock: FixedClock, app_engine: Engine, db_factory: Sessions) -> Iterator[World]:
    built = build_world(e2e_settings, clock, app_engine, db_factory)
    with built.client:
        yield built


@pytest.fixture
def ehr(world: World) -> Ehr:
    host = world.host(webhook=True)
    for key in ("patient_consent", "hipaa_acknowledgement", "procedure_consent"):
        host.publish_template(key)
    return host
