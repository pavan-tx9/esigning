"""Tests for the stand-in EHR.

The signing service is faked here with an ``httpx`` transport: these tests are about the host's
own half of the integration -- the embedding handshake, the re-authentication call, the webhook
check, what reaches a URL -- and not about the service, which has 1700 tests of its own. The real
thing is driven end to end by the Playwright specs in ``frontend/e2e/demo``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from demo_host.app import create_app
from demo_host.config import Config
from demo_host.esign_api import EsignClient
from demo_host.signatures import verify_signature
from demo_host.store import Store, build_store

SECRET = bytes.fromhex("a1" * 32)
ENVELOPE_ID = "11111111-2222-4333-8444-555555555555"
SEALED_SHA = "9f" * 32


def config() -> Config:
    return Config(
        api_url="http://esign.test",
        ui_url="http://esign.test",
        api_key="esk_test",
        host_id="00000000-0000-4000-8000-000000000000",
        webhook_secret=SECRET,
        public_url="http://localhost:8100",
        password="demo1234",
    )


class FakeService:
    """Just enough of the Host API to answer the demo host, plus a record of what it was asked."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.signer_status = "pending"
        self.envelope_status = "created"
        self.reauth_status = 200

    def handler(self, request: httpx.Request) -> httpx.Response:
        body: dict[str, Any] = json.loads(request.content) if request.content else {}
        path = request.url.path
        self.calls.append((request.method, path, body))

        if request.method == "POST" and path == "/v1/envelopes":
            return httpx.Response(201, json=self._envelope(body))
        if request.method == "GET" and path == f"/v1/envelopes/{ENVELOPE_ID}":
            return httpx.Response(200, json=self._envelope(None))
        if path.endswith("/sessions"):
            return httpx.Response(
                201,
                json={
                    "token": "est_faketoken_0123456789",
                    "session_id": "99999999-8888-4777-8666-555555555555",
                    "expires_at": "2026-09-21T21:00:00Z",
                },
            )
        if path.endswith("/reauth"):
            if self.reauth_status != 200:
                return httpx.Response(self.reauth_status, json={"error": {"code": "not_found", "message": ""}})
            return httpx.Response(
                200,
                json={
                    "session_id": "99999999-8888-4777-8666-555555555555",
                    "reauth_valid_until": "2026-09-21T20:02:00Z",
                },
            )
        if path == f"/v1/envelopes/{ENVELOPE_ID}/document":
            return httpx.Response(200, content=b"%PDF-1.7 sealed", headers={"content-type": "application/pdf"})
        if path == f"/v1/envelopes/{ENVELOPE_ID}/verification":
            return httpx.Response(
                200,
                json={
                    "envelope_id": ENVELOPE_ID,
                    "envelope_status": "sealed",
                    "ok": True,
                    "complete": True,
                    "checks": [{"name": "audit_chain", "status": "passed", "detail": "12 events"}],
                    "problems": [],
                    "audit": {"event_count": 12, "head_hash": "ab" * 32},
                    "blobs_checked": 4,
                    "seal": None,
                    "recorded": True,
                },
            )
        return httpx.Response(404, json={"error": {"code": "not_found", "message": ""}})  # pragma: no cover

    def _envelope(self, created: dict[str, Any] | None) -> dict[str, Any]:
        roles = (
            [s["role_key"] for s in created["signers"]] if created is not None else ["patient", "witness", "clinician"]
        )
        return {
            "id": ENVELOPE_ID,
            "status": self.envelope_status,
            "document_type": "hipaa_acknowledgement",
            "template_key": "hipaa_acknowledgement",
            "template_version": 1,
            "signing_order": "parallel",
            "signers": [
                {
                    "id": f"aaaaaaaa-0000-4000-8000-00000000000{index}",
                    "role_key": role,
                    "role_label": role.title(),
                    "display_name": "redacted",
                    "capacity": "self",
                    "order_index": index,
                    "requires_reauth": role == "clinician",
                    "status": self.signer_status,
                }
                for index, role in enumerate(roles)
            ],
            "presented_sha256": None,
            "current_revision_sha256": None,
            "sealed_sha256": SEALED_SHA,
            "created_at": "2026-09-21T19:00:00Z",
            "expires_at": "2026-10-05T19:00:00Z",
            "supersedes_envelope_id": None,
            "superseded_by_envelope_id": None,
        }


@pytest.fixture
def service() -> FakeService:
    return FakeService()


@pytest.fixture
def store() -> Store:
    return build_store()


@pytest.fixture
def client(service: FakeService, store: Store) -> TestClient:
    esign = EsignClient("http://esign.test", "esk_test", transport=httpx.MockTransport(service.handler))
    return TestClient(create_app(config(), store=store, client=esign))


def sign_in(client: TestClient, username: str) -> None:
    response = client.post("/login", data={"username": username, "password": "demo1234"}, follow_redirects=False)
    assert response.status_code == 303


def deliver(client: TestClient, payload: dict[str, Any], *, secret: bytes = SECRET, skew: int = 0) -> httpx.Response:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    stamp = int((datetime.now(UTC) + timedelta(seconds=skew)).timestamp())
    mac = hmac.new(secret, f"{stamp}.".encode("ascii") + body, hashlib.sha256).hexdigest()
    response: httpx.Response = client.post(
        "/webhooks/esign",
        content=body,
        headers={"X-Esign-Signature": f"t={stamp},v1={mac}", "Content-Type": "application/json"},
    )
    return response


def sealed_payload(delivery_id: str = "d-1") -> dict[str, Any]:
    return {
        "id": delivery_id,
        "event": "envelope.sealed",
        "occurred_at": "2026-09-21T19:30:00.000000Z",
        "envelope_id": ENVELOPE_ID,
        "status": "sealed",
        "template_key": "hipaa_acknowledgement",
        "template_version": 1,
        "presented_sha256": "11" * 32,
        "current_revision_sha256": "22" * 32,
        "sealed_sha256": SEALED_SHA,
        "supersedes_envelope_id": None,
        "signers": [{"id": "aaaaaaaa-0000-4000-8000-000000000000", "role_key": "patient", "status": "signed"}],
    }


# --------------------------------------------------------------------------- the webhook check


def test_a_good_signature_is_accepted_and_a_tampered_body_is_not() -> None:
    body = b'{"event":"envelope.sealed"}'
    now = datetime.now(UTC)
    stamp = int(now.timestamp())
    mac = hmac.new(SECRET, f"{stamp}.".encode("ascii") + body, hashlib.sha256).hexdigest()
    header = f"t={stamp},v1={mac}"

    assert verify_signature(SECRET, body, header, now=now)
    assert not verify_signature(SECRET, body + b" ", header, now=now)
    assert not verify_signature(bytes.fromhex("bb" * 32), body, header, now=now)
    assert not verify_signature(SECRET, body, header, now=now + timedelta(minutes=6))
    assert not verify_signature(SECRET, body, "nonsense", now=now)
    assert not verify_signature(b"", body, header, now=now)


def test_an_unverified_delivery_changes_nothing(client: TestClient, store: Store) -> None:
    task = next(t for t in store.tasks.values() if t.template_key == "hipaa_acknowledgement")
    task.envelope_id = ENVELOPE_ID

    response = deliver(client, sealed_payload(), secret=bytes.fromhex("cc" * 32))

    assert response.status_code == 401
    assert store.documents == {}
    assert store.webhooks[0].verified is False


def test_a_replayed_delivery_is_refused(client: TestClient, store: Store) -> None:
    task = next(t for t in store.tasks.values() if t.template_key == "hipaa_acknowledgement")
    task.envelope_id = ENVELOPE_ID

    assert deliver(client, sealed_payload(), skew=-3600).status_code == 401
    assert store.documents == {}


def test_a_sealed_webhook_files_the_document_once(client: TestClient, store: Store) -> None:
    task = next(t for t in store.tasks.values() if t.template_key == "hipaa_acknowledgement")
    task.envelope_id = ENVELOPE_ID

    assert deliver(client, sealed_payload()).status_code == 200
    # At-least-once delivery: the same delivery id again must not file a second copy.
    assert deliver(client, sealed_payload()).status_code == 200

    filed = list(store.documents.values())
    assert len(filed) == 1
    assert filed[0].pdf == b"%PDF-1.7 sealed"
    assert filed[0].sealed_sha256 == SEALED_SHA
    assert filed[0].patient_id == task.patient_id


# --------------------------------------------------------------------------- the worklist


def test_the_worklist_lists_what_this_person_has_to_sign(client: TestClient, store: Store) -> None:
    sign_in(client, "maria")
    page = client.get("/worklist").text
    assert "Acknowledgement of privacy practices" in page
    assert "Consent to a procedure" in page
    # Grace's child's consent is not Maria's business.
    sams_task = next(t for t in store.tasks.values() if t.title == "Consent to treatment")
    assert sams_task.id not in page


def test_signing_in_is_required(client: TestClient) -> None:
    for path in ["/worklist", "/kiosk", "/webhooks"]:
        assert client.get(path, follow_redirects=False).headers["location"] == "/"


def test_the_wrong_password_does_not_sign_anybody_in(client: TestClient) -> None:
    response = client.post("/login", data={"username": "maria", "password": "nope"}, follow_redirects=False)
    assert response.status_code == 401
    assert client.get("/worklist", follow_redirects=False).status_code == 303


# --------------------------------------------------------------------------- the embedding handshake


def test_opening_a_task_creates_an_envelope_and_a_session(
    client: TestClient, store: Store, service: FakeService
) -> None:
    sign_in(client, "maria")
    task = next(t for t in store.tasks.values() if t.template_key == "hipaa_acknowledgement")

    response = client.post(f"/tasks/{task.id}/open", follow_redirects=False)

    assert response.headers["location"] == f"/sign/{task.id}"
    created = next(body for method, path, body in service.calls if path == "/v1/envelopes" and method == "POST")
    assert created["patient_ref"] == store.patients[task.patient_id].mrn
    assert created["signers"][0]["host_user_id"] == "u-maria"
    # The envelope is created once: a second open reuses it.
    client.post(f"/tasks/{task.id}/open", follow_redirects=False)
    assert sum(1 for method, path, _ in service.calls if method == "POST" and path == "/v1/envelopes") == 1


def test_the_token_arrives_in_a_body_and_never_in_a_url(client: TestClient, store: Store) -> None:
    sign_in(client, "maria")
    task = next(t for t in store.tasks.values() if t.template_key == "hipaa_acknowledgement")
    client.post(f"/tasks/{task.id}/open", follow_redirects=False)

    page = client.get(f"/sign/{task.id}")
    assert page.status_code == 200
    # The page itself carries no token: it asks for one after the iframe says it is ready.
    assert "est_" not in page.text

    handed = client.post(f"/sign/{task.id}/token").json()
    assert handed["token"].startswith("est_")
    assert handed["session_id"] == "99999999-8888-4777-8666-555555555555"


def test_somebody_elses_task_is_refused(client: TestClient, store: Store) -> None:
    sign_in(client, "ben")
    task = next(t for t in store.tasks.values() if t.template_key == "hipaa_acknowledgement")

    assert client.post(f"/tasks/{task.id}/open", follow_redirects=False).headers["location"].endswith("not_your_task")
    assert client.post(f"/sign/{task.id}/token").status_code == 403


# --------------------------------------------------------------------------- re-authentication


def test_reauth_needs_the_password_and_is_attested_server_to_server(
    client: TestClient, store: Store, service: FakeService
) -> None:
    sign_in(client, "priya")
    task = next(t for t in store.tasks.values() if t.template_key == "procedure_consent")
    client.post(f"/tasks/{task.id}/open", follow_redirects=False)

    refused = client.post(f"/sign/{task.id}/reauth", json={"password": "wrong"})
    assert refused.status_code == 401
    assert not any(path.endswith("/reauth") for _, path, _ in service.calls)

    accepted = client.post(f"/sign/{task.id}/reauth", json={"password": "demo1234"})
    assert accepted.status_code == 200
    method, path, body = next(c for c in service.calls if c[1].endswith("/reauth"))
    assert method == "POST"
    assert path == "/v1/sessions/99999999-8888-4777-8666-555555555555/reauth"
    assert body["method"] == "password"


def test_a_reauth_for_a_session_we_did_not_start_is_refused(client: TestClient, store: Store) -> None:
    sign_in(client, "priya")
    task = next(t for t in store.tasks.values() if t.template_key == "procedure_consent")
    client.post(f"/tasks/{task.id}/open", follow_redirects=False)

    response = client.post(
        f"/sign/{task.id}/reauth",
        json={"password": "demo1234", "session_id": "00000000-0000-4000-8000-000000000999"},
    )

    assert response.status_code == 409


# --------------------------------------------------------------------------- kiosk


def test_the_kiosk_is_staff_only_and_records_the_identity_check(
    client: TestClient, store: Store, service: FakeService
) -> None:
    sign_in(client, "maria")
    assert client.get("/kiosk").status_code == 403

    client.post("/logout")
    sign_in(client, "alice")
    task = next(t for t in store.tasks.values() if t.template_key == "hipaa_acknowledgement")

    response = client.post(
        "/kiosk/start", data={"task_id": task.id, "identity_check": "photo_id"}, follow_redirects=False
    )

    assert response.headers["location"] == f"/sign/{task.id}"
    _method, _path, body = next(c for c in service.calls if c[1].endswith("/sessions"))
    assert body["kiosk"] == {"staff_user_id": "u-alice", "identity_check": "photo_id"}
    # The signature is the patient's; the member of staff only attests to the identity check.
    assert body["auth"]["method"] == "staff_verified"
    assert task.signer_ids["patient"] == "aaaaaaaa-0000-4000-8000-000000000000"


def test_finishing_a_kiosk_run_forgets_the_session(client: TestClient, store: Store) -> None:
    sign_in(client, "alice")
    task = next(t for t in store.tasks.values() if t.template_key == "hipaa_acknowledgement")
    client.post("/kiosk/start", data={"task_id": task.id, "identity_check": "wristband"}, follow_redirects=False)
    assert task.sessions

    client.post("/kiosk/finish", data={"task_id": task.id}, follow_redirects=False)

    assert task.kiosk is None
    assert task.sessions == {}


# --------------------------------------------------------------------------- the chart


def test_the_chart_shows_the_sealed_copy_and_verifies_it(client: TestClient, store: Store) -> None:
    task = next(t for t in store.tasks.values() if t.template_key == "hipaa_acknowledgement")
    task.envelope_id = ENVELOPE_ID
    deliver(client, sealed_payload())
    document = next(iter(store.documents.values()))
    sign_in(client, "maria")

    chart = client.get(f"/chart/{task.patient_id}")
    assert chart.status_code == 200
    assert document.id in chart.text

    pdf = client.get(f"/chart/document/{document.id}/pdf")
    assert pdf.content == b"%PDF-1.7 sealed"
    assert pdf.headers["cache-control"] == "no-store"

    report = client.post(f"/chart/document/{document.id}/verify")
    assert "Verified." in report.text


def test_a_patient_cannot_open_another_patients_chart(client: TestClient, store: Store) -> None:
    sign_in(client, "maria")
    other = next(p for p in store.patients.values() if p.name == "Sam Okafor")

    assert client.get(f"/chart/{other.id}").status_code == 403


def test_a_guardian_can_open_the_chart_they_look_after(client: TestClient, store: Store) -> None:
    sign_in(client, "grace")
    sam = next(p for p in store.patients.values() if p.name == "Sam Okafor")

    assert client.get(f"/chart/{sam.id}").status_code == 200


# --------------------------------------------------------------------------- PHI never reaches a URL


def test_no_identifying_detail_can_reach_a_url(client: TestClient, store: Store) -> None:
    """Every path segment this app hands out is an opaque id."""
    sign_in(client, "grace")
    task = next(t for t in store.tasks.values() if t.title == "Consent to treatment")
    client.post(f"/tasks/{task.id}/open", follow_redirects=False)
    deliver(client, {**sealed_payload("d-2"), "envelope_id": task.envelope_id})

    secrets_in_the_open = (
        [p.name for p in store.patients.values()]
        + [p.date_of_birth for p in store.patients.values()]
        + [p.mrn for p in store.patients.values()]
    )

    seen: list[str] = []
    for page in ["/worklist", f"/sign/{task.id}", f"/chart/{task.patient_id}", "/webhooks"]:
        response = client.get(page)
        assert response.status_code == 200
        seen.extend(link.split('"')[0] for link in response.text.split('href="')[1:] if link.startswith("/"))
        seen.extend(link.split('"')[0] for link in response.text.split('action="')[1:] if link.startswith("/"))
    assert seen
    for url in seen:
        for detail in secrets_in_the_open:
            assert detail.replace(" ", "") not in url.replace("%20", "")
            assert detail not in url
        assert "est_" not in url
        assert "esk_" not in url
