"""Tests for the stand-in EHR.

The signing service is faked here with an ``httpx`` transport: these tests are about the host's
own half of the integration -- the embedding handshake, the re-authentication call, the webhook
check, what reaches a URL -- and not about the service, which has 1700 tests of its own. The real
thing is driven end to end by the Playwright specs in ``frontend/e2e/demo``.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader

from demo_host.app import create_app
from demo_host.config import Config
from demo_host.esign_api import EsignClient
from demo_host.reports import render
from demo_host.signatures import verify_signature
from demo_host.store import Store, Task, build_store

SECRET = bytes.fromhex("a1" * 32)
ENVELOPE_ID = "11111111-2222-4333-8444-555555555555"
ARCHIVE_ID = "22222222-3333-4444-8555-666666666666"
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
        self.sessions_created = 0
        self.archives: list[tuple[bytes, dict[str, Any]]] = []
        #: Addendum 2: ``(document bytes, body)`` per multipart ``POST /v1/envelopes``.
        self.documents: list[tuple[bytes, dict[str, Any]]] = []
        self.idempotency: list[str] = []
        self.revoked: list[str] = []
        #: The last envelope this fake was asked to create, so a later GET describes that one.
        self.created: dict[str, Any] | None = None
        self.created_source = "template"

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        content_type = request.headers.get("content-type", "")
        if content_type.startswith("multipart/form-data"):
            # Two routes are multipart: POST /v1/archives (a scan) and, since Addendum 2, POST
            # /v1/envelopes (a document the host generated). Both put a JSON ``body`` beside the
            # file. Only the shape is checked here; the real thing is exercised by the Playwright
            # specs against the real service.
            body = _multipart_body(request)
            self.calls.append((request.method, path, body))
            sent = json.loads(body["body"])
            if path == "/v1/envelopes":
                self.idempotency.append(request.headers.get("idempotency-key", ""))
                self.documents.append((body["document"], sent))
                self.created, self.created_source = sent, "host_document"
                return httpx.Response(201, json=self._envelope(sent, source="host_document"))
            self.archives.append((body["scan"], sent))
            return httpx.Response(201, json=self._archive_view())
        body = json.loads(request.content) if request.content else {}
        self.calls.append((request.method, path, body))
        if request.method == "POST" and path == "/v1/envelopes":
            self.idempotency.append(request.headers.get("idempotency-key", ""))
            self.created, self.created_source = body, "template"
            return httpx.Response(201, json=self._envelope(body))
        if request.method == "GET" and path == f"/v1/envelopes/{ENVELOPE_ID}":
            return httpx.Response(200, json=self._envelope(self.created, source=self.created_source))
        if path.endswith("/adopted-signature/revoke"):
            self.revoked.append(path.split("/")[3])
            return httpx.Response(200, json={"revoked": path.split("/")[3] == "u-priya"})
        if path.endswith("/sessions"):
            self.sessions_created += 1
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
        if path in (f"/v1/envelopes/{ENVELOPE_ID}/document", f"/v1/envelopes/{ARCHIVE_ID}/document"):
            return httpx.Response(200, content=b"%PDF-1.7 sealed", headers={"content-type": "application/pdf"})
        if request.method == "GET" and path == f"/v1/envelopes/{ARCHIVE_ID}":
            return httpx.Response(200, json=self._archive_view())
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

    def _archive_view(self) -> dict[str, Any]:
        return {
            **self._envelope(None),
            "id": ARCHIVE_ID,
            "kind": "paper_archive",
            "status": "completed_pending_seal",
            "template_key": None,
            "template_version": None,
            "signing_order": None,
            "signers": [],
            "sealed_sha256": None,
            "paper_signed_on": "2026-09-01",
            "attested_at": "2026-09-21T19:00:00Z",
        }

    def _envelope(self, created: dict[str, Any] | None, *, source: str = "template") -> dict[str, Any]:
        roles = (
            [s["role_key"] for s in created["signers"]] if created is not None else ["patient", "witness", "clinician"]
        )
        supplied = source == "host_document"
        return {
            "id": ENVELOPE_ID,
            "status": self.envelope_status,
            "source": source,
            "document_type": "clinical_report" if supplied else "hipaa_acknowledgement",
            "template_key": None if supplied else "hipaa_acknowledgement",
            "template_version": None if supplied else 1,
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


def _multipart_body(request: httpx.Request) -> dict[str, Any]:
    """The parts of a multipart request, by name; file parts as bytes."""
    boundary = request.headers["content-type"].split("boundary=")[1].encode()
    parts: dict[str, Any] = {}
    for chunk in request.content.split(b"--" + boundary)[1:-1]:
        head, _, payload = chunk.lstrip(b"\r\n").partition(b"\r\n\r\n")
        name = head.split(b'name="')[1].split(b'"')[0].decode()
        value = payload[:-2] if payload.endswith(b"\r\n") else payload
        parts[name] = value if b"filename=" in head else value.decode()
    return parts


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
    # Recorded as having arrived and failed the check, with nothing taken from the body: the event
    # name and the envelope id in it are a stranger's claims until the signature says otherwise.
    refused = store.webhooks[0]
    assert refused.verified is False
    assert (refused.event, refused.envelope_id) == ("", "")
    assert "nothing was read" in refused.note


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


# --------------------------------------------------------------------------- Addendum 1: paper documents


def test_staff_file_a_paper_document_with_an_attestation(
    client: TestClient, store: Store, service: FakeService
) -> None:
    sign_in(client, "alice")
    maria = next(p for p in store.patients.values() if p.name == "Maria Alvarez")
    scan = (Path(__file__).resolve().parents[1] / "src/demo_host/static/sample-scan.pdf").read_bytes()

    response = client.post(
        "/archive",
        data={
            "patient_id": maria.id,
            "title": "Consent to treatment (signed on paper)",
            "document_type": "patient_consent",
            "paper_signed_on": "2026-09-01",
            "original_disposition": "retained",
            "signer_name": ["Maria Alvarez", ""],
            "signer_capacity": ["self", "witness"],
            "true_copy": "yes",
        },
        files={"scan": ("scan.pdf", scan, "application/pdf")},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == f"/chart/{maria.id}?filed=1"
    sent_scan, body = service.archives[0]
    assert sent_scan == scan
    assert body["patient_ref"] == maria.mrn
    assert body["document_type"] == "patient_consent"
    assert body["paper_signed_on"] == "2026-09-01"
    # The attesting party is the member of staff who is signed in, by opaque id and by name; the
    # people who signed the paper are named, and an empty second row is not a signer.
    assert body["attestation"]["staff_user_id"] == "u-alice"
    assert body["attestation"]["staff_display_name"] == "Alice Wu"
    assert body["attestation"]["statement"] == "true_copy"
    assert body["attestation"]["paper_signers"] == [{"display_name": "Maria Alvarez", "capacity": "self"}]
    filing = store.archives[ARCHIVE_ID]
    assert filing.patient_id == maria.id and filing.filed_by == "u-alice"

    # The chart says it is on its way, and the sealed webhook files it as a paper archive.
    chart = client.get(f"/chart/{maria.id}?filed=1")
    assert "archive-filed" in chart.text
    deliver(
        client,
        {**sealed_payload("d-archive"), "envelope_id": ARCHIVE_ID, "template_key": None, "kind": "paper_archive"},
    )
    document = store.document_for_envelope(ARCHIVE_ID)
    assert document is not None and document.kind == "paper_archive"
    assert document.paper_signed_on == "2026-09-01" and document.template_key is None
    page = client.get(f"/chart/document/{document.id}")
    assert "signed on paper on 2026-09-01" in page.text
    assert "not prove the ink signature is genuine" in page.text


def test_filing_without_the_attestation_or_a_pdf_goes_nowhere(
    client: TestClient, store: Store, service: FakeService
) -> None:
    sign_in(client, "alice")
    maria = next(p for p in store.patients.values() if p.name == "Maria Alvarez")
    fields = {
        "patient_id": maria.id,
        "title": "x",
        "document_type": "patient_consent",
        "paper_signed_on": "2026-09-01",
        "original_disposition": "retained",
        "signer_name": ["Maria Alvarez"],
        "signer_capacity": ["self"],
    }
    unattested = client.post(
        "/archive",
        data=fields,
        files={"scan": ("scan.pdf", b"%PDF-1.4 fake", "application/pdf")},
        follow_redirects=False,
    )
    assert unattested.headers["location"] == "/archive?problem_code=incomplete"
    not_a_pdf = client.post(
        "/archive",
        data={**fields, "true_copy": "yes"},
        files={"scan": ("scan.png", b"\x89PNG", "image/png")},
        follow_redirects=False,
    )
    assert not_a_pdf.headers["location"] == "/archive?problem_code=not_a_pdf"
    assert service.archives == []
    sign_in(client, "maria")
    assert client.get("/archive").status_code == 403


# --------------------------------------------------------------------------- Addendum 1: the signing queue


def test_the_queue_confirms_once_on_the_first_documents_session_and_keeps_it(
    client: TestClient, store: Store, service: FakeService
) -> None:
    sign_in(client, "priya")
    page = client.get("/queue")
    assert page.status_code == 200
    # Everything she signs as a clinician: the three orders, and the procedure consent that is
    # still waiting on the patient and the witness, which is listed but not ready.
    assert page.text.count('data-testid="queue-task"') == 4
    assert page.text.count('data-testid="queue-sign"') == 3
    assert 'data-testid="queue-confirmed"' not in page.text

    confirmed = client.post("/queue/reauth", data={"password": "demo1234"}, follow_redirects=False)
    assert confirmed.headers["location"] == "/queue"
    first = next(t for t in store.queue_for(store.users["u-priya"]) if t.template_key == "clinical_order")
    assert first.envelope_id == ENVELOPE_ID and "clinician" in first.sessions
    reauth = next(body for method, path, body in service.calls if path.endswith("/reauth"))
    assert reauth["method"] == "password"
    assert service.sessions_created == 1
    assert "queue-confirmed" in client.get("/queue").text

    # Opening that document keeps the session the attestation was made on rather than minting a
    # new one, which would revoke it and the attestation with it.
    opened = client.post(f"/tasks/{first.id}/open", data={"return_to": "/queue"}, follow_redirects=False)
    assert opened.headers["location"] == f"/sign/{first.id}?return_to=/queue"
    assert service.sessions_created == 1
    sign_page = client.get(f"/sign/{first.id}?return_to=/queue")
    assert 'data-return-url="/queue"' in sign_page.text

    # A return address is one of two known pages, never something the request chose.
    elsewhere = client.post(
        f"/tasks/{first.id}/open", data={"return_to": "https://evil.example"}, follow_redirects=False
    )
    assert elsewhere.headers["location"] == f"/sign/{first.id}"


def test_the_queue_is_for_clinicians_and_needs_the_password(client: TestClient, service: FakeService) -> None:
    sign_in(client, "priya")
    wrong = client.post("/queue/reauth", data={"password": "nope"}, follow_redirects=False)
    assert wrong.headers["location"] == "/queue?problem_code=wrong_password"
    assert not [c for c in service.calls if c[1].endswith("/reauth")]
    sign_in(client, "maria")
    assert client.get("/queue").status_code == 403


# --------------------------------------------------------------------------- Addendum 1: saved signatures


def test_staff_can_remove_a_saved_signature_and_are_told_whether_there_was_one(
    client: TestClient, service: FakeService
) -> None:
    sign_in(client, "alice")
    assert 'data-username="priya"' in client.get("/people").text
    had_one = client.post("/people/u-priya/revoke-signature", follow_redirects=False)
    assert had_one.headers["location"] == "/people?result=revoked"
    had_none = client.post("/people/u-maria/revoke-signature", follow_redirects=False)
    assert had_none.headers["location"] == "/people?result=nothing_saved"
    assert service.revoked == ["u-priya", "u-maria"]
    assert 'data-result="revoked"' in client.get("/people?result=revoked").text
    sign_in(client, "priya")
    assert client.get("/people").status_code == 403
    assert (
        client.post("/people/u-maria/revoke-signature", follow_redirects=False).headers["location"]
        == "/people?result=refused"
    )


# --------------------------------------------------------------------------- Addendum 2: reports


def report(store: Store, reference: str) -> Task:
    return next(t for t in store.tasks.values() if t.report is not None and t.report.reference == reference)


def widgets(pdf: bytes) -> dict[int, list[str]]:
    """The AcroForm widget names on each page, the way the signing service will read them."""
    found: dict[int, list[str]] = {}
    reader = PdfReader(io.BytesIO(pdf))
    for number, page in enumerate(reader.pages, start=1):
        names = [str(annotation.get_object()["/T"]) for annotation in page.get("/Annots") or []]
        if names:
            found[number] = names
    return found


def test_a_report_is_rendered_to_its_stated_length_with_a_named_signature_block(store: Store) -> None:
    task = report(store, "RPT-2291")
    assert task.report is not None

    pdf = store.upload_for(task)

    reader = PdfReader(io.BytesIO(pdf))
    assert len(reader.pages) == task.report.pages == 30
    # The whole contract with the service: two widgets, named after the role, on the last page.
    assert widgets(pdf) == {30: ["clinician_signature", "clinician_date"]}
    # The patient is named on the document because the document is their record. Nothing about
    # them reaches an identifier: the reference, not the name, is what the service is told.
    assert "Maria Alvarez" in reader.pages[0].extract_text()
    assert "RPT-2291" in reader.pages[0].extract_text()
    # Reproducible, because the Idempotency-Key on this route hashes the document as well: a
    # retry that rendered different bytes would be a different request, not a replay.
    assert render(task.report) == pdf
    assert task.upload_sha256 == hashlib.sha256(pdf).hexdigest()


def test_a_co_signed_report_carries_a_second_named_block(store: Store) -> None:
    task = report(store, "RPT-2292")
    assert task.report is not None

    pdf = store.upload_for(task)

    assert len(PdfReader(io.BytesIO(pdf)).pages) == 25
    assert widgets(pdf) == {25: ["clinician_signature", "clinician_date", "cosigner_signature", "cosigner_date"]}
    assert [signer.role_key for signer in task.signers] == ["clinician", "cosigner"]


def test_opening_a_report_uploads_the_document_and_takes_the_host_document_path(
    client: TestClient, store: Store, service: FakeService
) -> None:
    sign_in(client, "priya")
    task = report(store, "RPT-2291")

    response = client.post(f"/tasks/{task.id}/open", data={"return_to": "/reports"}, follow_redirects=False)

    assert response.headers["location"] == f"/sign/{task.id}?return_to=/reports"
    document, body = service.documents[0]
    assert document.startswith(b"%PDF") and document == task.upload
    # No template, no version, no prefill: there is nothing to merge into a document we wrote.
    assert "template_key" not in body and "template_version" not in body and "prefill" not in body
    assert body["document_type"] == "clinical_report"
    assert body["patient_ref"] == store.patients[task.patient_id].mrn
    assert body["host_document_ref"] == f"report-{task.id}"
    assert body["fields"] == {"mode": "named"}
    assert body["signers"][0]["host_user_id"] == "u-priya"
    assert body["signer_roles"] == [
        {
            "key": "clinician",
            "label": "Responsible clinician",
            "allowed_capacities": ["clinician"],
            "requires_reauth": True,
            "order_index": 0,
            "required": True,
        }
    ]
    assert service.idempotency == [task.id]
    # One envelope, however many times it is opened, and the same bytes if it ever is sent again.
    client.post(f"/tasks/{task.id}/open", data={"return_to": "/reports"}, follow_redirects=False)
    assert len(service.documents) == 1


def test_a_co_signed_report_declares_both_roles_in_order(
    client: TestClient, store: Store, service: FakeService
) -> None:
    sign_in(client, "priya")
    task = report(store, "RPT-2292")

    client.post(f"/tasks/{task.id}/open", data={"return_to": "/reports"}, follow_redirects=False)

    _document, body = service.documents[0]
    assert body["signing_order"] == "sequential"
    assert [role["key"] for role in body["signer_roles"]] == ["clinician", "cosigner"]
    assert [role["order_index"] for role in body["signer_roles"]] == [0, 1]
    # Both sign in a professional capacity, so both are asked to confirm who they are.
    assert all(role["requires_reauth"] for role in body["signer_roles"])


def test_reports_are_for_clinicians_and_are_not_on_the_worklist_or_in_the_queue(
    client: TestClient, store: Store
) -> None:
    sign_in(client, "priya")
    page = client.get("/reports")
    assert page.status_code == 200
    assert page.text.count('data-testid="report"') == 2
    assert "RPT-2291" in page.text and "RPT-2292" in page.text
    # A report is read, not run through: the worklist and the signing queue are unchanged.
    assert "Annual care summary" not in client.get("/worklist").text
    assert "Annual care summary" not in client.get("/queue").text
    assert client.get("/queue").text.count('data-testid="queue-task"') == 4
    # Tomas sees only the one he co-signs, and it is waiting on the consultant.
    sign_in(client, "tomas")
    his = client.get("/reports").text
    assert his.count('data-testid="report"') == 1
    assert "Multidisciplinary case review" in his
    sign_in(client, "maria")
    assert client.get("/reports").status_code == 403


def test_the_uploaded_bytes_can_be_read_back_and_only_by_a_signer(client: TestClient, store: Store) -> None:
    """The page links to exactly what was sent, so it can be held against the upload hash the
    service recorded. Nobody else's business, though: it is the patient's whole record."""
    task = report(store, "RPT-2291")
    sign_in(client, "priya")

    sent = client.get(f"/reports/{task.id}/generated.pdf")

    assert sent.status_code == 200
    assert sent.content == store.upload_for(task)
    assert sent.headers["cache-control"] == "no-store"
    sign_in(client, "tomas")
    assert client.get(f"/reports/{task.id}/generated.pdf").status_code == 403


def test_a_sealed_report_is_filed_in_the_chart_as_a_document_this_system_supplied(
    client: TestClient, store: Store
) -> None:
    sign_in(client, "priya")
    task = report(store, "RPT-2291")
    client.post(f"/tasks/{task.id}/open", data={"return_to": "/reports"}, follow_redirects=False)

    deliver(client, {**sealed_payload("d-report"), "template_key": None, "source": "host_document"})

    filed = store.document_for_envelope(ENVELOPE_ID)
    assert filed is not None
    assert (filed.kind, filed.page_count, filed.template_key) == ("host_document", 30, None)
    assert filed.host_document_ref == f"report-{task.id}"
    assert filed.upload_sha256 == task.upload_sha256
    page = client.get(f"/chart/document/{filed.id}").text
    assert "Report supplied by this records system, 30 pages" in page
    assert task.upload_sha256 is not None and task.upload_sha256 in page


def test_a_reports_page_puts_nothing_about_the_patient_in_a_url(client: TestClient, store: Store) -> None:
    sign_in(client, "priya")
    task = report(store, "RPT-2291")
    client.post(f"/tasks/{task.id}/open", data={"return_to": "/reports"}, follow_redirects=False)

    page = client.get("/reports")

    links = [link.split('"')[0] for link in page.text.split('href="')[1:] if link.startswith("/")]
    links += [link.split('"')[0] for link in page.text.split('action="')[1:] if link.startswith("/")]
    assert links
    for url in links:
        for patient in store.patients.values():
            assert patient.name.replace(" ", "") not in url.replace("%20", "")
            assert patient.mrn not in url
        assert "est_" not in url and "esk_" not in url
