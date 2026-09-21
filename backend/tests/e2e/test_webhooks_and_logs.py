"""Webhooks are signed and retried; no log line anywhere in a full run carries PHI."""

from __future__ import annotations

import io
import json
from datetime import timedelta

import structlog
from sqlalchemy import text

from esign.logging import LOGGABLE_KEYS, RESERVED_KEYS, configure_logging
from esign.webhooks import SIGNATURE_HEADER, sign, verify_signature
from esign.worker import run_once
from tests.e2e.conftest import CLINICIAN_NAME, PATIENT_NAME, PREFILL, WITNESS_NAME, Ehr, World


def test_webhooks_are_signed_carry_no_phi_and_verify(ehr: Ehr, world: World) -> None:
    envelope = ehr.create_envelope("procedure_consent")
    ehr.sign_everyone(envelope, ("patient", "witness", "clinician"))

    # Nothing is sent from a request: deliveries are queued with the change and sent by the worker.
    assert ehr.deliveries == []
    tick = run_once(world.rt, send=ehr.receive)
    assert tick.webhooks_delivered == 2 and tick.webhooks_failed == 0

    assert ehr.webhook_secret is not None
    events = []
    for url, body, headers in ehr.deliveries:
        assert url == "https://ehr.example/hooks/esign"
        assert verify_signature(ehr.webhook_secret, body, headers[SIGNATURE_HEADER], now=world.clock.now())
        # A different secret, a changed body and a stale timestamp all fail.
        assert not verify_signature(b"\x00" * 32, body, headers[SIGNATURE_HEADER], now=world.clock.now())
        assert not verify_signature(ehr.webhook_secret, body + b" ", headers[SIGNATURE_HEADER], now=world.clock.now())
        later = world.clock.now() + timedelta(minutes=10)
        assert not verify_signature(ehr.webhook_secret, body, headers[SIGNATURE_HEADER], now=later)
        timestamp = int(headers[SIGNATURE_HEADER].split(",")[0].removeprefix("t="))
        assert headers[SIGNATURE_HEADER] == sign(ehr.webhook_secret, body, timestamp)

        payload = json.loads(body)
        events.append(payload["event"])
        assert payload["envelope_id"] == envelope["id"]
        for secret in (PATIENT_NAME, WITNESS_NAME, CLINICIAN_NAME, "chart-77120", "doc-5531", *PREFILL.values()):
            assert secret not in body.decode()
    assert events == ["envelope.completed", "envelope.sealed"]
    sealed = json.loads(ehr.deliveries[-1][1])
    assert sealed["status"] == "sealed"
    assert sealed["sealed_sha256"] == ehr.envelope(envelope["id"])["sealed_sha256"]

    # Delivered once: the next tick has nothing to do.
    assert run_once(world.rt, send=ehr.receive).webhooks_delivered == 0


def test_a_failed_delivery_is_retried_with_backoff(ehr: Ehr, world: World) -> None:
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    assert ehr.post(f"/envelopes/{envelope['id']}/void", {"reason_code": "entered_in_error"}).status_code == 200

    attempts: list[int] = []

    def host_is_down(url: str, body: bytes, headers: dict[str, str]) -> int:
        attempts.append(1)
        if len(attempts) == 1:
            raise ConnectionError("connection refused")
        return 503

    assert run_once(world.rt, send=host_is_down).webhooks_failed == 1
    assert run_once(world.rt, send=host_is_down).webhooks_failed == 0  # backing off, not hammering
    world.clock.advance(timedelta(seconds=31))
    assert run_once(world.rt, send=host_is_down).webhooks_failed == 1  # a 503 is a failure too
    world.clock.advance(timedelta(minutes=3))
    tick = run_once(world.rt, send=ehr.receive)
    assert tick.webhooks_delivered == 1
    assert json.loads(ehr.deliveries[0][1])["event"] == "envelope.voided"

    with world.sessions() as db:
        row = db.execute(text("SELECT attempts, last_status, delivered_at FROM webhook_deliveries")).one()
    assert (row.attempts, row.last_status) == (3, 204)
    assert row.delivered_at == world.clock.now()


def test_no_log_line_in_a_full_run_contains_a_name_or_a_prefill_value(ehr: Ehr, world: World) -> None:
    """SPEC 12. The real logging pipeline renders into a buffer while a three-signer envelope goes
    from creation to seal, a copy is downloaded, the trail is read, the envelope is verified, a
    webhook goes out, and a handful of requests fail on purpose."""
    buffer = io.StringIO()
    configure_logging(level="DEBUG", json_output=True, app_env="test", stream=buffer)
    try:
        envelope = ehr.create_envelope("procedure_consent")
        kiosk = {"staff_user_id": "nurse-4471", "identity_check": "photo_id"}
        patient = ehr.open_session(envelope, "patient", method="staff_verified", kiosk=kiosk)
        payload = patient.review_and_consent()
        assert payload["session"]["kiosk"] is True
        assert patient.sign(payload, key="p").status_code == 200
        ehr.sign_everyone(envelope, ("witness", "clinician"))
        assert ehr.envelope(envelope["id"])["status"] == "sealed"
        assert patient.get("/copy").status_code == 200
        assert ehr.get(f"/envelopes/{envelope['id']}/document").status_code == 200
        ehr.audit_types(envelope["id"])
        assert ehr.verification(envelope["id"])["complete"] is True
        run_once(world.rt, send=ehr.receive)

        # Failures log too, and a rejected value must not be quoted back into a log line.
        bad = ehr.envelope_body("procedure_consent")
        bad["signers"][0]["host_user_id"] = PATIENT_NAME
        assert ehr.post("/envelopes", bad).status_code == 422
        assert (
            ehr.post("/envelopes", {**ehr.envelope_body("procedure_consent"), "note": PATIENT_NAME}).status_code == 422
        )
        assert world.client.get("/v1/signing/session", headers={"Authorization": "Bearer est_nope"}).status_code == 401
        declined = ehr.create_envelope("patient_consent")
        refuser = ehr.open_session(declined, "patient")
        refuser.get("/document")
        assert refuser.post("/decline", {"reason_code": "prefers_paper"}).status_code == 200
    finally:
        structlog.reset_defaults()
        configure_logging(level="INFO", app_env="test")

    lines = [json.loads(line) for line in buffer.getvalue().splitlines() if line.startswith("{")]
    events = {str(line["event"]) for line in lines}
    assert {
        "envelope.created",
        "signer.signed",
        "document.sealed",
        "api.request",
        "audit.appended",
        "verification.performed",
        "webhook.delivered",
        "signer.declined",
        "identity.session_created",
    } <= events, sorted(events)

    rendered = buffer.getvalue()
    forbidden = (
        PATIENT_NAME,
        WITNESS_NAME,
        CLINICIAN_NAME,
        "Okonkwo",
        "Featherstonehaugh",
        "Ravensworth",
        *PREFILL.values(),
        "Routine physiotherapy",
        patient.token,
        ehr.api_key,
    )
    for secret in forbidden:
        assert secret not in rendered, f"a log line carried {secret[:6]}..."
    for line in lines:
        assert "dropped_fields" not in line, line  # nothing even *tried* to log an unlisted key
        assert set(line) <= LOGGABLE_KEYS | RESERVED_KEYS, line

    # The same goes for what is stored outside the rows that are allowed to hold PHI.
    with world.sessions() as db:
        trail = db.execute(text("SELECT string_agg(to_jsonb(a.*)::text, ' ') FROM audit_events a")).scalar_one()
        hooks = db.execute(text("SELECT string_agg(payload::text, ' ') FROM webhook_deliveries")).scalar_one()
        keys = db.execute(
            text("SELECT coalesce(string_agg(response_body::text, ' '), '') FROM idempotency_keys")
        ).scalar_one()
    for secret in forbidden:
        assert secret not in trail and secret not in hooks and secret not in keys
