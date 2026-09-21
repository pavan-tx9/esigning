"""Decline, void, expiry and supersede, through the HTTP API."""

from __future__ import annotations

from datetime import timedelta

from esign.worker import run_once
from tests.e2e.conftest import Ehr, World


def test_a_decline_ends_the_envelope_for_everyone(ehr: Ehr, world: World) -> None:
    envelope = ehr.create_envelope("procedure_consent")
    patient = ehr.open_session(envelope, "patient")
    patient.session()
    assert patient.get("/document").status_code == 200

    # The reason is a code from a fixed list. Free text is how PHI reaches an audit trail.
    free_text = patient.post("/decline", {"reason_code": "I would rather talk to my daughter first"})
    assert free_text.status_code == 422
    assert "daughter" not in free_text.text

    declined = patient.post("/decline", {"reason_code": "prefers_paper"})
    assert declined.status_code == 200, declined.text
    assert declined.json() == {
        "envelope": {"id": envelope["id"], "status": "declined"},
        "signer": {"id": patient.signer_id, "status": "declined"},
    }

    after = ehr.envelope(envelope["id"])
    assert after["status"] == "declined"
    assert ehr.audit_types(envelope["id"])[-2:] == ["signer.declined", "envelope.declined"]

    # Every session on the envelope is over, and no new one can be opened.
    assert patient.get("/session").status_code == 401
    assert ehr.open_session_response(envelope, "witness").status_code == 409
    report = ehr.verification(envelope["id"])
    assert report["ok"] is True and report["complete"] is False


def test_a_host_can_void_before_completion_and_never_after(ehr: Ehr, world: World) -> None:
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    patient = ehr.open_session(envelope, "patient")
    payload = patient.review_and_consent()

    sentence = ehr.post(f"/envelopes/{envelope['id']}/void", {"reason_code": "Wrong patient, sorry"})
    assert sentence.status_code == 422
    # A slug is not enough: a host-invented code is free text with underscores.
    invented = ehr.post(f"/envelopes/{envelope['id']}/void", {"reason_code": "wrong_diagnosis_hiv"})
    assert invented.status_code == 422 and invented.json()["error"]["code"] == "invalid_reason_code"

    voided = ehr.post(f"/envelopes/{envelope['id']}/void", {"reason_code": "entered_in_error"})
    assert voided.status_code == 200, voided.text
    assert voided.json()["status"] == "voided"
    assert ehr.audit_types(envelope["id"])[-1] == "envelope.voided"

    # The signer's session died with the envelope.
    assert patient.sign(payload, key="too-late").status_code == 401
    assert ehr.post(f"/envelopes/{envelope['id']}/void", {"reason_code": "entered_in_error"}).status_code == 409

    sealed = ehr.create_envelope("hipaa_acknowledgement")
    ehr.sign_everyone(sealed, ("patient",))
    assert ehr.envelope(sealed["id"])["status"] == "sealed"
    refused = ehr.post(f"/envelopes/{sealed['id']}/void", {"reason_code": "entered_in_error"})
    assert refused.status_code == 409
    assert refused.json()["error"]["code"] == "envelope_sealed"


def test_an_envelope_past_its_date_cannot_be_signed_and_the_worker_expires_it(ehr: Ehr, world: World) -> None:
    expires_at = (world.clock.now() + timedelta(minutes=10)).isoformat()
    envelope = ehr.create_envelope("hipaa_acknowledgement", expires_at=expires_at)
    patient = ehr.open_session(envelope, "patient")
    payload = patient.review_and_consent()

    past = ehr.post("/envelopes", ehr.envelope_body("hipaa_acknowledgement", expires_at="2020-01-01T00:00:00Z"))
    assert past.status_code == 422

    # The sweep has not run, and that must not matter: the session is still alive (30 minutes),
    # and the envelope's date alone stops the signature.
    world.clock.advance(timedelta(minutes=11))
    assert ehr.envelope(envelope["id"])["status"] == "in_progress"
    late = patient.sign(payload, key="late")
    assert late.status_code == 409
    assert late.json()["error"]["code"] == "envelope_expired"
    assert ehr.open_session_response(envelope, "patient").status_code == 409

    tick = run_once(world.rt, send=ehr.receive)
    assert tick.expired == 1
    assert ehr.envelope(envelope["id"])["status"] == "expired"
    assert ehr.audit_types(envelope["id"])[-1] == "envelope.expired"
    assert run_once(world.rt, send=ehr.receive).expired == 0


def test_a_sealed_envelope_is_corrected_by_superseding_it_exactly_once(ehr: Ehr, world: World) -> None:
    original = ehr.create_envelope("hipaa_acknowledgement")

    # Only a sealed envelope can be superseded; an open one is voided instead.
    early = ehr.post("/envelopes", ehr.envelope_body("hipaa_acknowledgement", supersedes_envelope_id=original["id"]))
    assert early.status_code == 409

    ehr.sign_everyone(original, ("patient",))
    sealed_before = ehr.envelope(original["id"])

    correction = ehr.create_envelope("hipaa_acknowledgement", supersedes_envelope_id=original["id"])
    assert correction["supersedes_envelope_id"] == original["id"]

    old = ehr.envelope(original["id"])
    assert old["superseded_by_envelope_id"] == correction["id"]
    # The sealed document itself is never touched.
    assert old["status"] == "sealed" and old["sealed_sha256"] == sealed_before["sealed_sha256"]
    assert ehr.audit_types(original["id"])[-1] == "envelope.superseded"
    assert ehr.verification(original["id"])["complete"] is True

    twice = ehr.post("/envelopes", ehr.envelope_body("hipaa_acknowledgement", supersedes_envelope_id=original["id"]))
    assert twice.status_code == 409
    assert twice.json()["error"]["code"] == "already_superseded"
