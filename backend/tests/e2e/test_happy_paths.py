"""Single signer, three signers in sequence with clinician re-authentication, and parallel."""

from __future__ import annotations

import io

from pypdf import PdfReader

from tests.e2e.conftest import CLINICIAN_NAME, PATIENT_NAME, Ehr, World


def test_a_single_signer_envelope_goes_from_created_to_sealed_and_verifies(ehr: Ehr, world: World) -> None:
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    assert envelope["status"] == "created"
    assert len(envelope["presented_sha256"]) == 64
    assert envelope["sealed_sha256"] is None

    # Not sealed yet: the host is told so, plainly.
    early = ehr.get(f"/envelopes/{envelope['id']}/document")
    assert early.status_code == 409
    assert early.json()["error"]["code"] == "not_sealed"

    patient = ehr.open_session(envelope, "patient")
    session = patient.session()
    assert session["signer"]["display_name"] == PATIENT_NAME
    assert session["envelope"]["status"] == "created"
    assert session["session"]["id"] == patient.session_id
    assert session["decline_reasons"][0]["code"] == "prefers_paper"
    assert {f["type"] for f in session["fields"]} == {"signature", "date_signed"}

    payload = patient.review_and_consent()
    assert patient.session()["envelope"]["status"] == "in_progress"

    signed = patient.sign(payload, key="sign-once")
    assert signed.status_code == 200, signed.text
    assert signed.json()["signer"]["status"] == "signed"
    # The response reports the state as of the signature; the inline seal attempt follows it.
    assert signed.json()["envelope"]["status"] == "completed_pending_seal"

    after = ehr.envelope(envelope["id"])
    assert after["status"] == "sealed"
    assert len(after["sealed_sha256"]) == 64

    # The signer's copy and the host's copy are the same sealed bytes.
    copy = patient.get("/copy")
    assert copy.status_code == 200
    assert copy.headers["content-type"] == "application/pdf"
    assert copy.headers["cache-control"] == "no-store"
    document = ehr.get(f"/envelopes/{envelope['id']}/document")
    assert document.status_code == 200
    assert document.headers["cache-control"] == "no-store"
    assert document.content == copy.content

    # The sealed PDF carries the signature block and the certificate of completion.
    text = "".join(page.extract_text() or "" for page in PdfReader(io.BytesIO(document.content)).pages)
    assert "Certificate of completion" in text
    assert envelope["id"] in text

    assert ehr.audit_types(envelope["id"]) == [
        "envelope.created",
        "document.prepared",
        "session.created",
        "document.presented",
        "document.viewed",
        "consent.accepted",
        "signer.signed",
        "envelope.completed",
        "document.finalized",
        "document.sealed",
        "document.stored",
        "document.downloaded",
        "document.downloaded",
    ]

    report = ehr.verification(envelope["id"])
    assert report["ok"] is True, report["problems"]
    assert report["complete"] is True
    assert report["seal"]["profile"] == "PAdES-B-LT"
    assert report["seal"]["trusted"] is True
    assert not [c for c in report["checks"] if c["status"] != "passed"]
    assert ehr.audit_types(envelope["id"])[-1] == "verification.performed"

    # Once signed, the surviving session is good for the copy and nothing else.
    again = patient.sign(payload, key="a-different-key")
    assert again.status_code == 409


def test_three_signers_in_sequence_with_clinician_reauthentication(ehr: Ehr, world: World) -> None:
    envelope = ehr.create_envelope("procedure_consent")

    # Sequential order gates session creation: the witness cannot start before the patient signs.
    blocked = ehr.open_session_response(envelope, "witness")
    assert blocked.status_code == 409
    assert "session.rejected" in ehr.audit_types(envelope["id"])

    patient = ehr.open_session(envelope, "patient")
    payload = patient.review_and_consent()
    assert [s["role_label"] for s in payload["other_signers"]] == ["Witness", "Clinician"]
    assert PATIENT_NAME not in str(payload["other_signers"]) and CLINICIAN_NAME not in str(payload)
    assert patient.sign(payload, key="patient").status_code == 200

    # The patient has signed, others remain: no copy yet, and an honest reason why.
    waiting = patient.get("/copy")
    assert waiting.status_code == 409
    assert waiting.json()["error"]["code"] == "envelope_not_complete"

    witness = ehr.open_session(envelope, "witness")
    payload = witness.review_and_consent()
    assert witness.sign(payload, key="witness", kind="click").status_code == 200

    clinician = ehr.open_session(envelope, "clinician", method="password+mfa")
    payload = clinician.review_and_consent()
    assert payload["signer"]["requires_reauth"] is True
    assert payload["signer"]["reauth_valid_until"] is None

    # SPEC 12: a clinician signing without a fresh re-authentication is forbidden.
    refused = clinician.sign(payload, key="clinician-1", kind="typed")
    assert refused.status_code == 403
    assert refused.json()["error"]["code"] == "reauth_required"
    assert ehr.envelope(envelope["id"])["status"] == "in_progress"

    assert ehr.reauth(clinician).status_code == 200
    assert clinician.session()["signer"]["reauth_valid_until"] is not None

    # A re-authentication goes stale: after the window the signature is refused again.
    world.clock.advance(world.settings.reauth_max_age_seconds + 1)
    assert clinician.sign(payload, key="clinician-2", kind="typed").status_code == 403

    assert ehr.reauth(clinician).status_code == 200
    signed = clinician.sign(payload, key="clinician-3", kind="typed")
    assert signed.status_code == 200, signed.text

    assert ehr.envelope(envelope["id"])["status"] == "sealed"
    types = ehr.audit_types(envelope["id"])
    assert types.count("signer.signed") == 3
    assert types.count("auth.reauthenticated") == 2
    report = ehr.verification(envelope["id"])
    assert report["ok"] and report["complete"], report["problems"]

    # Everyone who signed can now fetch the same sealed copy.
    assert patient.get("/copy").status_code == 200


def test_parallel_signers_may_sign_in_any_order(ehr: Ehr, world: World) -> None:
    envelope = ehr.create_envelope("procedure_consent", signing_order="parallel")

    # Any order: all three sessions open at once, and the clinician goes first.
    clinician = ehr.open_session(envelope, "clinician", method="sso")
    witness = ehr.open_session(envelope, "witness")
    patient = ehr.open_session(envelope, "patient")

    clinician_payload = clinician.review_and_consent()
    patient_payload = patient.review_and_consent()
    assert ehr.reauth(clinician).status_code == 200
    assert clinician.sign(clinician_payload, key="c").status_code == 200

    # The patient was shown revision 1 and signs on top of the clinician's revision: both hashes
    # are in the trail, so the divergence is visible rather than smoothed over.
    assert patient.sign(patient_payload, key="p").status_code == 200
    events = ehr.get(f"/envelopes/{envelope['id']}/audit").json()["events"]
    patient_signed = [e for e in events if e["event_type"] == "signer.signed"][1]
    assert patient_signed["data"]["presented_sha256"] == envelope["presented_sha256"]
    assert patient_signed["data"]["base_revision_sha256"] != envelope["presented_sha256"]

    witness_payload = witness.review_and_consent()
    assert witness.sign(witness_payload, key="w").status_code == 200

    assert ehr.envelope(envelope["id"])["status"] == "sealed"
    report = ehr.verification(envelope["id"])
    assert report["ok"] and report["complete"], report["problems"]


def test_a_typed_signature_at_the_configured_bound_is_accepted(ehr: Ehr, world: World) -> None:
    """SPEC section 9: ``typed_text`` is bounded by ``MAX_TYPED_SIGNATURE_CHARS`` (200), and that
    bound has one definition in ``Settings`` (SPEC section 13).

    The documents module used to keep a private, smaller copy (80), so a typed signature between
    the two was accepted by the wire schema and by the envelope service and then refused while
    stamping -- under the envelope row lock, as a bare 422 with no message of its own.
    """
    limit = world.settings.max_typed_signature_chars
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    patient = ehr.open_session(envelope, "patient")
    payload = patient.review_and_consent()

    captures = [
        {"field_id": f["id"], "kind": "typed", "typed_text": "N" * limit}
        for f in payload["fields"]
        if f["type"] == "signature"
    ]
    signed = patient.post(
        "/sign", {"intent_confirmed": True, "captures": captures}, **{"Idempotency-Key": "typed-at-bound"}
    )
    assert signed.status_code == 200, signed.text
    assert ehr.envelope(envelope["id"])["status"] == "sealed"


def test_a_typed_signature_over_the_bound_is_refused_at_the_edge(ehr: Ehr, world: World) -> None:
    """One character more is a 422 from the request model, before anything is stamped or stored."""
    over = "N" * (world.settings.max_typed_signature_chars + 1)
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    patient = ehr.open_session(envelope, "patient")
    payload = patient.review_and_consent()

    captures = [
        {"field_id": f["id"], "kind": "typed", "typed_text": over}
        for f in payload["fields"]
        if f["type"] == "signature"
    ]
    refused = patient.post(
        "/sign", {"intent_confirmed": True, "captures": captures}, **{"Idempotency-Key": "typed-over-bound"}
    )
    assert refused.status_code == 422, refused.text
    # Refused while the request body is being turned into captures, so nothing was stamped.
    assert refused.json()["error"]["code"] == "capture_shape_invalid"
    assert ehr.envelope(envelope["id"])["signers"][0]["status"] == "consented"
