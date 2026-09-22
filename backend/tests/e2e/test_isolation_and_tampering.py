"""One host never sees another's data, and verification catches what the database cannot stop."""

from __future__ import annotations

import os
from uuid import uuid4

from sqlalchemy import Engine, text

from esign.storage import content_key
from tests.e2e.conftest import Ehr, World


def test_a_host_never_reaches_another_hosts_data(ehr: Ehr, world: World) -> None:
    envelope = ehr.create_envelope("procedure_consent")
    patient = ehr.open_session(envelope, "patient")

    stranger = world.host("Lakeside EHR")
    unknown = str(uuid4())

    # Foreign and non-existent look identical: not_found, never forbidden (SPEC section 10).
    for target in (envelope["id"], unknown):
        for response in (
            stranger.get(f"/envelopes/{target}"),
            stranger.get(f"/envelopes/{target}/document"),
            stranger.get(f"/envelopes/{target}/audit"),
            stranger.get(f"/envelopes/{target}/verification"),
            stranger.post(f"/envelopes/{target}/void", {"reason_code": "entered_in_error"}),
            stranger.post(
                f"/envelopes/{target}/signers/{patient.signer_id}/sessions",
                {"auth": {"method": "password", "auth_time": world.clock.now().isoformat()}},
            ),
        ):
            assert response.status_code == 404, response.text
            assert response.json()["error"]["code"] == "not_found"

    # Another host's session cannot be re-authenticated, another host's template cannot be used,
    # published, or superseded against.
    reauth = stranger.post(
        f"/sessions/{patient.session_id}/reauth", {"method": "password+mfa", "auth_time": world.clock.now().isoformat()}
    )
    assert reauth.status_code == 404
    assert stranger.get("/templates").json() == {"templates": []}
    assert stranger.get("/templates/procedure_consent").status_code == 404
    assert stranger.post("/templates/procedure_consent/versions/1/retire").status_code == 404
    assert stranger.post("/envelopes", stranger.envelope_body("procedure_consent")).status_code == 404
    stranger.publish_template("hipaa_acknowledgement")
    theirs = stranger.post(
        "/envelopes", stranger.envelope_body("hipaa_acknowledgement", supersedes_envelope_id=envelope["id"])
    )
    assert theirs.status_code == 404

    # Nothing the stranger did left a mark on the envelope, and it is still the owner's to use.
    assert "verification.performed" not in ehr.audit_types(envelope["id"])
    assert ehr.envelope(envelope["id"])["status"] == "created"

    # Credentials are checked, and a signer token is not a host key or the other way round.
    assert world.client.get(f"/v1/envelopes/{envelope['id']}").status_code == 401
    assert world.client.get(f"/v1/envelopes/{envelope['id']}", headers=patient.headers).status_code == 401
    assert world.client.get("/v1/signing/session", headers=ehr.headers).status_code == 401


def test_a_signer_cannot_fill_someone_elses_field_or_supply_the_date(ehr: Ehr, world: World) -> None:
    envelope = ehr.create_envelope("procedure_consent", signing_order="parallel")
    patient = ehr.open_session(envelope, "patient")
    payload = patient.review_and_consent()
    mine = patient.captures(payload)

    foreign = patient.post(
        "/sign",
        {"intent_confirmed": True, "captures": [*mine, {"field_id": "witness_signature", "kind": "click"}]},
        **{"Idempotency-Key": "k1"},
    )
    assert foreign.status_code == 403
    assert foreign.json()["error"]["code"] == "foreign_field"

    dated = patient.post(
        "/sign",
        {
            "intent_confirmed": True,
            "captures": [*mine, {"field_id": "patient_date", "kind": "typed", "typed_text": "2020-01-01"}],
        },
        **{"Idempotency-Key": "k2"},
    )
    assert dated.status_code == 422
    assert dated.json()["error"]["code"] == "client_supplied_date"

    # The client never supplies bytes, hashes, timestamps or identity: unknown keys are refused.
    for extra in ({"signed_at": "2020-01-01T00:00:00Z"}, {"document_sha256": "00" * 32}, {"pdf_base64": "JVBERg=="}):
        smuggled = patient.post(
            "/sign", {"intent_confirmed": True, "captures": mine, **extra}, **{"Idempotency-Key": "k3"}
        )
        assert smuggled.status_code == 422
    unconfirmed = patient.post("/sign", {"intent_confirmed": False, "captures": mine}, **{"Idempotency-Key": "k4"})
    assert unconfirmed.status_code == 422

    # The typed-signature bound is a setting, applied at the edge before anything is stamped.
    signature = next(item["id"] for item in payload["fields"] if item["type"] == "signature")
    too_long = [c for c in mine if c["field_id"] != signature] + [
        {"field_id": signature, "kind": "typed", "typed_text": "x" * (world.settings.max_typed_signature_chars + 1)}
    ]
    long = patient.post("/sign", {"intent_confirmed": True, "captures": too_long}, **{"Idempotency-Key": "k7"})
    assert long.status_code == 422
    assert long.json()["error"]["code"] == "capture_shape_invalid"

    assert ehr.envelope(envelope["id"])["current_revision_sha256"] == envelope["presented_sha256"]
    assert patient.sign(payload, key="k5").status_code == 200


def test_a_value_capture_cannot_claim_a_signature_kind(ehr: Ehr, world: World) -> None:
    """The trail records how a field was filled. A checkbox capture that also says ``kind: click``
    would let the browser choose that wording, so the mixture is not a wire shape at all: 422 at
    the edge, nothing stamped, and the well-formed request still goes through afterwards."""
    envelope = ehr.create_envelope("patient_consent")
    patient = ehr.open_session(envelope, "patient")
    payload = patient.review_and_consent()
    mine = patient.captures(payload)
    checkbox = next(item["id"] for item in payload["fields"] if item["type"] == "checkbox")

    for claimed in (
        {"field_id": checkbox, "kind": "click", "checked": True},
        {"field_id": checkbox, "kind": "drawn", "checked": True},
        {"field_id": checkbox, "checked": True, "typed_text": "x"},
        {"field_id": checkbox},
    ):
        captures = [c for c in mine if c["field_id"] != checkbox] + [claimed]
        response = patient.post("/sign", {"intent_confirmed": True, "captures": captures}, **{"Idempotency-Key": "k1"})
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "validation_failed"

    assert ehr.envelope(envelope["id"])["current_revision_sha256"] == envelope["presented_sha256"]
    assert patient.sign(payload, key="k2").status_code == 200
    signed = next(e for e in ehr.audit(envelope["id"]) if e["event_type"] == "signer.signed")
    assert {c["field_id"]: c["kind"] for c in signed["data"]["captures"]}[checkbox] == "checkbox"


def test_signing_before_viewing_or_consenting_is_a_conflict(ehr: Ehr, world: World) -> None:
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    patient = ehr.open_session(envelope, "patient")
    payload = patient.session()

    assert patient.post("/viewed", {"pages_viewed": payload["envelope"]["page_count"]}).status_code == 409
    assert patient.sign(payload, key="s1").status_code == 409
    assert patient.get("/document").status_code == 200
    assert (
        patient.post("/consent", {"consent_version": payload["consent"]["version"], "accepted": True}).status_code
        == 409
    )

    short = patient.post("/viewed", {"pages_viewed": payload["envelope"]["page_count"] - 1})
    assert short.status_code == 422
    assert short.json()["error"]["code"] == "pages_not_all_viewed"
    assert patient.post("/viewed", {"pages_viewed": payload["envelope"]["page_count"]}).status_code == 200
    assert patient.sign(payload, key="s2").status_code == 409  # viewed, not yet consented

    stale = patient.post("/consent", {"consent_version": "1999-01", "accepted": True})
    assert stale.status_code == 409
    assert (
        patient.post("/consent", {"consent_version": payload["consent"]["version"], "accepted": False}).status_code
        == 422
    )


def _sealed(ehr: Ehr) -> dict[str, object]:
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    ehr.sign_everyone(envelope, ("patient",))
    sealed = ehr.envelope(str(envelope["id"]))
    assert sealed["status"] == "sealed"
    assert ehr.verification(str(envelope["id"]))["complete"] is True
    return sealed


def test_a_tampered_sealed_blob_is_caught(ehr: Ehr, world: World) -> None:
    sealed = _sealed(ehr)
    path = world.settings.blob_fs_root / content_key(bytes.fromhex(str(sealed["sealed_sha256"])))
    original = path.read_bytes()

    # Someone with access to the disk flips one byte of the stored, sealed PDF.
    tampered = bytearray(original)
    tampered[len(tampered) // 2] ^= 0x01
    os.chmod(path, 0o644)  # noqa: PTH101 - the file is deliberately read-only
    path.write_bytes(bytes(tampered))

    report = ehr.verification(str(sealed["id"]))
    assert report["ok"] is False and report["complete"] is False
    failed = {c["name"]: c["detail"] for c in report["checks"] if c["status"] == "failed"}
    assert any(name.endswith("_sealed_hash") and "integrity_failure" in detail for name, detail in failed.items())
    assert "seal" in failed  # it could not be validated, and the report says so rather than skipping it

    # The document is never served once it no longer matches its hash.
    served = ehr.get(f"/envelopes/{sealed['id']}/document")
    assert served.status_code == 500
    assert served.json()["error"]["code"] == "blob_corrupt"
    assert b"%PDF" not in served.content

    # A check that fails is still recorded as having happened.
    events = ehr.get(f"/envelopes/{sealed['id']}/audit").json()["events"]
    assert events[-1]["event_type"] == "verification.performed"
    assert events[-1]["data"]["ok"] is False


def test_a_tampered_audit_row_is_caught(ehr: Ehr, world: World, owner_engine: Engine) -> None:
    sealed = _sealed(ehr)

    # The app role cannot do this at all, and the owner role hits the trigger. Only someone who
    # can disable triggers gets this far -- which is exactly who the hash chain is for.
    with owner_engine.begin() as conn:
        conn.execute(text("ALTER TABLE audit_events DISABLE TRIGGER USER"))
        conn.execute(
            text(
                "UPDATE audit_events SET actor_user_id = 'someone-else' "
                "WHERE stream_id = :id AND event_type = 'signer.signed'"
            ),
            {"id": sealed["id"]},
        )
        conn.execute(text("ALTER TABLE audit_events ENABLE TRIGGER USER"))

    report = ehr.verification(str(sealed["id"]))
    assert report["ok"] is False
    failed = {c["name"]: c["detail"] for c in report["checks"] if c["status"] == "failed"}
    assert "audit_chain" in failed and "hash mismatch" in failed["audit_chain"]
    # The seal itself is still good: the report says exactly what failed and what did not.
    assert report["seal"]["ok"] is True


def test_a_removed_audit_row_is_caught(ehr: Ehr, world: World, owner_engine: Engine) -> None:
    sealed = _sealed(ehr)
    with owner_engine.begin() as conn:
        conn.execute(text("ALTER TABLE audit_events DISABLE TRIGGER USER"))
        conn.execute(
            text("DELETE FROM audit_events WHERE stream_id = :id AND event_type = 'consent.accepted'"),
            {"id": sealed["id"]},
        )
        conn.execute(text("ALTER TABLE audit_events ENABLE TRIGGER USER"))

    report = ehr.verification(str(sealed["id"]))
    failed = {c["name"]: c["detail"] for c in report["checks"] if c["status"] == "failed"}
    assert "gap" in failed["audit_chain"]
    assert "certificate_head_hash" in failed  # the certificate counted an event that is gone


def test_reauthentication_cannot_be_attested_after_the_signature(ehr: Ehr, world: World) -> None:
    """The session a signer signed from stays live for the copy download, and used to accept
    ``POST /v1/sessions/{id}/reauth`` for ever afterwards.

    ``reauth_attestations`` is append-only, so every such call wrote an ``auth.reauthenticated``
    event that can never be corrected -- and the certificate used to print the newest attestation
    on the session rather than the one the signature actually used.
    """
    envelope = ehr.create_envelope("procedure_consent")
    ehr.sign_everyone(envelope, ("patient", "witness"))

    clinician = ehr.open_session(envelope, "clinician", method="password+mfa")
    payload = clinician.review_and_consent()
    assert ehr.reauth(clinician).status_code == 200
    assert clinician.sign(payload, key="sign-clinician").status_code == 200
    assert ehr.envelope(envelope["id"])["status"] == "sealed"

    # That session is still live, for the copy download only. It must not accept a fresh
    # attestation now that the signature is inside the sealed bytes.
    assert clinician.get("/copy").status_code == 200
    refused = ehr.reauth(clinician)
    assert refused.status_code == 409, refused.text
    assert refused.json()["error"]["code"] == "envelope_not_live"

    assert ehr.audit_types(envelope["id"]).count("auth.reauthenticated") == 1


def test_reauthentication_is_refused_once_that_signer_has_signed(ehr: Ehr, world: World) -> None:
    """Parallel order, so the envelope is still live while this signer is finished."""
    envelope = ehr.create_envelope("procedure_consent", signing_order="parallel")
    clinician = ehr.open_session(envelope, "clinician", method="password+mfa")
    payload = clinician.review_and_consent()
    assert ehr.reauth(clinician).status_code == 200
    assert clinician.sign(payload, key="sign-clinician-first").status_code == 200
    assert ehr.envelope(envelope["id"])["status"] == "in_progress"

    refused = ehr.reauth(clinician)
    assert refused.status_code == 409, refused.text
    assert refused.json()["error"]["code"] == "signer_finished"
    assert ehr.audit_types(envelope["id"]).count("auth.reauthenticated") == 1


def test_reauthentication_is_refused_for_a_role_that_does_not_need_it(ehr: Ehr, world: World) -> None:
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    patient = ehr.open_session(envelope, "patient")
    refused = ehr.reauth(patient)
    assert refused.status_code == 409, refused.text
    assert refused.json()["error"]["code"] == "reauth_not_required"
    assert "auth.reauthenticated" not in ehr.audit_types(envelope["id"])
