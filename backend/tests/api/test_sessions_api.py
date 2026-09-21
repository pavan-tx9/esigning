"""Session creation over the Host API: what the host attests, and what is recorded when it is refused."""

from __future__ import annotations

from datetime import timedelta

from tests.e2e.conftest import Ehr, World


def _open(ehr: Ehr, envelope: dict[str, object], body: dict[str, object]):  # type: ignore[no-untyped-def]
    signer_id = ehr.signer_id(envelope, "patient")  # type: ignore[arg-type]
    return ehr.post(f"/envelopes/{envelope['id']}/signers/{signer_id}/sessions", body)


def test_refused_sessions_are_recorded_and_survive_the_rollback(ehr: Ehr, world: World) -> None:
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    now = world.clock.now()

    cases = [
        ({"auth": {"method": "password", "auth_time": (now - timedelta(hours=13)).isoformat()}}, "auth_too_old"),
        (
            {"auth": {"method": "password", "auth_time": (now + timedelta(seconds=5)).isoformat()}},
            "auth_time_in_future",
        ),
        ({"auth": {"method": "staff_verified", "auth_time": now.isoformat()}}, "kiosk_context_required"),
        (
            {
                "auth": {"method": "staff_verified", "auth_time": now.isoformat()},
                "kiosk": {"staff_user_id": "Nurse Priya Raman", "identity_check": "photo_id"},
            },
            "invalid_kiosk_context",  # a staff *name* is not an identifier, and would reach the trail
        ),
    ]
    for body, code in cases:
        refused = _open(ehr, envelope, body)
        assert refused.status_code == 422, refused.text
        assert refused.json()["error"]["code"] == code
        assert "Priya" not in refused.text

    events = ehr.get(f"/envelopes/{envelope['id']}/audit").json()["events"]
    rejected = [e["data"]["reason_code"] for e in events if e["event_type"] == "session.rejected"]
    assert rejected == [code for _, code in cases]
    assert "Priya" not in str(events)

    # Values outside the closed vocabularies never get as far as the identity module.
    assert _open(ehr, envelope, {"auth": {"method": "fingerprint", "auth_time": now.isoformat()}}).status_code == 422
    assert _open(ehr, envelope, {"auth": {"method": "password", "auth_time": "yesterday"}}).status_code == 422
    # A naive timestamp is not a time anyone can be held to.
    naive = _open(ehr, envelope, {"auth": {"method": "password", "auth_time": "2026-03-17T14:00:00"}})
    assert naive.status_code == 422 and naive.json()["error"]["code"] == "invalid_auth_time"


def test_a_kiosk_session_records_the_staff_member_and_the_check(ehr: Ehr, world: World) -> None:
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    kiosk = {"staff_user_id": "nurse-4471", "identity_check": "dob_and_name"}
    patient = ehr.open_session(envelope, "patient", method="staff_verified", kiosk=kiosk)
    assert patient.session()["session"]["kiosk"] is True

    events = ehr.get(f"/envelopes/{envelope['id']}/audit").json()["events"]
    created = next(e for e in events if e["event_type"] == "session.created")
    assert created["data"]["kiosk"] is True
    assert created["data"]["kiosk_staff_user_id"] == "nurse-4471"
    assert created["data"]["kiosk_identity_check"] == "dob_and_name"
    assert created["data"]["auth_method"] == "staff_verified"
    assert created["context"]["session_id"] == patient.session_id

    # The signature is the patient's, never the staff member's.
    payload = patient.review_and_consent()
    assert patient.sign(payload, key="kiosk-sign").status_code == 200
    events = ehr.get(f"/envelopes/{envelope['id']}/audit").json()["events"]
    signed = next(e for e in events if e["event_type"] == "signer.signed")
    assert signed["actor"] == {"user_id": "pt-100482", "role": "patient", "capacity": "self", "on_behalf_of": None}
    assert signed["context"]["auth_method"] == "staff_verified"


def test_a_new_session_revokes_the_previous_one(ehr: Ehr, world: World) -> None:
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    first = ehr.open_session(envelope, "patient")
    second = ehr.open_session(envelope, "patient")
    assert first.get("/session").status_code == 401
    assert second.get("/session").status_code == 200

    world.clock.advance(world.settings.session_ttl_seconds + 1)
    assert second.get("/session").status_code == 401
