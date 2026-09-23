"""A person signing two forms at one desk, over HTTP (Addendum 3 C).

The rules are settled in ``test_resolution.py``; these run the whole stack -- host API, signer API,
envelope service, identity, audit -- because the questions here are different ones: what the
session payload offers the UI, what the UI may send back, what the server does with a claim it
cannot confirm, and whether a client that has never heard of any of this still works.
"""

from __future__ import annotations

from typing import Any

from esign.audit.canonical import canonical_value
from esign.clock import FixedClock
from tests.consent_span.conftest import (
    PATIENT,
    SITTING_SECONDS,
    SOMEBODY_ELSE,
    Sitting,
    SittingFactory,
    agree,
    review,
)


def first_form(s: Sitting, *, host_user_id: str = PATIENT) -> dict[str, Any]:
    """The form the patient reads the disclosure on, and agrees to in the ordinary way."""
    envelope = s.form(host_user_id=host_user_id)
    signer = s.ehr.open_session(envelope, "patient")
    payload = review(signer)
    assert payload["consent"]["standing"] is None, "the first form of a sitting has nothing to stand on"
    assert agree(signer, payload).status_code == 200
    return envelope


def test_with_the_span_off_the_second_form_asks_again(sitting: SittingFactory) -> None:
    """The shipped behaviour, over HTTP: no standing block, and a claim of one is refused."""
    s = sitting(0)
    first = first_form(s)
    second = s.form()
    signer = s.ehr.open_session(second, "patient")
    payload = review(signer)

    assert payload["consent"]["standing"] is None
    refused = agree(signer, payload, relies_on=str(first["id"]))
    assert refused.status_code == 409
    assert refused.json()["error"]["code"] == "consent_not_standing"

    # ...and the ordinary post still works, which is what the UI does on that refusal.
    assert agree(signer, payload).status_code == 200


def test_the_session_payload_offers_the_standing_acceptance(sitting: SittingFactory, clock: FixedClock) -> None:
    """What screen 1 needs to show "You agreed to sign electronically at 09:12" instead of the
    checkbox: when it was agreed, and which document it was agreed on."""
    s = sitting(SITTING_SECONDS)
    agreed_at = clock.now()
    first = first_form(s)

    clock.advance(180)
    signer = s.ehr.open_session(s.form(), "patient")
    block = s.consent_block(signer)

    assert block["standing"] == {
        "accepted_at": agreed_at.isoformat().replace("+00:00", "Z"),
        "envelope_id": str(first["id"]),
    }
    # The disclosure itself is still served beside it: the UI offers "Read the notice", and a
    # standing acceptance is a fact about this very text.
    assert block["body"]
    assert block["version"]


def test_the_second_form_records_its_own_acceptance_naming_the_first(
    sitting: SittingFactory, clock: FixedClock
) -> None:
    s = sitting(SITTING_SECONDS)
    agreed_at = clock.now()
    first = first_form(s)
    clock.advance(180)

    second = s.form()
    signer = s.ehr.open_session(second, "patient")
    payload = review(signer)
    assert agree(signer, payload, relies_on=str(first["id"])).status_code == 200

    # The row on *this* envelope is set exactly as it is without the span (SPEC section 16 C).
    row = s.signers_row(str(second["id"]))
    assert row.status == "consented"
    assert row.consent_text_id is not None
    assert row.consented_at == clock.now()

    events = s.consent_events(str(second["id"]))
    assert len(events) == 1
    data = events[0]["data"]
    assert data["relied_on_envelope_id"] == str(first["id"])
    # Audit data is canonical JSON: RFC 3339 UTC with exactly six fractional digits.
    assert data["relied_on_accepted_at"] == canonical_value(agreed_at)
    assert data["consent_text_id"] == str(row.consent_text_id)


def test_a_client_that_sends_nothing_new_is_unaffected(sitting: SittingFactory) -> None:
    """Backward compatibility: with the span on, a UI that posts the old body is recorded the old
    way -- an acceptance of its own, relying on nothing."""
    s = sitting(SITTING_SECONDS)
    first_form(s)
    signer = s.ehr.open_session(s.form(), "patient")
    payload = review(signer)

    assert agree(signer, payload).status_code == 200
    data = s.consent_events(str(payload["envelope"]["id"]))[0]["data"]
    assert data["relied_on_envelope_id"] is None


def test_another_patients_acceptance_is_refused(sitting: SittingFactory) -> None:
    """The one refusal a real deployment would actually see from a confused client, and the one
    that matters most: a signer can never stand on somebody else's agreement."""
    s = sitting(SITTING_SECONDS)
    theirs = first_form(s, host_user_id=SOMEBODY_ELSE)

    mine = s.form(host_user_id=PATIENT)
    signer = s.ehr.open_session(mine, "patient")
    payload = review(signer)
    assert payload["consent"]["standing"] is None
    refused = agree(signer, payload, relies_on=str(theirs["id"]))
    assert refused.status_code == 409
    assert refused.json()["error"]["code"] == "consent_not_standing"


def test_another_hosts_envelope_is_refused(sitting: SittingFactory) -> None:
    """And an envelope this host cannot even see is not a hint about whether it exists: the same
    refusal, for the same reason, as one that is simply too old."""
    s = sitting(SITTING_SECONDS)
    other = s.world.host("Another EHR")
    other.publish_template("patient_consent")
    theirs = first_form_for(s, other)

    signer = s.ehr.open_session(s.form(), "patient")
    payload = review(signer)
    refused = agree(signer, payload, relies_on=str(theirs["id"]))
    assert refused.status_code == 409
    assert refused.json()["error"]["code"] == "consent_not_standing"


def first_form_for(s: Sitting, ehr: Any) -> dict[str, Any]:
    """``first_form`` for a host other than the sitting's own."""
    envelope = s.form(ehr=ehr)
    signer = ehr.open_session(envelope, "patient")
    payload = review(signer)
    assert agree(signer, payload).status_code == 200
    return envelope


def test_after_the_sitting_has_run_out_the_disclosure_comes_back(sitting: SittingFactory, clock: FixedClock) -> None:
    """A patient who comes back in the afternoon reads the notice again."""
    span = 300
    s = sitting(span)
    first = first_form(s)

    clock.advance(span + 1)
    signer = s.ehr.open_session(s.form(), "patient")
    payload = review(signer)
    assert payload["consent"]["standing"] is None
    assert agree(signer, payload, relies_on=str(first["id"])).status_code == 409


def test_a_kiosk_session_is_offered_nothing_and_may_claim_nothing(sitting: SittingFactory) -> None:
    """The shared clinic tablet: the next person to hold it is somebody else, so the disclosure
    is shown every time -- the same rule that keeps a saved signature off a kiosk (Addendum 1 B)."""
    s = sitting(SITTING_SECONDS)
    first = first_form(s)

    on_the_tablet = s.ehr.open_session(
        s.form(),
        "patient",
        method="staff_verified",
        kiosk={"staff_user_id": "staff-2207", "identity_check": "photo_id"},
    )
    payload = review(on_the_tablet)
    assert payload["session"]["kiosk"] is True
    assert payload["consent"]["standing"] is None
    assert agree(on_the_tablet, payload, relies_on=str(first["id"])).status_code == 409


def test_an_unknown_envelope_id_is_refused_like_any_other_claim(sitting: SittingFactory) -> None:
    """A stale tab, a typo, a guess: all of them are "please agree here", never a 404 that would
    say whether some other host's envelope exists."""
    s = sitting(SITTING_SECONDS)
    first_form(s)
    signer = s.ehr.open_session(s.form(), "patient")
    payload = review(signer)

    refused = agree(signer, payload, relies_on="11111111-2222-4333-8444-555555555555")
    assert refused.status_code == 409
    assert refused.json()["error"]["code"] == "consent_not_standing"


def test_the_body_still_refuses_what_it_always_refused(sitting: SittingFactory) -> None:
    """The consent body is closed (SPEC section 9): the new field is one more declared key, not a
    door for anything else, and it has to be an id."""
    s = sitting(SITTING_SECONDS)
    signer = s.ehr.open_session(s.form(), "patient")
    payload = review(signer)

    version = payload["consent"]["version"]
    assert signer.post("/consent", {"consent_version": version, "accepted": True, "relies_on": "x"}).status_code == 422
    assert (
        signer.post(
            "/consent", {"consent_version": version, "accepted": True, "relies_on_envelope_id": "not-an-id"}
        ).status_code
        == 422
    )
