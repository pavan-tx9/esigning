"""A clinician signing several documents in a row, over HTTP (Addendum 1 C).

The span exists for one workflow: a clinician with a queue of consents re-authenticates once and
then signs each document in turn. These run the whole stack -- host API, signer API, envelope
service, identity, audit -- because the question is not only "does ``fresh_reauth`` resolve" but
"does the signature that comes out say what it rests on".

Every envelope here is ``parallel`` so the clinician can sign first: the queue is about the
clinician's own sessions, and a patient and a witness signing first would only make it slower.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from esign.clock import FixedClock
from tests.e2e.conftest import Ehr
from tests.reauth_span.conftest import DEMO_SPAN_SECONDS, Queue, QueueFactory


def envelope_for(ehr: Ehr, *, clinician_user_id: str = "dr-0311") -> dict[str, Any]:
    """A procedure consent whose clinician is a named user of this host."""
    body = ehr.envelope_body("procedure_consent", signing_order="parallel")
    for signer in body["signers"]:
        if signer["role_key"] == "clinician":
            signer["host_user_id"] = clinician_user_id
    response = ehr.post("/envelopes", body)
    assert response.status_code == 201, response.text
    created: dict[str, Any] = response.json()
    return created


def first_document(q: Queue, *, clinician_user_id: str = "dr-0311") -> dict[str, Any]:
    """The document the clinician re-authenticates for: the hand-off happens exactly once."""
    envelope = envelope_for(q.ehr, clinician_user_id=clinician_user_id)
    clinician = q.ehr.open_session(envelope, "clinician", method="password+mfa")
    payload = clinician.review_and_consent()
    assert payload["signer"]["reauth_valid_until"] is None
    assert payload["signer"]["reauth_scope"] is None
    assert q.ehr.reauth(clinician).status_code == 200
    assert clinician.sign(payload, key=f"first-{envelope['id']}").status_code == 200
    return envelope


def signed_data(q: Queue, envelope_id: str) -> dict[str, Any]:
    events = [e for e in q.ehr.audit(envelope_id) if e["event_type"] == "signer.signed"]
    assert len(events) == 1, [e["event_type"] for e in q.ehr.audit(envelope_id)]
    data: dict[str, Any] = events[0]["data"]
    return data


def when(value: str) -> datetime:
    return datetime.fromisoformat(value).astimezone(UTC)


def test_the_first_documents_signature_rests_on_its_own_attestation(queue: QueueFactory) -> None:
    """The scope is recorded whether or not anything was borrowed, so "session" is a positive
    statement rather than the absence of one."""
    q = queue(DEMO_SPAN_SECONDS)
    envelope = first_document(q)

    data = signed_data(q, envelope["id"])
    assert data["reauth_used"] is True
    assert data["reauth_scope"] == "session"
    assert data["reauth_age_seconds"] == 0
    assert data["reauth_attestation_id"] == str(q.attestation_ids()[0])


def test_with_the_span_off_the_second_document_demands_its_own_attestation(queue: QueueFactory) -> None:
    """The shipped configuration. One attestation, one document, exactly as before the addendum."""
    q = queue(0)
    first_document(q)

    second = envelope_for(q.ehr)
    clinician = q.ehr.open_session(second, "clinician", method="password+mfa")
    payload = clinician.review_and_consent()
    assert payload["signer"]["reauth_valid_until"] is None
    assert payload["signer"]["reauth_scope"] is None

    refused = clinician.sign(payload, key=f"second-{second['id']}")
    assert refused.status_code == 403, refused.text
    assert refused.json()["error"]["code"] == "reauth_required"


def test_with_the_span_on_the_second_document_borrows_the_first_attestation(
    queue: QueueFactory, clock: FixedClock
) -> None:
    q = queue(DEMO_SPAN_SECONDS)
    first = first_document(q)
    attestation_id = q.attestation_ids()[0]
    clock.advance(45)

    second = envelope_for(q.ehr)
    clinician = q.ehr.open_session(second, "clinician", method="password+mfa")
    payload = clinician.review_and_consent()
    # The UI skips the hand-off on the strength of these two, so they have to agree with what the
    # signature will actually be allowed to rest on.
    assert payload["signer"]["reauth_scope"] == "span"
    assert when(payload["signer"]["reauth_valid_until"]) == clock.now() + timedelta(seconds=120 - 45)

    assert clinician.sign(payload, key=f"second-{second['id']}").status_code == 200

    data = signed_data(q, second["id"])
    assert data["reauth_used"] is True
    assert data["reauth_scope"] == "span"
    assert data["reauth_method"] == "password+mfa"
    assert data["reauth_age_seconds"] == 45
    assert data["reauth_attestation_id"] == str(attestation_id)
    # Nothing was attested for this document: the host called /reauth once, on the first one.
    assert "auth.reauthenticated" not in q.ehr.audit_types(second["id"])
    assert q.attestation_ids() == [attestation_id]
    assert signed_data(q, first["id"])["reauth_attestation_id"] == str(attestation_id)


def test_after_the_span_has_run_out_the_second_document_demands_its_own(queue: QueueFactory, clock: FixedClock) -> None:
    """A span shorter than ``REAUTH_MAX_AGE_SECONDS``, so this is the span ending and not the
    attestation ageing out."""
    q = queue(30)
    first_document(q)
    clock.advance(31)

    second = envelope_for(q.ehr)
    clinician = q.ehr.open_session(second, "clinician", method="password+mfa")
    payload = clinician.review_and_consent()
    assert payload["signer"]["reauth_valid_until"] is None

    refused = clinician.sign(payload, key=f"second-{second['id']}")
    assert refused.status_code == 403, refused.text
    assert refused.json()["error"]["code"] == "reauth_required"

    # And the way out is the ordinary one: the host re-authenticates for this document.
    assert q.ehr.reauth(clinician).status_code == 200
    assert clinician.sign(payload, key=f"second-{second['id']}").status_code == 200
    assert signed_data(q, second["id"])["reauth_scope"] == "session"


def test_an_attestation_older_than_the_maximum_age_is_refused_inside_the_span(
    queue: QueueFactory, clock: FixedClock
) -> None:
    """The span is capped at 900 seconds, which is longer than the 120 an attestation may be. The
    maximum age still decides: the span says which documents an attestation covers, not how stale
    it may be."""
    q = queue(900)
    first_document(q)
    clock.advance(121)

    second = envelope_for(q.ehr)
    clinician = q.ehr.open_session(second, "clinician", method="password+mfa")
    payload = clinician.review_and_consent()
    assert payload["signer"]["reauth_valid_until"] is None

    refused = clinician.sign(payload, key=f"second-{second['id']}")
    assert refused.status_code == 403, refused.text
    assert refused.json()["error"]["code"] == "reauth_required"


def test_another_clinician_on_the_same_host_never_borrows(queue: QueueFactory) -> None:
    q = queue(DEMO_SPAN_SECONDS)
    first_document(q)

    theirs = envelope_for(q.ehr, clinician_user_id="dr-9999")
    other = q.ehr.open_session(theirs, "clinician", method="password+mfa")
    payload = other.review_and_consent()
    assert payload["signer"]["reauth_valid_until"] is None

    refused = other.sign(payload, key=f"theirs-{theirs['id']}")
    assert refused.status_code == 403, refused.text
    assert refused.json()["error"]["code"] == "reauth_required"


def test_the_same_user_id_at_another_host_never_borrows(queue: QueueFactory) -> None:
    """Two hosts may number their clinicians the same way. An attestation never leaves its host."""
    q = queue(DEMO_SPAN_SECONDS)
    first_document(q)

    stranger = q.world.host("Lakeside EHR")
    stranger.publish_template("procedure_consent")
    theirs = envelope_for(stranger, clinician_user_id="dr-0311")
    clinician = stranger.open_session(theirs, "clinician", method="password+mfa")
    payload = clinician.review_and_consent()
    assert payload["signer"]["reauth_valid_until"] is None

    refused = clinician.sign(payload, key=f"stranger-{theirs['id']}")
    assert refused.status_code == 403, refused.text
    assert refused.json()["error"]["code"] == "reauth_required"


def test_a_role_that_does_not_reauthenticate_is_untouched_by_the_span(queue: QueueFactory) -> None:
    """The span only ever answers a question the envelope service asks for a re-authenticating
    role. A patient's session payload and signature say nothing about it either way."""
    q = queue(DEMO_SPAN_SECONDS)
    envelope = first_document(q)

    patient = q.ehr.open_session(envelope, "patient")
    payload = patient.review_and_consent()
    assert payload["signer"]["requires_reauth"] is False
    assert payload["signer"]["reauth_valid_until"] is None
    assert payload["signer"]["reauth_scope"] is None
    assert patient.sign(payload, key=f"patient-{envelope['id']}").status_code == 200

    data = [e for e in q.ehr.audit(envelope["id"]) if e["event_type"] == "signer.signed"][-1]["data"]
    assert data["reauth_used"] is False
    assert data["reauth_scope"] is None
    assert data["reauth_attestation_id"] is None
    assert data["reauth_age_seconds"] is None
