"""What a borrowed attestation leaves behind: the certificate, and the checks that re-derive it.

The span weakens per-document proof, so the containment has to be visible in the two places a
dispute actually reaches: the certificate of completion inside the sealed bytes, and the
verification report. A signature that borrowed an attestation says so on the page a court reads,
and verification goes back to the ``reauth_attestations`` row to confirm the trail's account of it.
"""

from __future__ import annotations

import io
import re
from typing import Any

import pytest
from pypdf import PdfReader
from sqlalchemy import Engine, text

from esign.clock import FixedClock
from esign.config import REAUTH_SPAN_MAX_SECONDS, Settings
from tests.reauth_span.conftest import DEMO_SPAN_SECONDS, Queue, QueueFactory
from tests.reauth_span.test_signing_queue import envelope_for, first_document, signed_data

#: How long after the first signature the second document is signed.
BORROWED_AFTER_SECONDS = 45


def seal(q: Queue, envelope: dict[str, Any]) -> dict[str, Any]:
    """Everyone else signs, so the envelope completes and the worker's inline attempt seals it."""
    q.ehr.sign_everyone(envelope, ("patient", "witness"))
    sealed = q.ehr.envelope(str(envelope["id"]))
    assert sealed["status"] == "sealed", sealed
    return sealed


def a_queue_of_two(q: Queue, clock: FixedClock) -> tuple[dict[str, Any], dict[str, Any]]:
    """Two sealed procedure consents: the first re-authenticated for, the second borrowing it."""
    first = first_document(q)
    seal(q, first)

    clock.advance(BORROWED_AFTER_SECONDS)
    second = envelope_for(q.ehr)
    clinician = q.ehr.open_session(second, "clinician", method="password+mfa")
    payload = clinician.review_and_consent()
    assert clinician.sign(payload, key=f"second-{second['id']}").status_code == 200
    assert signed_data(q, second["id"])["reauth_scope"] == "span"
    seal(q, second)
    return first, second


def certificate_text(q: Queue, envelope_id: str) -> str:
    response = q.ehr.get(f"/envelopes/{envelope_id}/document")
    assert response.status_code == 200, response.text
    pages = PdfReader(io.BytesIO(response.content)).pages
    return re.sub(r"\s+", " ", "\n".join(page.extract_text() or "" for page in pages))


def failed_checks(report: dict[str, Any]) -> dict[str, str]:
    return {c["name"]: c["detail"] for c in report["checks"] if c["status"] == "failed"}


def test_the_certificate_says_which_attestation_each_signature_rests_on(queue: QueueFactory, clock: FixedClock) -> None:
    q = queue(DEMO_SPAN_SECONDS)
    first, second = a_queue_of_two(q, clock)

    # The document the clinician re-authenticated for says so plainly.
    assert "for this document" in certificate_text(q, str(first["id"]))

    # The one that borrowed it says where the confirmation came from and how old it was, so a
    # reader is never left to assume the clinician confirmed their identity for this signature.
    borrowed = certificate_text(q, str(second["id"]))
    assert "in an earlier session" in borrowed
    assert f"{BORROWED_AFTER_SECONDS} seconds before signing" in borrowed
    assert "password+mfa" in borrowed


def test_verification_passes_and_reports_the_attestation_check(queue: QueueFactory, clock: FixedClock) -> None:
    q = queue(DEMO_SPAN_SECONDS)
    _, second = a_queue_of_two(q, clock)

    report = q.ehr.verification(str(second["id"]))
    assert report["ok"] is True
    assert report["complete"] is True
    checks = {c["name"]: c["status"] for c in report["checks"]}
    assert checks["reauth_attestations_match_trail"] == "passed"


def test_an_envelope_with_no_reauthenticating_signer_still_runs_the_check(queue: QueueFactory) -> None:
    """Passed, not skipped: the check ran and found nothing to contradict."""
    q = queue(DEMO_SPAN_SECONDS)
    q.ehr.publish_template("hipaa_acknowledgement")
    envelope = q.ehr.create_envelope("hipaa_acknowledgement")
    q.ehr.sign_everyone(envelope, ("patient",))

    report = q.ehr.verification(str(envelope["id"]))
    check = next(c for c in report["checks"] if c["name"] == "reauth_attestations_match_trail")
    assert check["status"] == "passed"
    assert report["ok"] is True


@pytest.mark.parametrize(
    ("statement", "expected"),
    [
        ("UPDATE reauth_attestations SET method = 'pin' WHERE id = :id", "method"),
        ("UPDATE reauth_attestations SET auth_time = auth_time - interval '1 hour' WHERE id = :id", "auth_time"),
        ("DELETE FROM reauth_attestations WHERE id = :id", "not in the database"),
        ("UPDATE reauth_attestations SET host_user_id = 'dr-9999' WHERE id = :id", "another user"),
    ],
)
def test_tampering_with_the_borrowed_attestation_is_caught(
    queue: QueueFactory, clock: FixedClock, owner_engine: Engine, statement: str, expected: str
) -> None:
    """The trail records the attestation's id, method and age; the row is the thing those describe.

    Neither the app role nor the owner role can change this table -- the grants stop one and the
    append-only trigger stops the other -- so the tamper here disables the trigger first, which is
    exactly the access the hash chain and this check exist for. The audit chain itself is intact
    afterwards: the attestation lives in a different envelope's stream, so without this check the
    borrowed evidence could be rewritten and the borrowing document would still verify clean.
    """
    q = queue(DEMO_SPAN_SECONDS)
    _, second = a_queue_of_two(q, clock)
    attestation_id = q.attestation_ids()[0]
    assert q.ehr.verification(str(second["id"]))["ok"] is True

    with owner_engine.begin() as conn:
        conn.execute(text("ALTER TABLE reauth_attestations DISABLE TRIGGER USER"))
        conn.execute(text(statement), {"id": attestation_id})
        conn.execute(text("ALTER TABLE reauth_attestations ENABLE TRIGGER USER"))

    report = q.ehr.verification(str(second["id"]))
    assert report["ok"] is False
    failed = failed_checks(report)
    assert "reauth_attestations_match_trail" in failed
    assert expected in failed["reauth_attestations_match_trail"]
    # The seal and the chain are untouched: the report says exactly what failed and what did not.
    assert "audit_chain" not in failed
    assert report["seal"]["ok"] is True


@pytest.mark.parametrize("seconds", [REAUTH_SPAN_MAX_SECONDS + 1, 86_400])
def test_a_span_past_the_cap_is_refused_at_startup_rather_than_clamped(seconds: int) -> None:
    """The 900 second ceiling is the number compliance is quoted, so it is a test rather than a
    reading of the code: a span past it refuses to start, and is never quietly narrowed."""
    with pytest.raises(ValueError, match="reauth_span_seconds"):
        Settings(reauth_span_seconds=seconds)


def test_the_cap_itself_is_accepted() -> None:
    """And the boundary is the boundary: 900 is a legal span, 901 is not."""
    assert Settings(reauth_span_seconds=REAUTH_SPAN_MAX_SECONDS).reauth_span_seconds == REAUTH_SPAN_MAX_SECONDS


def test_a_borrowed_attestation_older_than_the_cap_is_caught(
    queue: QueueFactory, clock: FixedClock, owner_engine: Engine
) -> None:
    """A ``span`` signature can never have borrowed an attestation older than the cap.

    The span a host was configured with at the time is not recoverable years later, but the
    900-second ceiling is a property of the code -- ``Settings`` refuses to hold more -- so an
    event claiming a day-old borrowed attestation describes a signature this service could not
    have produced, however consistent the rest of it is made to look. The row is backdated to
    match, so the ``auth_time`` cross-check is satisfied and the only thing left to object is the
    bound itself.
    """
    q = queue(DEMO_SPAN_SECONDS)
    _, second = a_queue_of_two(q, clock)
    attestation_id = q.attestation_ids()[0]
    over_cap = 86_400

    with owner_engine.begin() as conn:
        conn.execute(text("ALTER TABLE audit_events DISABLE TRIGGER USER"))
        conn.execute(
            text(
                "UPDATE audit_events SET data = jsonb_set(data, '{reauth_age_seconds}', to_jsonb(CAST(:age AS bigint))) "
                "WHERE stream_id = :env AND event_type = 'signer.signed' AND data ->> 'reauth_used' = 'true'"
            ),
            {"age": over_cap, "env": second["id"]},
        )
        conn.execute(text("ALTER TABLE audit_events ENABLE TRIGGER USER"))
        conn.execute(text("ALTER TABLE reauth_attestations DISABLE TRIGGER USER"))
        conn.execute(
            text(
                "UPDATE reauth_attestations SET auth_time = ("
                "  SELECT occurred_at - make_interval(secs => CAST(:age AS int)) FROM audit_events "
                "  WHERE stream_id = :env AND event_type = 'signer.signed' AND data ->> 'reauth_used' = 'true'"
                ") WHERE id = :id"
            ),
            {"age": over_cap, "env": second["id"], "id": attestation_id},
        )
        conn.execute(text("ALTER TABLE reauth_attestations ENABLE TRIGGER USER"))

    failed = failed_checks(q.ehr.verification(str(second["id"])))
    assert "reauth_attestations_match_trail" in failed
    assert "older than the maximum span" in failed["reauth_attestations_match_trail"]
    # The bound is what objected, not the age cross-check: the row was moved to agree with the
    # forged age, which is exactly what a careful forger would do.
    assert "auth_time" not in failed["reauth_attestations_match_trail"]
