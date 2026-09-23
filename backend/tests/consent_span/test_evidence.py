"""What a standing acceptance leaves behind (Addendum 3 C).

Consent once per sitting means one document's signature rests on something that happened on
another document. That is a real weakening of "every signer was shown the disclosure and agreed to
it here", so the containment has to be visible in the two places a dispute actually reaches: the
certificate of completion inside the sealed bytes, and the verification report.

The certificate says it in words. Verification goes to the other envelope's trail and looks for
the acceptance -- which is the point: without that, ``relied_on_envelope_id`` is a pair of values
this envelope's own hash chain cannot contradict.
"""

from __future__ import annotations

import io
import re
from typing import Any

import pytest
from pypdf import PdfReader
from sqlalchemy import Engine, text

from esign.clock import FixedClock
from tests.consent_span.conftest import SITTING_SECONDS, Sitting, SittingFactory, agree, review
from tests.consent_span.test_sitting import first_form

#: How long after the first form the second one is agreed to.
LATER_SECONDS = 180


def certificate_text(s: Sitting, envelope_id: str) -> str:
    response = s.ehr.get(f"/envelopes/{envelope_id}/document")
    assert response.status_code == 200, response.text
    pages = PdfReader(io.BytesIO(response.content)).pages
    return re.sub(r"\s+", " ", "\n".join(page.extract_text() or "" for page in pages))


def failed_checks(report: dict[str, Any]) -> dict[str, str]:
    return {c["name"]: c["detail"] for c in report["checks"] if c["status"] == "failed"}


def sign_and_seal(s: Sitting, envelope: dict[str, Any], signer: Any, payload: dict[str, Any]) -> dict[str, Any]:
    """The patient signs, which is the last signature on a patient consent, so it seals."""
    assert signer.sign(payload, key=f"sign-{envelope['id']}").status_code == 200
    sealed = s.ehr.envelope(str(envelope["id"]))
    assert sealed["status"] == "sealed", sealed
    return sealed


def a_sitting_of_two(s: Sitting, clock: FixedClock) -> tuple[dict[str, Any], dict[str, Any]]:
    """Two sealed patient consents: the disclosure read on the first, standing for the second."""
    first = first_form(s)
    signer = s.ehr.open_session(first, "patient")
    # The session that agreed was revoked when this one opened; the document has to be re-read.
    payload = review(signer)
    sign_and_seal(s, first, signer, payload)

    clock.advance(LATER_SECONDS)
    second = s.form()
    next_signer = s.ehr.open_session(second, "patient")
    payload = review(next_signer)
    assert payload["consent"]["standing"] is not None
    assert agree(next_signer, payload, relies_on=str(first["id"])).status_code == 200
    sign_and_seal(s, second, next_signer, payload)
    return first, second


def test_the_certificate_says_the_agreement_was_given_earlier_in_the_sitting(
    sitting: SittingFactory, clock: FixedClock
) -> None:
    """A reader must not be left to infer from two nearby timestamps that the notice was shown
    twice. The document whose disclosure was actually displayed says nothing extra; the one that
    stood on it says where the agreement came from."""
    s = sitting(SITTING_SECONDS)
    first, second = a_sitting_of_two(s, clock)

    assert "given for an earlier document in the same sitting" not in certificate_text(s, str(first["id"]))
    assert "given for an earlier document in the same sitting" in certificate_text(s, str(second["id"]))


def test_verification_passes_and_reports_the_consent_check(sitting: SittingFactory, clock: FixedClock) -> None:
    s = sitting(SITTING_SECONDS)
    _, second = a_sitting_of_two(s, clock)

    report = s.ehr.verification(str(second["id"]))
    assert report["ok"] is True
    assert report["complete"] is True
    assert ("consent_relied_on_matches_trail", "passed") in [(c["name"], c["status"]) for c in report["checks"]]


def test_an_envelope_whose_consent_stood_on_nothing_still_runs_the_check(sitting: SittingFactory) -> None:
    """Passed, not skipped: most envelopes collect their own consent, and a check that quietly
    does not run is indistinguishable from one that does."""
    s = sitting(0)
    envelope = s.form()
    signer = s.ehr.open_session(envelope, "patient")
    payload = review(signer)
    assert agree(signer, payload).status_code == 200
    sign_and_seal(s, envelope, signer, payload)

    checks = {c["name"]: c["status"] for c in s.ehr.verification(str(envelope["id"]))["checks"]}
    assert checks["consent_relied_on_matches_trail"] == "passed"


@pytest.mark.parametrize(
    ("statement", "what"),
    [
        (
            "UPDATE audit_events SET data = jsonb_set(data, '{consent_text_id}', "
            "  to_jsonb(CAST('11111111-2222-4333-8444-555555555555' AS text))) "
            "WHERE stream_id = :env AND event_type = 'consent.accepted'",
            "another disclosure",
        ),
        (
            "UPDATE audit_events SET actor_user_id = 'pt-999999' "
            "WHERE stream_id = :env AND event_type = 'consent.accepted'",
            "another person",
        ),
        (
            "UPDATE audit_events SET occurred_at = occurred_at - interval '2 hours' "
            "WHERE stream_id = :env AND event_type = 'consent.accepted'",
            "another time",
        ),
    ],
    ids=["disclosure", "person", "time"],
)
def test_a_relied_on_acceptance_that_is_not_in_that_trail_is_caught(
    sitting: SittingFactory, clock: FixedClock, owner_engine: Engine, statement: str, what: str
) -> None:
    """The acceptance the second document rested on is rewritten out of the first one's trail.

    Neither role can do this -- the grants stop one and the append-only trigger stops the other --
    so the tamper disables the trigger first, which is exactly the access the hash chain exists
    for. What matters is where the damage shows up: the *second* envelope's own chain is untouched
    and still verifies, so without this check its certificate would go on claiming an agreement
    that the record no longer contains.
    """
    s = sitting(SITTING_SECONDS)
    first, second = a_sitting_of_two(s, clock)
    assert s.ehr.verification(str(second["id"]))["ok"] is True, what

    with owner_engine.begin() as conn:
        conn.execute(text("ALTER TABLE audit_events DISABLE TRIGGER USER"))
        conn.execute(text(statement), {"env": first["id"]})
        conn.execute(text("ALTER TABLE audit_events ENABLE TRIGGER USER"))

    report = s.ehr.verification(str(second["id"]))
    assert report["ok"] is False
    failed = failed_checks(report)
    assert "consent_relied_on_matches_trail" in failed
    assert "no matching acceptance" in failed["consent_relied_on_matches_trail"]
    # The borrowing envelope is otherwise intact: the report says exactly what failed.
    assert "audit_chain" not in failed
    assert report["seal"]["ok"] is True


def test_a_relied_on_acceptance_given_from_a_kiosk_is_caught(
    sitting: SittingFactory, clock: FixedClock, owner_engine: Engine
) -> None:
    """SPEC section 16 C's hardest rule, re-derived rather than assumed.

    "A kiosk session never has standing consent" is enforced at record time by one ``NOT EXISTS``
    in one SQL string, and no code path now produces an envelope that breaks it. That is exactly
    the kind of guarantee this module exists to re-check: an older build, a direct row write or a
    future path around the repository would otherwise leave a document whose consent rested on a
    shared clinic tablet verifying clean.
    """
    s = sitting(SITTING_SECONDS)
    first, second = a_sitting_of_two(s, clock)
    assert s.ehr.verification(str(second["id"]))["ok"] is True

    with owner_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE signing_sessions SET kiosk_staff_user_id = 'staff-2207', "
                "  kiosk_identity_check = 'photo_id' "
                "WHERE signer_id IN (SELECT id FROM signers WHERE envelope_id = :env)"
            ),
            {"env": first["id"]},
        )

    report = s.ehr.verification(str(second["id"]))
    assert report["ok"] is False
    failed = failed_checks(report)
    assert "kiosk session" in failed["consent_relied_on_matches_trail"]


def test_a_chain_that_outlasts_the_maximum_span_is_caught(
    sitting: SittingFactory, clock: FixedClock, owner_engine: Engine
) -> None:
    """The cap verification re-checks is on the whole chain, not on one hop.

    A forged root -- a display time pushed back past the hour the code allows -- is a document
    claiming a sitting this service could never have produced, and the check says so even though
    the acceptance it names is really in the other envelope's trail.
    """
    s = sitting(SITTING_SECONDS)
    _, second = a_sitting_of_two(s, clock)

    with owner_engine.begin() as conn:
        conn.execute(text("ALTER TABLE audit_events DISABLE TRIGGER USER"))
        conn.execute(
            text(
                "UPDATE audit_events SET data = jsonb_set(data, '{relied_on_root_accepted_at}', "
                "  to_jsonb(to_char(occurred_at - interval '3 hours', "
                '    \'YYYY-MM-DD"T"HH24:MI:SS.US"Z"\'))) '
                "WHERE stream_id = :env AND event_type = 'consent.accepted'"
            ),
            {"env": second["id"]},
        )
        conn.execute(text("ALTER TABLE audit_events ENABLE TRIGGER USER"))

    failed = failed_checks(s.ehr.verification(str(second["id"])))
    assert "outside the maximum span" in failed["consent_relied_on_matches_trail"]


def test_the_certificate_says_when_the_disclosure_was_displayed(sitting: SittingFactory, clock: FixedClock) -> None:
    """ "Earlier in the same sitting" reads the same whether that was three minutes or an hour ago,
    and the difference is what a reader is weighing. The line names the moment."""
    s = sitting(SITTING_SECONDS)
    displayed_at = clock.now()
    _, second = a_sitting_of_two(s, clock)

    shown = displayed_at.strftime("%Y-%m-%d %H:%M:%S UTC")
    assert f"disclosure displayed {shown}" in certificate_text(s, str(second["id"]))


def test_a_relied_on_envelope_that_is_gone_is_caught(
    sitting: SittingFactory, clock: FixedClock, owner_engine: Engine
) -> None:
    """A pointer at an envelope that is not there at all: reported, never passed over."""
    s = sitting(SITTING_SECONDS)
    _, second = a_sitting_of_two(s, clock)

    with owner_engine.begin() as conn:
        conn.execute(text("ALTER TABLE audit_events DISABLE TRIGGER USER"))
        conn.execute(
            text(
                "UPDATE audit_events SET data = jsonb_set(data, '{relied_on_envelope_id}', "
                "  to_jsonb(CAST('11111111-2222-4333-8444-555555555555' AS text))) "
                "WHERE stream_id = :env AND event_type = 'consent.accepted'"
            ),
            {"env": second["id"]},
        )
        conn.execute(text("ALTER TABLE audit_events ENABLE TRIGGER USER"))

    failed = failed_checks(s.ehr.verification(str(second["id"])))
    assert "consent_relied_on_matches_trail" in failed
    assert "not in the database" in failed["consent_relied_on_matches_trail"]
