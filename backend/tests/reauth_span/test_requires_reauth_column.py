"""``signers.requires_reauth`` is a mutable copy, and it is not allowed to be the whole gate.

The column is written once, at ``EnvelopeService.create``, from the template role plus the rule
that a clinician re-authenticates whatever the role says. After that it sits on ``signers``, which
the runtime role may UPDATE in full, and no audit event records it -- ``envelope.created`` carries
only a signer count, and ``session.created`` and ``signer.signed`` do not carry it at all.

So an UPDATE to it is two separate attacks, and these are both of them:

* before signing, it is the first line of ``_require_fresh_reauth``: flipped to false, a clinician
  signature is accepted with no ``POST /v1/sessions/{id}/reauth`` at all, and ``reauth_used:
  false`` in the trail makes the result look internally consistent;
* between signing and sealing -- ``completed_pending_seal`` is an expected, hours-long state
  whenever KMS, the TSA or storage is backing off -- it is what the certificate's
  re-authentication block is gated on: flipped then, the certificate prints "not required" and the
  attestation id, method, scope and time vanish from bytes that can never be corrected, while
  ``signer.signed`` still records all four.

Both are answered the same way: re-derive the requirement from the template version, which is
immutable (``tests/foundation/test_template_immutability.py``), rather than trust the copy.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import Engine, text

from esign.clock import FixedClock
from esign.config import Settings
from esign.contracts import IntegrityFailure
from esign.sealing import build_sealer
from tests.archives.test_void_and_supersede import SealOutage
from tests.e2e.conftest import Sessions, build_world
from tests.reauth_span.conftest import DEMO_SPAN_SECONDS, Queue
from tests.reauth_span.test_signing_queue import envelope_for, first_document


@pytest.fixture
def stalled(span_settings: Settings, clock: FixedClock, app_engine: Engine, db_factory: Sessions) -> Iterator[Queue]:
    """A queue whose seal never lands, so a completed envelope waits in ``completed_pending_seal``.

    Reached honestly, through a key service that is down: that is the state a real outage produces,
    and it is the window this test is about.
    """
    settings = span_settings.model_copy(update={"reauth_span_seconds": DEMO_SPAN_SECONDS})
    world = build_world(settings, clock, app_engine, db_factory, sealer=SealOutage(build_sealer(settings, clock)))
    with world.client:
        ehr = world.host()
        ehr.publish_template("procedure_consent")
        yield Queue(world=world, ehr=ehr)


def _flip(q: Queue, envelope_id: str) -> None:
    with q.world.sessions() as db:
        db.execute(
            text("UPDATE signers SET requires_reauth = false WHERE envelope_id = :id AND role_key = 'clinician'"),
            {"id": envelope_id},
        )
        flipped = db.execute(
            text("SELECT requires_reauth FROM signers WHERE envelope_id = :id AND role_key = 'clinician'"),
            {"id": envelope_id},
        ).scalar_one()
        db.commit()
    assert flipped is False


def test_a_flipped_column_does_not_let_a_clinician_sign_without_an_attestation(stalled: Queue) -> None:
    """Harm (a). The template role says the clinician re-authenticates and the template version is
    immutable, so the row saying otherwise is the row being wrong -- not the requirement going
    away. No ``POST /v1/sessions/{id}/reauth`` was ever made here."""
    q = stalled
    envelope = envelope_for(q.ehr)
    clinician = q.ehr.open_session(envelope, "clinician", method="password+mfa")
    payload = clinician.review_and_consent()
    _flip(q, str(envelope["id"]))

    refused = clinician.sign(payload, key=f"flipped-{envelope['id']}")

    assert refused.status_code == 403, refused.text
    assert refused.json()["error"]["code"] == "reauth_required"
    # And nothing was applied on the way to that refusal.
    assert [e["event_type"] for e in q.ehr.audit(str(envelope["id"]))].count("signer.signed") == 0


def test_a_flipped_column_does_not_refuse_the_attestation_that_would_answer_it(stalled: Queue) -> None:
    """And the gate's other side: ``POST /v1/sessions/{id}/reauth`` reads the same requirement.

    ``assert_reauth_allowed`` refuses an attestation that could not belong to a signature, and
    ``reauth_not_required`` is one of its refusals. Read off the column, a flip would answer the
    host "this role does not re-authenticate" for a signature that then demands one -- the
    clinician stuck with no way through, and the operator told the opposite of what the signing
    route would say. Both sides re-derive it from the immutable template version, so they agree.
    """
    q = stalled
    envelope = envelope_for(q.ehr)
    clinician = q.ehr.open_session(envelope, "clinician", method="password+mfa")
    clinician.review_and_consent()
    _flip(q, str(envelope["id"]))

    attested = q.ehr.reauth(clinician)

    assert attested.status_code == 200, attested.text
    assert "auth.reauthenticated" in q.ehr.audit_types(str(envelope["id"]))


def test_a_column_flipped_while_the_seal_waits_stops_the_seal(stalled: Queue) -> None:
    """Harm (b). The certificate is built at seal time from this row, so the disagreement has to
    stop the seal rather than be printed into bytes that can never be re-sealed."""
    q = stalled
    envelope = first_document(q)
    q.ehr.sign_everyone(envelope, ("patient", "witness"))
    assert q.ehr.envelope(str(envelope["id"]))["status"] == "completed_pending_seal"

    _flip(q, str(envelope["id"]))

    with q.world.rt.transaction() as db, pytest.raises(IntegrityFailure) as seen:
        q.world.rt.envelopes.seal_pending(db, UUID(str(envelope["id"])))
    assert seen.value.code == "certificate_evidence_mismatch"
    assert q.ehr.envelope(str(envelope["id"]))["status"] == "completed_pending_seal"


def test_a_column_flipped_after_the_fact_is_reported_by_verification(stalled: Queue) -> None:
    """And the same comparison runs afterwards, for a row changed once it was too late to refuse.

    The trail, the attestation row and the signature are all untouched -- only the mutable column
    moved -- so without this the report came back ``ok`` while the certificate's whole
    re-authentication block had been switched off.
    """
    q = stalled
    envelope = first_document(q)
    assert q.ehr.verification(str(envelope["id"]))["ok"] is True

    _flip(q, str(envelope["id"]))

    report = q.ehr.verification(str(envelope["id"]))
    assert report["ok"] is False, report
    failed: dict[str, Any] = {c["name"]: c["detail"] for c in report["checks"] if c["status"] == "failed"}
    assert "signer_rows_match_trail" in failed
    assert "requires_reauth" in failed["signer_rows_match_trail"]
    # Nothing else moved: the chain and every other row comparison still hold.
    assert "audit_chain" not in failed
    assert "reauth_attestations_match_trail" not in failed
