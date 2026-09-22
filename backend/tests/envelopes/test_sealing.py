"""Sealing: the certificate, validating the sealer's own output, and failing closed."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from datetime import timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from esign.config import Settings
from esign.contracts import (
    AuthContext,
    Capture,
    Conflict,
    EnvelopeView,
    Host,
    IntegrityFailure,
    RequestContext,
    SealUnavailable,
    SealValidation,
)
from esign.ids import new_id
from tests.envelopes.conftest import CTX, HIPAA_PAIR, PATIENT_CONSENT, PROCEDURE_CONSENT, Bench

PNG = b"\x89PNG\r\n\x1a\n" + b"scribbled signature bytes"


def sig(field_id: str = "patient_sig") -> Capture:
    return Capture(field_id=field_id, kind="drawn", image_png=PNG)


def completed(bench: Bench, db: Session) -> tuple[Host, EnvelopeView]:
    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    bench.consent(db)
    view = bench.create(db, host, PATIENT_CONSENT)
    session = bench.session(db, bench.signer_id(view, "patient"))
    bench.ready_to_sign(db, session)
    bench.service.sign(db, session, [sig()], CTX)
    return host, view


# --------------------------------------------------------------------------- the happy path


def test_sealing_stores_the_final_documents_and_marks_the_envelope(bench: Bench, db: Session) -> None:
    _host, view = completed(bench, db)

    result = bench.service.seal_pending(db, view.id)

    assert result.status == "sealed"
    assert result.sealed_sha256 is not None
    assert bench.revisions(db, view.id) == [
        (1, "presented"),
        (2, "signer_applied"),
        (3, "final_unsealed"),
        (4, "sealed"),
    ]
    assert bench.event_types(db, view.id)[-3:] == ["document.finalized", "document.sealed", "document.stored"]

    row = db.execute(
        text("SELECT sealed_sha256, sealed_at, status FROM envelopes WHERE id = :id"), {"id": view.id}
    ).one()
    assert bytes(row.sealed_sha256) == result.sealed_sha256
    assert row.sealed_at == bench.clock.now()


def test_the_sealed_blob_carries_the_retention_date(bench: Bench, db: Session, settings: Settings) -> None:
    _host, view = completed(bench, db)
    result = bench.service.seal_pending(db, view.id)

    assert result.sealed_sha256 is not None
    retain_until = bench.blobs.retain_until_for(result.sealed_sha256, db)
    assert retain_until is not None
    assert abs((retain_until - settings.retain_until("patient_consent", bench.clock.now())).total_seconds()) < 1
    kinds = {kind for kind, _ in bench.blobs.puts}
    assert {"presented_pdf", "signature_image", "revision_pdf", "final_unsealed_pdf", "sealed_pdf"} <= kinds


def test_the_seal_job_is_marked_complete(bench: Bench, db: Session) -> None:
    _host, view = completed(bench, db)
    bench.service.seal_pending(db, view.id)

    row = db.execute(
        text("SELECT completed_at, last_error_code FROM seal_jobs WHERE envelope_id = :id"), {"id": view.id}
    ).one()
    assert row.completed_at == bench.clock.now()
    assert row.last_error_code is None


def test_the_sealed_bytes_are_what_the_sealer_returned(bench: Bench, db: Session) -> None:
    _host, view = completed(bench, db)
    result = bench.service.seal_pending(db, view.id)

    assert result.sealed_sha256 is not None
    sealed = bench.blobs.get(db, result.sealed_sha256)
    assert sealed.endswith(b"\n% sealed")
    assert b"%PDF-certificate" in sealed  # the certificate is inside the sealed bytes


def test_sealing_twice_is_a_conflict(bench: Bench, db: Session) -> None:
    _host, view = completed(bench, db)
    bench.service.seal_pending(db, view.id)

    with pytest.raises(Conflict) as seen:
        bench.service.seal_pending(db, view.id)
    assert seen.value.code == "already_sealed"
    assert bench.event_types(db, view.id).count("document.sealed") == 1


def test_sealing_before_everyone_has_signed_is_a_conflict(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, HIPAA_PAIR)
    bench.consent(db)
    view = bench.create(db, host, HIPAA_PAIR)
    patient = bench.session(db, bench.signer_id(view, "patient"))
    bench.ready_to_sign(db, patient)
    bench.service.sign(db, patient, [sig()], CTX)

    with pytest.raises(Conflict) as seen:
        bench.service.seal_pending(db, view.id)
    assert seen.value.code == "not_pending_seal"
    assert bench.sealer.seal_calls == 0


# --------------------------------------------------------------------------- the certificate


def test_the_certificate_summary_is_built_from_the_record(bench: Bench, db: Session) -> None:
    host = bench.host(db)
    bench.template(db, host, PROCEDURE_CONSENT)
    bench.consent(db)
    view = bench.create(db, host, PROCEDURE_CONSENT, signing_order="sequential")

    for role_key, captures in (
        ("patient", [sig(), Capture("patient_ack", checked=True)]),
        ("witness", [sig("witness_sig")]),
    ):
        session = bench.session(db, bench.signer_id(view, role_key))
        bench.ready_to_sign(db, session)
        bench.service.sign(db, session, captures, CTX)
    clinician = bench.session(db, bench.signer_id(view, "clinician"))
    bench.ready_to_sign(db, clinician)
    bench.reauth(db, clinician, "sso")
    bench.service.sign(db, clinician, [sig("clinician_sig")], CTX)

    bench.service.seal_pending(db, view.id)
    summary = bench.documents.last_summary

    assert summary.envelope_id == view.id
    assert summary.document_type == "procedure_consent"
    assert summary.template_key == "procedure_consent"
    assert summary.template_version == 1
    assert summary.presented_sha256 == view.presented_sha256
    assert [s.role_label for s in summary.signers] == ["Patient", "Witness", "Clinician"]
    assert [s.capacity for s in summary.signers] == ["self", "witness", "clinician"]
    assert [s.reauth_method for s in summary.signers] == [None, None, "sso"]
    assert all(s.auth_method == "password" for s in summary.signers)
    assert all(s.ip == "198.51.100.7" for s in summary.signers)
    assert all(s.user_agent == "EsignTest/1.0" for s in summary.signers)
    assert all(s.consent_version == "2026-09" for s in summary.signers)
    assert all(s.viewed_at <= s.consented_at <= s.signed_at for s in summary.signers)


def test_the_certificate_counts_the_audit_trail_as_it_stood(bench: Bench, db: Session) -> None:
    _host, view = completed(bench, db)
    before = bench.audit.list(db, "envelope", view.id)

    bench.service.seal_pending(db, view.id)
    summary = bench.documents.last_summary

    assert summary.audit_event_count == len(before)
    assert summary.audit_head_hash == before[-1].event_hash
    finalized = next(e for e in bench.audit.list(db, "envelope", view.id) if str(e.event_type) == "document.finalized")
    assert finalized.data["audit_event_count"] == len(before)
    assert finalized.data["audit_head_hash"] == before[-1].event_hash.hex()


def test_the_certificate_carries_the_kiosk_details(bench: Bench, db: Session) -> None:
    from esign.contracts import KioskContext

    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    bench.consent(db)
    view = bench.create(db, host, PATIENT_CONSENT)
    kiosk = KioskContext(staff_user_id="staff-42", identity_check="photo_id")
    session = bench.session(db, bench.signer_id(view, "patient"), method="staff_verified", kiosk=kiosk)
    bench.ready_to_sign(db, session)
    bench.service.sign(db, session, [sig()], CTX)

    bench.service.seal_pending(db, view.id)
    signer = bench.documents.last_summary.signers[0]

    # SPEC section 8: the signature is attributed to the patient, never to the staff member.
    assert signer.display_name == "Patient Person"
    assert signer.kiosk_staff_user_id == "staff-42"
    assert signer.kiosk_identity_check == "photo_id"


def test_sealing_refuses_when_the_record_is_incomplete(bench: Bench, db: Session) -> None:
    """A signer row missing its consent cannot be certified, whatever the status column says."""
    _host, view = completed(bench, db)
    db.execute(text("UPDATE signers SET consent_text_id = NULL WHERE envelope_id = :id"), {"id": view.id})

    with pytest.raises(IntegrityFailure) as seen:
        bench.service.seal_pending(db, view.id)
    assert seen.value.code == "incomplete_signer_evidence"
    assert bench.sealer.seal_calls == 0


def test_a_corrupted_final_revision_stops_the_seal(bench: Bench, db: Session) -> None:
    _host, view = completed(bench, db)
    sha = db.execute(text("SELECT current_revision_sha256 FROM envelopes WHERE id = :id"), {"id": view.id}).scalar_one()
    bench.blobs.corrupt(bytes(sha))

    with pytest.raises(IntegrityFailure):
        bench.service.seal_pending(db, view.id)
    assert bench.sealer.seal_calls == 0


# --------------------------------------------------------------------------- validating our own output


def test_a_seal_that_does_not_validate_is_refused(bench: Bench, db: Session) -> None:
    """SPEC section 3: never fail open. The sealer's own word is not enough."""
    _host, view = completed(bench, db)
    bench.sealer.bad_validation = True

    with pytest.raises(SealUnavailable) as seen:
        bench.service.seal_pending(db, view.id)
    assert seen.value.code == "seal_validation_failed"
    assert bench.sealer.validate_calls == 1


def test_the_envelope_stays_pending_when_validation_fails(bench: Bench, db: Session) -> None:
    _host, view = completed(bench, db)
    bench.sealer.bad_validation = True
    # ``seal_pending`` rolls its own transaction back before recording the failure, so the
    # setup this assertion reads has to be committed first.
    db.commit()

    with pytest.raises(SealUnavailable):
        bench.service.seal_pending(db, view.id)

    row = db.execute(text("SELECT status, sealed_sha256 FROM envelopes WHERE id = :id"), {"id": view.id}).one()
    assert row.status == "completed_pending_seal"
    assert row.sealed_sha256 is None


@pytest.mark.parametrize(
    ("intact", "covers", "trusted", "timestamp_valid"),
    [
        pytest.param(False, True, True, True, id="a flipped byte"),
        pytest.param(True, False, True, True, id="an appended update"),
        pytest.param(True, True, False, True, id="an untrusted chain"),
        pytest.param(True, True, True, False, id="a bad timestamp"),
    ],
)
def test_every_kind_of_validation_failure_refuses(
    bench: Bench, db: Session, intact: bool, covers: bool, trusted: bool, timestamp_valid: bool
) -> None:
    """SPEC section 5 lists four ways a seal can be wrong. None of them may end as 'sealed'."""
    _host, view = completed(bench, db)
    verdict = SealValidation(
        intact=intact,
        covers_whole_document=covers,
        trusted=trusted,
        timestamp_valid=timestamp_valid,
        profile="PAdES-B-T",
        signer_cert_sha256=b"\x00" * 32,
        signing_time=bench.clock.now(),
        problems=("something is wrong",),
    )
    bench.sealer.validate = lambda pdf: verdict  # type: ignore[method-assign]
    # ``seal_pending`` rolls its own transaction back before recording the failure, so the
    # setup this assertion reads has to be committed first.
    db.commit()

    with pytest.raises(SealUnavailable):
        bench.service.seal_pending(db, view.id)
    assert bench.status(db, view.id) == "completed_pending_seal"


# --------------------------------------------------------------------------- failure and retry


def test_a_seal_failure_is_recorded_and_the_job_backs_off(
    committing_bench: Bench,
    db_factory: Callable[[], AbstractContextManager[Session]],
) -> None:
    """SPEC 12: KMS down -> envelope stays pending, seal.failed recorded, retry succeeds later.

    The failure has to survive the rollback of the attempt that caused it, which is why this test
    uses really-committing sessions rather than the rolled-back ``db`` fixture.
    """
    bench = committing_bench
    with db_factory() as setup:
        _host, view = completed(bench, setup)
        setup.commit()

    bench.sealer.fail_times = 1
    with db_factory() as attempt, pytest.raises(SealUnavailable) as seen:
        bench.service.seal_pending(attempt, view.id)
    assert seen.value.code == "kms_unavailable"

    with db_factory() as check:
        status = check.execute(text("SELECT status FROM envelopes WHERE id = :id"), {"id": view.id}).scalar_one()
        assert status == "completed_pending_seal"

        job = check.execute(
            text(
                "SELECT attempts, next_attempt_at, last_error_code, completed_at FROM seal_jobs WHERE envelope_id = :id"
            ),
            {"id": view.id},
        ).one()
        assert job.attempts == 1
        assert job.last_error_code == "kms_unavailable"
        assert job.completed_at is None
        assert job.next_attempt_at == bench.clock.now() + timedelta(minutes=1)

        events = bench.audit.list(check, "envelope", view.id)
        failed = [e for e in events if str(e.event_type) == "seal.failed"]
        assert len(failed) == 1
        assert failed[0].data == {"error_code": "kms_unavailable", "attempt": 1, "retry_in_seconds": 60}
        # Nothing anywhere reports the document as complete.
        assert "document.sealed" not in [str(e.event_type) for e in events]
        assert [e.sequence for e in events] == list(range(1, len(events) + 1))

    # ...and the retry succeeds.
    with db_factory() as retry:
        result = bench.service.seal_pending(retry, view.id)
        retry.commit()
    assert result.status == "sealed"

    with db_factory() as after:
        job = after.execute(
            text("SELECT attempts, completed_at FROM seal_jobs WHERE envelope_id = :id"), {"id": view.id}
        ).one()
        assert job.completed_at is not None
        assert job.attempts == 1  # the failed attempt is still counted


def test_repeated_failures_walk_the_backoff_schedule(
    committing_bench: Bench,
    db_factory: Callable[[], AbstractContextManager[Session]],
) -> None:
    bench = committing_bench
    with db_factory() as setup:
        _host, view = completed(bench, setup)
        setup.commit()

    bench.sealer.fail_times = 3
    expected = [timedelta(minutes=1), timedelta(minutes=5), timedelta(minutes=15)]
    for attempt_no, delay in enumerate(expected, start=1):
        with db_factory() as attempt, pytest.raises(SealUnavailable):
            bench.service.seal_pending(attempt, view.id)
        with db_factory() as check:
            job = check.execute(
                text("SELECT attempts, next_attempt_at FROM seal_jobs WHERE envelope_id = :id"), {"id": view.id}
            ).one()
            assert job.attempts == attempt_no
            assert job.next_attempt_at == bench.clock.now() + delay

    with db_factory() as final:
        assert bench.service.seal_pending(final, view.id).status == "sealed"
        final.commit()


def test_a_failure_with_no_independent_session_still_refuses(bench: Bench, db: Session) -> None:
    """Without a way to record the failure the seal still fails closed; it is just louder."""
    _host, view = completed(bench, db)
    bench.sealer.fail_times = 1
    # ``seal_pending`` rolls its own transaction back before recording the failure, so the
    # setup this assertion reads has to be committed first.
    db.commit()

    with pytest.raises(SealUnavailable):
        bench.service.seal_pending(db, view.id)
    assert bench.status(db, view.id) == "completed_pending_seal"


# --------------------------------------------------------------------------- the trail is the source


def test_the_certificate_records_the_signers_address_not_the_hosts(bench: Bench, db: Session) -> None:
    """SPEC section 6: the certificate carries *the signer's* IP and user agent.

    The signing session's ``ip``/``user_agent`` columns are written from the host's server-to-server
    ``POST .../sessions`` call, so reading them here printed the EHR backend's address and its HTTP
    library on every patient's certificate. The signer's own provenance is on ``signer.signed``.
    """
    host_ctx = RequestContext(ip="10.0.0.1", user_agent="ehr-backend", auth_method="password")
    browser_ctx = RequestContext(ip="203.0.113.9", user_agent="Browser/1", auth_method="password")

    host = bench.host(db)
    bench.template(db, host, PATIENT_CONSENT)
    bench.consent(db)
    view = bench.create(db, host, PATIENT_CONSENT)
    signer_id = bench.signer_id(view, "patient")
    # The host opens the session from its own backend...
    auth = AuthContext(method="password", auth_time=bench.clock.now() - timedelta(minutes=1))
    _token, session = bench.identity.create_session(db, signer_id=signer_id, auth=auth, kiosk=None, ctx=host_ctx)
    # ...and the patient's browser does everything else.
    bench.service.present(db, session, browser_ctx)
    bench.service.record_viewed(db, session, 3, browser_ctx)
    bench.service.accept_consent(db, session, "2026-09", browser_ctx)
    bench.service.sign(db, session, [sig()], browser_ctx)

    bench.service.seal_pending(db, view.id)
    signer = bench.documents.last_summary.signers[0]
    assert signer.ip == "203.0.113.9"
    assert signer.user_agent == "Browser/1"
    # The host's attestation of *how* they authenticated still comes from the session.
    assert signer.auth_method == "password"


def test_the_certificate_shows_no_reauth_for_a_role_that_does_not_need_one(bench: Bench, db: Session) -> None:
    """An attestation can exist against a session without having been used for the signature."""
    _host, view = completed(bench, db)
    session_id = db.execute(
        text("SELECT id FROM signing_sessions WHERE signer_id = :s"),
        {"s": bench.signer_id(view, "patient")},
    ).scalar_one()
    db.execute(
        text(
            "INSERT INTO reauth_attestations (id, session_id, method, auth_time, attested_at) "
            "VALUES (:id, :session, 'password', :at, :at)"
        ),
        {"id": new_id(), "session": session_id, "at": bench.clock.now()},
    )

    bench.service.seal_pending(db, view.id)
    signer = bench.documents.last_summary.signers[0]
    assert signer.reauth_method is None


def test_a_row_rewritten_between_the_signature_and_the_seal_stops_the_seal(bench: Bench, db: Session) -> None:
    """SPEC section 3 step 7: the certificate is built from the audit trail.

    ``signers`` is fully UPDATE-able by the runtime role, and a delayed seal (a KMS or TSA outage
    backs off for hours) leaves a window in which a row could be rewritten and then printed into
    bytes that can never be re-sealed. The trail still says otherwise, and the disagreement is the
    finding.
    """
    _host, view = completed(bench, db)
    db.execute(
        text("UPDATE signers SET signed_at = signed_at - interval '3 hours' WHERE envelope_id = :i"),
        {"i": view.id},
    )
    db.commit()

    with pytest.raises(IntegrityFailure) as seen:
        bench.service.seal_pending(db, view.id)
    assert seen.value.code == "certificate_evidence_mismatch"
    assert bench.status(db, view.id) == "completed_pending_seal"
