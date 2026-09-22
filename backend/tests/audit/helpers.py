"""Helpers for the audit tests: valid sample ``data`` for every event type, and a way to tamper.

The sample data matters more than it looks: a parametrised test appends every event type and then
verifies the chain, which is what proves that each declared shape survives the round trip through
``jsonb`` and re-hashes to the same digest.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from esign.contracts import EventType

#: A stable pretend digest, so a failing assertion is readable.
DIGEST_A = bytes.fromhex("3b1f8c2d4e5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e")
DIGEST_B = bytes.fromhex("9a8b7c6d5e4f30211203f4e5d6c7b8a9f0e1d2c3b4a59687786950413223145f")
DIGEST_C = bytes.fromhex("5d41402abc4b2a76b9719d911017c592a1b2c3d4e5f60718293a4b5c6d7e8f90")

UUID_A = UUID("7c3f1d2e-5a64-4b8f-9c10-2e4a6b8d0f31")
UUID_B = UUID("b4d5e6f7-8a9b-4c0d-9e1f-2a3b4c5d6e7f")
UUID_C = UUID("1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9")

WHEN = datetime(2026, 4, 1, 9, 0, 0, tzinfo=UTC)

_SAMPLES: dict[EventType, Callable[[], dict[str, Any]]] = {
    EventType.TEMPLATE_PUBLISHED: lambda: {
        "template_id": UUID_A,
        "template_key": "patient_consent",
        "template_version": 3,
        "template_version_id": UUID_B,
        "pdf_sha256": DIGEST_A,
        "page_count": 4,
        "field_count": 6,
        "signer_role_count": 2,
    },
    EventType.TEMPLATE_RETIRED: lambda: {
        "template_id": UUID_A,
        "template_key": "patient_consent",
        "template_version": 3,
        "template_version_id": UUID_B,
    },
    EventType.ENVELOPE_CREATED: lambda: {
        "host_id": UUID_A,
        "template_key": "procedure_consent",
        "template_version": 1,
        "template_version_id": UUID_B,
        "document_type": "procedure_consent",
        "signing_order": "sequential",
        "signer_count": 3,
        "expires_at": WHEN,
        "supersedes_envelope_id": None,
    },
    EventType.DOCUMENT_PREPARED: lambda: {
        "revision_no": 1,
        "revision_kind": "presented",
        "page_count": 3,
        "size_bytes": 20481,
        "prefill_field_count": 4,
    },
    EventType.SESSION_CREATED: lambda: {
        "signer_id": UUID_A,
        "role_key": "patient",
        "auth_method": "portal_otp",
        "auth_time": WHEN,
        "expires_at": WHEN,
        "kiosk": True,
        "kiosk_staff_user_id": "staff-9912",
        "kiosk_identity_check": "photo_id",
    },
    EventType.SESSION_REJECTED: lambda: {
        "signer_id": UUID_A,
        "role_key": "witness",
        "reason_code": "out_of_order",
    },
    EventType.DOCUMENT_PRESENTED: lambda: {
        "signer_id": UUID_A,
        "revision_no": 1,
        "page_count": 3,
        "size_bytes": 20481,
    },
    EventType.DOCUMENT_VIEWED: lambda: {"signer_id": UUID_A, "pages_viewed": 3, "page_count": 3},
    EventType.CONSENT_ACCEPTED: lambda: {
        "signer_id": UUID_A,
        "consent_text_id": UUID_B,
        "consent_version": "2026-09",
        "locale": "en-US",
        "body_sha256": DIGEST_A,
    },
    EventType.REAUTH_ATTESTED: lambda: {
        "signer_id": UUID_A,
        "method": "password+mfa",
        "auth_time": WHEN,
    },
    EventType.SIGNER_SIGNED: lambda: {
        "signer_id": UUID_A,
        "role_key": "patient",
        "capacity": "self",
        "consent_version": "2026-09",
        "reauth_used": False,
        "presented_sha256": DIGEST_A,
        "base_revision_sha256": DIGEST_A,
        "revision_no": 2,
        "revision_sha256": DIGEST_B,
        "capture_count": 2,
        "captures": [
            {"field_id": "patient_sig", "kind": "drawn"},
            {"field_id": "patient_initials", "kind": "typed"},
        ],
    },
    EventType.SIGNER_DECLINED: lambda: {
        "signer_id": UUID_A,
        "role_key": "patient",
        "reason_code": "prefers_paper",
    },
    EventType.ENVELOPE_DECLINED: lambda: {
        "signer_id": UUID_A,
        "reason_code": "prefers_paper",
    },
    EventType.ENVELOPE_COMPLETED: lambda: {
        "signer_count": 2,
        "revision_no": 3,
        "final_revision_sha256": DIGEST_B,
    },
    EventType.DOCUMENT_FINALIZED: lambda: {
        "certificate_sha256": DIGEST_A,
        "page_count": 5,
        "size_bytes": 30720,
        "audit_event_count": 12,
        "audit_head_hash": DIGEST_C,
    },
    EventType.SEAL_FAILED: lambda: {
        "error_code": "seal_unavailable",
        "attempt": 2,
        "retry_in_seconds": 300,
    },
    EventType.DOCUMENT_SEALED: lambda: {
        "seal_profile": "PAdES-B-LT",
        "key_backend": "aws_kms",
        "signer_cert_sha256": DIGEST_A,
        "timestamp_time": WHEN,
        "size_bytes": 31000,
    },
    EventType.DOCUMENT_STORED: lambda: {
        "blob_kind": "sealed_pdf",
        "size_bytes": 31000,
        "retain_until": WHEN,
    },
    EventType.DOCUMENT_DOWNLOADED: lambda: {
        "blob_kind": "sealed_pdf",
        "audience": "signer",
        "size_bytes": 31000,
    },
    EventType.ENVELOPE_VOIDED: lambda: {"reason_code": "created_in_error"},
    EventType.ENVELOPE_EXPIRED: dict,
    EventType.ENVELOPE_SUPERSEDED: lambda: {"superseded_by_envelope_id": UUID_C},
    EventType.VERIFICATION_PERFORMED: lambda: {
        "ok": True,
        "audit_ok": True,
        "audit_event_count": 12,
        "audit_head_hash": DIGEST_C,
        "seal_intact": True,
        "seal_trusted": True,
        "seal_covers_whole_document": True,
        "seal_timestamp_valid": True,
        "seal_profile": "PAdES-B-LT",
        "blobs_checked": 3,
        "problem_count": 0,
    },
    # Addendum 1
    EventType.ARCHIVE_CREATED: lambda: {
        "host_id": UUID_A,
        "document_type": "procedure_consent",
        "page_count": 6,
        "size_bytes": 1_204_811,
        "scan_sha256": DIGEST_A,
        "supersedes_envelope_id": None,
    },
    EventType.ARCHIVE_ATTESTED: lambda: {
        "staff_user_id": "staff-3310",
        "statement": "true_copy",
        "original_disposition": "retained",
        "paper_signer_count": 2,
        # The names and the paper date, jointly digested: they are PHI, and a mutable column the
        # trail cannot contradict is not evidence.
        "attested_detail_sha256": DIGEST_B,
    },
    EventType.SIGNATURE_ADOPTED: lambda: {
        "signer_id": UUID_A,
        "adopted_signature_id": UUID_B,
        "kind": "drawn",
        "image_sha256": DIGEST_B,
        "typed_text_sha256": None,
    },
    EventType.SIGNATURE_ADOPTION_REVOKED: lambda: {
        "host_id": UUID_A,
        "host_user_id": "user-90412",
        "adopted_signature_id": UUID_B,
        "reason": "replaced",
    },
    # Addendum 2
    EventType.DOCUMENT_SUPPLIED: lambda: {
        "upload_sha256": DIGEST_A,
        "presented_sha256": DIGEST_B,
        "page_count": 27,
        "field_source": "named_fields",
        "host_document_ref": "report-55120",
    },
}


def sample_data(event_type: EventType) -> dict[str, Any]:
    """Valid ``data`` for this event type. Raises for a type nobody has written a sample for."""
    return _SAMPLES[event_type]()


ALL_EVENT_TYPES = tuple(EventType)


@contextmanager
def triggers_disabled(owner_db: Session, table: str) -> Iterator[None]:
    """Turn the append-only triggers off for one table, as the owner role, for one block.

    The only way to write a tampering test: the whole point of the triggers is that this is
    otherwise impossible. It needs the owner role, and it is confined to the test suite -- no
    application code can reach it, and the app role could not run it if it tried.
    """
    owner_db.execute(text(f'ALTER TABLE "{table}" DISABLE TRIGGER USER'))
    try:
        yield
    finally:
        owner_db.execute(text(f'ALTER TABLE "{table}" ENABLE TRIGGER USER'))


def tamper(owner_db: Session, *, event_id: UUID, column: str, value: Any, cast_to: str | None = None) -> None:
    """Change one column of one stored audit event, triggers and all.

    ``cast_to`` is for the columns psycopg will not adapt on its own from a plain parameter:
    ``jsonb`` and ``inet``.
    """
    placeholder = ":value" if cast_to is None else f"CAST(:value AS {cast_to})"
    with triggers_disabled(owner_db, "audit_events"):
        owner_db.execute(
            text(f"UPDATE audit_events SET {column} = {placeholder} WHERE id = :id"),
            {"value": value, "id": event_id},
        )


def drop_event(owner_db: Session, event_id: UUID) -> None:
    """Remove one stored event, as an attacker with database access would."""
    with triggers_disabled(owner_db, "audit_events"):
        owner_db.execute(text("DELETE FROM audit_events WHERE id = :id"), {"id": event_id})
