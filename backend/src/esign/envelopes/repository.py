"""Row access for the envelopes module.

Plain SQL against the schema in ``migrations/0001_schema.sql``. No ORM models: the schema is the
cross-module contract and belongs to the architecture, so this module reads and writes it as it
is rather than mirroring it in classes that could drift.

Every function takes a ``Session`` inside a transaction the caller owns, and none of them commit.
``lock_envelope`` is the serialisation point for the whole module: every state change goes through
it first, so two requests against one envelope queue up instead of interleaving.

On SQL construction: every value is a bound parameter, always. The only text ever interpolated
into a statement is a column list held in a module constant, or a column name chosen from a
literal tuple a few lines above -- never anything that came in with a request. The ``# noqa: S608``
markers below each sit on one of those, and nowhere else.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from esign.contracts import BlobKind, Capacity, EnvelopeStatus, SignerStatus

__all__ = [
    "EnvelopeRow",
    "SessionAttestation",
    "SignerRow",
    "TemplateVersionRow",
    "complete_seal_job",
    "due_envelope_ids",
    "enqueue_seal_job",
    "fail_seal_job",
    "find_template_version",
    "insert_capture",
    "insert_envelope",
    "insert_revision",
    "insert_signer",
    "latest_revision_no",
    "load_envelope",
    "load_signer",
    "load_signers",
    "load_template_version",
    "lock_envelope",
    "next_revision_no",
    "revoke_envelope_sessions",
    "revoke_other_sessions",
    "seal_job_attempts",
    "session_attestation",
    "set_session_presented",
    "superseded_by",
    "update_envelope",
    "update_signer",
]


# --------------------------------------------------------------------------- rows


@dataclass(frozen=True)
class EnvelopeRow:
    id: UUID
    host_id: UUID
    template_version_id: UUID
    document_type: str
    patient_ref: str
    host_document_ref: str | None
    signing_order: str
    status: EnvelopeStatus
    presented_sha256: bytes | None
    current_revision_sha256: bytes | None
    sealed_sha256: bytes | None
    supersedes_envelope_id: UUID | None
    expires_at: datetime
    created_at: datetime
    completed_at: datetime | None
    sealed_at: datetime | None


@dataclass(frozen=True)
class SignerRow:
    id: UUID
    envelope_id: UUID
    role_key: str
    host_user_id: str
    display_name: str
    capacity: Capacity
    on_behalf_of: str | None
    order_index: int
    requires_reauth: bool
    status: SignerStatus
    consent_text_id: UUID | None
    viewed_at: datetime | None
    consented_at: datetime | None
    signed_at: datetime | None
    declined_at: datetime | None
    decline_reason_code: str | None
    #: The revision this signer last confirmed they had read every page of (``0501``).
    viewed_sha256: bytes | None = None


@dataclass(frozen=True)
class TemplateVersionRow:
    id: UUID
    template_id: UUID
    host_id: UUID
    template_key: str
    template_name: str
    document_type: str
    version: int
    status: str
    pdf_sha256: bytes
    fields: Any
    prefill_fields: Any
    signer_roles: Any


# --------------------------------------------------------------------------- coercion


def _uuid(value: Any) -> UUID:
    return value if isinstance(value, UUID) else UUID(str(value))


def _opt_uuid(value: Any) -> UUID | None:
    return None if value is None else _uuid(value)


def _bytes(value: Any) -> bytes:
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, bytes):
        return value
    raise TypeError(f"expected bytes from the database, got {type(value).__name__}")


def _opt_bytes(value: Any) -> bytes | None:
    return None if value is None else _bytes(value)


def _utc(value: Any) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"expected a datetime from the database, got {type(value).__name__}")
    if value.tzinfo is None:
        raise ValueError("the database returned a naive datetime; every column is timestamptz")
    return value.astimezone(UTC)


def _opt_utc(value: Any) -> datetime | None:
    return None if value is None else _utc(value)


def _envelope(row: Any) -> EnvelopeRow:
    return EnvelopeRow(
        id=_uuid(row.id),
        host_id=_uuid(row.host_id),
        template_version_id=_uuid(row.template_version_id),
        document_type=str(row.document_type),
        patient_ref=str(row.patient_ref),
        host_document_ref=None if row.host_document_ref is None else str(row.host_document_ref),
        signing_order=str(row.signing_order),
        status=str(row.status),  # type: ignore[arg-type]  # CHECK-constrained in the schema
        presented_sha256=_opt_bytes(row.presented_sha256),
        current_revision_sha256=_opt_bytes(row.current_revision_sha256),
        sealed_sha256=_opt_bytes(row.sealed_sha256),
        supersedes_envelope_id=_opt_uuid(row.supersedes_envelope_id),
        expires_at=_utc(row.expires_at),
        created_at=_utc(row.created_at),
        completed_at=_opt_utc(row.completed_at),
        sealed_at=_opt_utc(row.sealed_at),
    )


def _signer(row: Any) -> SignerRow:
    return SignerRow(
        id=_uuid(row.id),
        envelope_id=_uuid(row.envelope_id),
        role_key=str(row.role_key),
        host_user_id=str(row.host_user_id),
        display_name=str(row.display_name),
        capacity=str(row.capacity),  # type: ignore[arg-type]  # CHECK-constrained in the schema
        on_behalf_of=None if row.on_behalf_of is None else str(row.on_behalf_of),
        order_index=int(row.order_index),
        requires_reauth=bool(row.requires_reauth),
        status=str(row.status),  # type: ignore[arg-type]  # CHECK-constrained in the schema
        consent_text_id=_opt_uuid(row.consent_text_id),
        viewed_at=_opt_utc(row.viewed_at),
        consented_at=_opt_utc(row.consented_at),
        signed_at=_opt_utc(row.signed_at),
        declined_at=_opt_utc(row.declined_at),
        decline_reason_code=None if row.decline_reason_code is None else str(row.decline_reason_code),
        viewed_sha256=_opt_bytes(row.viewed_sha256),
    )


_ENVELOPE_COLUMNS = (
    "id, host_id, template_version_id, document_type, patient_ref, host_document_ref, signing_order, "
    "status, presented_sha256, current_revision_sha256, sealed_sha256, supersedes_envelope_id, "
    "expires_at, created_at, completed_at, sealed_at"
)

_SIGNER_COLUMNS = (
    "id, envelope_id, role_key, host_user_id, display_name, capacity, on_behalf_of, order_index, "
    "requires_reauth, status, consent_text_id, viewed_at, consented_at, signed_at, declined_at, "
    "decline_reason_code, viewed_sha256"
)


# --------------------------------------------------------------------------- envelopes


def lock_envelope(db: Session, envelope_id: UUID) -> EnvelopeRow | None:
    """``SELECT ... FOR UPDATE`` on the envelope row: the module's one serialisation point."""
    row = db.execute(
        text(f"SELECT {_ENVELOPE_COLUMNS} FROM envelopes WHERE id = :id FOR UPDATE"),  # noqa: S608 - see the note on SQL construction above
        {"id": envelope_id},
    ).one_or_none()
    return None if row is None else _envelope(row)


def load_envelope(db: Session, envelope_id: UUID) -> EnvelopeRow | None:
    row = db.execute(
        text(f"SELECT {_ENVELOPE_COLUMNS} FROM envelopes WHERE id = :id"),  # noqa: S608 - see the note on SQL construction above
        {"id": envelope_id},
    ).one_or_none()
    return None if row is None else _envelope(row)


def insert_envelope(
    db: Session,
    *,
    envelope_id: UUID,
    host_id: UUID,
    template_version_id: UUID,
    document_type: str,
    patient_ref: str,
    host_document_ref: str | None,
    signing_order: str,
    presented_sha256: bytes,
    supersedes_envelope_id: UUID | None,
    expires_at: datetime,
    created_at: datetime,
) -> None:
    db.execute(
        text(
            "INSERT INTO envelopes (id, host_id, template_version_id, document_type, patient_ref, "
            "  host_document_ref, signing_order, status, presented_sha256, current_revision_sha256, "
            "  supersedes_envelope_id, expires_at, created_at) "
            "VALUES (:id, :host_id, :tv, :document_type, :patient_ref, :host_document_ref, :signing_order, "
            "  'created', :sha, :sha, :supersedes, :expires_at, :created_at)"
        ),
        {
            "id": envelope_id,
            "host_id": host_id,
            "tv": template_version_id,
            "document_type": document_type,
            "patient_ref": patient_ref,
            "host_document_ref": host_document_ref,
            "signing_order": signing_order,
            "sha": presented_sha256,
            "supersedes": supersedes_envelope_id,
            "expires_at": expires_at,
            "created_at": created_at,
        },
    )


def update_envelope(
    db: Session,
    envelope_id: UUID,
    *,
    status: EnvelopeStatus | None = None,
    current_revision_sha256: bytes | None = None,
    sealed_sha256: bytes | None = None,
    completed_at: datetime | None = None,
    sealed_at: datetime | None = None,
    voided_at: datetime | None = None,
    void_reason_code: str | None = None,
) -> None:
    """Write back only the columns this transition actually moves."""
    assignments: list[str] = []
    params: dict[str, Any] = {"id": envelope_id}
    for column, value in (
        ("status", status),
        ("current_revision_sha256", current_revision_sha256),
        ("sealed_sha256", sealed_sha256),
        ("completed_at", completed_at),
        ("sealed_at", sealed_at),
        ("voided_at", voided_at),
        ("void_reason_code", void_reason_code),
    ):
        if value is not None:
            assignments.append(f"{column} = :{column}")
            params[column] = value
    if not assignments:
        return
    db.execute(text(f"UPDATE envelopes SET {', '.join(assignments)} WHERE id = :id"), params)  # noqa: S608 - see the note on SQL construction above


def superseded_by(db: Session, envelope_id: UUID) -> UUID | None:
    row = db.execute(
        text("SELECT id FROM envelopes WHERE supersedes_envelope_id = :id ORDER BY created_at LIMIT 1"),
        {"id": envelope_id},
    ).one_or_none()
    return None if row is None else _uuid(row.id)


def due_envelope_ids(db: Session, now: datetime, *, limit: int = 500) -> list[UUID]:
    """Live envelopes whose expiry has passed, locked for this transaction.

    ``SKIP LOCKED`` so two workers sweeping at once share the work instead of blocking, and so a
    signature in flight (which holds the envelope's row lock) is never expired out from under the
    person signing it.
    """
    rows = db.execute(
        text(
            "SELECT id FROM envelopes "
            "WHERE status IN ('created', 'in_progress') AND expires_at <= :now "
            "ORDER BY expires_at LIMIT :limit FOR UPDATE SKIP LOCKED"
        ),
        {"now": now, "limit": limit},
    ).all()
    return [_uuid(row.id) for row in rows]


# --------------------------------------------------------------------------- signers


def load_signers(db: Session, envelope_id: UUID) -> tuple[SignerRow, ...]:
    rows = db.execute(
        text(f"SELECT {_SIGNER_COLUMNS} FROM signers WHERE envelope_id = :id ORDER BY order_index, role_key"),  # noqa: S608 - see the note on SQL construction above
        {"id": envelope_id},
    ).all()
    return tuple(_signer(row) for row in rows)


def load_signer(db: Session, signer_id: UUID) -> SignerRow | None:
    row = db.execute(
        text(f"SELECT {_SIGNER_COLUMNS} FROM signers WHERE id = :id"),  # noqa: S608 - see the note on SQL construction above
        {"id": signer_id},
    ).one_or_none()
    return None if row is None else _signer(row)


def insert_signer(
    db: Session,
    *,
    signer_id: UUID,
    envelope_id: UUID,
    role_key: str,
    host_user_id: str,
    display_name: str,
    capacity: str,
    on_behalf_of: str | None,
    order_index: int,
    requires_reauth: bool,
) -> None:
    db.execute(
        text(
            "INSERT INTO signers (id, envelope_id, role_key, host_user_id, display_name, capacity, "
            "  on_behalf_of, order_index, requires_reauth, status) "
            "VALUES (:id, :env, :role_key, :host_user_id, :display_name, :capacity, :on_behalf_of, "
            "  :order_index, :requires_reauth, 'pending')"
        ),
        {
            "id": signer_id,
            "env": envelope_id,
            "role_key": role_key,
            "host_user_id": host_user_id,
            "display_name": display_name,
            "capacity": capacity,
            "on_behalf_of": on_behalf_of,
            "order_index": order_index,
            "requires_reauth": requires_reauth,
        },
    )


def update_signer(
    db: Session,
    signer_id: UUID,
    *,
    status: SignerStatus | None = None,
    consent_text_id: UUID | None = None,
    viewed_at: datetime | None = None,
    consented_at: datetime | None = None,
    signed_at: datetime | None = None,
    declined_at: datetime | None = None,
    decline_reason_code: str | None = None,
    viewed_sha256: bytes | None = None,
    only_if_unset: frozenset[str] = frozenset(),
) -> None:
    """Write back a signer transition.

    ``only_if_unset`` names timestamp columns that must keep their first value: a second
    ``viewed`` must not rewrite when the signer first saw the document. ``viewed_sha256`` is the
    exception among the view columns: it names the bytes *most recently* confirmed, because that is
    what ``sign`` checks the session's presented hash against.
    """
    assignments: list[str] = []
    params: dict[str, Any] = {"id": signer_id}
    for column, value in (
        ("status", status),
        ("consent_text_id", consent_text_id),
        ("viewed_at", viewed_at),
        ("consented_at", consented_at),
        ("signed_at", signed_at),
        ("declined_at", declined_at),
        ("decline_reason_code", decline_reason_code),
        ("viewed_sha256", viewed_sha256),
    ):
        if value is None:
            continue
        params[column] = value
        if column in only_if_unset:
            assignments.append(f"{column} = COALESCE({column}, :{column})")
        else:
            assignments.append(f"{column} = :{column}")
    if not assignments:
        return
    db.execute(text(f"UPDATE signers SET {', '.join(assignments)} WHERE id = :id"), params)  # noqa: S608 - see the note on SQL construction above


# --------------------------------------------------------------------------- template versions


def load_template_version(db: Session, template_version_id: UUID) -> TemplateVersionRow | None:
    row = db.execute(
        text(
            "SELECT v.id, v.template_id, t.host_id, t.key AS template_key, t.name AS template_name, t.document_type, "
            "       v.version, v.status, v.pdf_sha256, v.fields, v.prefill_fields, v.signer_roles "
            "FROM template_versions v JOIN templates t ON t.id = v.template_id WHERE v.id = :id"
        ),
        {"id": template_version_id},
    ).one_or_none()
    return None if row is None else _template_version(row)


def find_template_version(db: Session, *, host_id: UUID, key: str, version: int | None) -> TemplateVersionRow | None:
    """A host's template version. ``version=None`` means the highest published one.

    Host scoped in the query itself, so another host's template is simply not there.
    """
    if version is None:
        sql = (
            "SELECT v.id, v.template_id, t.host_id, t.key AS template_key, t.name AS template_name, t.document_type, "
            "       v.version, v.status, v.pdf_sha256, v.fields, v.prefill_fields, v.signer_roles "
            "FROM template_versions v JOIN templates t ON t.id = v.template_id "
            "WHERE t.host_id = :host_id AND t.key = :key AND v.status = 'published' "
            "ORDER BY v.version DESC LIMIT 1"
        )
        params: dict[str, Any] = {"host_id": host_id, "key": key}
    else:
        sql = (
            "SELECT v.id, v.template_id, t.host_id, t.key AS template_key, t.name AS template_name, t.document_type, "
            "       v.version, v.status, v.pdf_sha256, v.fields, v.prefill_fields, v.signer_roles "
            "FROM template_versions v JOIN templates t ON t.id = v.template_id "
            "WHERE t.host_id = :host_id AND t.key = :key AND v.version = :version"
        )
        params = {"host_id": host_id, "key": key, "version": version}
    row = db.execute(text(sql), params).one_or_none()
    return None if row is None else _template_version(row)


def _template_version(row: Any) -> TemplateVersionRow:
    return TemplateVersionRow(
        id=_uuid(row.id),
        template_id=_uuid(row.template_id),
        host_id=_uuid(row.host_id),
        template_key=str(row.template_key),
        template_name=str(row.template_name),
        document_type=str(row.document_type),
        version=int(row.version),
        status=str(row.status),
        pdf_sha256=_bytes(row.pdf_sha256),
        fields=row.fields,
        prefill_fields=row.prefill_fields,
        signer_roles=row.signer_roles,
    )


# --------------------------------------------------------------------------- revisions


def latest_revision_no(db: Session, envelope_id: UUID) -> int:
    """The highest revision number so far, or 0 before the document has been prepared."""
    row = db.execute(
        text("SELECT COALESCE(MAX(revision_no), 0) AS high FROM document_revisions WHERE envelope_id = :id"),
        {"id": envelope_id},
    ).one()
    return int(row.high)


def next_revision_no(db: Session, envelope_id: UUID) -> int:
    return latest_revision_no(db, envelope_id) + 1


def insert_revision(
    db: Session,
    *,
    revision_id: UUID,
    envelope_id: UUID,
    revision_no: int,
    kind: str,
    sha256: bytes,
    signer_id: UUID | None,
    created_at: datetime,
) -> None:
    db.execute(
        text(
            "INSERT INTO document_revisions (id, envelope_id, revision_no, kind, sha256, signer_id, created_at) "
            "VALUES (:id, :env, :no, :kind, :sha, :signer, :at)"
        ),
        {
            "id": revision_id,
            "env": envelope_id,
            "no": revision_no,
            "kind": kind,
            "sha": sha256,
            "signer": signer_id,
            "at": created_at,
        },
    )


def revision_sha(db: Session, envelope_id: UUID, kind: str) -> bytes | None:
    row = db.execute(
        text(
            "SELECT sha256 FROM document_revisions WHERE envelope_id = :id AND kind = :kind "
            "ORDER BY revision_no DESC LIMIT 1"
        ),
        {"id": envelope_id, "kind": kind},
    ).one_or_none()
    return None if row is None else _bytes(row.sha256)


# --------------------------------------------------------------------------- sessions and captures


def set_session_presented(db: Session, session_id: UUID, sha256: bytes) -> None:
    db.execute(
        text("UPDATE signing_sessions SET presented_sha256 = :sha WHERE id = :id"),
        {"id": session_id, "sha": sha256},
    )


def session_presented_sha(db: Session, session_id: UUID) -> bytes | None:
    row = db.execute(
        text("SELECT presented_sha256 FROM signing_sessions WHERE id = :id"),
        {"id": session_id},
    ).one_or_none()
    return None if row is None else _opt_bytes(row.presented_sha256)


def revoke_other_sessions(db: Session, *, signer_id: UUID, keep_session_id: UUID, at: datetime) -> int:
    """Revoke every live session for this signer except the one that just signed.

    The surviving session is what lets the person download their copy from the screen they are
    already on; ``EnvelopeService.may_download_copy`` is what limits it to that.
    """
    revoked = db.execute(
        text(
            "UPDATE signing_sessions SET revoked_at = :at "
            "WHERE signer_id = :signer AND id <> :keep AND revoked_at IS NULL RETURNING id"
        ),
        {"signer": signer_id, "keep": keep_session_id, "at": at},
    ).all()
    return len(revoked)


def revoke_envelope_sessions(db: Session, envelope_id: UUID, at: datetime) -> int:
    """Revoke every live session on the envelope. Used when it ends without completing."""
    revoked = db.execute(
        text(
            "UPDATE signing_sessions SET revoked_at = :at "
            "WHERE revoked_at IS NULL AND signer_id IN (SELECT id FROM signers WHERE envelope_id = :env) "
            "RETURNING id"
        ),
        {"env": envelope_id, "at": at},
    ).all()
    return len(revoked)


@dataclass(frozen=True)
class SessionAttestation:
    """What the *host* attested when it opened the signing session, server to server.

    Deliberately not ``ip``/``user_agent``: those columns are written from the host's own request,
    so they describe the EHR backend, not the person signing. The certificate takes the signer's
    address and client from the ``signer.signed`` event instead. These three are the host's
    attestation, and the append-only ``session.created`` event is their primary record; this row is
    the fallback for a trail written before that event existed.
    """

    session_id: UUID
    auth_method: str
    kiosk_staff_user_id: str | None
    kiosk_identity_check: str | None


def session_attestation(db: Session, *, signer_id: UUID, at_or_before: datetime | None) -> SessionAttestation | None:
    """The session this signer used, as the host described it."""
    clause = "AND created_at <= :at " if at_or_before is not None else ""
    row = db.execute(
        text(
            "SELECT id, auth_method, kiosk_staff_user_id, kiosk_identity_check "  # noqa: S608 - see the note on SQL construction above
            f"FROM signing_sessions WHERE signer_id = :signer {clause}"
            "ORDER BY created_at DESC LIMIT 1"
        ),
        {"signer": signer_id, "at": at_or_before},
    ).one_or_none()
    if row is None:
        return None
    return SessionAttestation(
        session_id=_uuid(row.id),
        auth_method=str(row.auth_method),
        kiosk_staff_user_id=None if row.kiosk_staff_user_id is None else str(row.kiosk_staff_user_id),
        kiosk_identity_check=None if row.kiosk_identity_check is None else str(row.kiosk_identity_check),
    )


def insert_capture(
    db: Session,
    *,
    capture_id: UUID,
    signer_id: UUID,
    field_id: str,
    kind: str,
    image_sha256: bytes | None,
    typed_text: str | None,
    created_at: datetime,
) -> None:
    db.execute(
        text(
            "INSERT INTO signature_captures (id, signer_id, field_id, kind, image_sha256, typed_text, created_at) "
            "VALUES (:id, :signer, :field_id, :kind, :image, :typed, :at)"
        ),
        {
            "id": capture_id,
            "signer": signer_id,
            "field_id": field_id,
            "kind": kind,
            "image": image_sha256,
            "typed": typed_text,
            "at": created_at,
        },
    )


def capture_count(db: Session, signer_id: UUID) -> int:
    row = db.execute(
        text("SELECT count(*) AS n FROM signature_captures WHERE signer_id = :id"),
        {"id": signer_id},
    ).one()
    return int(row.n)


# --------------------------------------------------------------------------- seal jobs


def enqueue_seal_job(db: Session, envelope_id: UUID, at: datetime) -> None:
    db.execute(
        text(
            "INSERT INTO seal_jobs (envelope_id, attempts, next_attempt_at) VALUES (:id, 0, :at) "
            "ON CONFLICT (envelope_id) DO NOTHING"
        ),
        {"id": envelope_id, "at": at},
    )


def seal_job_attempts(db: Session, envelope_id: UUID) -> int:
    row = db.execute(
        text("SELECT attempts FROM seal_jobs WHERE envelope_id = :id"),
        {"id": envelope_id},
    ).one_or_none()
    return 0 if row is None else int(row.attempts)


def fail_seal_job(db: Session, envelope_id: UUID, *, error_code: str, next_attempt_at: datetime) -> int:
    """Count the failure and push the next attempt out. Returns the new attempt count."""
    row = db.execute(
        text(
            "INSERT INTO seal_jobs (envelope_id, attempts, next_attempt_at, last_error_code) "
            "VALUES (:id, 1, :next, :code) "
            "ON CONFLICT (envelope_id) DO UPDATE SET attempts = seal_jobs.attempts + 1, "
            "  next_attempt_at = :next, last_error_code = :code, locked_at = NULL "
            "RETURNING attempts"
        ),
        {"id": envelope_id, "next": next_attempt_at, "code": error_code},
    ).one()
    return int(row.attempts)


def complete_seal_job(db: Session, envelope_id: UUID, at: datetime) -> None:
    db.execute(
        text(
            "INSERT INTO seal_jobs (envelope_id, attempts, next_attempt_at, completed_at) "
            "VALUES (:id, 1, :at, :at) "
            "ON CONFLICT (envelope_id) DO UPDATE SET completed_at = :at, locked_at = NULL"
        ),
        {"id": envelope_id, "at": at},
    )


def blob_kind_of(db: Session, sha256: bytes) -> BlobKind | None:
    row = db.execute(text("SELECT kind FROM blobs WHERE sha256 = :sha"), {"sha": sha256}).one_or_none()
    return None if row is None else str(row.kind)  # type: ignore[return-value]  # CHECK-constrained
