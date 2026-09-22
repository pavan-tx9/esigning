"""Small helpers for the foundation tests. Modules should not import from here."""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from esign.ids import new_id

#: Postgres SQLSTATEs the foundation tests care about.
INSUFFICIENT_PRIVILEGE = "42501"
RAISE_EXCEPTION = "P0001"


def sqlstate(exc: DBAPIError) -> str | None:
    """The SQLSTATE of a wrapped driver error, or None if there is not one."""
    return getattr(exc.orig, "sqlstate", None)


def digest(label: str) -> bytes:
    """A deterministic 32-byte value that stands in for a real SHA-256."""
    return hashlib.sha256(label.encode()).digest()


def insert_blob(db: Session, label: str, *, kind: str = "template_pdf") -> bytes:
    sha = digest(label)
    db.execute(
        _sql(
            "INSERT INTO blobs (sha256, size_bytes, kind, storage_key) "
            "VALUES (:sha, :size, :kind, :key) ON CONFLICT DO NOTHING"
        ),
        {"sha": sha, "size": 1024, "kind": kind, "key": f"probe/{label}"},
    )
    return sha


def insert_host(db: Session, name: str = "probe host") -> UUID:
    host_id = new_id()
    db.execute(
        _sql("INSERT INTO hosts (id, name, api_key_hash) VALUES (:id, :name, :key)"),
        {"id": host_id, "name": name, "key": digest(f"key:{host_id}")},
    )
    return host_id


def insert_template_version(db: Session, *, status: str = "draft") -> UUID:
    """A host, a blob, a template and one version. Returns the template_version id."""
    host_id = insert_host(db)
    pdf_sha = insert_blob(db, f"template:{host_id}")
    template_id = new_id()
    db.execute(
        _sql("INSERT INTO templates (id, host_id, key, name, document_type) VALUES (:id, :host, :key, :name, :dt)"),
        {
            "id": template_id,
            "host": host_id,
            "key": f"probe_{template_id.hex[:8]}",
            "name": "Probe template",
            "dt": "patient_consent",
        },
    )
    version_id = new_id()
    db.execute(
        _sql(
            "INSERT INTO template_versions "
            "(id, template_id, version, status, pdf_sha256, fields, signer_roles) "
            "VALUES (:id, :tpl, 1, :status, :sha, '[]'::jsonb, '[]'::jsonb)"
        ),
        {"id": version_id, "tpl": template_id, "status": status, "sha": pdf_sha},
    )
    return version_id


def insert_envelope(db: Session) -> UUID:
    version_id = insert_template_version(db)
    envelope_id = new_id()
    db.execute(
        _sql(
            "INSERT INTO envelopes "
            "(id, host_id, template_version_id, document_type, patient_ref, signing_order, status, expires_at) "
            "SELECT :id, t.host_id, :tv, 'patient_consent', 'patient-ref', 'parallel', 'created', "
            "       now() + interval '14 days' "
            "FROM template_versions v JOIN templates t ON t.id = v.template_id WHERE v.id = :tv"
        ),
        {"id": envelope_id, "tv": version_id},
    )
    return envelope_id


def insert_signer(db: Session, envelope_id: UUID | None = None) -> UUID:
    envelope_id = envelope_id or insert_envelope(db)
    signer_id = new_id()
    db.execute(
        _sql(
            "INSERT INTO signers "
            "(id, envelope_id, role_key, host_user_id, display_name, capacity, order_index, "
            " requires_reauth, status) "
            "VALUES (:id, :env, 'patient', 'host-user', 'Probe Signer', 'self', 0, false, 'pending')"
        ),
        {"id": signer_id, "env": envelope_id},
    )
    return signer_id


def insert_session(db: Session, signer_id: UUID | None = None) -> UUID:
    signer_id = signer_id or insert_signer(db)
    session_id = new_id()
    db.execute(
        _sql(
            "INSERT INTO signing_sessions (id, signer_id, token_hash, auth_method, auth_time, expires_at) "
            "VALUES (:id, :signer, :token, 'password', now(), now() + interval '30 minutes')"
        ),
        {"id": session_id, "signer": signer_id, "token": digest(f"token:{session_id}")},
    )
    return session_id


def insert_document_revision(db: Session) -> UUID:
    envelope_id = insert_envelope(db)
    revision_id = new_id()
    sha = insert_blob(db, f"revision:{revision_id}", kind="presented_pdf")
    db.execute(
        _sql(
            "INSERT INTO document_revisions (id, envelope_id, revision_no, kind, sha256) "
            "VALUES (:id, :env, 1, 'presented', :sha)"
        ),
        {"id": revision_id, "env": envelope_id, "sha": sha},
    )
    return revision_id


def insert_consent_text(db: Session) -> UUID:
    consent_id = new_id()
    db.execute(
        _sql(
            "INSERT INTO consent_texts (id, version, locale, body, body_sha256, effective_at) "
            "VALUES (:id, :version, 'en-US', 'Probe disclosure body.', :sha, now())"
        ),
        {"id": consent_id, "version": f"probe-{consent_id.hex[:8]}", "sha": digest(str(consent_id))},
    )
    return consent_id


def insert_reauth_attestation(db: Session) -> UUID:
    session_id = insert_session(db)
    attestation_id = new_id()
    db.execute(
        _sql(
            "INSERT INTO reauth_attestations (id, session_id, method, auth_time) "
            "VALUES (:id, :session, 'password+mfa', now())"
        ),
        {"id": attestation_id, "session": session_id},
    )
    return attestation_id


def insert_adopted_signature(db: Session) -> UUID:
    """One live saved signature, with the host, envelope, signer and session it points at.

    ``typed`` rather than ``drawn`` so no blob is needed; the CHECKs tie each kind to its own
    column. ``host_user_id`` is unique per row because of the partial unique index that keeps at
    most one live signature per user per host.
    """
    signer_id = insert_signer(db)
    session_id = insert_session(db, signer_id)
    envelope_id = db.execute(_sql("SELECT envelope_id FROM signers WHERE id = :id"), {"id": signer_id}).scalar_one()
    host_id = db.execute(_sql("SELECT host_id FROM envelopes WHERE id = :id"), {"id": envelope_id}).scalar_one()
    adopted_id = new_id()
    db.execute(
        _sql(
            "INSERT INTO adopted_signatures "
            "(id, host_id, host_user_id, kind, typed_text, created_in_envelope_id, created_by_session_id) "
            "VALUES (:id, :host, :user, 'typed', 'Probe Signer', :env, :session)"
        ),
        {
            "id": adopted_id,
            "host": host_id,
            "user": f"probe-{adopted_id.hex[:8]}",
            "env": envelope_id,
            "session": session_id,
        },
    )
    return adopted_id


#: One row in each append-only table, so a trigger test has something to try to change.
#:
#: ``adopted_signatures`` (Addendum 1 B) is append-only with one exception -- a live row may be
#: revoked, once -- so it holds UPDATE where the others do not, but DELETE and TRUNCATE are shut
#: the same way and are proved here alongside them.
APPEND_ONLY_ROW_MAKERS: dict[str, Any] = {
    "blobs": lambda db: insert_blob(db, f"trigger-probe:{new_id()}"),
    "document_revisions": insert_document_revision,
    "consent_texts": insert_consent_text,
    "reauth_attestations": insert_reauth_attestation,
    "adopted_signatures": insert_adopted_signature,
}


def insert_audit_event(
    db: Session,
    *,
    stream_id: UUID | None = None,
    sequence: int = 1,
    occurred_at: datetime | None = None,
) -> UUID:
    """One audit row. The hashes are stand-ins: the evidence module owns the real chaining."""
    event_id = new_id()
    db.execute(
        _sql(
            "INSERT INTO audit_events "
            "(id, stream_type, stream_id, sequence, event_type, data, occurred_at, "
            " prev_event_hash, event_hash) "
            "VALUES (:id, 'envelope', :stream, :seq, 'envelope.created', '{}'::jsonb, "
            "        COALESCE(:at, now()), :prev, :hash)"
        ),
        {
            "id": event_id,
            "stream": stream_id or new_id(),
            "seq": sequence,
            "at": occurred_at,
            "prev": bytes(32),
            "hash": digest(str(event_id)),
        },
    )
    return event_id


def _sql(statement: str) -> Any:
    from sqlalchemy import text

    return text(statement)
