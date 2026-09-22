"""Saved signatures (SPEC section 8, Addendum 1 B).

A signer may keep the signature they adopted so the next session offers it again. Three rules
carry the whole feature, and every one of them is enforced here rather than by the caller:

* **Only the signer creates one.** ``adopt_signature`` takes a *session id*, never a user: the
  row's owner is read from that session's signer and envelope rows, so there is no argument a host
  could pass to save a signature for somebody else. There is no host path to creation at all.
* **Never from a kiosk.** A patient on a shared clinic tablet must not leave their signature
  behind for the next person the tablet is handed to.
* **At most one live row per user per host.** The partial unique index says so; adopting again
  revokes the old row (``replaced``) in the same transaction, under an advisory lock so two
  concurrent signatures cannot both insert.

Rows are never deleted -- a ``signature_captures`` row may point at one -- and the only UPDATE the
schema's trigger permits is the one revocation. This module writes no audit event: the API layer
appends ``signature.adopted`` and ``signature.adoption_revoked``, exactly as it does for the
session events.
"""

from __future__ import annotations

from datetime import datetime
from typing import Final, cast
from uuid import UUID

from sqlalchemy import RowMapping, text
from sqlalchemy.orm import Session

from esign.contracts import (
    AdoptedRevokeReason,
    AdoptedSignature,
    AdoptedSignatureKind,
    Conflict,
    Forbidden,
    Unauthorized,
    ValidationFailed,
)
from esign.db import advisory_xact_lock
from esign.identity.rows import opt_str, opt_time, raw_bytes, req_str, req_time, req_uuid
from esign.ids import advisory_lock_key, new_id

__all__ = ["adopt_signature", "live_adopted_signature", "revoke_adopted_signature"]

_COLUMNS: Final = (
    "id, host_id, host_user_id, kind, image_sha256, typed_text, created_in_envelope_id, "
    "created_by_session_id, created_at, revoked_at, revoke_reason"
)

#: ``replaced`` is written by :func:`adopt_signature` alone. A caller asking for it would be
#: claiming a replacement that did not happen, and the row can never be corrected afterwards.
_CALLER_REASONS: Final[frozenset[str]] = frozenset({"user", "host"})


def _row_to_adopted(row: RowMapping) -> AdoptedSignature:
    return AdoptedSignature(
        id=req_uuid(row, "id"),
        host_id=req_uuid(row, "host_id"),
        host_user_id=req_str(row, "host_user_id"),
        kind=cast(AdoptedSignatureKind, req_str(row, "kind")),
        image_sha256=None if row["image_sha256"] is None else raw_bytes(row, "image_sha256"),
        typed_text=opt_str(row, "typed_text"),
        created_in_envelope_id=req_uuid(row, "created_in_envelope_id"),
        created_by_session_id=req_uuid(row, "created_by_session_id"),
        created_at=req_time(row, "created_at"),
        revoked_at=opt_time(row, "revoked_at"),
        revoke_reason=cast(AdoptedRevokeReason | None, opt_str(row, "revoke_reason")),
    )


def _lock_user(db: Session, host_id: UUID, host_user_id: str) -> None:
    """Serialise every write for one user on one host.

    The partial unique index already makes two live rows impossible, but without this the loser of
    a race gets a constraint violation (a 500) in the middle of a signature that otherwise
    succeeded. With it, the second writer waits, sees the first row and revokes it as ``replaced``.
    """
    advisory_xact_lock(db, advisory_lock_key("identity.adopted", f"{host_id}:{host_user_id}"))


def live_adopted_signature(db: Session, *, host_id: UUID, host_user_id: str) -> AdoptedSignature | None:
    """The one unrevoked saved signature for this user on this host, or ``None``."""
    row = (
        db.execute(
            text(
                f"SELECT {_COLUMNS} FROM adopted_signatures "  # noqa: S608 - fixed column list
                "WHERE host_id = :host_id AND host_user_id = :host_user_id AND revoked_at IS NULL"
            ),
            {"host_id": host_id, "host_user_id": host_user_id},
        )
        .mappings()
        .first()
    )
    return None if row is None else _row_to_adopted(row)


def _session_for_adoption(db: Session, session_id: UUID, now: datetime) -> RowMapping:
    """The session a signature may be saved from, or the reason it may not be."""
    row = (
        db.execute(
            text(
                "SELECT ss.id AS id, ss.revoked_at AS revoked_at, ss.expires_at AS expires_at, "
                "       ss.kiosk_staff_user_id AS kiosk_staff_user_id, "
                "       s.id AS signer_id, s.status AS signer_status, s.host_user_id AS host_user_id, "
                "       e.id AS envelope_id, e.host_id AS host_id "
                "FROM signing_sessions ss "
                "JOIN signers s ON s.id = ss.signer_id "
                "JOIN envelopes e ON e.id = s.envelope_id "
                "WHERE ss.id = :id"
            ),
            {"id": session_id},
        )
        .mappings()
        .first()
    )
    # Unknown, revoked and expired are one indistinguishable failure, as everywhere else a session
    # is resolved: the caller learns nothing about which it was.
    if row is None or opt_time(row, "revoked_at") is not None or now >= req_time(row, "expires_at"):
        raise Unauthorized("invalid credentials")
    if opt_str(row, "kiosk_staff_user_id") is not None:
        raise Forbidden("a shared tablet does not keep a signature", code="adoption_not_allowed")
    if req_str(row, "signer_status") != "signed":
        # The row is created *after* the signature succeeds, in the same transaction: a saved
        # signature that never signed anything is a signature nobody ever applied.
        raise Conflict("this signer has not signed", code="signature_not_applied")
    return row


def _checked_payload(
    db: Session,
    *,
    kind: AdoptedSignatureKind,
    image_sha256: bytes | None,
    typed_text: str | None,
    max_typed_chars: int,
) -> tuple[bytes | None, str | None]:
    """``kind`` and its payload, or ``invalid_adopted_signature``. One shape or the other."""
    if kind == "drawn":
        if image_sha256 is None or typed_text is not None:
            raise ValidationFailed("a drawn signature is saved by its image", code="invalid_adopted_signature")
        stored = db.execute(
            text("SELECT kind FROM blobs WHERE sha256 = :sha"), {"sha": image_sha256}
        ).scalar_one_or_none()
        if stored != "signature_image":
            # The sign path stored the sanitised PNG a moment ago; anything else names bytes this
            # service never accepted as a signature.
            raise ValidationFailed("no such signature image", code="invalid_adopted_signature")
        return image_sha256, None
    if kind == "typed":
        if image_sha256 is not None:
            raise ValidationFailed("a typed signature is saved by its text", code="invalid_adopted_signature")
        cleaned = (typed_text or "").strip()
        if not cleaned or len(cleaned) > max_typed_chars:
            raise ValidationFailed("a typed signature is missing or too long", code="invalid_adopted_signature")
        return None, cleaned
    raise ValidationFailed("unknown saved signature kind", code="invalid_adopted_signature")


def adopt_signature(
    db: Session,
    session_id: UUID,
    *,
    kind: AdoptedSignatureKind,
    image_sha256: bytes | None,
    typed_text: str | None,
    now: datetime,
    max_typed_chars: int,
) -> AdoptedSignature:
    """Save the signature adopted in this session for the session's own signer."""
    session = _session_for_adoption(db, session_id, now)
    image, typed = _checked_payload(
        db, kind=kind, image_sha256=image_sha256, typed_text=typed_text, max_typed_chars=max_typed_chars
    )
    host_id = req_uuid(session, "host_id")
    host_user_id = req_str(session, "host_user_id")

    _lock_user(db, host_id, host_user_id)
    _revoke_live(db, host_id=host_id, host_user_id=host_user_id, reason="replaced", now=now)

    adopted_id = new_id()
    db.execute(
        text(
            "INSERT INTO adopted_signatures "
            "(id, host_id, host_user_id, kind, image_sha256, typed_text, created_in_envelope_id, "
            " created_by_session_id, created_at) "
            "VALUES (:id, :host_id, :host_user_id, :kind, :image, :typed, :envelope_id, :session_id, :created_at)"
        ),
        {
            "id": adopted_id,
            "host_id": host_id,
            "host_user_id": host_user_id,
            "kind": kind,
            "image": image,
            "typed": typed,
            "envelope_id": req_uuid(session, "envelope_id"),
            "session_id": session_id,
            "created_at": now,
        },
    )
    return AdoptedSignature(
        id=adopted_id,
        host_id=host_id,
        host_user_id=host_user_id,
        kind=kind,
        image_sha256=image,
        typed_text=typed,
        created_in_envelope_id=req_uuid(session, "envelope_id"),
        created_by_session_id=session_id,
        created_at=now,
    )


def revoke_adopted_signature(
    db: Session, *, host_id: UUID, host_user_id: str, reason: AdoptedRevokeReason, now: datetime
) -> AdoptedSignature | None:
    """Revoke the user's live saved signature. ``None`` when they had none: idempotent, and a user
    of another host is indistinguishable from a user with nothing saved."""
    if reason not in _CALLER_REASONS:
        raise ValidationFailed("a saved signature is revoked by its user or its host", code="invalid_revoke_reason")
    _lock_user(db, host_id, host_user_id)
    return _revoke_live(db, host_id=host_id, host_user_id=host_user_id, reason=reason, now=now)


def _revoke_live(
    db: Session, *, host_id: UUID, host_user_id: str, reason: AdoptedRevokeReason, now: datetime
) -> AdoptedSignature | None:
    """The one UPDATE the row ever takes: ``revoked_at`` and ``revoke_reason``, together, once."""
    row = (
        db.execute(
            text(
                "UPDATE adopted_signatures SET revoked_at = :now, revoke_reason = :reason "  # noqa: S608
                "WHERE host_id = :host_id AND host_user_id = :host_user_id AND revoked_at IS NULL "
                f"RETURNING {_COLUMNS}"  # a fixed column list, not input
            ),
            {"now": now, "reason": reason, "host_id": host_id, "host_user_id": host_user_id},
        )
        .mappings()
        .first()
    )
    return None if row is None else _row_to_adopted(row)
