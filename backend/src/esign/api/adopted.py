"""Saved signatures at the HTTP layer (SPEC sections 8 and 9, Addendum 1 B).

The identity module owns the rows and every rule about them; it writes no audit event, exactly as
it writes none for a session. So the two events live here, beside the routes that cause them, and
in the same transaction as the change they describe:

* ``signature.adopted`` on the envelope stream of the session the signature was saved in -- the
  signature that was applied is in that stream too, one event earlier;
* ``signature.adoption_revoked`` on the ``system`` stream, keyed by host: a user's saved signature
  outlives any one envelope, so there is no envelope this belongs to. Revocation is recorded
  whoever asked for it -- the signer, the host, or a replacement.

Which user is acted for is never read from a request body: a signer's pair comes from their
session's rows, a host's from the path plus the key it authenticated with.
"""

from __future__ import annotations

import hashlib
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from esign.contracts import (
    Actor,
    AdoptedRevokeReason,
    AdoptedSignature,
    AdoptedSignatureKind,
    Capture,
    EventType,
    Forbidden,
    RequestContext,
    SessionInfo,
    ValidationFailed,
)
from esign.runtime import Runtime

__all__ = ["adoption_source", "revoke_and_record", "save_adopted_signature", "signer_actor"]


def signer_actor(session: SessionInfo, capacity: str | None = None) -> Actor:
    """The signer, as the trail identifies them: their opaque host user id."""
    return Actor(user_id=session.host_user_id, capacity=capacity)  # type: ignore[arg-type]  # Capacity literal


def adoption_source(captures: list[Capture]) -> Capture:
    """The capture whose signature ``save_adopted_signature: true`` saves.

    The UI adopts one signature per session and applies it to each field, so the first drawn or
    typed capture *is* the signature that was adopted. An ``adopted`` capture is not one: it is
    already saved, and saving it again would revoke the row it was read from and replace it with
    a copy of itself.
    """
    source = next((c for c in captures if c.kind in ("drawn", "typed")), None)
    if source is None:
        raise ValidationFailed("there is no drawn or typed signature to save", code="no_signature_to_save")
    return source


def save_adopted_signature(
    rt: Runtime, db: Session, session: SessionInfo, source: Capture, ctx: RequestContext, *, capacity: str | None = None
) -> AdoptedSignature:
    """Keep the signature this session just applied, in the transaction that applied it.

    Called after ``EnvelopeService.sign`` has succeeded: the row is evidence that a signature was
    adopted, and a signature that was refused adopted nothing. Replacing an earlier saved
    signature revokes it (``replaced``), and both facts are recorded.
    """
    if session.kiosk is not None:
        # The identity module refuses this too. Refusing here as well means the signature is never
        # applied and then rolled back for a reason the signer could have been told up front.
        raise Forbidden("a shared tablet does not keep a signature", code="adoption_not_allowed")

    kind: AdoptedSignatureKind = "drawn" if source.kind == "drawn" else "typed"
    image_sha256: bytes | None = None
    if kind == "drawn":
        if source.image_png is None:  # pragma: no cover - the sign path refused it already
            raise ValidationFailed("there is no drawn signature to save", code="no_signature_to_save")
        # ``sign`` stored the *sanitised* PNG as a ``signature_image`` blob a moment ago, and the
        # blob store is content-addressed, so sanitising the same bytes again names that blob
        # exactly. The row points at the bytes that were stamped, never at the client's original.
        image_sha256 = hashlib.sha256(rt.documents.sanitize_signature_png(source.image_png)).digest()

    replaced = rt.identity.get_adopted_signature(db, host_id=session.host_id, host_user_id=session.host_user_id)
    adopted = rt.identity.adopt_signature(
        db, session.id, kind=kind, image_sha256=image_sha256, typed_text=source.typed_text
    )
    data: dict[str, Any] = {
        "signer_id": session.signer_id,
        "adopted_signature_id": adopted.id,
        "kind": adopted.kind,
        "image_sha256": adopted.image_sha256,
        # A digest, never the text: a typed signature is a name.
        "typed_text_sha256": (
            None if adopted.typed_text is None else hashlib.sha256(adopted.typed_text.encode("utf-8")).digest()
        ),
    }
    rt.audit.append(
        db,
        stream_type="envelope",
        stream_id=session.envelope_id,
        event_type=EventType.SIGNATURE_ADOPTED,
        actor=signer_actor(session, capacity),
        ctx=ctx,
        data=data,
    )
    if replaced is not None:
        _record_revocation(rt, db, replaced, reason="replaced", actor=signer_actor(session, capacity), ctx=ctx)
    return adopted


def revoke_and_record(
    rt: Runtime,
    db: Session,
    *,
    host_id: UUID,
    host_user_id: str,
    reason: AdoptedRevokeReason,
    actor: Actor,
    ctx: RequestContext,
) -> AdoptedSignature | None:
    """Revoke a user's saved signature and record it. ``None`` when they had none.

    Idempotent, and silent about whose user this is: a user of another host and a user with
    nothing saved get the same answer, because the lookup is scoped to ``host_id`` and finds
    nothing either way.
    """
    revoked = rt.identity.revoke_adopted_signature(db, host_id=host_id, host_user_id=host_user_id, reason=reason)
    if revoked is not None:
        _record_revocation(rt, db, revoked, reason=reason, actor=actor, ctx=ctx)
    return revoked


def _record_revocation(
    rt: Runtime,
    db: Session,
    revoked: AdoptedSignature,
    *,
    reason: AdoptedRevokeReason,
    actor: Actor,
    ctx: RequestContext,
) -> None:
    """``signature.adoption_revoked`` on the ``system`` stream, one chain per host."""
    rt.audit.append(
        db,
        stream_type="system",
        stream_id=revoked.host_id,
        event_type=EventType.SIGNATURE_ADOPTION_REVOKED,
        actor=actor,
        ctx=ctx,
        data={
            "host_id": revoked.host_id,
            "host_user_id": revoked.host_user_id,
            "adopted_signature_id": revoked.id,
            "reason": reason,
        },
    )
