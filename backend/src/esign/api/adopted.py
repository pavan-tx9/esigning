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
from collections.abc import Mapping
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
    FieldType,
    Forbidden,
    RequestContext,
    SessionInfo,
    ValidationFailed,
)
from esign.db import advisory_xact_lock
from esign.ids import advisory_lock_key
from esign.runtime import Runtime

__all__ = ["adoption_source", "revoke_and_record", "save_adopted_signature", "signer_actor"]


def signer_actor(session: SessionInfo, capacity: str | None = None) -> Actor:
    """The signer, as the trail identifies them: their opaque host user id."""
    return Actor(user_id=session.host_user_id, capacity=capacity)  # type: ignore[arg-type]  # Capacity literal


def adoption_source(captures: list[Capture], field_types: Mapping[str, FieldType]) -> Capture:
    """The capture whose signature ``save_adopted_signature: true`` saves.

    A saved signature is offered back for *signature* fields, so only a capture landing on one is a
    candidate. The UI builds its captures in reading order and fills an initials field with the
    signer's initials, which on a template that asks for initials before the signature (page 2 of
    ``procedure_consent``, say) is the first drawn-or-typed capture in the request -- and saving
    that would keep "MO" as the signature the next session offers and stamps.

    Past that, the UI adopts one signature per session and applies it to every field, so the first
    such capture *is* the signature that was adopted. An ``adopted`` capture is not one: it is
    already saved, and saving it again would revoke the row it was read from and replace it with
    a copy of itself.
    """
    source = next(
        (c for c in captures if c.kind in ("drawn", "typed") and field_types.get(c.field_id) == "signature"), None
    )
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
        # The image the row points at is the one the trail says was applied: ``signer.signed``'s
        # ``CaptureRef`` for this field carries the digest of the sanitised PNG ``sign`` stored a
        # moment ago, so the saved signature is tied to the hash chain, never to the client's bytes.
        image_sha256 = _applied_image_sha256(rt, db, session, source.field_id)

    # The row named in ``signature.adoption_revoked`` has to be the row that was actually revoked.
    # ``adopt_signature`` takes this same per-user lock before replacing whatever is live, but it
    # takes it *after* this read: without the lock here, two signatures by the same user (a
    # clinician working a queue from two tabs) interleave as "T1 reads A, T2 replaces A with B,
    # T1 replaces B" -- and T1 would then record A as revoked a second time while B, the row that
    # really stopped being offered, is never named on an append-only stream that cannot be
    # corrected. Taking it before the read serialises the pair.
    advisory_xact_lock(db, advisory_lock_key("identity.adopted", f"{session.host_id}:{session.host_user_id}"))
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


def _applied_image_sha256(rt: Runtime, db: Session, session: SessionInfo, field_id: str) -> bytes:
    """The digest of the drawn signature ``sign`` just stamped into ``field_id``, from the trail.

    The ``signer.signed`` event this session appended in this transaction records one
    ``CaptureRef`` per capture, and a drawn one carries ``image_sha256``: the content address of
    the sanitised PNG stored as a ``signature_image`` blob. Reading it back from the chain, rather
    than re-deriving it from the request, means the row can only ever name ink the trail vouches
    for -- and ``adopt_signature`` checks that blob exists and is a signature image.
    """
    signed = [
        event
        for event in rt.audit.list(db, "envelope", session.envelope_id)
        if event.event_type == EventType.SIGNER_SIGNED and event.ctx.session_id == session.id
    ]
    if not signed:  # pragma: no cover - ``sign`` appended it a moment ago
        raise ValidationFailed("there is no signature to save", code="no_signature_to_save")
    for ref in signed[-1].data.get("captures") or []:
        if isinstance(ref, dict) and ref.get("field_id") == field_id and ref.get("image_sha256"):
            return bytes.fromhex(str(ref["image_sha256"]))
    raise ValidationFailed("there is no drawn signature to save", code="no_signature_to_save")


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
