"""Request bodies and response shapes (SPEC section 9).

Request models forbid unknown keys: a client that sends ``date_signed``, a hash, a timestamp or a
PDF is refused rather than ignored, because a value we silently drop is a value the client believes
we used. Responses are built by hand from contract types, so nothing reaches the wire by accident.
"""

from __future__ import annotations

import base64
import binascii
from datetime import UTC, datetime
from typing import Any, Final, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from esign.api.template_service import TemplateVersionView, TemplateView
from esign.config import Settings
from esign.contracts import (
    DECLINE_REASON_CODES,
    AuditEvent,
    AuthContext,
    AuthMethod,
    Capacity,
    Capture,
    CaptureKind,
    ConsentText,
    EnvelopeView,
    IdentityCheck,
    KioskContext,
    NewEnvelope,
    NewSigner,
    SessionInfo,
    SigningView,
    ValidationFailed,
)

__all__ = [
    "DECLINE_REASON_LABELS",
    "ConsentBody",
    "DeclineBody",
    "NewEnvelopeBody",
    "ReauthBody",
    "SessionBody",
    "SignBody",
    "ViewedBody",
    "VoidBody",
    "audit_event_json",
    "envelope_json",
    "signer_ack_json",
    "signing_session_json",
    "template_json",
    "timestamp",
]


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --------------------------------------------------------------------------- host requests


class SignerBody(_Body):
    role_key: str = Field(max_length=64)
    host_user_id: str = Field(max_length=128)
    display_name: str = Field(max_length=200)
    capacity: Capacity
    on_behalf_of: str | None = Field(default=None, max_length=128)


class NewEnvelopeBody(_Body):
    template_key: str = Field(max_length=64)
    template_version: int | None = Field(default=None, ge=1)
    patient_ref: str = Field(max_length=128)
    host_document_ref: str | None = Field(default=None, max_length=200)
    signing_order: Literal["sequential", "parallel"]
    signers: list[SignerBody] = Field(min_length=1, max_length=20)
    prefill: dict[str, str] = Field(default_factory=dict, max_length=200)
    expires_at: datetime | None = None
    supersedes_envelope_id: UUID | None = None

    def to_contract(self) -> NewEnvelope:
        return NewEnvelope(
            template_key=self.template_key,
            template_version=self.template_version,
            patient_ref=self.patient_ref,
            host_document_ref=self.host_document_ref,
            signing_order=self.signing_order,
            signers=tuple(
                NewSigner(
                    role_key=s.role_key,
                    host_user_id=s.host_user_id,
                    display_name=s.display_name,
                    capacity=s.capacity,
                    on_behalf_of=s.on_behalf_of,
                )
                for s in self.signers
            ),
            prefill=dict(self.prefill),
            expires_at=self.expires_at,
            supersedes_envelope_id=self.supersedes_envelope_id,
        )


class VoidBody(_Body):
    reason_code: str = Field(max_length=64)


class AuthBody(_Body):
    method: AuthMethod
    auth_time: datetime

    def to_contract(self) -> AuthContext:
        return AuthContext(method=self.method, auth_time=self.auth_time)


class KioskBody(_Body):
    staff_user_id: str = Field(max_length=128)
    identity_check: IdentityCheck


class SessionBody(_Body):
    auth: AuthBody
    kiosk: KioskBody | None = None

    def kiosk_context(self) -> KioskContext | None:
        if self.kiosk is None:
            return None
        return KioskContext(staff_user_id=self.kiosk.staff_user_id, identity_check=self.kiosk.identity_check)


class ReauthBody(AuthBody):
    pass


# --------------------------------------------------------------------------- signer requests


class ViewedBody(_Body):
    pages_viewed: int = Field(ge=0, le=10_000)


class ConsentBody(_Body):
    consent_version: str = Field(max_length=64)
    accepted: Literal[True]  # there is no way to post "I do not agree": that is the decline path
    locale: str | None = Field(default=None, max_length=35)


class CaptureBody(_Body):
    field_id: str = Field(max_length=64)
    kind: CaptureKind | None = None
    image_png_base64: str | None = None
    typed_text: str | None = Field(default=None, max_length=200)
    checked: bool | None = None
    text_value: str | None = Field(default=None, max_length=2000)


class SignBody(_Body):
    intent_confirmed: Literal[True]
    captures: list[CaptureBody] = Field(max_length=200)

    def to_contract(self, settings: Settings) -> list[Capture]:
        """Decode, nothing more. Which field takes which shape is the envelope service's decision,
        made against the template under the envelope lock."""
        # Base64 is 4 characters per 3 bytes; refuse an oversized image before decoding it.
        max_chars = (settings.max_signature_png_bytes * 4) // 3 + 8
        out: list[Capture] = []
        for item in self.captures:
            image: bytes | None = None
            if item.image_png_base64 is not None:
                if len(item.image_png_base64) > max_chars:
                    raise ValidationFailed("the signature image is too large", code="signature_image_too_large")
                try:
                    image = base64.b64decode(item.image_png_base64, validate=True)
                except (binascii.Error, ValueError):
                    raise ValidationFailed(
                        "the signature image is not valid base64", code="capture_shape_invalid"
                    ) from None
            out.append(
                Capture(
                    field_id=item.field_id,
                    kind=item.kind,
                    image_png=image,
                    typed_text=item.typed_text,
                    checked=item.checked,
                    text_value=item.text_value,
                )
            )
        return out


class DeclineBody(_Body):
    reason_code: str = Field(max_length=64)


# --------------------------------------------------------------------------- responses

DECLINE_REASON_LABELS: Final[dict[str, str]] = {
    "prefers_paper": "I would rather sign on paper",
    "needs_more_time": "I need more time to read this",
    "disagrees_with_terms": "I do not agree with what it says",
    "needs_interpreter": "I need an interpreter",
    "incorrect_information": "Some of the information is wrong",
    "not_the_right_signer": "I am not the right person to sign this",
    "wants_to_ask_a_question": "I want to ask a question first",
    "other": "Another reason",
}
if set(DECLINE_REASON_LABELS) != set(DECLINE_REASON_CODES):  # pragma: no cover - import-time guard
    raise RuntimeError("every decline reason code needs a label, and only those")


def timestamp(value: datetime | None) -> str | None:
    """RFC 3339, UTC, ``Z``. The database hands back aware datetimes in the session's zone."""
    return None if value is None else value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _hex(value: bytes | None) -> str | None:
    return None if value is None else value.hex()


def _id(value: UUID | None) -> str | None:
    return None if value is None else str(value)


def envelope_json(view: EnvelopeView) -> dict[str, Any]:
    """``EnvelopeView`` for the host. Display names are the host's own data, returned to it."""
    return {
        "id": str(view.id),
        "status": view.status,
        "document_type": view.document_type,
        "template_key": view.template_key,
        "template_version": view.template_version,
        "signing_order": view.signing_order,
        "signers": [
            {
                "id": str(s.id),
                "role_key": s.role_key,
                "role_label": s.role_label,
                "display_name": s.display_name,
                "capacity": s.capacity,
                "order_index": s.order_index,
                "requires_reauth": s.requires_reauth,
                "status": s.status,
            }
            for s in view.signers
        ],
        "presented_sha256": _hex(view.presented_sha256),
        "current_revision_sha256": _hex(view.current_revision_sha256),
        "sealed_sha256": _hex(view.sealed_sha256),
        "created_at": timestamp(view.created_at),
        "expires_at": timestamp(view.expires_at),
        "supersedes_envelope_id": _id(view.supersedes_envelope_id),
        "superseded_by_envelope_id": _id(view.superseded_by_envelope_id),
    }


def signer_ack_json(view: EnvelopeView, signer_id: UUID) -> dict[str, Any]:
    """The body of every signer POST: ids and statuses only. No names -- it may be stored as an
    idempotent replay, and the UI refetches the session for everything else."""
    signer = next((s for s in view.signers if s.id == signer_id), None)
    return {
        "envelope": {"id": str(view.id), "status": view.status},
        "signer": {"id": str(signer_id), "status": signer.status if signer else None},
    }


def signing_session_json(view: SigningView, consent: ConsentText, session: SessionInfo) -> dict[str, Any]:
    return {
        "envelope": {
            "id": str(view.envelope_id),
            "status": view.envelope_status,
            "document_type": view.document_type,
            "title": view.title,
            "page_count": view.page_count,
            "expires_at": timestamp(view.expires_at),
        },
        "signer": {
            "id": str(view.signer.id),
            "display_name": view.signer.display_name,
            "role_label": view.signer.role_label,
            "capacity": view.signer.capacity,
            "on_behalf_of_label": view.on_behalf_of_label,
            "status": view.signer.status,
            "requires_reauth": view.signer.requires_reauth,
            "reauth_valid_until": timestamp(view.reauth_valid_until),
        },
        "other_signers": [{"role_label": label, "status": status} for label, status in view.other_signers],
        "fields": [
            {
                "id": f.id,
                "type": f.type,
                "page": f.page,
                "rect": {"x": f.rect.x, "y": f.rect.y, "w": f.rect.w, "h": f.rect.h},
                "required": f.required,
                "label": f.label,
            }
            for f in view.fields
        ],
        "consent": {"version": consent.version, "locale": consent.locale, "body": consent.body},
        "session": {
            "id": str(session.id),
            "expires_at": timestamp(session.expires_at),
            "kiosk": session.kiosk is not None,
        },
        "decline_reasons": [{"code": code, "label": DECLINE_REASON_LABELS[code]} for code in DECLINE_REASON_CODES],
    }


def audit_event_json(event: AuditEvent) -> dict[str, Any]:
    return {
        "id": str(event.id),
        "sequence": event.sequence,
        "event_type": str(event.event_type),
        "occurred_at": timestamp(event.occurred_at),
        "actor": {
            "user_id": event.actor.user_id,
            "role": event.actor.role,
            "capacity": event.actor.capacity,
            "on_behalf_of": event.actor.on_behalf_of,
        },
        "context": {
            "ip": event.ctx.ip,
            "user_agent": event.ctx.user_agent,
            "auth_method": event.ctx.auth_method,
            "session_id": _id(event.ctx.session_id),
        },
        "document_sha256": _hex(event.document_sha256),
        "data": event.data,
        "prev_event_hash": event.prev_event_hash.hex(),
        "event_hash": event.event_hash.hex(),
    }


def _version_json(version: TemplateVersionView) -> dict[str, Any]:
    return {
        "version": version.version,
        "status": version.status,
        "pdf_sha256": version.pdf_sha256.hex(),
        "fields": version.fields,
        "prefill_fields": version.prefill_fields,
        "signer_roles": version.signer_roles,
        "created_at": timestamp(version.created_at),
        "published_at": timestamp(version.published_at),
    }


def template_json(view: TemplateView, *, detail: bool = True) -> dict[str, Any]:
    body: dict[str, Any] = {
        "key": view.key,
        "name": view.name,
        "document_type": view.document_type,
        "created_at": timestamp(view.created_at),
    }
    if detail:
        body["versions"] = [_version_json(v) for v in view.versions]
    else:
        body["versions"] = [{"version": v.version, "status": v.status} for v in view.versions]
    return body
