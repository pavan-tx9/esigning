"""The envelope service: every state transition an envelope or a signer can make.

Shape of every mutating method, without exception:

1. lock the envelope row (``SELECT ... FOR UPDATE``) -- the one serialisation point;
2. re-read the signers *inside* the lock, so the decision is made on current rows;
3. ask :mod:`esign.envelopes.state`, a pure function, whether the command is legal;
4. do the work, write the rows, append the audit event -- all in the caller's transaction.

A refusal at step 3 changes nothing. An exception anywhere rolls the whole step back, which is why
the audit event and the state change share one transaction: an envelope can never move without the
event that explains why, and an event can never describe a move that did not happen.

PHI discipline: ``display_name``, prefill values and PDF bytes live in the database, the blob store
and the PDF. They never reach a log line or an audit ``data`` payload. What may appear in ``data``
has exactly one definition -- ``esign.audit.events.EVENT_DATA_MODELS`` -- which the audit log
enforces on every append, and which this module's tests run against (the fake audit log validates
through it), so the two sides cannot drift apart silently.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any, Final, Literal
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from esign.clock import Clock
from esign.config import Settings
from esign.contracts import (
    DECLINE_REASON_CODES,
    VOID_REASON_CODES,
    Actor,
    ActorRole,
    AuditLog,
    BlobService,
    Capacity,
    Capture,
    CertificateSigner,
    CertificateSummary,
    Conflict,
    DocumentService,
    EnvelopeNotifier,
    EnvelopeView,
    EsignError,
    EventType,
    FieldDef,
    Forbidden,
    Host,
    IdentityService,
    IntegrityFailure,
    NewEnvelope,
    NewSigner,
    NotFound,
    RequestContext,
    Sealer,
    SealUnavailable,
    SessionInfo,
    SignerRoleDef,
    SignerStamp,
    SignerView,
    SigningFieldView,
    SigningView,
    ValidationFailed,
    WebhookEvent,
    is_opaque_id,
)
from esign.envelopes import repository as repo
from esign.envelopes.definitions import (
    SIGNABLE_FIELD_TYPES,
    parse_field_defs,
    parse_prefill_fields,
    parse_signer_roles,
)
from esign.envelopes.state import (
    LIVE_ENVELOPE_STATUSES,
    Command,
    EnvelopeState,
    Refusal,
    SignerState,
    Transition,
    decide,
    next_backoff,
)
from esign.ids import new_id
from esign.logging import get_logger

__all__ = [
    "DECLINE_REASON_CODES",
    "EnvelopeServiceImpl",
    "SessionScope",
    "build_envelope_service",
]

log = get_logger(__name__)

#: A factory for a fresh, independently committing session. Used only to record a seal failure
#: after the failed attempt's transaction has been rolled back.
SessionScope = Callable[[], AbstractContextManager[Session]]

_SEAL_REASON = "Certified complete by the e-signing service"


@dataclass(frozen=True)
class _Loaded:
    """An envelope and everything a decision needs, read under the row lock."""

    envelope: repo.EnvelopeRow
    signers: tuple[repo.SignerRow, ...]
    roles: dict[str, SignerRoleDef]
    template: repo.TemplateVersionRow


class EnvelopeServiceImpl:
    """``EnvelopeService``. Collaborators arrive by constructor injection (SPEC section 2)."""

    def __init__(
        self,
        settings: Settings,
        clock: Clock,
        *,
        audit_log: AuditLog,
        blob_service: BlobService,
        document_service: DocumentService,
        identity_service: IdentityService,
        sealer: Sealer,
        new_session: SessionScope | None = None,
        notifier: EnvelopeNotifier | None = None,
    ) -> None:
        self._settings = settings
        self._clock = clock
        self._audit = audit_log
        self._blobs = blob_service
        self._documents = document_service
        self._identity = identity_service
        self._sealer = sealer
        self._new_session = new_session
        self._notifier = notifier

    # ----------------------------------------------------------------- creation

    def create(self, db: Session, host: Host, spec: NewEnvelope, ctx: RequestContext) -> EnvelopeView:
        now = self._clock.now()
        template = self._resolve_template(db, host, spec)
        if not self._settings.is_approved_document_type(template.document_type):
            raise ValidationFailed("document type is not approved here", code="document_type_not_approved")

        roles = parse_signer_roles(template.signer_roles)
        prefill_fields = parse_prefill_fields(template.prefill_fields)
        parse_field_defs(template.fields)  # reject a broken template before any PDF work

        if spec.signing_order not in ("sequential", "parallel"):
            # The schema's CHECK would catch this, but as a driver error with no usable code.
            raise ValidationFailed("unknown signing order", code="signing_order_invalid")

        patient_ref = _require_opaque(spec.patient_ref, "patient_ref_invalid")
        planned = self._plan_signers(spec, roles, patient_ref)
        expires_at = self._resolve_expiry(spec.expires_at, now)
        superseded = self._lock_superseded(db, host, spec.supersedes_envelope_id)

        # BlobService.get re-hashes: a stored template that no longer matches its hash raises
        # IntegrityFailure here rather than being quietly turned into a document someone signs.
        template_pdf = self._blobs.get(db, template.pdf_sha256)
        prepared = self._documents.prepare(template_pdf, list(prefill_fields), dict(spec.prefill))
        page_count = self._documents.page_count(prepared)
        retain_until = self._settings.retain_until(template.document_type, now)
        presented = self._blobs.put(db, prepared, kind="presented_pdf", retain_until=retain_until)

        envelope_id = new_id()
        repo.insert_envelope(
            db,
            envelope_id=envelope_id,
            host_id=host.id,
            template_version_id=template.id,
            document_type=template.document_type,
            patient_ref=patient_ref,
            host_document_ref=spec.host_document_ref,
            signing_order=spec.signing_order,
            presented_sha256=presented.sha256,
            supersedes_envelope_id=superseded.id if superseded else None,
            expires_at=expires_at,
            created_at=now,
        )
        for signer, role in planned:
            repo.insert_signer(
                db,
                signer_id=new_id(),
                envelope_id=envelope_id,
                role_key=role.key,
                host_user_id=signer.host_user_id,
                display_name=signer.display_name,
                capacity=signer.capacity,
                on_behalf_of=signer.on_behalf_of,
                order_index=role.order_index,
                requires_reauth=role.requires_reauth,  # from the role, never from the request
            )
        repo.insert_revision(
            db,
            revision_id=new_id(),
            envelope_id=envelope_id,
            revision_no=1,
            kind="presented",
            sha256=presented.sha256,
            signer_id=None,
            created_at=now,
        )

        actor = Actor(user_id=None, role="host")
        self._append(
            db,
            envelope_id,
            EventType.ENVELOPE_CREATED,
            actor=actor,
            ctx=ctx,
            data={
                "host_id": host.id,
                "template_key": template.template_key,
                "template_version": template.version,
                "template_version_id": template.id,
                "document_type": template.document_type,
                "signing_order": spec.signing_order,
                "signer_count": len(planned),
                "expires_at": expires_at,
                "supersedes_envelope_id": superseded.id if superseded else None,
            },
        )
        self._append(
            db,
            envelope_id,
            EventType.DOCUMENT_PREPARED,
            actor=actor,
            ctx=ctx,
            document_sha256=presented.sha256,
            data={
                "revision_no": 1,
                "revision_kind": "presented",
                "page_count": page_count,
                "size_bytes": presented.size_bytes,
                # A count, never the keys or the values: prefill is chart data.
                "prefill_field_count": len(spec.prefill),
            },
        )
        if superseded is not None:
            self._append(
                db,
                superseded.id,
                EventType.ENVELOPE_SUPERSEDED,
                actor=actor,
                ctx=ctx,
                data={"superseded_by_envelope_id": envelope_id},
            )

        log.info(
            "envelope.created",
            envelope_id=envelope_id,
            host_id=host.id,
            template_key=template.template_key,
            template_version=template.version,
            document_type=template.document_type,
            signing_order=spec.signing_order,
            signer_count=len(planned),
            presented_sha256=presented.sha256,
        )
        # `prepared`, `spec.prefill` and the display names never leave this frame: nothing above
        # stores or logs them outside the PDF and the signers table.
        return self.get(db, host, envelope_id)

    # ----------------------------------------------------------------- reads

    def get(self, db: Session, host: Host, envelope_id: UUID) -> EnvelopeView:
        return self._view(db, self._load(db, envelope_id, host=host, lock=False))

    def assert_signer_may_start(self, db: Session, host: Host, envelope_id: UUID, signer_id: UUID) -> None:
        loaded = self._load(db, envelope_id, host=host, lock=True)
        signer = self._signer_of(loaded, signer_id)
        self._refuse_if_past_expiry(loaded)
        self._decide(loaded, Command.START_SESSION, signer.id)

    def may_download_copy(self, db: Session, session: SessionInfo) -> bool:
        """Whether this session may still fetch the signed copy.

        Signing revokes the signer's other sessions but deliberately leaves alive the one they
        signed from, so they can download their copy from the screen they are already on. This is
        the gate that holds that surviving session to exactly that one job: it never re-opens
        signing, and it says nothing until everyone has signed.
        """
        signer = repo.load_signer(db, session.signer_id)
        if signer is None or signer.envelope_id != session.envelope_id or signer.status != "signed":
            return False
        envelope = repo.load_envelope(db, signer.envelope_id)
        return envelope is not None and envelope.status in ("completed_pending_seal", "sealed")

    def signing_view(self, db: Session, session: SessionInfo) -> SigningView:
        """What the signing UI shows. Read-only: no lock, no event. Other signers appear by role
        label and status only -- one signer never learns another's name from this service."""
        loaded = self._load(db, session.envelope_id, host=None, lock=False)
        signer = self._signer_of(loaded, session.signer_id)
        fields = parse_field_defs(loaded.template.fields)
        current = _require_revision(loaded.envelope.current_revision_sha256)
        fresh = self._identity.fresh_reauth(db, session.id) if signer.requires_reauth else None
        return SigningView(
            envelope_id=loaded.envelope.id,
            envelope_status=loaded.envelope.status,
            document_type=loaded.envelope.document_type,
            title=loaded.template.template_name,
            page_count=self._documents.page_count(self._blobs.get(db, current)),
            expires_at=loaded.envelope.expires_at,
            signer=self._signer_view(loaded, signer),
            on_behalf_of_label=signer.on_behalf_of,
            reauth_valid_until=(
                fresh.auth_time + timedelta(seconds=self._settings.reauth_max_age_seconds) if fresh else None
            ),
            other_signers=tuple(
                (loaded.roles[s.role_key].label if s.role_key in loaded.roles else s.role_key, s.status)
                for s in sorted(loaded.signers, key=lambda s: (s.order_index, s.role_key))
                if s.id != signer.id
            ),
            fields=tuple(
                SigningFieldView(id=f.id, type=f.type, page=f.page, rect=f.rect, required=f.required, label=f.label)
                for f in fields
                if f.signer_role == signer.role_key
            ),
        )

    # ----------------------------------------------------------------- downloads

    def signer_copy(self, db: Session, session: SessionInfo, ctx: RequestContext) -> bytes | None:
        loaded = self._load(db, session.envelope_id, host=None, lock=True)
        signer = self._signer_of(loaded, session.signer_id)
        if signer.status != "signed":
            raise Forbidden("the copy is available to a signer who has signed", code="copy_not_available")
        status = loaded.envelope.status
        if status == "completed_pending_seal":
            return None
        if status != "sealed":
            # Other signers are still to sign, or the envelope ended some other way. Either way
            # there is no sealed document, and nothing short of one is ever handed out as "the copy".
            raise Conflict("the signed document is not available yet", code="envelope_not_complete")
        return self._download(db, loaded, actor=_signer_actor(signer), ctx=ctx, audience="signer")

    def sealed_document(self, db: Session, host: Host, envelope_id: UUID, ctx: RequestContext) -> bytes:
        loaded = self._load(db, envelope_id, host=host, lock=True)
        if loaded.envelope.status != "sealed":
            raise Conflict("the envelope is not sealed", code="not_sealed")
        return self._download(db, loaded, actor=Actor(user_id=None, role="host"), ctx=ctx, audience="host")

    def _download(
        self, db: Session, loaded: _Loaded, *, actor: Actor, ctx: RequestContext, audience: Literal["signer", "host"]
    ) -> bytes:
        sha = loaded.envelope.sealed_sha256
        if sha is None:
            raise IntegrityFailure("a sealed envelope has no sealed document", code="missing_sealed_document")
        pdf = self._blobs.get(db, sha)  # re-hashed on read; IntegrityFailure is never caught here
        self._append(
            db,
            loaded.envelope.id,
            EventType.DOCUMENT_DOWNLOADED,
            actor=actor,
            ctx=ctx,
            document_sha256=sha,
            data={"blob_kind": "sealed_pdf", "audience": audience, "size_bytes": len(pdf)},
        )
        log.info("document.downloaded", envelope_id=loaded.envelope.id, document_sha256=sha, size_bytes=len(pdf))
        return pdf

    # ----------------------------------------------------------------- signer flow

    def present(self, db: Session, session: SessionInfo, ctx: RequestContext) -> bytes:
        loaded, signer = self._load_for_session(db, session)
        transition = self._decide(loaded, Command.PRESENT, signer.id)
        sha = _require_revision(loaded.envelope.current_revision_sha256)

        # Re-hashes on read: a revision that no longer matches raises IntegrityFailure instead of
        # being served to a signer. Never caught here.
        pdf = self._blobs.get(db, sha)

        self._apply_envelope_transition(db, loaded, transition, now=self._clock.now())
        repo.set_session_presented(db, session.id, sha)
        self._append(
            db,
            loaded.envelope.id,
            EventType.DOCUMENT_PRESENTED,
            actor=_signer_actor(signer),
            ctx=ctx,
            document_sha256=sha,
            data={
                "signer_id": signer.id,
                "revision_no": repo.latest_revision_no(db, loaded.envelope.id),
                "page_count": self._documents.page_count(pdf),
                "size_bytes": len(pdf),
            },
        )
        log.info(
            "document.presented",
            envelope_id=loaded.envelope.id,
            signer_id=signer.id,
            session_id=session.id,
            document_sha256=sha,
        )
        return pdf

    def record_viewed(self, db: Session, session: SessionInfo, pages_viewed: int, ctx: RequestContext) -> None:
        loaded, signer = self._load_for_session(db, session)
        transition = self._decide(loaded, Command.VIEW, signer.id)
        now = self._clock.now()

        # Nobody can have viewed what they were never shown, and the claim is only worth recording
        # against the bytes this session actually received.
        presented = repo.session_presented_sha(db, session.id)
        if presented is None:
            raise Conflict("the document has not been served to this session", code="not_presented")

        # The UI's claim is checked against the bytes this session was actually served, not
        # against a number the UI also supplied.
        page_count = self._documents.page_count(self._blobs.get(db, presented))
        if pages_viewed != page_count:
            raise ValidationFailed("every page must be displayed before continuing", code="pages_not_all_viewed")

        self._apply_envelope_transition(db, loaded, transition, now=now)
        repo.update_signer(
            db,
            signer.id,
            status=transition.signer_status,
            viewed_at=now,
            only_if_unset=frozenset({"viewed_at"}),
        )
        self._append(
            db,
            loaded.envelope.id,
            EventType.DOCUMENT_VIEWED,
            actor=_signer_actor(signer),
            ctx=ctx,
            document_sha256=presented,
            data={"signer_id": signer.id, "pages_viewed": pages_viewed, "page_count": page_count},
        )
        log.info("document.viewed", envelope_id=loaded.envelope.id, signer_id=signer.id, session_id=session.id)

    def accept_consent(
        self, db: Session, session: SessionInfo, consent_version: str, ctx: RequestContext, *, locale: str | None = None
    ) -> None:
        loaded, signer = self._load_for_session(db, session)
        transition = self._decide(loaded, Command.CONSENT, signer.id)
        now = self._clock.now()

        # The disclosure recorded is the one in the language the signer read it in.
        current = self._identity.current_consent(db, locale or self._settings.default_locale)
        if consent_version != current.version:
            # They agreed to a disclosure that is no longer current. Make them read the new one
            # rather than recording consent to text they were not shown.
            raise Conflict("the consent disclosure has changed", code="consent_version_stale")

        self._apply_envelope_transition(db, loaded, transition, now=now)
        repo.update_signer(
            db,
            signer.id,
            status=transition.signer_status,
            consent_text_id=current.id,
            consented_at=now,
            only_if_unset=frozenset({"consented_at"}),
        )
        self._append(
            db,
            loaded.envelope.id,
            EventType.CONSENT_ACCEPTED,
            actor=_signer_actor(signer),
            ctx=ctx,
            data={
                "signer_id": signer.id,
                "consent_text_id": current.id,
                "consent_version": current.version,
                "locale": current.locale,
                "body_sha256": current.body_sha256,
            },
        )
        log.info(
            "consent.accepted",
            envelope_id=loaded.envelope.id,
            signer_id=signer.id,
            consent_version=current.version,
            locale=current.locale,
        )

    def sign(self, db: Session, session: SessionInfo, captures: list[Capture], ctx: RequestContext) -> EnvelopeView:
        loaded, signer = self._load_for_session(db, session)
        transition = self._decide(loaded, Command.SIGN, signer.id)
        now = self._clock.now()

        reauth_method = self._require_fresh_reauth(db, signer, session)
        presented = repo.session_presented_sha(db, session.id)
        if presented is None:
            raise Conflict("the document has not been served to this session", code="not_presented")

        fields = parse_field_defs(loaded.template.fields)
        mine = tuple(f for f in fields if f.signer_role == signer.role_key)
        by_id = {f.id: f for f in fields}
        accepted = self._check_captures(fields, mine, captures, signer.role_key)

        base_sha = _require_revision(loaded.envelope.current_revision_sha256)
        base_pdf = self._blobs.get(db, base_sha)

        stamp = SignerStamp(
            signer_id=signer.id,
            display_name=signer.display_name,
            capacity=signer.capacity,
            on_behalf_of_label=signer.on_behalf_of,
            signed_at=now,  # server time; the client never supplies a date_signed value
        )
        stamped = self._documents.apply_signer_marks(base_pdf, list(mine), list(accepted), stamp)
        retain_until = self._settings.retain_until(loaded.envelope.document_type, now)
        revision = self._blobs.put(db, stamped, kind="revision_pdf", retain_until=retain_until)

        self._store_captures(db, signer.id, accepted, now, retain_until=retain_until)

        revision_no = repo.next_revision_no(db, loaded.envelope.id)
        repo.insert_revision(
            db,
            revision_id=new_id(),
            envelope_id=loaded.envelope.id,
            revision_no=revision_no,
            kind="signer_applied",
            sha256=revision.sha256,
            signer_id=signer.id,
            created_at=now,
        )
        repo.update_envelope(db, loaded.envelope.id, current_revision_sha256=revision.sha256)
        repo.update_signer(db, signer.id, status="signed", signed_at=now)

        self._append(
            db,
            loaded.envelope.id,
            EventType.SIGNER_SIGNED,
            actor=_signer_actor(signer),
            ctx=ctx,
            document_sha256=revision.sha256,
            data={
                "signer_id": signer.id,
                "role_key": signer.role_key,
                "capacity": signer.capacity,
                "consent_version": self._consent_version(db, signer),
                "reauth_used": reauth_method is not None,
                "reauth_method": reauth_method,
                # All three hashes, always: what this signer was shown, what they signed on top
                # of, and what came out. In a parallel envelope another signer may have moved the
                # document in between, and that has to be visible rather than smoothed over.
                "presented_sha256": presented,
                "base_revision_sha256": base_sha,
                "revision_no": revision_no,
                "revision_sha256": revision.sha256,
                "capture_count": len(accepted),
                "captures": [{"field_id": c.field_id, "kind": c.kind or by_id[c.field_id].type} for c in accepted],
            },
        )

        self._apply_envelope_transition(db, loaded, transition, now=now)
        if transition.completes_envelope:
            self._append(
                db,
                loaded.envelope.id,
                EventType.ENVELOPE_COMPLETED,
                actor=_signer_actor(signer),
                ctx=ctx,
                document_sha256=revision.sha256,
                data={
                    "signer_count": len(loaded.signers),
                    "revision_no": revision_no,
                    "final_revision_sha256": revision.sha256,
                },
            )
            repo.enqueue_seal_job(db, loaded.envelope.id, now)

        # Signing ends this signer's ability to act. The session they signed from survives, for the
        # copy download only (see may_download_copy); every other session they hold is revoked.
        revoked = self._identity.revoke_sessions(db, signer.id, except_session_id=session.id)

        log.info(
            "signer.signed",
            envelope_id=loaded.envelope.id,
            signer_id=signer.id,
            session_id=session.id,
            revision_no=revision_no,
            document_sha256=revision.sha256,
            presented_sha256=presented,
            capture_count=len(accepted),
            count=revoked,
            envelope_status=transition.envelope_status,
        )
        view = self._view(db, self._reload(db, loaded))
        if transition.completes_envelope:
            self._notify(db, "envelope.completed", view)
        return view

    def decline(self, db: Session, session: SessionInfo, reason_code: str, ctx: RequestContext) -> EnvelopeView:
        loaded, signer = self._load_for_session(db, session)
        transition = self._decide(loaded, Command.DECLINE, signer.id)
        if reason_code not in DECLINE_REASON_CODES:
            raise ValidationFailed("unknown decline reason", code="unknown_reason_code")
        now = self._clock.now()

        repo.update_signer(db, signer.id, status="declined", declined_at=now, decline_reason_code=reason_code)
        self._apply_envelope_transition(db, loaded, transition, now=now)
        self._append(
            db,
            loaded.envelope.id,
            EventType.SIGNER_DECLINED,
            actor=_signer_actor(signer),
            ctx=ctx,
            data={"signer_id": signer.id, "role_key": signer.role_key, "reason_code": reason_code},
        )
        # The envelope-level fact, stated rather than left to be inferred from the signer's event.
        self._append(
            db,
            loaded.envelope.id,
            EventType.ENVELOPE_DECLINED,
            actor=_signer_actor(signer),
            ctx=ctx,
            data={"signer_id": signer.id, "reason_code": reason_code},
        )
        repo.revoke_envelope_sessions(db, loaded.envelope.id, now)
        log.info(
            "signer.declined",
            envelope_id=loaded.envelope.id,
            signer_id=signer.id,
            decline_reason_code=reason_code,
        )
        view = self._view(db, self._reload(db, loaded))
        self._notify(db, "envelope.declined", view)
        return view

    # ----------------------------------------------------------------- host actions

    def void(self, db: Session, host: Host, envelope_id: UUID, reason_code: str, ctx: RequestContext) -> EnvelopeView:
        loaded = self._load(db, envelope_id, host=host, lock=True)
        transition = self._decide(loaded, Command.VOID, None)
        if reason_code not in VOID_REASON_CODES:
            raise ValidationFailed("unknown void reason", code="invalid_reason_code")
        now = self._clock.now()

        repo.update_envelope(
            db,
            envelope_id,
            status=transition.envelope_status,
            voided_at=now,
            void_reason_code=reason_code,
        )
        self._append(
            db,
            envelope_id,
            EventType.ENVELOPE_VOIDED,
            actor=Actor(user_id=None, role="host"),
            ctx=ctx,
            data={"reason_code": reason_code},
        )
        repo.revoke_envelope_sessions(db, envelope_id, now)
        log.info("envelope.voided", envelope_id=envelope_id, host_id=host.id, reason_code=reason_code)
        view = self._view(db, self._reload(db, loaded))
        self._notify(db, "envelope.voided", view)
        return view

    def expire_due(self, db: Session) -> int:
        now = self._clock.now()
        expired = 0
        for envelope_id in repo.due_envelope_ids(db, now):
            loaded = self._load(db, envelope_id, host=None, lock=True)
            if loaded.envelope.expires_at > now:
                continue  # it was extended between the sweep query and the lock
            decision = self._decide_or_none(loaded, Command.EXPIRE, None)
            if decision is None:
                continue  # it finished under us; that is not an error
            repo.update_envelope(db, envelope_id, status=decision.envelope_status)
            self._append(
                db,
                envelope_id,
                EventType.ENVELOPE_EXPIRED,
                actor=Actor(user_id=None, role="system"),
                ctx=RequestContext(),
                data={},
            )
            repo.revoke_envelope_sessions(db, envelope_id, now)
            log.info("envelope.expired", envelope_id=envelope_id)
            self._notify(db, "envelope.expired", self._view(db, self._reload(db, loaded)))
            expired += 1
        return expired

    # ----------------------------------------------------------------- sealing

    def seal_pending(self, db: Session, envelope_id: UUID) -> EnvelopeView:
        loaded = self._load(db, envelope_id, host=None, lock=True)
        transition = self._decide(loaded, Command.SEAL, None)
        try:
            return self._seal(db, loaded, transition)
        except Exception as exc:
            # Nothing of the attempt survives the caller's rollback -- that is the point. The
            # envelope stays completed_pending_seal and the failure is recorded in a step of its
            # own, so the trail still explains why nothing happened. That holds for the retryable
            # failures (SealUnavailable, StorageUnavailable) and equally for the ones that are
            # not: an integrity failure or a bug leaves the envelope pending, recorded and loud.
            self._on_seal_failure(envelope_id, exc.code if isinstance(exc, EsignError) else "internal_error")
            raise

    def _seal(self, db: Session, loaded: _Loaded, transition: Transition) -> EnvelopeView:
        envelope = loaded.envelope
        now = self._clock.now()
        final_revision_sha = _require_revision(envelope.current_revision_sha256)
        summary = self._certificate_summary(db, loaded, final_revision_sha)

        certificate = self._documents.build_certificate(summary)
        signed_pdf = self._blobs.get(db, final_revision_sha)
        final_unsealed = self._documents.finalize(signed_pdf, certificate)

        retain_until = self._settings.retain_until(envelope.document_type, now)
        unsealed = self._blobs.put(db, final_unsealed, kind="final_unsealed_pdf", retain_until=retain_until)
        unsealed_no = repo.next_revision_no(db, envelope.id)
        repo.insert_revision(
            db,
            revision_id=new_id(),
            envelope_id=envelope.id,
            revision_no=unsealed_no,
            kind="final_unsealed",
            sha256=unsealed.sha256,
            signer_id=None,
            created_at=now,
        )
        result = self._sealer.seal(final_unsealed, reason=_SEAL_REASON, envelope_id=envelope.id)

        # The sealer's own word is not enough. If its output does not validate then we are not
        # sealed, whatever it returned: stay pending, record why, let the job back off.
        validation = self._sealer.validate(result.sealed_pdf)
        if not validation.ok:
            log.error(
                "seal.validation_failed",
                envelope_id=envelope.id,
                seal_profile=result.profile,
                intact=validation.intact,
                covers_whole_document=validation.covers_whole_document,
                trusted=validation.trusted,
                timestamp_valid=validation.timestamp_valid,
                problems=list(validation.problems),
            )
            raise SealUnavailable("the seal did not validate", code="seal_validation_failed")

        sealed = self._blobs.put(db, result.sealed_pdf, kind="sealed_pdf", retain_until=retain_until)
        sealed_no = repo.next_revision_no(db, envelope.id)
        repo.insert_revision(
            db,
            revision_id=new_id(),
            envelope_id=envelope.id,
            revision_no=sealed_no,
            kind="sealed",
            sha256=sealed.sha256,
            signer_id=None,
            created_at=now,
        )
        repo.update_envelope(
            db,
            envelope.id,
            status=transition.envelope_status,
            sealed_sha256=sealed.sha256,
            sealed_at=now,
        )
        # The three events go in together, at the end. Nothing is appended to the envelope's audit
        # stream before this point, so a failed attempt holds no lock on that stream and the
        # separate session in _on_seal_failure can record seal.failed without waiting on it.
        self._append(
            db,
            envelope.id,
            EventType.DOCUMENT_FINALIZED,
            actor=_SYSTEM,
            ctx=RequestContext(),
            document_sha256=unsealed.sha256,
            data={
                "certificate_sha256": hashlib.sha256(certificate).digest(),
                "page_count": self._documents.page_count(final_unsealed),
                "size_bytes": unsealed.size_bytes,
                "audit_event_count": summary.audit_event_count,
                "audit_head_hash": summary.audit_head_hash,
            },
        )
        self._append(
            db,
            envelope.id,
            EventType.DOCUMENT_SEALED,
            actor=_SYSTEM,
            ctx=RequestContext(),
            document_sha256=sealed.sha256,
            data={
                "seal_profile": result.profile,
                "key_backend": self._settings.seal_key_backend,
                "signer_cert_sha256": result.signer_cert_sha256,
                "timestamp_time": result.timestamp_time,
                "size_bytes": sealed.size_bytes,
            },
        )
        self._append(
            db,
            envelope.id,
            EventType.DOCUMENT_STORED,
            actor=_SYSTEM,
            ctx=RequestContext(),
            document_sha256=sealed.sha256,
            data={
                "blob_kind": "sealed_pdf",
                "size_bytes": sealed.size_bytes,
                "retain_until": retain_until,
            },
        )
        repo.complete_seal_job(db, envelope.id, now)
        log.info(
            "document.sealed",
            envelope_id=envelope.id,
            seal_profile=result.profile,
            sealed_sha256=sealed.sha256,
            size_bytes=sealed.size_bytes,
        )
        view = self._view(db, self._reload(db, loaded))
        self._notify(db, "envelope.sealed", view)
        return view

    def _on_seal_failure(self, envelope_id: UUID, error_code: str) -> None:
        """Record ``seal.failed`` so it survives the rollback of the failed attempt.

        The attempt's own transaction is about to be rolled back by the caller, taking the unsealed
        revision and everything else with it -- which is correct, and is exactly why the event that
        explains the failure has to be written somewhere else. ``_seal`` appends nothing to the
        envelope's audit stream until the seal has validated, so the dying transaction holds no
        lock this session needs; it never touches the envelope row either.
        """
        if self._new_session is None:
            # No independent session was injected, so the failure can be reported but not
            # recorded. Say so loudly rather than implying the trail is complete.
            log.error("seal.failed_unrecorded", envelope_id=envelope_id, error_code=error_code)
            return
        try:
            with self._new_session() as fresh:
                # The failed attempt's transaction is still open and holds the envelope row lock,
                # and it is *this thread* that would have to release it -- so anything in here
                # that waited on that lock would wait forever, invisibly to Postgres's deadlock
                # detector. Nothing below should (the job row exists, so no foreign-key check
                # touches the envelope), but a bound turns "should not" into "cannot hang".
                fresh.execute(text("SET LOCAL lock_timeout = '5s'"))
                attempts = repo.seal_job_attempts(fresh, envelope_id) + 1
                delay = next_backoff(attempts)
                repo.fail_seal_job(
                    fresh,
                    envelope_id,
                    error_code=error_code,
                    next_attempt_at=self._clock.now() + delay,
                )
                self._append(
                    fresh,
                    envelope_id,
                    EventType.SEAL_FAILED,
                    actor=_SYSTEM,
                    ctx=RequestContext(),
                    data={
                        "error_code": error_code,
                        "attempt": attempts,
                        "retry_in_seconds": int(delay.total_seconds()),
                    },
                )
                fresh.commit()
            log.warning("seal.failed", envelope_id=envelope_id, error_code=error_code)
        except IntegrityFailure:
            raise
        except Exception:
            # Recording the failure must never mask the failure itself: the caller re-raises
            # SealUnavailable, the envelope stays completed_pending_seal, nothing reports complete.
            log.error("seal.failed_unrecorded", envelope_id=envelope_id, error_code=error_code)

    # ----------------------------------------------------------------- certificate

    def _certificate_summary(self, db: Session, loaded: _Loaded, final_revision_sha: bytes) -> CertificateSummary:
        envelope = loaded.envelope
        events = self._audit.list(db, "envelope", envelope.id)
        if not events:
            raise IntegrityFailure("the envelope has no audit trail", code="missing_audit_trail")

        signers = tuple(
            self._certificate_signer(db, loaded, row)
            for row in sorted(loaded.signers, key=lambda s: (s.order_index, s.role_key))
        )
        return CertificateSummary(
            envelope_id=envelope.id,
            document_type=envelope.document_type,
            template_key=loaded.template.template_key,
            template_version=loaded.template.version,
            # The configured profile: the certificate is inside the sealed bytes, so it is written
            # before the seal exists. The profile actually achieved is in document.sealed.
            seal_profile=self._settings.seal_profile,
            presented_sha256=_require_revision(envelope.presented_sha256),
            final_revision_sha256=final_revision_sha,
            created_at=envelope.created_at,
            completed_at=envelope.completed_at or self._clock.now(),
            signers=signers,
            audit_event_count=len(events),
            audit_head_hash=events[-1].event_hash,
        )

    def _certificate_signer(self, db: Session, loaded: _Loaded, row: repo.SignerRow) -> CertificateSigner:
        # Refuse to certify what the record does not actually show. Every one of these would mean
        # a certificate claiming evidence that is not there.
        if row.status != "signed":
            raise IntegrityFailure("a signer has not signed", code="incomplete_signer_evidence")
        if row.viewed_at is None or row.consented_at is None or row.signed_at is None:
            raise IntegrityFailure("a signer is missing a timestamp", code="incomplete_signer_evidence")
        if row.consent_text_id is None:
            raise IntegrityFailure("a signer has no recorded consent", code="incomplete_signer_evidence")

        evidence = repo.session_evidence(db, signer_id=row.id, at_or_before=row.signed_at)
        if evidence is None:
            raise IntegrityFailure("a signer has no recorded session", code="incomplete_signer_evidence")
        consent = self._identity.get_consent(db, row.consent_text_id)
        role = loaded.roles.get(row.role_key)

        return CertificateSigner(
            signer_id=row.id,
            display_name=row.display_name,
            role_label=role.label if role else row.role_key,
            capacity=row.capacity,
            auth_method=evidence.auth_method,
            reauth_method=repo.latest_reauth_method(db, evidence.session_id),
            consent_version=consent.version,
            viewed_at=row.viewed_at,
            consented_at=row.consented_at,
            signed_at=row.signed_at,
            ip=evidence.ip,
            user_agent=evidence.user_agent,
            kiosk_staff_user_id=evidence.kiosk_staff_user_id,
            kiosk_identity_check=evidence.kiosk_identity_check,
        )

    # ----------------------------------------------------------------- captures

    def _check_captures(
        self,
        all_fields: Sequence[FieldDef],
        mine: Sequence[FieldDef],
        captures: Sequence[Capture],
        role_key: str,
    ) -> tuple[Capture, ...]:
        """Validate what the client sent and return the sanitised captures to stamp.

        This happens before anything is stored or stamped, and it does not delegate the
        authorisation question to the document service: whether a field is this signer's is
        decided here, against the template, under the envelope lock.
        """
        by_id = {f.id: f for f in all_fields}
        mine_ids = {f.id for f in mine}

        seen: set[str] = set()
        accepted: list[Capture] = []
        for capture in captures:
            field = by_id.get(capture.field_id)
            if field is None:
                raise ValidationFailed("a capture names a field this template does not have", code="unknown_field")
            if field.signer_role != role_key or capture.field_id not in mine_ids:
                # SPEC 12: a capture for someone else's field is rejected.
                raise Forbidden("that field belongs to another signer", code="foreign_field")
            if capture.field_id in seen:
                raise ValidationFailed("a field was captured twice", code="duplicate_capture")
            seen.add(capture.field_id)
            if field.type == "date_signed":
                # SPEC 6: date_signed is filled by the server from Clock, never by the client.
                raise ValidationFailed("the signing date is set by the server", code="client_supplied_date")
            accepted.append(self._check_one(field, capture))

        missing = [f.id for f in mine if f.required and f.type != "date_signed" and f.id not in seen]
        if missing:
            raise ValidationFailed("a required field has no capture", code="missing_required_field")
        return tuple(accepted)

    def _check_one(self, field: FieldDef, capture: Capture) -> Capture:
        if field.type in SIGNABLE_FIELD_TYPES:
            if capture.checked is not None or capture.text_value is not None:
                raise ValidationFailed("a signature field takes a signature", code="capture_shape_invalid")
            if capture.kind == "drawn":
                if not capture.image_png or capture.typed_text is not None:
                    raise ValidationFailed("a drawn capture needs an image", code="capture_shape_invalid")
                # The client's bytes never reach the PDF: they are decoded, bounded and re-encoded
                # first, and it is the sanitised result that is stamped and stored.
                return Capture(
                    field_id=field.id, kind="drawn", image_png=self._documents.sanitize_signature_png(capture.image_png)
                )
            if capture.kind == "typed":
                if not capture.typed_text or not capture.typed_text.strip() or capture.image_png is not None:
                    raise ValidationFailed("a typed capture needs text", code="capture_shape_invalid")
                return Capture(field_id=field.id, kind="typed", typed_text=capture.typed_text.strip())
            if capture.kind == "click":
                if capture.image_png is not None or capture.typed_text is not None:
                    raise ValidationFailed("a click capture carries no payload", code="capture_shape_invalid")
                return Capture(field_id=field.id, kind="click")
            raise ValidationFailed("unknown capture kind", code="capture_shape_invalid")

        if field.type == "checkbox":
            if capture.checked is None:
                raise ValidationFailed("a checkbox field needs a checked value", code="capture_shape_invalid")
            return Capture(field_id=field.id, checked=capture.checked)

        if field.type == "text":
            if capture.text_value is None or not capture.text_value.strip():
                raise ValidationFailed("a text field needs a value", code="capture_shape_invalid")
            return Capture(field_id=field.id, text_value=capture.text_value)

        raise ValidationFailed("unsupported field type", code="capture_shape_invalid")

    def _store_captures(
        self, db: Session, signer_id: UUID, accepted: Sequence[Capture], now: datetime, *, retain_until: datetime
    ) -> None:
        """Row-level evidence for the signature marks themselves.

        Only signature marks get a row: ``signature_captures`` is shaped for them (its CHECK
        constraints tie ``kind`` to the payload), and the values of text and checkbox fields are
        evidence-covered by the revision hash instead.
        """
        for capture in accepted:
            if capture.kind == "drawn" and capture.image_png is not None:
                blob = self._blobs.put(db, capture.image_png, kind="signature_image", retain_until=retain_until)
                repo.insert_capture(
                    db,
                    capture_id=new_id(),
                    signer_id=signer_id,
                    field_id=capture.field_id,
                    kind="drawn",
                    image_sha256=blob.sha256,
                    typed_text=None,
                    created_at=now,
                )
            elif capture.kind == "typed" and capture.typed_text is not None:
                repo.insert_capture(
                    db,
                    capture_id=new_id(),
                    signer_id=signer_id,
                    field_id=capture.field_id,
                    kind="typed",
                    image_sha256=None,
                    typed_text=capture.typed_text,
                    created_at=now,
                )
            elif capture.kind == "click":
                repo.insert_capture(
                    db,
                    capture_id=new_id(),
                    signer_id=signer_id,
                    field_id=capture.field_id,
                    kind="click",
                    image_sha256=None,
                    typed_text=None,
                    created_at=now,
                )

    # ----------------------------------------------------------------- shared machinery

    def _resolve_template(self, db: Session, host: Host, spec: NewEnvelope) -> repo.TemplateVersionRow:
        found = repo.find_template_version(db, host_id=host.id, key=spec.template_key, version=spec.template_version)
        if found is None:
            # Another host's template and no template at all look the same on purpose (SPEC 10).
            raise NotFound("no such published template version", code="template_not_found")
        if found.status != "published":
            raise Conflict("that template version is not published", code="template_not_published")
        return found

    def _plan_signers(
        self, spec: NewEnvelope, roles: Sequence[SignerRoleDef], patient_ref: str
    ) -> tuple[tuple[NewSigner, SignerRoleDef], ...]:
        by_key = {role.key: role for role in roles}
        if not spec.signers:
            raise ValidationFailed("an envelope needs at least one signer", code="signers_required")

        planned: list[tuple[NewSigner, SignerRoleDef]] = []
        used: set[str] = set()
        for signer in spec.signers:
            role = by_key.get(signer.role_key)
            if role is None:
                raise ValidationFailed("a signer names a role this template does not declare", code="unknown_role")
            if signer.role_key in used:
                raise ValidationFailed("two signers share a role", code="duplicate_role")
            used.add(signer.role_key)
            if signer.capacity not in role.allowed_capacities:
                raise ValidationFailed("that capacity is not allowed for this role", code="capacity_not_allowed")
            # Stored stripped: a trailing space in a display name ends up in the caption on the
            # signature block, and from there in the sealed bytes.
            cleaned = replace(
                signer,
                display_name=_require_text(signer.display_name, "display_name_required", limit=200),
                # Becomes the audit actor: an identifier, never a name (the trail refuses those,
                # and it is better refused here than at the moment the person signs).
                host_user_id=_require_opaque(signer.host_user_id, "host_user_id_invalid"),
            )
            _check_on_behalf_of(cleaned, patient_ref)
            planned.append((cleaned, role))

        if [role.key for role in roles if role.required and role.key not in used]:
            # Every required role signs; only a role the template marks optional may be left out.
            raise ValidationFailed("the template declares a role with no signer", code="missing_required_role")
        return tuple(planned)

    def _resolve_expiry(self, requested: datetime | None, now: datetime) -> datetime:
        if requested is None:
            return self._settings.default_expiry(now)
        if requested.tzinfo is None:
            raise ValidationFailed("expires_at must carry a timezone", code="expires_at_invalid")
        if requested <= now:
            raise ValidationFailed("expires_at is already past", code="expires_at_invalid")
        return requested

    def _lock_superseded(self, db: Session, host: Host, envelope_id: UUID | None) -> repo.EnvelopeRow | None:
        if envelope_id is None:
            return None
        old = repo.lock_envelope(db, envelope_id)
        if old is None or old.host_id != host.id:
            raise NotFound("no such envelope", code="not_found")
        decision = decide(EnvelopeState(old.status, old.signing_order, ()), Command.SUPERSEDE)
        if isinstance(decision, Refusal):
            raise Conflict("only a sealed envelope can be superseded", code=decision.code)
        if repo.superseded_by(db, envelope_id) is not None:
            raise Conflict("that envelope has already been superseded", code="already_superseded")
        return old

    def _require_fresh_reauth(self, db: Session, signer: repo.SignerRow, session: SessionInfo) -> str | None:
        """``requires_reauth`` was copied from the template role at creation. Never from input."""
        if not signer.requires_reauth:
            return None
        fresh = self._identity.fresh_reauth(db, session.id)
        if fresh is None:
            raise Forbidden("this role must re-authenticate before signing", code="reauth_required")
        return fresh.method

    def _load(self, db: Session, envelope_id: UUID, *, host: Host | None, lock: bool) -> _Loaded:
        envelope = repo.lock_envelope(db, envelope_id) if lock else repo.load_envelope(db, envelope_id)
        if envelope is None or (host is not None and envelope.host_id != host.id):
            # A host asking about another host's envelope is told it does not exist (SPEC 10).
            raise NotFound("no such envelope", code="not_found")
        return self._hydrate(db, envelope)

    def _reload(self, db: Session, loaded: _Loaded) -> _Loaded:
        envelope = repo.load_envelope(db, loaded.envelope.id)
        if envelope is None:  # pragma: no cover - it was locked a moment ago
            raise NotFound("no such envelope", code="not_found")
        return self._hydrate(db, envelope)

    def _hydrate(self, db: Session, envelope: repo.EnvelopeRow) -> _Loaded:
        template = repo.load_template_version(db, envelope.template_version_id)
        if template is None:
            raise IntegrityFailure("the envelope's template version is missing", code="missing_template_version")
        return _Loaded(
            envelope=envelope,
            signers=repo.load_signers(db, envelope.id),
            roles={role.key: role for role in parse_signer_roles(template.signer_roles)},
            template=template,
        )

    def _load_for_session(self, db: Session, session: SessionInfo) -> tuple[_Loaded, repo.SignerRow]:
        """Load under the envelope lock, then check the session really belongs to this envelope."""
        loaded = self._load(db, session.envelope_id, host=None, lock=True)
        signer = repo.load_signer(db, session.signer_id)
        if signer is None or signer.envelope_id != loaded.envelope.id:
            raise NotFound("no such signer", code="not_found")
        self._refuse_if_past_expiry(loaded)
        return loaded, signer

    def _refuse_if_past_expiry(self, loaded: _Loaded) -> None:
        """An envelope past its date is over, whether or not the sweep has got to it yet.

        ``expire_due`` is a background job, and a background job that is not running must not be
        the only thing standing between a lapsed consent and a signature on it.
        """
        if loaded.envelope.status in LIVE_ENVELOPE_STATUSES and loaded.envelope.expires_at <= self._clock.now():
            raise Conflict("this envelope has expired", code="envelope_expired")

    @staticmethod
    def _signer_of(loaded: _Loaded, signer_id: UUID) -> repo.SignerRow:
        signer = next((s for s in loaded.signers if s.id == signer_id), None)
        if signer is None:
            raise NotFound("no such signer", code="not_found")
        return signer

    @staticmethod
    def _state(loaded: _Loaded) -> EnvelopeState:
        return EnvelopeState(
            status=loaded.envelope.status,
            signing_order=loaded.envelope.signing_order,
            signers=tuple(
                SignerState(signer_id=s.id, order_index=s.order_index, status=s.status) for s in loaded.signers
            ),
        )

    def _decide(self, loaded: _Loaded, command: Command, signer_id: UUID | None) -> Transition:
        decision = decide(self._state(loaded), command, signer_id=signer_id)
        if isinstance(decision, Refusal):
            raise Conflict("that is not possible in the envelope's current state", code=decision.code)
        return decision

    def _decide_or_none(self, loaded: _Loaded, command: Command, signer_id: UUID | None) -> Transition | None:
        decision = decide(self._state(loaded), command, signer_id=signer_id)
        return None if isinstance(decision, Refusal) else decision

    def _apply_envelope_transition(
        self, db: Session, loaded: _Loaded, transition: Transition, *, now: datetime
    ) -> None:
        if transition.envelope_status == loaded.envelope.status and not transition.completes_envelope:
            return
        repo.update_envelope(
            db,
            loaded.envelope.id,
            status=transition.envelope_status,
            completed_at=now if transition.completes_envelope else None,
        )

    def _append(
        self,
        db: Session,
        stream_id: UUID,
        event_type: EventType,
        *,
        actor: Actor,
        ctx: RequestContext,
        document_sha256: bytes | None = None,
        data: dict[str, Any] | None = None,
    ) -> None:
        payload = {key: value for key, value in (data or {}).items() if value is not None}
        self._audit.append(
            db,
            stream_type="envelope",
            stream_id=stream_id,
            event_type=event_type,
            actor=actor,
            ctx=ctx,
            document_sha256=document_sha256,
            data=payload,
        )

    def _view(self, db: Session, loaded: _Loaded) -> EnvelopeView:
        envelope = loaded.envelope
        return EnvelopeView(
            id=envelope.id,
            status=envelope.status,
            document_type=envelope.document_type,
            template_key=loaded.template.template_key,
            template_version=loaded.template.version,
            signing_order=envelope.signing_order,
            signers=tuple(self._signer_view(loaded, row) for row in loaded.signers),
            presented_sha256=envelope.presented_sha256,
            sealed_sha256=envelope.sealed_sha256,
            expires_at=envelope.expires_at,
            supersedes_envelope_id=envelope.supersedes_envelope_id,
            superseded_by_envelope_id=repo.superseded_by(db, envelope.id),
            current_revision_sha256=envelope.current_revision_sha256,
            created_at=envelope.created_at,
            host_id=envelope.host_id,
        )

    def _notify(self, db: Session, event: WebhookEvent, view: EnvelopeView) -> None:
        if self._notifier is not None:
            self._notifier.envelope_event(db, event=event, envelope=view)

    def _consent_version(self, db: Session, signer: repo.SignerRow) -> str:
        if signer.consent_text_id is None:  # pragma: no cover - the state machine requires consent first
            raise IntegrityFailure("a signer has no recorded consent", code="incomplete_signer_evidence")
        return self._identity.get_consent(db, signer.consent_text_id).version

    @staticmethod
    def _signer_view(loaded: _Loaded, row: repo.SignerRow) -> SignerView:
        role = loaded.roles.get(row.role_key)
        return SignerView(
            id=row.id,
            role_key=row.role_key,
            role_label=role.label if role else row.role_key,
            display_name=row.display_name,
            capacity=row.capacity,
            order_index=row.order_index,
            requires_reauth=row.requires_reauth,
            status=row.status,
        )


_SYSTEM: Final[Actor] = Actor(user_id=None, role="system")

_ACTOR_ROLE_BY_CAPACITY: Final[dict[Capacity, ActorRole]] = {
    "self": "patient",
    "guardian": "patient",
    "proxy": "patient",
    "witness": "staff",
    "interpreter": "staff",
    "clinician": "clinician",
}


def _signer_actor(signer: repo.SignerRow) -> Actor:
    return Actor(
        user_id=signer.host_user_id,
        role=_ACTOR_ROLE_BY_CAPACITY.get(signer.capacity, "patient"),
        capacity=signer.capacity,
        on_behalf_of=signer.on_behalf_of,
    )


def _check_on_behalf_of(signer: NewSigner, patient_ref: str) -> None:
    needs = signer.capacity in ("guardian", "proxy")
    if needs and not signer.on_behalf_of:
        raise ValidationFailed("a guardian or proxy must say who they act for", code="on_behalf_of_required")
    if not needs and signer.on_behalf_of:
        raise ValidationFailed("only a guardian or proxy acts on behalf of someone", code="on_behalf_of_not_allowed")
    if needs and signer.on_behalf_of != patient_ref:
        # The schema says on_behalf_of is the envelope's patient_ref. A different value would
        # attribute the signature to somebody who is not on this document.
        raise ValidationFailed("a guardian or proxy acts for this envelope's patient", code="on_behalf_of_mismatch")


def _require_text(value: str, code: str, *, limit: int) -> str:
    text_value = (value or "").strip()
    if not text_value or len(text_value) > limit:
        raise ValidationFailed("a required value is missing or too long", code=code)
    return text_value


def _require_opaque(value: str, code: str) -> str:
    text_value = (value or "").strip()
    if not is_opaque_id(text_value):
        raise ValidationFailed("an identifier must be opaque: no spaces, not a name or a date", code=code)
    return text_value


def _require_revision(sha: bytes | None) -> bytes:
    if sha is None:
        raise IntegrityFailure("the envelope has no current revision", code="missing_revision")
    return sha


def build_envelope_service(
    settings: Settings,
    clock: Clock,
    *,
    audit_log: AuditLog,
    blob_service: BlobService,
    document_service: DocumentService,
    identity_service: IdentityService,
    sealer: Sealer,
    new_session: SessionScope | None = None,
    notifier: EnvelopeNotifier | None = None,
) -> EnvelopeServiceImpl:
    """The module's one factory (SPEC section 2).

    ``new_session`` is how ``seal_pending`` records ``seal.failed`` in a step of its own: the
    failed attempt's transaction has to be rolled back to release its locks, so the event that
    explains the failure cannot be written inside it.
    """
    return EnvelopeServiceImpl(
        settings,
        clock,
        audit_log=audit_log,
        blob_service=blob_service,
        document_service=document_service,
        identity_service=identity_service,
        sealer=sealer,
        new_session=new_session,
        notifier=notifier,
    )
