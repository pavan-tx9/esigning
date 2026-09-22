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
    AuditEvent,
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
            # The bytes, not just the fact. ``viewed`` is a signer-level status carried across
            # sessions, so without this a signer who read revision 1 in session 1 could sign
            # revision 2 in session 2 with no ``document.viewed`` covering what they signed.
            viewed_sha256=presented,
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
        if signer.viewed_sha256 != presented:
            # Presented but not *viewed*: these are the bytes this session was served, and the
            # signer has not said they read them. A fresh POST /viewed is the way forward.
            raise Conflict("this document has not been read in full", code="not_viewed")

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
                "captures": [_capture_ref(c, by_id[c.field_id]) for c in accepted],
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
            # Nothing of the attempt survives the rollback -- that is the point. The envelope stays
            # completed_pending_seal and the failure is recorded in a step of its own, so the trail
            # still explains why nothing happened. That holds for the retryable failures
            # (SealUnavailable, StorageUnavailable) and equally for the ones that are not: an
            # integrity failure or a bug leaves the envelope pending, recorded and loud.
            #
            # The rollback happens *here*, before the failure is recorded, rather than being left
            # to the caller. Once ``_seal`` has made its first append it holds the audit stream's
            # advisory lock for the rest of the transaction, and once it has touched ``seal_jobs``
            # it holds that row -- and it is this thread that would have to release them. The
            # separate session would then wait on locks only it can free, hit its 5s
            # ``lock_timeout`` and abort, leaving no ``seal.failed`` in the trail at all.
            db.rollback()
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

        The attempt's own transaction has already been rolled back by ``seal_pending``, taking the
        unsealed revision, the envelope row lock, the audit stream's advisory lock and the seal-job
        row lock with it -- which is correct, and is exactly why the event that explains the
        failure has to be written somewhere else, and why it has to be written *after* the
        rollback rather than alongside a transaction still holding what it needs.
        """
        if self._new_session is None:
            # No independent session was injected, so the failure can be reported but not
            # recorded. Say so loudly rather than implying the trail is complete.
            log.error("seal.failed_unrecorded", envelope_id=envelope_id, error_code=error_code)
            return
        try:
            with self._new_session() as fresh:
                # ``seal_pending`` has rolled the attempt back, so nothing here should wait on a
                # lock only this thread could release. The bound stays anyway: it turns "should
                # not" into "cannot hang", invisibly to Postgres's deadlock detector.
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
        """Build the certificate of completion from the audit trail (SPEC section 3, step 7).

        The mutable rows -- ``signers``, ``signing_sessions``, ``envelopes`` -- are a convenience
        copy of facts the append-only trail already holds. They are still fully UPDATE-able by the
        runtime role, and a delayed seal (a KMS or TSA outage backs off for hours) leaves a window
        in which one of them could be rewritten and then printed into bytes that can never be
        re-sealed. So every dated fact on the certificate is read from the event that recorded it,
        the rows are compared against those events, and a disagreement stops the seal
        (``certificate_evidence_mismatch``) instead of being certified.
        """
        envelope = loaded.envelope

        # The certificate quotes the trail's length and head hash as evidence, and the seal makes
        # that quotation permanent: there is no delete path and no second seal. So the chain is
        # re-verified here, before anything is certified. A broken chain is an IntegrityFailure,
        # which leaves the envelope completed_pending_seal with seal.failed recorded -- pending,
        # recorded and loud (SPEC section 3), rather than sealed around a false claim.
        chain = self._audit.verify(db, "envelope", envelope.id)
        if not chain.ok:
            log.error(
                "seal.audit_chain_broken",
                envelope_id=envelope.id,
                audit_event_count=chain.event_count,
                problems=list(chain.problems),
            )
            raise IntegrityFailure("the envelope's audit chain does not verify", code="audit_chain_broken")
        if chain.event_count == 0 or chain.head_hash is None:
            raise IntegrityFailure("the envelope has no audit trail", code="missing_audit_trail")

        events = self._audit.list(db, "envelope", envelope.id)

        completed = _last_event(events, EventType.ENVELOPE_COMPLETED)
        if completed is None:
            raise IntegrityFailure("the envelope has no completion event", code="missing_completed_at")
        if envelope.completed_at is None:
            # Every path into completed_pending_seal writes completed_at in the same transaction,
            # so this cannot happen -- and if it does, the honest answer is to refuse rather than
            # to put the current time on the certificate as though it were the completion time.
            raise IntegrityFailure("the envelope has no completion time", code="missing_completed_at")
        _require_agreement(envelope.id, None, "envelopes.completed_at", envelope.completed_at, completed.occurred_at)

        prepared = _first_event(events, EventType.DOCUMENT_PREPARED)
        presented_sha = _require_revision(envelope.presented_sha256)
        if prepared is None or prepared.document_sha256 != presented_sha:
            raise IntegrityFailure(
                "the presented revision does not match document.prepared", code="certificate_evidence_mismatch"
            )

        signers = tuple(
            self._certificate_signer(db, loaded, events, row)
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
            presented_sha256=presented_sha,
            final_revision_sha256=final_revision_sha,
            created_at=envelope.created_at,
            completed_at=completed.occurred_at,
            signers=signers,
            audit_event_count=chain.event_count,
            audit_head_hash=chain.head_hash,
        )

    def _certificate_signer(
        self, db: Session, loaded: _Loaded, events: Sequence[AuditEvent], row: repo.SignerRow
    ) -> CertificateSigner:
        # Refuse to certify what the record does not actually show. Every one of these would mean
        # a certificate claiming evidence that is not there.
        if row.status != "signed":
            raise IntegrityFailure("a signer has not signed", code="incomplete_signer_evidence")
        if row.viewed_at is None or row.consented_at is None or row.signed_at is None:
            raise IntegrityFailure("a signer is missing a timestamp", code="incomplete_signer_evidence")
        if row.consent_text_id is None:
            raise IntegrityFailure("a signer has no recorded consent", code="incomplete_signer_evidence")

        signed = _one_event(events, EventType.SIGNER_SIGNED, row.id)
        # The rows keep the *first* view and the *first* consent (``only_if_unset``), so the
        # earliest event of each kind is the one they are a copy of.
        viewed = _first_event(events, EventType.DOCUMENT_VIEWED, row.id)
        consented = _first_event(events, EventType.CONSENT_ACCEPTED, row.id)
        if signed is None or viewed is None or consented is None:
            raise IntegrityFailure("a signer's trail is incomplete", code="incomplete_signer_evidence")

        mismatch = (loaded.envelope.id, row.id)
        _require_agreement(*mismatch, "signers.viewed_at", row.viewed_at, viewed.occurred_at)
        _require_agreement(*mismatch, "signers.consented_at", row.consented_at, consented.occurred_at)
        _require_agreement(*mismatch, "signers.signed_at", row.signed_at, signed.occurred_at)
        _require_same(*mismatch, "signers.role_key", row.role_key, signed.data.get("role_key"))
        _require_same(*mismatch, "signers.capacity", row.capacity, signed.data.get("capacity"))

        consent = self._identity.get_consent(db, row.consent_text_id)
        _require_same(
            *mismatch, "signers.consent_text_id", str(row.consent_text_id), consented.data.get("consent_text_id")
        )
        _require_same(*mismatch, "consent version", consent.version, consented.data.get("consent_version"))

        # Where the signer actually was. The signing session's ``ip``/``user_agent`` columns are the
        # *host backend's* -- it is the host that opens the session, server to server -- so reading
        # them here would print the EHR's address and its HTTP client on every patient's
        # certificate. ``signer.signed`` carries the context of the signer's own request.
        ip = signed.ctx.ip
        user_agent = signed.ctx.user_agent

        # How the person authenticated, and the kiosk context, are the *host's* attestation, not
        # the browser's: the append-only ``session.created`` event is their record, and the session
        # row is the fallback. Where both exist they must agree.
        session_event = _session_created_for(events, signed)
        attested = repo.session_attestation(db, signer_id=row.id, at_or_before=signed.occurred_at)
        auth_method = _attested_value(
            *mismatch, "auth_method", session_event, "auth_method", None if attested is None else attested.auth_method
        )
        if not auth_method:
            raise IntegrityFailure("a signer's trail records no authentication", code="incomplete_signer_evidence")
        kiosk_staff_user_id = _attested_value(
            *mismatch,
            "kiosk_staff_user_id",
            session_event,
            "kiosk_staff_user_id",
            None if attested is None else attested.kiosk_staff_user_id,
        )
        kiosk_identity_check = _attested_value(
            *mismatch,
            "kiosk_identity_check",
            session_event,
            "kiosk_identity_check",
            None if attested is None else attested.kiosk_identity_check,
        )

        role = loaded.roles.get(row.role_key)
        return CertificateSigner(
            signer_id=row.id,
            # Not in the trail, and cannot be: a display name is PHI and the audit allowlist
            # refuses it. The certificate is inside the sealed bytes, where PHI belongs.
            display_name=row.display_name,
            role_label=role.label if role else row.role_key,
            capacity=row.capacity,
            auth_method=auth_method,
            # The method actually used for *this* signature, not the newest attestation on the
            # session: a host can still POST /reauth while the copy-download session is alive, and
            # a role that does not require re-authentication never used one (SPEC section 6).
            reauth_method=_reauth_method(signed, requires_reauth=row.requires_reauth),
            consent_version=consent.version,
            viewed_at=viewed.occurred_at,
            consented_at=consented.occurred_at,
            signed_at=signed.occurred_at,
            ip=ip,
            user_agent=user_agent,
            kiosk_staff_user_id=kiosk_staff_user_id,
            kiosk_identity_check=kiosk_identity_check,
        )

    def assert_reauth_allowed(self, db: Session, envelope_id: UUID, signer_id: UUID) -> None:
        """Refuse a re-authentication attestation that cannot belong to a signature.

        The identity module only checks that the session is live, and the session a signer signed
        from deliberately stays live so they can download their copy. Without this, a host could
        attest re-authentication after the signature, for a role that never needed one, or against
        an envelope that is already sealed -- and each of those appends ``auth.reauthenticated`` to
        an append-only trail where it can never be corrected.
        """
        loaded = self._load(db, envelope_id, host=None, lock=True)
        signer = self._signer_of(loaded, signer_id)
        if loaded.envelope.status not in ("created", "in_progress"):
            raise Conflict("this envelope is no longer being signed", code="envelope_not_live")
        if signer.status in ("signed", "declined"):
            raise Conflict("this signer has finished", code="signer_finished")
        if not signer.requires_reauth:
            raise Conflict("this role does not re-authenticate", code="reauth_not_required")

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
        if not accepted:
            # A signature with no marks is not evidence of anything: the bytes that come out are
            # the bytes that went in, and `signer.signed` would claim a signature the document
            # does not carry. Reachable whenever every one of this signer's fields is optional.
            raise ValidationFailed("a signature needs at least one mark", code="no_captures")
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
                return Capture(
                    field_id=field.id,
                    kind="typed",
                    typed_text=_require_text(
                        capture.typed_text, "capture_shape_invalid", limit=self._settings.max_typed_signature_chars
                    ),
                )
            if capture.kind == "click":
                if capture.image_png is not None or capture.typed_text is not None:
                    raise ValidationFailed("a click capture carries no payload", code="capture_shape_invalid")
                return Capture(field_id=field.id, kind="click")
            raise ValidationFailed("unknown capture kind", code="capture_shape_invalid")

        if field.type == "checkbox":
            if capture.checked is None:
                raise ValidationFailed("a checkbox field needs a checked value", code="capture_shape_invalid")
            if capture.text_value is not None:
                raise ValidationFailed("a checkbox field takes a checked value", code="capture_shape_invalid")
            _refuse_signature_payload(capture)
            return Capture(field_id=field.id, checked=capture.checked)

        if field.type == "text":
            if capture.text_value is None or not capture.text_value.strip():
                raise ValidationFailed("a text field needs a value", code="capture_shape_invalid")
            if capture.checked is not None:
                raise ValidationFailed("a text field takes a text value", code="capture_shape_invalid")
            _refuse_signature_payload(capture)
            return Capture(
                field_id=field.id,
                text_value=_require_text(
                    capture.text_value, "capture_shape_invalid", limit=self._settings.max_text_field_chars
                ),
            )

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


def _refuse_signature_payload(capture: Capture) -> None:
    """A checkbox or text capture carries no signature payload -- and, crucially, no ``kind``.

    ``Capture.kind`` is documented as "signature and initials fields only; None for checkbox/text",
    and the ``signer.signed`` event records ``kind or <the template's field type>``. Accepting a
    client-supplied ``kind`` here would therefore let the browser decide how the trail says a
    checkbox was filled ("click" instead of "checkbox"). SPEC section 4: nothing in an audit row
    comes from client JSON except through validated, typed fields. So the shape is refused rather
    than ignored, and the trail's capture kind always comes from the template.
    """
    if capture.kind is not None:
        raise ValidationFailed("this field takes no signature kind", code="capture_shape_invalid")
    if capture.image_png is not None or capture.typed_text is not None:
        raise ValidationFailed("this field takes no signature payload", code="capture_shape_invalid")


def _capture_ref(capture: Capture, field: FieldDef) -> dict[str, Any]:
    """What the trail records about one capture: the field, how it was filled, and a digest.

    The digest is what ties the row in ``signature_captures`` to the hash chain. The value itself
    never goes in: a typed signature is a name, and a drawn one is an image.
    """
    ref: dict[str, Any] = {"field_id": capture.field_id, "kind": capture.kind or field.type}
    if capture.image_png is not None:
        # The same value ``BlobService.put`` will key the image by: it is content-addressed.
        ref["image_sha256"] = hashlib.sha256(capture.image_png).digest()
    if capture.typed_text is not None:
        ref["typed_text_sha256"] = hashlib.sha256(capture.typed_text.encode("utf-8")).digest()
    return ref


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


# --------------------------------------------------------------------------- trail-sourced evidence

#: How far a mutable row's timestamp may sit from the event that recorded the same fact.
#:
#: They are written in one transaction but from two ``Clock`` reads, so they differ by microseconds
#: under a real clock. A minute is far wider than that and far narrower than any rewrite worth
#: detecting: an ``UPDATE signers SET signed_at = ...`` that matters moves the time by more.
_EVIDENCE_TOLERANCE: Final = timedelta(seconds=60)


def _matches_signer(event: AuditEvent, signer_id: UUID | None) -> bool:
    return signer_id is None or str(event.data.get("signer_id")) == str(signer_id)


def _first_event(
    events: Sequence[AuditEvent], event_type: EventType, signer_id: UUID | None = None
) -> AuditEvent | None:
    return next((e for e in events if e.event_type == event_type and _matches_signer(e, signer_id)), None)


def _last_event(
    events: Sequence[AuditEvent], event_type: EventType, signer_id: UUID | None = None
) -> AuditEvent | None:
    found = [e for e in events if e.event_type == event_type and _matches_signer(e, signer_id)]
    return found[-1] if found else None


def _one_event(events: Sequence[AuditEvent], event_type: EventType, signer_id: UUID) -> AuditEvent | None:
    """The single event of this type for this signer, or ``None`` if there is not exactly one.

    Two ``signer.signed`` events for one signer would mean the envelope lock failed to serialise
    two signatures, which is not a thing to average over on a certificate.
    """
    found = [e for e in events if e.event_type == event_type and _matches_signer(e, signer_id)]
    return found[0] if len(found) == 1 else None


def _session_created_for(events: Sequence[AuditEvent], signed: AuditEvent) -> AuditEvent | None:
    """The ``session.created`` event for the session this signature came from.

    Matched by session id where the signing request carried one; otherwise the most recent session
    opened for this signer at or before the signature.
    """
    created = [
        e
        for e in events
        if e.event_type == EventType.SESSION_CREATED and _matches_signer(e, _opt_uuid(signed.data.get("signer_id")))
    ]
    if signed.ctx.session_id is not None:
        exact = [e for e in created if e.ctx.session_id == signed.ctx.session_id]
        if exact:
            return exact[-1]
    earlier = [e for e in created if e.occurred_at <= signed.occurred_at]
    return earlier[-1] if earlier else None


def _attested_value(
    envelope_id: UUID,
    signer_id: UUID | None,
    what: str,
    session_event: AuditEvent | None,
    key: str,
    row_value: str | None,
) -> str | None:
    """One value the host attested when it opened the session.

    The append-only ``session.created`` event is the record; ``signing_sessions`` is a mutable copy
    of it. Where both are present they must agree, and where only the row is (a trail written
    before the API owned this event) the row stands.
    """
    from_event = None if session_event is None else _opt_str(session_event.data.get(key))
    if session_event is None:
        return row_value
    if row_value is not None and from_event != row_value:
        _mismatch(envelope_id, signer_id, f"signing_sessions.{what}")
    return from_event


def _reauth_method(signed: AuditEvent, *, requires_reauth: bool) -> str | None:
    if not requires_reauth or not signed.data.get("reauth_used"):
        return None
    return _opt_str(signed.data.get("reauth_method"))


def _opt_str(value: Any) -> str | None:
    return None if value is None else str(value)


def _opt_uuid(value: Any) -> UUID | None:
    if value is None:
        return None
    return value if isinstance(value, UUID) else UUID(str(value))


def _mismatch(envelope_id: UUID, signer_id: UUID | None, what: str) -> None:
    log.error(
        "seal.certificate_evidence_mismatch",
        envelope_id=envelope_id,
        signer_id=signer_id,
        problem=what,
    )
    raise IntegrityFailure("a stored row disagrees with the audit trail", code="certificate_evidence_mismatch")


def _require_agreement(
    envelope_id: UUID, signer_id: UUID | None, what: str, row_value: datetime, event_value: datetime
) -> None:
    if abs(row_value - event_value) > _EVIDENCE_TOLERANCE:
        _mismatch(envelope_id, signer_id, what)


def _require_same(envelope_id: UUID, signer_id: UUID | None, what: str, row_value: Any, event_value: Any) -> None:
    if event_value is None or str(row_value) != str(event_value):
        _mismatch(envelope_id, signer_id, what)


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
