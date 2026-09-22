"""Who is on the other end of the connection.

This module answers three questions and refuses to guess at any of them:

* **Which host is calling?** An ``esk_`` key, compared in constant time against a stored hash,
  ignoring disabled hosts.
* **Which signer is this session?** An ``est_`` token, bound to one signer, expiring on its own.
  Unknown, expired and revoked tokens are one indistinguishable ``Unauthorized``.
* **How recently did a human prove who they are?** The host's attestation of ``auth_time``, bounded
  by ``AUTH_MAX_AGE_SECONDS``, plus re-authentication attestations bounded by
  ``REAUTH_MAX_AGE_SECONDS``.

Everything here fails closed. An attestation that is in the future, older than the window, made
with a method we do not recognise, or that predates the session it claims to refresh, is rejected
rather than rounded into something acceptable. Nothing in this module reads the wall clock, and
nothing it writes to the database comes from the browser: ``ip`` and ``user_agent`` are captured
server-side and arrive through ``RequestContext``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Any, Final, cast, get_args
from uuid import UUID

from sqlalchemy import RowMapping, text
from sqlalchemy.orm import Session

from esign.config import Settings
from esign.contracts import (
    AdoptedRevokeReason,
    AdoptedSignature,
    AdoptedSignatureKind,
    AuthContext,
    AuthMethod,
    Clock,
    Conflict,
    ConsentText,
    Host,
    IdentityCheck,
    KioskContext,
    NotFound,
    ReauthEvidence,
    ReauthScope,
    RequestContext,
    SessionInfo,
    Unauthorized,
    ValidationFailed,
    is_opaque_id,
)
from esign.db import advisory_xact_lock
from esign.identity.adopted import adopt_signature as _adopt_signature
from esign.identity.adopted import live_adopted_signature
from esign.identity.adopted import revoke_adopted_signature as _revoke_adopted_signature
from esign.identity.client_ip import client_ip, parse_trusted_proxies
from esign.identity.consent_texts import normalise_locale, row_to_consent_text
from esign.identity.hosts import authenticate_host as _authenticate_host
from esign.identity.rows import opt_str, opt_time, raw_bytes, req_str, req_time, req_uuid
from esign.identity.tokens import SESSION_TOKEN_PREFIX, hashes_match, mint_token, parse_token, token_sha256
from esign.ids import advisory_lock_key, new_id
from esign.logging import get_logger

__all__ = ["AUTH_METHODS", "IDENTITY_CHECKS", "SqlIdentityService"]

#: The ways a host may say a user authenticated. Closed, because the value ends up on the
#: certificate of completion, and an open string there would be both unverifiable evidence and a
#: place free text could leak into.
AUTH_METHODS: Final[frozenset[str]] = frozenset(get_args(AuthMethod))

#: How staff established identity at a kiosk. Closed, for the same reason.
IDENTITY_CHECKS: Final[frozenset[str]] = frozenset(get_args(IdentityCheck))

#: ``staff_verified`` means a named member of staff vouched for the signer; without the kiosk
#: context naming them, the claim is unattributable and therefore worthless as evidence.
_KIOSK_REQUIRED_METHODS: Final = frozenset({"staff_verified"})

_MAX_STAFF_ID_CHARS: Final = 128
_MAX_USER_AGENT_CHARS: Final = 512

#: Every session query joins ``signers s`` and ``envelopes e``: ``SessionInfo`` carries whose
#: session it is (``host_id``, ``host_user_id``), and those come from the rows, never the request.
_SESSION_COLUMNS: Final = (
    "ss.id AS id, ss.signer_id AS signer_id, ss.token_hash AS token_hash, "
    "ss.auth_method AS auth_method, ss.auth_time AS auth_time, "
    "ss.kiosk_staff_user_id AS kiosk_staff_user_id, ss.kiosk_identity_check AS kiosk_identity_check, "
    "ss.created_at AS created_at, ss.expires_at AS expires_at, ss.revoked_at AS revoked_at, "
    "s.envelope_id AS envelope_id, s.host_user_id AS host_user_id, e.host_id AS host_id"
)
_SESSION_JOINS: Final = "JOIN signers s ON s.id = ss.signer_id JOIN envelopes e ON e.id = s.envelope_id"

#: What ``fresh_reauth`` reads, and the filters that hold in *every* scope (Addendum 1 C): the
#: attestation is not in the future, is no older than ``REAUTH_MAX_AGE_SECONDS`` (``:cutoff``),
#: does not predate the session it was made for, that session is still live, and its method is one
#: we recognise. All of it is re-checked here rather than trusted from write time, because
#: ``reauth_attestations`` is append-only: a row written by an older or buggier path can never be
#: corrected, only ignored. ``ras`` is the session the attestation was *made for*.
_ATTESTATION_COLUMNS: Final = "ra.id AS id, ra.method AS method, ra.auth_time AS auth_time"
_ATTESTATION_USABLE: Final = (
    "ras.revoked_at IS NULL AND ras.expires_at > :now "
    "AND ra.auth_time >= ras.created_at "
    "AND ra.auth_time <= :now "
    "AND ra.auth_time >= :cutoff "
    "AND ra.method = ANY(CAST(:methods AS text[]))"
)
_ATTESTATION_ORDER: Final = "ORDER BY ra.auth_time DESC, ra.attested_at DESC LIMIT 1"

#: Scope ``session``: an attestation made for the session asking. This is the whole of
#: ``fresh_reauth`` when the span is off, which is the default.
_OWN_ATTESTATION_SQL: Final = (
    f"SELECT {_ATTESTATION_COLUMNS} FROM reauth_attestations ra "  # noqa: S608 - fixed fragments only
    "JOIN signing_sessions ras ON ras.id = ra.session_id "
    f"WHERE ra.session_id = :id AND {_ATTESTATION_USABLE} {_ATTESTATION_ORDER}"
)

#: Scope ``span``: an attestation made for *another* live session of the same user on the same
#: host. The pair is read from the asking session's own signer and envelope rows, so a different
#: user or a different host can never match however the caller asks; a row from before ``0700``
#: has no pair at all and is never borrowed. The session asking must itself be live: a span is a
#: shortcut through the hand-off, never a way around an expired or revoked session.
_SPAN_ATTESTATION_SQL: Final = (
    f"SELECT {_ATTESTATION_COLUMNS} FROM reauth_attestations ra "  # noqa: S608 - fixed fragments only
    "JOIN signing_sessions ras ON ras.id = ra.session_id "
    "JOIN signing_sessions asking ON asking.id = :id "
    "JOIN signers s ON s.id = asking.signer_id "
    "JOIN envelopes e ON e.id = s.envelope_id "
    "WHERE ra.session_id <> :id "
    "  AND ra.host_id IS NOT NULL "
    "  AND ra.host_id = e.host_id "
    "  AND ra.host_user_id = s.host_user_id "
    "  AND asking.revoked_at IS NULL "
    "  AND asking.expires_at > :now "
    f"  AND {_ATTESTATION_USABLE} {_ATTESTATION_ORDER}"
)


def _log() -> Any:
    """A logger resolved per call.

    Deliberately not a module-level proxy: structlog caches the assembled logger on first use, and
    a cached logger keeps writing to whatever stream was configured then -- which outlives test
    capture, reconfiguration and log rotation alike.
    """
    return get_logger("esign.identity")


class SqlIdentityService:
    """``IdentityService`` over Postgres. One instance per process; it holds no per-request state."""

    def __init__(self, settings: Settings, clock: Clock) -> None:
        # Parse the proxy ranges once, here, so a typo in configuration fails at startup instead of
        # quietly changing which address every audit event records.
        parse_trusted_proxies(settings.trusted_proxy_cidrs)
        self._settings = settings
        self._clock = clock
        # Same reasoning: a default locale that is not a locale is a startup problem, not a
        # per-request surprise in the middle of a signing flow.
        self._default_locale = normalise_locale(settings.default_locale)

    # ----------------------------------------------------------------- hosts

    def authenticate_host(self, db: Session, bearer: str) -> Host:
        return _authenticate_host(db, bearer)

    # ----------------------------------------------------------------- sessions

    def create_session(
        self,
        db: Session,
        *,
        signer_id: UUID,
        auth: AuthContext,
        kiosk: KioskContext | None,
        ctx: RequestContext,
    ) -> tuple[str, SessionInfo]:
        """Open a signing session for one signer and return its token exactly once.

        Envelope state is deliberately not checked here: the envelopes module owns that question
        and answers it through ``assert_signer_may_start``, which the API calls first.
        """
        now = self._now()
        checked_auth = self._validate_auth(auth, now=now, max_age=self._settings.auth_max_age_seconds)
        checked_kiosk = self._validate_kiosk(kiosk, method=checked_auth.method)

        # Serialise per signer: two hosts opening a session at once must not leave two live ones.
        advisory_xact_lock(db, advisory_lock_key("identity.signer", signer_id))

        row = (
            db.execute(
                text(
                    "SELECT s.id AS id, s.envelope_id AS envelope_id, s.host_user_id AS host_user_id, "
                    "e.host_id AS host_id FROM signers s JOIN envelopes e ON e.id = s.envelope_id WHERE s.id = :id"
                ),
                {"id": signer_id},
            )
            .mappings()
            .first()
        )
        if row is None:
            raise NotFound("signer", code="signer_not_found")
        envelope_id = req_uuid(row, "envelope_id")

        self._revoke_live_sessions(db, signer_id, now)

        token = mint_token(SESSION_TOKEN_PREFIX)
        session_id = new_id()
        expires_at = now + timedelta(seconds=self._settings.session_ttl_seconds)
        db.execute(
            text(
                "INSERT INTO signing_sessions "
                "(id, signer_id, token_hash, auth_method, auth_time, kiosk_staff_user_id, "
                " kiosk_identity_check, ip, user_agent, created_at, expires_at) "
                "VALUES (:id, :signer_id, :token_hash, :auth_method, :auth_time, :staff_user_id, "
                "        :identity_check, CAST(:ip AS inet), :user_agent, :created_at, :expires_at)"
            ),
            {
                "id": session_id,
                "signer_id": signer_id,
                "token_hash": token_sha256(token),
                "auth_method": checked_auth.method,
                "auth_time": checked_auth.auth_time,
                "staff_user_id": checked_kiosk.staff_user_id if checked_kiosk else None,
                "identity_check": checked_kiosk.identity_check if checked_kiosk else None,
                "ip": _storable_ip(ctx.ip),
                "user_agent": _storable_user_agent(ctx.user_agent),
                "created_at": now,
                "expires_at": expires_at,
            },
        )
        _log().info(
            "identity.session_created",
            session_id=session_id,
            signer_id=signer_id,
            envelope_id=envelope_id,
            auth_method=checked_auth.method,
            kiosk=checked_kiosk is not None,
        )
        info = SessionInfo(
            id=session_id,
            signer_id=signer_id,
            envelope_id=envelope_id,
            auth=checked_auth,
            kiosk=checked_kiosk,
            expires_at=expires_at,
            host_id=req_uuid(row, "host_id"),
            host_user_id=req_str(row, "host_user_id"),
        )
        return token, info

    def authenticate_session(self, db: Session, bearer: str) -> SessionInfo:
        """Resolve a session token. Unknown, expired and revoked are the same failure."""
        token = parse_token(bearer, SESSION_TOKEN_PREFIX)
        if token is None:
            raise Unauthorized("invalid credentials")
        presented = token_sha256(token)
        row = (
            db.execute(
                text(
                    f"SELECT {_SESSION_COLUMNS} FROM signing_sessions ss "  # noqa: S608 - fixed column list
                    f"{_SESSION_JOINS} WHERE ss.token_hash = :token_hash"
                ),
                {"token_hash": presented},
            )
            .mappings()
            .first()
        )
        if row is None or not hashes_match(raw_bytes(row, "token_hash"), presented):
            raise Unauthorized("invalid credentials")
        if opt_time(row, "revoked_at") is not None:
            raise Unauthorized("invalid credentials")
        if self._now() >= req_time(row, "expires_at"):
            raise Unauthorized("invalid credentials")
        return _row_to_session_info(row)

    def revoke_sessions(self, db: Session, signer_id: UUID, *, except_session_id: UUID | None = None) -> int:
        """Revoke every live session for a signer, optionally sparing one. Idempotent."""
        return self._revoke_live_sessions(db, signer_id, self._now(), except_session_id=except_session_id)

    def _revoke_live_sessions(
        self, db: Session, signer_id: UUID, now: datetime, *, except_session_id: UUID | None = None
    ) -> int:
        result = db.execute(
            text(
                "UPDATE signing_sessions SET revoked_at = :now WHERE signer_id = :signer_id AND revoked_at IS NULL "
                "AND (CAST(:keep AS uuid) IS NULL OR id <> CAST(:keep AS uuid))"
            ),
            {"now": now, "signer_id": signer_id, "keep": except_session_id},
        )
        return int(getattr(result, "rowcount", 0) or 0)

    def session_host_id(self, db: Session, session_id: UUID) -> UUID:
        """The host that owns the envelope this session belongs to.

        ``attest_reauth`` takes no host, so the API layer authorises with this before calling it:
        one host must never be able to refresh another host's session.
        """
        row = (
            db.execute(
                text(
                    "SELECT e.host_id AS host_id FROM signing_sessions ss "
                    "JOIN signers s ON s.id = ss.signer_id "
                    "JOIN envelopes e ON e.id = s.envelope_id WHERE ss.id = :id"
                ),
                {"id": session_id},
            )
            .mappings()
            .first()
        )
        if row is None:
            raise NotFound("session", code="session_not_found")
        return req_uuid(row, "host_id")

    # ----------------------------------------------------------------- re-authentication

    def attest_reauth(self, db: Session, *, host: Host, session_id: UUID, auth: AuthContext) -> SessionInfo:
        """Record that the host re-authenticated the user for this session.

        A session that belongs to another host's envelope does not exist as far as this host is
        concerned: ``NotFound``, never ``Forbidden`` (SPEC section 10).

        Rejected, rather than recorded and ignored later: an attestation older than the
        re-authentication window, in the future, or predating the session itself. The table is
        append-only, so anything written here is written for good.
        """
        now = self._now()
        checked = self._validate_auth(auth, now=now, max_age=self._settings.reauth_max_age_seconds)
        row = (
            db.execute(
                text(
                    f"SELECT {_SESSION_COLUMNS} FROM signing_sessions ss "  # noqa: S608 - fixed column list
                    f"{_SESSION_JOINS} WHERE ss.id = :id"
                ),
                {"id": session_id},
            )
            .mappings()
            .first()
        )
        if row is None or req_uuid(row, "host_id") != host.id:
            raise NotFound("session", code="session_not_found")
        if opt_time(row, "revoked_at") is not None or now >= req_time(row, "expires_at"):
            raise Conflict("session is not live", code="session_not_live")
        if checked.auth_time < req_time(row, "created_at"):
            raise ValidationFailed("re-authentication predates the session", code="reauth_predates_session")
        # Whose attestation this is, copied from the session's signer and envelope rows and never
        # from the request (Addendum 1 C). It is what lets ``fresh_reauth`` find an attestation by
        # user within the span; ``0700`` leaves the rows written before it without the pair, and
        # those are never borrowed.
        db.execute(
            text(
                "INSERT INTO reauth_attestations "
                "(id, session_id, method, auth_time, attested_at, host_id, host_user_id) "
                "VALUES (:id, :session_id, :method, :auth_time, :attested_at, :host_id, :host_user_id)"
            ),
            {
                "id": new_id(),
                "session_id": session_id,
                "method": checked.method,
                "auth_time": checked.auth_time,
                "attested_at": now,
                "host_id": req_uuid(row, "host_id"),
                "host_user_id": req_str(row, "host_user_id"),
            },
        )
        _log().info("identity.reauth_attested", session_id=session_id, reauth_method=checked.method)
        return _row_to_session_info(row)

    def fresh_reauth(self, db: Session, session_id: UUID) -> ReauthEvidence | None:
        """The attestation that covers a signature in this session right now, or ``None``.

        This session's own attestation first (``scope="session"``). Only when there is none, and
        only when ``REAUTH_SPAN_SECONDS`` is above zero, the most recent one for the same
        ``(host_id, host_user_id)`` on another of that user's live sessions on the same host
        (``scope="span"``) -- the signing queue of Addendum 1 C. With the span off, which is the
        default, the answer is exactly what it was before the addendum.

        The span never reaches further back than ``REAUTH_MAX_AGE_SECONDS``: an attestation older
        than that covers nothing, span or no span. What the span weakens is *which document* an
        attestation covers, never *how old* it may be.
        """
        now = self._now()
        max_age_cutoff = now - timedelta(seconds=self._settings.reauth_max_age_seconds)
        own = self._attestation(db, _OWN_ATTESTATION_SQL, session_id, now=now, cutoff=max_age_cutoff)
        if own is not None:
            return own
        span_seconds = self._settings.reauth_span_seconds
        if span_seconds <= 0:
            # One attestation, one document. Nothing is borrowed unless a host has opted in.
            return None
        cutoff = max(max_age_cutoff, now - timedelta(seconds=span_seconds))
        return self._attestation(db, _SPAN_ATTESTATION_SQL, session_id, now=now, cutoff=cutoff, scope="span")

    def _attestation(
        self,
        db: Session,
        sql: str,
        session_id: UUID,
        *,
        now: datetime,
        cutoff: datetime,
        scope: ReauthScope = "session",
    ) -> ReauthEvidence | None:
        row = (
            db.execute(
                text(sql),
                {"id": session_id, "now": now, "cutoff": cutoff, "methods": sorted(AUTH_METHODS)},
            )
            .mappings()
            .first()
        )
        if row is None:
            return None
        method = req_str(row, "method")
        if method not in AUTH_METHODS:  # pragma: no cover - the query filters on the same set
            return None
        return ReauthEvidence(
            attestation_id=req_uuid(row, "id"),
            method=cast(AuthMethod, method),
            auth_time=req_time(row, "auth_time"),
            scope=scope,
        )

    # ----------------------------------------------------------------- adopted signatures

    def get_adopted_signature(self, db: Session, *, host_id: UUID, host_user_id: str) -> AdoptedSignature | None:
        """The user's one live saved signature, or ``None`` (Addendum 1 B).

        A pure lookup: asking about the right user is the caller's job, and every caller resolves
        the pair from rows -- the session for a signer, the path plus the authenticated host for a
        host -- never from a request body.
        """
        return live_adopted_signature(db, host_id=host_id, host_user_id=host_user_id)

    def adopt_signature(
        self,
        db: Session,
        session_id: UUID,
        *,
        kind: AdoptedSignatureKind,
        image_sha256: bytes | None = None,
        typed_text: str | None = None,
    ) -> AdoptedSignature:
        """Save the signature adopted in this session, for the session's own signer.

        Everything it enforces -- live non-kiosk session, the signer has signed, the payload
        matches the kind, one live row per user -- is in :mod:`esign.identity.adopted`.
        """
        adopted = _adopt_signature(
            db,
            session_id,
            kind=kind,
            image_sha256=image_sha256,
            typed_text=typed_text,
            now=self._now(),
            max_typed_chars=self._settings.max_typed_signature_chars,
        )
        # The saved signature's id belongs in the audit trail, which the API layer writes; a log
        # line says only that this session saved one, and of which kind.
        _log().info(
            "identity.signature_adopted",
            session_id=session_id,
            envelope_id=adopted.created_in_envelope_id,
            capture_kind=adopted.kind,
        )
        return adopted

    def revoke_adopted_signature(
        self, db: Session, *, host_id: UUID, host_user_id: str, reason: AdoptedRevokeReason
    ) -> AdoptedSignature | None:
        """Revoke the user's live saved signature, once. ``None`` when there was none."""
        revoked = _revoke_adopted_signature(
            db, host_id=host_id, host_user_id=host_user_id, reason=reason, now=self._now()
        )
        if revoked is not None:
            _log().info("identity.signature_adoption_revoked", host_id=host_id, reason_code=reason)
        return revoked

    # ----------------------------------------------------------------- consent

    def current_consent(self, db: Session, locale: str) -> ConsentText:
        """The disclosure in force for a locale, falling back to the configured default locale."""
        now = self._now()
        try:
            wanted = normalise_locale(locale)
        except ValidationFailed:
            # An unusable locale from the UI is not a reason to show nobody a disclosure.
            wanted = self._default_locale
        for candidate in dict.fromkeys((wanted, self._default_locale)):
            row = (
                db.execute(
                    text(
                        "SELECT id, version, locale, body, body_sha256 FROM consent_texts "
                        "WHERE locale = :locale AND effective_at <= :now "
                        "ORDER BY effective_at DESC, version DESC LIMIT 1"
                    ),
                    {"locale": candidate, "now": now},
                )
                .mappings()
                .first()
            )
            if row is not None:
                return row_to_consent_text(row)
        raise NotFound("no consent text is in force", code="consent_not_found")

    def get_consent(self, db: Session, consent_text_id: UUID) -> ConsentText:
        """One stored disclosure by id, checked against its recorded hash."""
        row = (
            db.execute(
                text("SELECT id, version, locale, body, body_sha256 FROM consent_texts WHERE id = :id"),
                {"id": consent_text_id},
            )
            .mappings()
            .first()
        )
        if row is None:
            raise NotFound("consent text", code="consent_not_found")
        return row_to_consent_text(row)

    # ----------------------------------------------------------------- request provenance

    def client_ip(self, peer: str | None, forwarded_for: str | None = None) -> str | None:
        """The address to record for a request, honouring ``TRUSTED_PROXY_CIDRS``."""
        return client_ip(peer, forwarded_for, self._settings.trusted_proxy_cidrs)

    # ----------------------------------------------------------------- internals

    def _now(self) -> datetime:
        value = self._clock.now()
        if value.tzinfo is None:
            raise ValueError("clock returned a naive datetime")
        return value.astimezone(UTC)

    def _validate_auth(self, auth: AuthContext, *, now: datetime, max_age: int) -> AuthContext:
        if auth.method not in AUTH_METHODS:
            raise ValidationFailed("unsupported authentication method", code="unsupported_auth_method")
        if auth.auth_time.tzinfo is None:
            raise ValidationFailed("auth_time must be timezone aware", code="invalid_auth_time")
        auth_time = auth.auth_time.astimezone(UTC)
        if auth_time > now:
            raise ValidationFailed("auth_time is in the future", code="auth_time_in_future")
        if now - auth_time > timedelta(seconds=max_age):
            raise ValidationFailed("authentication is too old", code="auth_too_old")
        return AuthContext(method=auth.method, auth_time=auth_time)

    def _validate_kiosk(self, kiosk: KioskContext | None, *, method: str) -> KioskContext | None:
        if kiosk is None:
            if method in _KIOSK_REQUIRED_METHODS:
                raise ValidationFailed(
                    "staff-verified sessions must name the staff member", code="kiosk_context_required"
                )
            return None
        staff_user_id = kiosk.staff_user_id.strip()
        if not staff_user_id or len(staff_user_id) > _MAX_STAFF_ID_CHARS:
            raise ValidationFailed("kiosk staff_user_id is empty or too long", code="invalid_kiosk_context")
        if not is_opaque_id(staff_user_id):
            # It is recorded in the audit trail, which only takes identifiers: never a staff name.
            raise ValidationFailed("kiosk staff_user_id must be an opaque identifier", code="invalid_kiosk_context")
        if kiosk.identity_check not in IDENTITY_CHECKS:
            raise ValidationFailed("unsupported kiosk identity check", code="invalid_kiosk_context")
        return KioskContext(staff_user_id=staff_user_id, identity_check=kiosk.identity_check)


# --------------------------------------------------------------------------- helpers


def _row_to_session_info(row: RowMapping) -> SessionInfo:
    staff_user_id = opt_str(row, "kiosk_staff_user_id")
    identity_check = opt_str(row, "kiosk_identity_check")
    kiosk = (
        KioskContext(staff_user_id=staff_user_id, identity_check=cast(IdentityCheck, identity_check))
        if staff_user_id is not None and identity_check is not None
        else None
    )
    return SessionInfo(
        id=req_uuid(row, "id"),
        signer_id=req_uuid(row, "signer_id"),
        envelope_id=req_uuid(row, "envelope_id"),
        auth=AuthContext(method=cast(AuthMethod, req_str(row, "auth_method")), auth_time=req_time(row, "auth_time")),
        kiosk=kiosk,
        expires_at=req_time(row, "expires_at"),
        host_id=req_uuid(row, "host_id"),
        host_user_id=req_str(row, "host_user_id"),
    )


def _storable_ip(value: str | None) -> str | None:
    """Only a real address reaches the ``inet`` column; anything else is recorded as absent."""
    if not value:
        return None
    try:
        return str(ip_address(value.strip()))
    except ValueError:
        return None


def _storable_user_agent(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.replace("\x00", "").strip()
    if not cleaned:
        return None
    return cleaned[:_MAX_USER_AGENT_CHARS]
