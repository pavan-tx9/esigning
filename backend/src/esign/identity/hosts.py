"""Host registration and API-key authentication.

A host is an EHR deployment that calls the server-to-server API. It is identified by one key,
``esk_...``, which is shown once when it is created or rotated and stored only as a SHA-256 hash.

``allowed_origins`` is not decoration: it becomes the ``frame-ancestors`` CSP that decides who may
embed the signing UI, so it is validated here rather than wherever it is later interpolated.
"""

from __future__ import annotations

import secrets
from datetime import datetime
from typing import Final
from urllib.parse import urlsplit
from uuid import UUID

from sqlalchemy import RowMapping, text
from sqlalchemy.orm import Session

from esign.contracts import Clock, Host, NotFound, Unauthorized, ValidationFailed
from esign.identity.rows import req_str, req_uuid, str_tuple, to_utc
from esign.identity.tokens import HOST_KEY_PREFIX, hashes_match, mint_token, parse_token, token_sha256
from esign.ids import new_id

__all__ = [
    "authenticate_host",
    "create_host",
    "disable_host",
    "embedding_origins",
    "normalise_origin",
    "rotate_host_key",
    "rotate_webhook_secret",
    "webhook_target",
]

_MAX_NAME_CHARS: Final = 200
_MAX_ORIGINS: Final = 20
_MAX_ORIGIN_CHARS: Final = 255
_MAX_WEBHOOK_URL_CHARS: Final = 500
_LOOPBACK_HOSTS: Final = frozenset({"localhost", "127.0.0.1", "[::1]", "::1"})
_WEBHOOK_SECRET_BYTES: Final = 32


def _row_to_host(row: RowMapping) -> Host:
    return Host(id=req_uuid(row, "id"), name=req_str(row, "name"), allowed_origins=str_tuple(row, "allowed_origins"))


def normalise_origin(origin: str) -> str:
    """An origin is scheme + host + optional port, and nothing else.

    ``https://ehr.example.org`` is an origin. ``https://ehr.example.org/sign`` is not, and neither
    is ``*``: a wildcard here would let any page on the internet frame a signing session.
    """
    candidate = origin.strip().rstrip("/")
    if not candidate or len(candidate) > _MAX_ORIGIN_CHARS:
        raise ValidationFailed("origin is empty or too long", code="invalid_origin")
    parts = urlsplit(candidate)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValidationFailed("origin must be http(s)://host[:port]", code="invalid_origin")
    if parts.path or parts.query or parts.fragment or parts.username or parts.password:
        raise ValidationFailed("origin must not carry a path, query or credentials", code="invalid_origin")
    hostname = (parts.hostname or "").lower()
    if not hostname or "*" in hostname:
        raise ValidationFailed("origin must name one host", code="invalid_origin")
    if parts.scheme == "http" and hostname not in _LOOPBACK_HOSTS:
        raise ValidationFailed("only loopback origins may use http", code="invalid_origin")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValidationFailed("origin port is not a number", code="invalid_origin") from exc
    host_part = f"[{hostname}]" if ":" in hostname else hostname
    return f"{parts.scheme}://{host_part}" + (f":{port}" if port else "")


def _normalise_origins(origins: tuple[str, ...] | list[str]) -> list[str]:
    if len(origins) > _MAX_ORIGINS:
        raise ValidationFailed("too many allowed origins", code="invalid_origin")
    seen: list[str] = []
    for origin in origins:
        normalised = normalise_origin(origin)
        if normalised not in seen:
            seen.append(normalised)
    return seen


def _validate_webhook_url(url: str | None) -> str | None:
    if url is None:
        return None
    candidate = url.strip()
    if not candidate:
        return None
    if len(candidate) > _MAX_WEBHOOK_URL_CHARS:
        raise ValidationFailed("webhook url is too long", code="invalid_webhook_url")
    parts = urlsplit(candidate)
    hostname = (parts.hostname or "").lower()
    if parts.scheme not in ("http", "https") or not hostname:
        raise ValidationFailed("webhook url must be http(s)", code="invalid_webhook_url")
    if parts.scheme == "http" and hostname not in _LOOPBACK_HOSTS:
        raise ValidationFailed("webhook url must use https", code="invalid_webhook_url")
    return candidate


def _validate_name(name: str) -> str:
    cleaned = " ".join(name.split())
    if not cleaned or len(cleaned) > _MAX_NAME_CHARS:
        raise ValidationFailed("host name is empty or too long", code="invalid_host_name")
    return cleaned


def create_host(
    db: Session,
    name: str,
    allowed_origins: tuple[str, ...] | list[str] = (),
    webhook_url: str | None = None,
    *,
    clock: Clock,
) -> tuple[str, Host]:
    """Register a host and mint its first key.

    Returns ``(key, host)``. The key is the only copy: it is not stored, cannot be recovered, and
    ``esign hosts create`` prints it once. A webhook URL also mints the HMAC secret the webhooks
    module signs deliveries with; :func:`rotate_webhook_secret` returns it when the host needs it.
    """
    clean_name = _validate_name(name)
    origins = _normalise_origins(allowed_origins)
    webhook = _validate_webhook_url(webhook_url)
    key = mint_token(HOST_KEY_PREFIX)
    host_id = new_id()
    row = (
        db.execute(
            text(
                "INSERT INTO hosts (id, name, api_key_hash, allowed_origins, webhook_url, webhook_secret, created_at) "
                "VALUES (:id, :name, :key_hash, :origins, :webhook_url, :webhook_secret, :created_at) "
                "RETURNING id, name, allowed_origins"
            ),
            {
                "id": host_id,
                "name": clean_name,
                "key_hash": token_sha256(key),
                "origins": origins,
                "webhook_url": webhook,
                "webhook_secret": secrets.token_bytes(_WEBHOOK_SECRET_BYTES) if webhook else None,
                "created_at": _now(clock),
            },
        )
        .mappings()
        .one()
    )
    return key, _row_to_host(row)


def rotate_host_key(db: Session, host_id: UUID) -> tuple[str, Host]:
    """Mint a new key for a host. The previous key stops working immediately."""
    key = mint_token(HOST_KEY_PREFIX)
    row = (
        db.execute(
            text(
                "UPDATE hosts SET api_key_hash = :key_hash "
                "WHERE id = :id AND disabled_at IS NULL "
                "RETURNING id, name, allowed_origins"
            ),
            {"id": host_id, "key_hash": token_sha256(key)},
        )
        .mappings()
        .first()
    )
    if row is None:
        raise NotFound("host", code="host_not_found")
    return key, _row_to_host(row)


def rotate_webhook_secret(db: Session, host_id: UUID) -> bytes:
    """Mint a new webhook signing secret and return it once, for the CLI to print."""
    secret = secrets.token_bytes(_WEBHOOK_SECRET_BYTES)
    updated = db.execute(
        text("UPDATE hosts SET webhook_secret = :secret WHERE id = :id AND disabled_at IS NULL RETURNING id"),
        {"id": host_id, "secret": secret},
    ).first()
    if updated is None:
        raise NotFound("host", code="host_not_found")
    return secret


def webhook_target(db: Session, host_id: UUID) -> tuple[str, bytes] | None:
    """Where, and with which secret, to deliver this host's webhooks. ``None`` when the host has no
    webhook configured or has been disabled: nothing is sent to a host that can no longer call us."""
    row = (
        db.execute(
            text("SELECT webhook_url, webhook_secret FROM hosts WHERE id = :id AND disabled_at IS NULL"),
            {"id": host_id},
        )
        .mappings()
        .first()
    )
    if row is None or row["webhook_url"] is None or row["webhook_secret"] is None:
        return None
    return str(row["webhook_url"]), bytes(row["webhook_secret"])


def embedding_origins(db: Session, host_id: UUID) -> tuple[str, ...] | None:
    """The origins allowed to frame the signing UI for this host; ``None`` for an unknown or
    disabled host (the API then answers ``frame-ancestors 'none'``)."""
    row = (
        db.execute(text("SELECT allowed_origins FROM hosts WHERE id = :id AND disabled_at IS NULL"), {"id": host_id})
        .mappings()
        .first()
    )
    return None if row is None else tuple(str(origin) for origin in row["allowed_origins"] or ())


def disable_host(db: Session, host_id: UUID, *, clock: Clock) -> None:
    """Stop a host's key from authenticating. Idempotent; nothing it created is deleted."""
    updated = db.execute(
        text("UPDATE hosts SET disabled_at = :now WHERE id = :id AND disabled_at IS NULL RETURNING id"),
        {"id": host_id, "now": _now(clock)},
    ).first()
    if updated is not None:
        return
    exists = db.execute(text("SELECT 1 FROM hosts WHERE id = :id"), {"id": host_id}).first()
    if exists is None:
        raise NotFound("host", code="host_not_found")


def authenticate_host(db: Session, bearer: str) -> Host:
    """Resolve a presented API key to a host, or raise ``Unauthorized``.

    Every failure -- malformed, unknown, disabled -- is the same error with the same message, so a
    caller cannot use the API to discover which keys exist.
    """
    key = parse_token(bearer, HOST_KEY_PREFIX)
    if key is None:
        raise Unauthorized("invalid credentials")
    presented = token_sha256(key)
    row = (
        db.execute(
            text(
                "SELECT id, name, allowed_origins, api_key_hash FROM hosts "
                "WHERE api_key_hash = :h AND disabled_at IS NULL"
            ),
            {"h": presented},
        )
        .mappings()
        .first()
    )
    if row is None:
        raise Unauthorized("invalid credentials")
    stored = row["api_key_hash"]
    stored_bytes = bytes(stored) if isinstance(stored, bytearray | memoryview) else stored
    if not isinstance(stored_bytes, bytes) or not hashes_match(stored_bytes, presented):
        raise Unauthorized("invalid credentials")
    return _row_to_host(row)


def _now(clock: Clock) -> datetime:
    return to_utc(clock.now())
