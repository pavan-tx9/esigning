"""Webhooks to the host. See docs/SPEC.md section 9.

Three parts, deliberately separate:

``WebhookQueue``     an :class:`~esign.contracts.EnvelopeNotifier`. The envelope service calls it
                     inside the transaction that made the change, so a delivery row exists if and
                     only if the change committed. Nothing is sent from a request.
``sign`` / ``verify_signature``
                     ``X-Esign-Signature: t=<unix>,v1=<hex hmac-sha256 of "t.body">``. ``verify``
                     is what a host would write; it ships here so the tests and the demo host use
                     the same code a reader is told to copy.
``deliver_due``      the worker's half: lease due rows with ``SKIP LOCKED``, POST them, record the
                     outcome, back off. Safe to run in more than one process.

Payloads carry ids, statuses and hashes only (SPEC section 10). There is no display name, no
``patient_ref`` and no ``host_document_ref`` in one: a webhook leaves our network, and the host
already knows which envelope an id refers to.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Final
from uuid import UUID

import httpx
from sqlalchemy import text
from sqlalchemy.orm import Session

from esign.config import Settings
from esign.contracts import Clock, EnvelopeView, WebhookEvent
from esign.identity import webhook_target
from esign.ids import new_id
from esign.logging import get_logger

__all__ = [
    "SIGNATURE_HEADER",
    "WEBHOOK_BACKOFF_SCHEDULE",
    "Delivery",
    "HttpSender",
    "Sender",
    "WebhookQueue",
    "build_payload",
    "deliver_due",
    "sign",
    "verify_signature",
    "webhook_backoff",
]

log = get_logger(__name__)

SIGNATURE_HEADER: Final = "X-Esign-Signature"

#: After the Nth failed attempt, wait this long. Then hourly until ``webhook_max_attempts``.
WEBHOOK_BACKOFF_SCHEDULE: Final[tuple[timedelta, ...]] = (
    timedelta(seconds=30),
    timedelta(minutes=2),
    timedelta(minutes=10),
    timedelta(minutes=30),
    timedelta(hours=1),
)

#: How long a leased delivery is left alone before another worker may pick it up again. Longer
#: than any send can take, so two workers never POST the same row at once.
_LEASE: Final = timedelta(minutes=5)

#: A sender takes (url, body, headers) and returns the HTTP status, or raises on a transport error.
Sender = Callable[[str, bytes, dict[str, str]], int]
SessionScope = Callable[[], AbstractContextManager[Session]]


def webhook_backoff(attempts: int) -> timedelta:
    """Delay after the ``attempts``-th failure (1-based)."""
    index = max(1, attempts) - 1
    return WEBHOOK_BACKOFF_SCHEDULE[min(index, len(WEBHOOK_BACKOFF_SCHEDULE) - 1)]


# --------------------------------------------------------------------------- payload and signature


def _hex(value: bytes | None) -> str | None:
    return None if value is None else value.hex()


def build_payload(
    delivery_id: UUID, event: WebhookEvent, envelope: EnvelopeView, occurred_at: datetime
) -> dict[str, Any]:
    """Ids, statuses and hashes. Nothing else, ever."""
    return {
        "id": str(delivery_id),
        "event": event,
        "occurred_at": occurred_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "envelope_id": str(envelope.id),
        "status": envelope.status,
        "template_key": envelope.template_key,
        "template_version": envelope.template_version,
        "presented_sha256": _hex(envelope.presented_sha256),
        "current_revision_sha256": _hex(envelope.current_revision_sha256),
        "sealed_sha256": _hex(envelope.sealed_sha256),
        "supersedes_envelope_id": None
        if envelope.supersedes_envelope_id is None
        else str(envelope.supersedes_envelope_id),
        "signers": [{"id": str(s.id), "role_key": s.role_key, "status": s.status} for s in envelope.signers],
    }


def encode_body(payload: dict[str, Any]) -> bytes:
    """The exact bytes that are signed and sent. Sorted and compact, so they are reproducible."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign(secret: bytes, body: bytes, timestamp: int) -> str:
    """The ``X-Esign-Signature`` value for ``body`` sent at ``timestamp`` (unix seconds)."""
    mac = hmac.new(secret, f"{timestamp}.".encode("ascii") + body, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={mac}"


def verify_signature(secret: bytes, body: bytes, header: str, *, now: datetime, tolerance_seconds: int = 300) -> bool:
    """What a host does on receipt. Constant-time, and refuses a timestamp outside the tolerance
    so a captured delivery cannot be replayed later."""
    parts = dict(part.split("=", 1) for part in header.split(",") if "=" in part)
    try:
        timestamp = int(parts.get("t", ""))
    except ValueError:
        return False
    presented = parts.get("v1", "")
    if abs(int(now.timestamp()) - timestamp) > tolerance_seconds:
        return False
    expected = sign(secret, body, timestamp).split("v1=", 1)[1]
    return hmac.compare_digest(expected, presented)


# --------------------------------------------------------------------------- queue (request side)


class WebhookQueue:
    """``EnvelopeNotifier``: one ``webhook_deliveries`` row per event, in the caller's transaction."""

    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    def envelope_event(self, db: Session, *, event: WebhookEvent, envelope: EnvelopeView) -> None:
        if envelope.host_id is None:  # pragma: no cover - the envelope service always sets it
            return
        if webhook_target(db, envelope.host_id) is None:
            return  # the host has no webhook; there is nobody to tell
        delivery_id = new_id()
        now = self._clock.now()
        db.execute(
            text(
                "INSERT INTO webhook_deliveries (id, host_id, envelope_id, event, payload, attempts, next_attempt_at) "
                "VALUES (:id, :host_id, :envelope_id, :event, CAST(:payload AS jsonb), 0, :now)"
            ),
            {
                "id": delivery_id,
                "host_id": envelope.host_id,
                "envelope_id": envelope.id,
                "event": event,
                "payload": json.dumps(build_payload(delivery_id, event, envelope, now)),
                "now": now,
            },
        )
        log.info("webhook.queued", delivery_id=delivery_id, envelope_id=envelope.id, webhook_event=event)


# --------------------------------------------------------------------------- delivery (worker side)


@dataclass(frozen=True)
class Delivery:
    id: UUID
    host_id: UUID
    envelope_id: UUID
    event: str
    payload: dict[str, Any]
    attempts: int  # including the attempt this lease represents


class HttpSender:
    """POSTs with httpx. No redirects: a webhook URL that redirects is a URL we were not given."""

    def __init__(self, settings: Settings, *, transport: httpx.BaseTransport | None = None) -> None:
        # Explicit per-phase timeouts. ``webhook_timeout_seconds`` alone is a per-operation bound,
        # which says nothing about how many operations a trickling response may take.
        timeout = httpx.Timeout(
            connect=min(5.0, settings.webhook_timeout_seconds),
            read=settings.webhook_timeout_seconds,
            write=settings.webhook_timeout_seconds,
            pool=5.0,
        )
        self._client = httpx.Client(timeout=timeout, follow_redirects=False, transport=transport)

    def __call__(self, url: str, body: bytes, headers: dict[str, str]) -> int:
        """The status code, without reading the response body.

        ``Client.post`` reads the whole body into memory before it returns, and only the status is
        ever used. A host endpoint answering with gigabytes, or one chunk every few seconds, would
        otherwise hold the worker's single delivery loop -- delaying seal retries and expiries for
        every host in the same tick -- and grow its heap while doing it.
        """
        request = self._client.build_request("POST", url, content=body, headers=headers)
        response = self._client.send(request, stream=True)
        try:
            return response.status_code
        finally:
            response.close()

    def close(self) -> None:
        self._client.close()


def _lease(db: Session, *, now: datetime, max_attempts: int, limit: int) -> list[Delivery]:
    rows = db.execute(
        text(
            "UPDATE webhook_deliveries SET attempts = attempts + 1, next_attempt_at = :lease_until "
            "WHERE id IN ("
            "  SELECT id FROM webhook_deliveries "
            "  WHERE delivered_at IS NULL AND next_attempt_at <= :now AND attempts < :max_attempts "
            "  ORDER BY next_attempt_at, seq FOR UPDATE SKIP LOCKED LIMIT :limit) "
            "RETURNING id, host_id, envelope_id, event, payload, attempts, seq"
        ),
        {"now": now, "lease_until": now + _LEASE, "max_attempts": max_attempts, "limit": limit},
    ).all()
    # UPDATE ... RETURNING comes back in no particular order; send in the order they were queued.
    return [
        Delivery(
            id=row.id,
            host_id=row.host_id,
            envelope_id=row.envelope_id,
            event=str(row.event),
            payload=dict(row.payload),
            attempts=int(row.attempts),
        )
        for row in sorted(rows, key=lambda r: int(r.seq))
    ]


def deliver_due(
    new_session: SessionScope, send: Sender, clock: Clock, settings: Settings, *, limit: int = 50
) -> tuple[int, int]:
    """Send every due delivery once. Returns ``(delivered, failed)``.

    The lease is committed before anything is sent, so a second worker skips these rows and a
    crash mid-send costs one backoff period rather than a duplicate or a lost event. Delivery is
    at-least-once; the payload's ``id`` lets the host drop a repeat.
    """
    with new_session() as db:
        leased = _lease(db, now=clock.now(), max_attempts=settings.webhook_max_attempts, limit=limit)
        db.commit()

    delivered = failed = 0
    for delivery in leased:
        with new_session() as db:
            target = webhook_target(db, delivery.host_id)
        status: int | None = None
        if target is not None:
            url, secret = target
            body = encode_body(delivery.payload)
            headers = {
                "Content-Type": "application/json",
                "User-Agent": "esign-webhooks/1",
                SIGNATURE_HEADER: sign(secret, body, int(clock.now().timestamp())),
                "X-Esign-Event": delivery.event,
                "X-Esign-Delivery": str(delivery.id),
            }
            try:
                status = send(url, body, headers)
            except Exception:
                # The reason is a transport detail and may quote the URL; the row records that it
                # failed and when it will be tried again, which is all anyone needs.
                status = None
        ok = status is not None and 200 <= status < 300
        now = clock.now()
        with new_session() as db:
            if ok:
                db.execute(
                    text("UPDATE webhook_deliveries SET delivered_at = :now, last_status = :status WHERE id = :id"),
                    {"id": delivery.id, "now": now, "status": status},
                )
            else:
                db.execute(
                    text("UPDATE webhook_deliveries SET next_attempt_at = :next, last_status = :status WHERE id = :id"),
                    {"id": delivery.id, "next": now + webhook_backoff(delivery.attempts), "status": status},
                )
            db.commit()
        if ok:
            delivered += 1
            log.info(
                "webhook.delivered",
                delivery_id=delivery.id,
                envelope_id=delivery.envelope_id,
                webhook_event=delivery.event,
                http_status=status,
                attempts=delivery.attempts,
            )
        else:
            failed += 1
            log.warning(
                "webhook.failed",
                delivery_id=delivery.id,
                envelope_id=delivery.envelope_id,
                webhook_event=delivery.event,
                http_status=status,
                attempts=delivery.attempts,
                retry_in_seconds=int(webhook_backoff(delivery.attempts).total_seconds()),
            )
    return delivered, failed
