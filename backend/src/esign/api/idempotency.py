"""``Idempotency-Key`` (SPEC section 10): a retried request with the same key returns the first
response; the same key with a different body is a ``conflict``.

The key row is written in the *same transaction* as the work it guards:

* success commits the work and the stored response together, so there is never a signature
  without its recorded answer, or an answer without its signature;
* failure rolls both back, so a retry after an error is a fresh attempt and not a replayed error;
* two requests racing on one key serialise on the primary key: the second blocks on the first's
  uncommitted row, then finds the stored response and replays it.

Underneath this, the envelope service refuses a second signature outright, so even a client that
changes its key on retry cannot sign twice. This layer is what makes the retry *succeed* with the
original answer instead of failing with ``conflict``.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Final

from sqlalchemy import text
from sqlalchemy.orm import Session

from esign.contracts import Conflict, ValidationFailed

__all__ = ["StoredResponse", "begin", "complete", "request_hash"]

_KEY: Final = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")


@dataclass(frozen=True)
class StoredResponse:
    status: int
    body: dict[str, Any]


def request_hash(method: str, path: str, body: Any) -> bytes:
    """A digest of what was asked. The body may hold PHI; only its hash is kept."""
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(f"{method} {path}\n{canonical}".encode()).digest()


def begin(db: Session, *, scope: str, key: str, digest: bytes, now: datetime, ttl: timedelta) -> StoredResponse | None:
    """Claim the key for this transaction, or return the response stored by the request that
    already used it. Raises ``Conflict`` when the key was used for a different request."""
    if not _KEY.match(key):
        raise ValidationFailed("the idempotency key is malformed", code="idempotency_key_invalid")
    db.execute(
        text("DELETE FROM idempotency_keys WHERE scope = :scope AND key = :key AND created_at < :cutoff"),
        {"scope": scope, "key": key, "cutoff": now - ttl},
    )
    claimed = db.execute(
        text(
            "INSERT INTO idempotency_keys (scope, key, request_hash, created_at) "
            "VALUES (:scope, :key, :digest, :now) ON CONFLICT (scope, key) DO NOTHING RETURNING key"
        ),
        {"scope": scope, "key": key, "digest": digest, "now": now},
    ).first()
    if claimed is not None:
        return None
    row = db.execute(
        text(
            "SELECT request_hash, response_status, response_body FROM idempotency_keys WHERE scope = :scope AND key = :key"
        ),
        {"scope": scope, "key": key},
    ).first()
    if row is None or row.response_status is None:  # pragma: no cover - rows only commit with a response
        raise Conflict("that request is still being processed", code="idempotency_in_progress")
    if bytes(row.request_hash) != digest:
        raise Conflict("that idempotency key was used for a different request", code="idempotency_key_reused")
    return StoredResponse(status=int(row.response_status), body=dict(row.response_body or {}))


def complete(db: Session, *, scope: str, key: str, status: int, body: dict[str, Any]) -> None:
    db.execute(
        text(
            "UPDATE idempotency_keys SET response_status = :status, response_body = CAST(:body AS jsonb) "
            "WHERE scope = :scope AND key = :key"
        ),
        {"scope": scope, "key": key, "status": status, "body": json.dumps(body)},
    )
