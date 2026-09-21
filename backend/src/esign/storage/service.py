"""Content-addressed, write-once blob storage over a backend plus the ``blobs`` table.

The table is the index (what exists, how big, what kind, how long it must survive) and the
backend holds the bytes. Both are append-only: the app role has ``SELECT, INSERT`` and nothing
else, the append-only trigger is the second line of defence, and there is no delete method on
this class, on either backend, or anywhere in this package.

Two ordering decisions worth stating, because both are about what survives a failure:

* **bytes first, row second.** The object is written before the row is inserted, so a committed
  ``blobs`` row always has content behind it. The reverse order could leave a row pointing at
  nothing, which is a lie the rest of the system would believe. The cost is that a rolled-back
  transaction can leave an orphan object; that is harmless, because the store is content-addressed
  and the next ``put`` of the same bytes adopts it.
* **a missing object is an integrity failure, not a miss.** If the row exists and the bytes are
  gone, :meth:`ContentAddressedBlobService.get` and :meth:`exists` raise rather than report
  absence. Reporting absence would let a caller treat destroyed evidence as "not ready yet".
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from typing import Any, Final, get_args

from sqlalchemy import text
from sqlalchemy.orm import Session

from esign.config import Settings
from esign.contracts import BlobKind, BlobRef, Clock, IntegrityFailure, NotFound, ValidationFailed
from esign.logging import get_logger
from esign.storage.objectstore import ObjectStore

__all__ = ["ContentAddressedBlobService"]

log = get_logger(__name__)

_BLOB_KINDS: Final[frozenset[str]] = frozenset(get_args(BlobKind))

_SELECT_SQL: Final[str] = """
SELECT sha256, size_bytes, kind, storage_key, retain_until
FROM blobs
WHERE sha256 = :sha256
"""

_INSERT_SQL: Final[str] = """
INSERT INTO blobs (sha256, size_bytes, kind, storage_key, retain_until)
VALUES (:sha256, :size_bytes, :kind, :storage_key, :retain_until)
ON CONFLICT (sha256) DO NOTHING
"""


class ContentAddressedBlobService:
    """:class:`~esign.contracts.BlobService` over an :class:`ObjectStore` and ``blobs``."""

    def __init__(self, store: ObjectStore, settings: Settings, clock: Clock) -> None:
        self._store = store
        self._settings = settings
        self._clock = clock

    @property
    def backend_name(self) -> str:
        return self._store.backend_name

    # ------------------------------------------------------------------ write

    def put(
        self,
        db: Session,
        data: bytes,
        *,
        kind: BlobKind,
        retain_until: datetime | None = None,
    ) -> BlobRef:
        """Store ``data`` and record it. Idempotent: the same bytes twice is one blob, one row.

        ``retain_until`` defaults to the configured retention floor rather than to "no retention":
        a blob with no retain-until would be deletable, and nothing in this service is allowed to
        produce evidence that is easier to destroy than the policy says.
        """
        if kind not in _BLOB_KINDS:
            raise ValidationFailed(f"unknown blob kind: {_safe(kind)}", code="blob_kind_invalid")
        if not isinstance(data, bytes | bytearray | memoryview):
            raise ValidationFailed("blob content must be bytes", code="blob_content_invalid")
        payload = bytes(data)
        if not payload:
            # An empty document is never evidence of anything, and storing one would let a
            # failure upstream masquerade as a stored artefact.
            raise ValidationFailed("refusing to store an empty blob", code="blob_empty")

        sha256 = hashlib.sha256(payload).digest()
        key = self._store.storage_key(sha256)
        effective_retain_until = self._retain_until(retain_until)

        existing = self._row(db, sha256)
        if existing is not None:
            self._adopt_existing(key, sha256, existing, effective_retain_until)
            return BlobRef(sha256=sha256, size_bytes=int(existing.size_bytes), kind=existing.kind)

        outcome = self._store.put(key, payload, sha256=sha256, retain_until=effective_retain_until)
        db.execute(
            text(_INSERT_SQL),
            {
                "sha256": sha256,
                "size_bytes": len(payload),
                "kind": kind,
                "storage_key": key,
                "retain_until": effective_retain_until,
            },
        )
        # A concurrent transaction may have won the race; the row it wrote is the truth.
        row = self._row(db, sha256)
        recorded_kind: BlobKind = row.kind if row is not None else kind
        recorded_size = int(row.size_bytes) if row is not None else len(payload)

        log.info(
            "blob.stored",
            backend=self.backend_name,
            sha256=sha256,
            size_bytes=recorded_size,
            blob_kind=recorded_kind,
            code=outcome,
        )
        return BlobRef(sha256=sha256, size_bytes=recorded_size, kind=recorded_kind)

    # ------------------------------------------------------------------ read

    def get(self, db: Session, sha256: bytes) -> bytes:
        """The stored bytes, re-hashed on the way out.

        Raises :class:`NotFound` when nothing was ever stored under this digest, and
        :class:`IntegrityFailure` when something was stored and what comes back is not it.
        """
        row = self._row(db, _require_digest(sha256))
        if row is None:
            raise NotFound(f"no blob {sha256.hex()}")

        data = self._store.get(row.storage_key)
        if data is None:
            raise IntegrityFailure(
                f"blob {sha256.hex()} is recorded but missing from the store",
                code="blob_missing",
            )
        if hashlib.sha256(data).digest() != bytes(sha256):
            raise IntegrityFailure(
                f"blob {sha256.hex()} does not match its recorded hash",
                code="blob_corrupt",
            )
        if len(data) != int(row.size_bytes):  # pragma: no cover - a size change implies a hash change
            raise IntegrityFailure(f"blob {sha256.hex()} has the wrong size", code="blob_corrupt")
        return data

    def exists(self, db: Session, sha256: bytes) -> bool:
        """True when the blob is recorded *and* retrievable.

        A recorded blob whose bytes have gone raises instead of answering ``False``: that is data
        loss, and the caller must not be allowed to paper over it with another ``put``.
        """
        row = self._row(db, _require_digest(sha256))
        if row is None:
            return False
        if not self._store.exists(row.storage_key):
            raise IntegrityFailure(
                f"blob {sha256.hex()} is recorded but missing from the store",
                code="blob_missing",
            )
        return True

    # ------------------------------------------------------------------ internals

    def _row(self, db: Session, sha256: bytes) -> Any:
        return db.execute(text(_SELECT_SQL), {"sha256": bytes(sha256)}).one_or_none()

    def _retain_until(self, requested: datetime | None) -> datetime:
        now = self._clock.now()
        if requested is None:
            # ``BlobService.put`` carries no document type, so a caller that does not supply a
            # date gets the configured floor (365-day years, matching ``Settings.retain_until``).
            # Callers that know the type -- the sealing path -- pass the longer date themselves.
            return now + timedelta(days=365 * self._settings.default_retention_years)
        if requested.tzinfo is None:
            raise ValidationFailed("retain_until must be timezone-aware", code="blob_retention_invalid")
        if requested <= now:
            raise ValidationFailed("retain_until must be in the future", code="blob_retention_invalid")
        return requested

    def _adopt_existing(self, key: str, sha256: bytes, row: Any, retain_until: datetime) -> None:
        """This content is already recorded. Confirm the bytes are still there, and never shorten
        the retention that was agreed for them; a later date is applied where the backend can."""
        if not self._store.exists(row.storage_key):
            raise IntegrityFailure(
                f"blob {sha256.hex()} is recorded but missing from the store",
                code="blob_missing",
            )
        recorded = row.retain_until
        if recorded is None or retain_until > recorded:
            # The ``blobs`` row is append-only, so it keeps the date agreed at first write; the
            # backend holds the effective one, and the backend is what actually resists deletion.
            self._store.extend_retention(key, retain_until)


def _require_digest(sha256: bytes) -> bytes:
    if not isinstance(sha256, bytes | bytearray | memoryview) or len(bytes(sha256)) != 32:
        raise ValidationFailed("a blob is addressed by a 32-byte SHA-256 digest", code="blob_digest_invalid")
    return bytes(sha256)


def _safe(value: object) -> str:
    return "".join(ch for ch in str(value) if ch.isalnum() or ch in "_-.")[:40]
