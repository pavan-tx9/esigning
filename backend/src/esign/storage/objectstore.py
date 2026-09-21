"""The backend seam: what a blob store has to be able to do, and nothing more.

Three verbs and two facts. There is no delete, no overwrite and no move, here or anywhere below
this line -- the way to be sure evidence cannot be rewritten is for the code that could rewrite it
not to exist.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Protocol

from esign.contracts import StorageUnavailable

__all__ = ["BlobStoreUnavailable", "ObjectStore", "PutOutcome", "content_key"]

#: What a :meth:`ObjectStore.put` did. ``already_present`` means the object was already there and
#: its content hashes to the same digest -- which is what makes ``put`` idempotent.
PutOutcome = Literal["created", "already_present"]


class BlobStoreUnavailable(StorageUnavailable):
    """The blob store did not answer, or refused for a reason that is not about this content.

    Retryable in the sense that matters: the caller must leave the envelope where it is rather
    than report work as finished. Messages here never carry a bucket name, key or URL.
    """

    code = "blob_store_unavailable"


def content_key(sha256: bytes, prefix: str = "") -> str:
    """The storage key for a digest: two levels of fan-out, then the full lowercase hex.

    Fan-out because a flat directory (or a flat S3 prefix) of hundreds of thousands of objects is
    slow to list and unpleasant to operate. The key is a pure function of the content, so two
    writers of the same bytes always agree on where they go.
    """
    if len(sha256) != 32:
        raise ValueError("storage keys are derived from a 32-byte SHA-256 digest")
    hexed = sha256.hex()
    return f"{prefix}{hexed[:2]}/{hexed[2:4]}/{hexed}"


class ObjectStore(Protocol):
    """A write-once object store. Implementations: ``fs`` for dev, ``s3`` for production."""

    backend_name: str

    def storage_key(self, sha256: bytes) -> str:
        """Where content with this digest lives. Deterministic."""

    def put(self, key: str, data: bytes, *, sha256: bytes, retain_until: datetime) -> PutOutcome:
        """Create the object, never replacing one that exists.

        Returns ``already_present`` when the key already holds exactly this content. Raises
        :class:`~esign.contracts.IntegrityFailure` when it holds something else, and
        :class:`BlobStoreUnavailable` when the store could not be reached.
        """

    def get(self, key: str) -> bytes | None:
        """The stored bytes, or ``None`` when the key does not exist."""

    def exists(self, key: str) -> bool: ...

    def extend_retention(self, key: str, retain_until: datetime) -> bool:
        """Push the retain-until date further out. Never shortens it.

        Returns ``True`` when the backend moved it, ``False`` when the backend cannot express
        retention at all or the existing date is already later.
        """
