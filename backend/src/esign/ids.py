"""Identifiers. Every id in the system is a UUIDv4 generated here."""

from __future__ import annotations

import hashlib
from uuid import UUID, uuid4

__all__ = ["advisory_lock_key", "is_uuid4", "new_id", "parse_id"]


def new_id() -> UUID:
    """A fresh UUIDv4. The only place the codebase mints an id."""
    return uuid4()


def parse_id(value: str) -> UUID:
    """Parse an id from the wire. Raises ``ValueError`` for anything malformed."""
    return UUID(value)


def is_uuid4(value: UUID) -> bool:
    return value.version == 4


def advisory_lock_key(namespace: str, value: UUID | str) -> int:
    """A stable 64-bit key for ``pg_advisory_xact_lock``.

    Signed, because Postgres advisory lock keys are ``bigint``. The namespace keeps two different
    kinds of lock (an audit stream and, say, a seal job) from colliding on the same uuid.
    """
    digest = hashlib.sha256(f"{namespace}:{value}".encode()).digest()
    unsigned = int.from_bytes(digest[:8], "big")
    return unsigned - (1 << 64) if unsigned >= (1 << 63) else unsigned
