"""Canonical JSON and the audit event hash.

Pure: no database, no clock, no settings. Everything here is a function of its arguments, so a
chain can be re-verified years from now by anyone holding the rows -- by hand if necessary. The
rules and a worked example live in ``README.md`` next to this file; this module is the normative
implementation of them.

Canonical JSON (SPEC section 4):

* object keys sorted by their UTF-8 code points, no insignificant whitespace (``{"a":1,"b":2}``)
* UTF-8 output, non-ASCII characters emitted literally rather than ``\\uXXXX``-escaped
* ``bytes`` as lowercase hex, ``UUID`` as its lowercase canonical string
* datetimes as RFC 3339 UTC with exactly six fractional digits and a ``Z`` suffix
* absent values as ``null``
* floats are rejected outright: no evidence field is a float, and their text form is not stable

``event_hash = SHA-256(canonical_json(event without event_hash))`` over exactly
:data:`HASHED_FIELDS`, which is the ``audit_events`` column list minus ``event_hash`` itself.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Final
from uuid import UUID

__all__ = [
    "HASHED_FIELDS",
    "ZERO_HASH",
    "canonical_json",
    "canonical_value",
    "compute_event_hash",
    "hash_input",
    "rfc3339",
]

#: ``prev_event_hash`` of the first event in a stream: 32 zero bytes.
ZERO_HASH: Final[bytes] = bytes(32)

#: Exactly the fields that go into the hash, in canonical (sorted) order. This is the
#: ``audit_events`` column list with ``event_hash`` removed -- every stored column is covered, so
#: tampering with any one of them is detectable. A test asserts it against the live schema.
HASHED_FIELDS: Final[tuple[str, ...]] = (
    "actor_capacity",
    "actor_role",
    "actor_user_id",
    "auth_method",
    "data",
    "document_sha256",
    "event_type",
    "id",
    "ip",
    "occurred_at",
    "on_behalf_of",
    "prev_event_hash",
    "sequence",
    "session_id",
    "stream_id",
    "stream_type",
    "user_agent",
)

_HASHED_FIELD_SET: Final[frozenset[str]] = frozenset(HASHED_FIELDS)

#: Ints outside this range would not survive a round trip through every JSON reader.
_MAX_SAFE_INT: Final[int] = 2**63 - 1


class CanonicalizationError(TypeError):
    """A value cannot be put in the audit trail deterministically.

    Carries the offending *type*, never the offending value: this exception can reach a log.
    """


def rfc3339(value: datetime) -> str:
    """RFC 3339 UTC with exactly six fractional digits and ``Z``.

    Naive datetimes are refused rather than assumed to be UTC. A timestamp whose zone is unknown
    is not evidence.
    """
    if value.tzinfo is None:
        raise CanonicalizationError("audit timestamps must be timezone-aware")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def canonical_value(value: Any) -> Any:
    """Convert a value to the JSON primitives the canonical form is built from.

    The accepted set is deliberately small. Anything else -- a float, a Decimal, a set, an
    arbitrary object -- raises, because a hash over it would not be reproducible by a third party
    reading the rows.
    """
    if value is None:
        return None
    if isinstance(value, bool):  # before int: bool is an int subclass
        return value
    if isinstance(value, int):
        if not -_MAX_SAFE_INT <= value <= _MAX_SAFE_INT:
            raise CanonicalizationError("integer out of range for the audit trail")
        return value
    if isinstance(value, Enum):
        return canonical_value(value.value)
    if isinstance(value, str):
        return value
    if isinstance(value, bytes | bytearray | memoryview):
        return bytes(value).hex()
    if isinstance(value, UUID):
        return str(value).lower()
    if isinstance(value, datetime):
        return rfc3339(value)
    if isinstance(value, IPv4Address | IPv6Address):
        return str(value)
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"object keys must be strings, got {type(key).__name__}")
            out[key] = canonical_value(item)
        return out
    if isinstance(value, Sequence):
        return [canonical_value(item) for item in value]
    raise CanonicalizationError(f"{type(value).__name__} has no canonical form in the audit trail")


def canonical_json(value: Any) -> bytes:
    """The canonical UTF-8 encoding of ``value``. Deterministic for equal inputs, always."""
    return json.dumps(
        canonical_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def hash_input(fields: Mapping[str, Any]) -> bytes:
    """The exact bytes that are hashed for one event.

    ``fields`` must carry every name in :data:`HASHED_FIELDS` and nothing else: a missing field
    would silently change the hash of every later event in the chain, and an extra one would be
    invisible to :func:`compute_event_hash` on the way back in.
    """
    present = frozenset(fields)
    if present != _HASHED_FIELD_SET:
        missing = sorted(_HASHED_FIELD_SET - present)
        extra = sorted(present - _HASHED_FIELD_SET)
        raise CanonicalizationError(f"hash input fields wrong (missing={missing}, unexpected={extra})")
    return canonical_json(dict(fields))


def compute_event_hash(fields: Mapping[str, Any]) -> bytes:
    """SHA-256 of :func:`hash_input`. The 32 raw bytes stored in ``audit_events.event_hash``."""
    return hashlib.sha256(hash_input(fields)).digest()
