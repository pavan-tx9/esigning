"""Typed reads out of a ``RowMapping``.

The modules here talk to Postgres through ``text()`` statements, so every column arrives as
``Any``. These helpers turn that back into real types at one boundary: a column that is not the
shape the schema promises raises here, naming the column and nothing else, rather than travelling
on as ``Any`` and failing somewhere that has no idea what went wrong.

Timestamps are normalised to UTC on the way in, because a comparison between an aware value from
Postgres and an aware value from ``Clock`` must never depend on the session's time zone.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import RowMapping

__all__ = ["opt_str", "opt_time", "raw_bytes", "req_str", "req_time", "req_uuid", "str_tuple", "to_utc"]


def _value(row: RowMapping, key: str) -> Any:
    try:
        return row[key]
    except KeyError as exc:  # pragma: no cover - a typo in a statement, not a runtime condition
        raise KeyError(f"column {key!r} is not in the result") from exc


def to_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise TypeError("naive datetime from the database; every timestamp column is timestamptz")
    return value.astimezone(UTC)


def req_uuid(row: RowMapping, key: str) -> UUID:
    value = _value(row, key)
    if isinstance(value, UUID):
        return value
    if isinstance(value, str):
        return UUID(value)
    raise TypeError(f"column {key!r} is not a uuid")


def req_str(row: RowMapping, key: str) -> str:
    value = _value(row, key)
    if isinstance(value, str):
        return value
    raise TypeError(f"column {key!r} is not text")


def opt_str(row: RowMapping, key: str) -> str | None:
    value = _value(row, key)
    if value is None:
        return None
    if isinstance(value, str):
        return value
    raise TypeError(f"column {key!r} is not text")


def req_time(row: RowMapping, key: str) -> datetime:
    value = _value(row, key)
    if isinstance(value, datetime):
        return to_utc(value)
    raise TypeError(f"column {key!r} is not a timestamp")


def opt_time(row: RowMapping, key: str) -> datetime | None:
    value = _value(row, key)
    if value is None:
        return None
    if isinstance(value, datetime):
        return to_utc(value)
    raise TypeError(f"column {key!r} is not a timestamp")


def raw_bytes(row: RowMapping, key: str) -> bytes:
    value = _value(row, key)
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray | memoryview):
        return bytes(value)
    raise TypeError(f"column {key!r} is not bytea")


def str_tuple(row: RowMapping, key: str) -> tuple[str, ...]:
    value = _value(row, key)
    if value is None:
        return ()
    if isinstance(value, list | tuple):
        return tuple(str(item) for item in value)
    raise TypeError(f"column {key!r} is not an array")
