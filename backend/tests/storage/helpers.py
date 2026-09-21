"""Helpers for the storage tests: reaching behind the service to break what it stored.

Corruption and deletion cannot be done through the service -- it has no method for either -- so
these reach the backend directly, which is what an attacker with filesystem or bucket access has.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sqlalchemy import text
from sqlalchemy.orm import Session

if TYPE_CHECKING:  # pragma: no cover - typing only
    from mypy_boto3_s3.client import S3Client


def digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def blob_row(db: Session, sha256: bytes) -> Any:
    return db.execute(
        text("SELECT sha256, size_bytes, kind, storage_key, retain_until FROM blobs WHERE sha256 = :s"),
        {"s": sha256},
    ).one_or_none()


def blob_count(db: Session, sha256: bytes) -> int:
    return int(db.execute(text("SELECT count(*) FROM blobs WHERE sha256 = :s"), {"s": sha256}).scalar_one())


def corrupt_file(path: Path, data: bytes = b"tampered") -> None:
    """Flip the contents of a stored file, as root could. The blobs are written read-only."""
    path.chmod(0o600)
    path.write_bytes(data)
    path.chmod(0o444)


def delete_file(path: Path) -> None:
    path.chmod(0o600)
    path.unlink()


def corrupt_object(client: S3Client, bucket: str, key: str, data: bytes = b"tampered") -> None:
    """Overwrite an object. Object Lock protects versions from deletion, not the bucket from
    gaining a new current version -- which is exactly why ``get`` re-hashes."""
    client.put_object(Bucket=bucket, Key=key, Body=data)


def delete_object(client: S3Client, bucket: str, key: str) -> None:
    """Add a delete marker, so the current version is gone. The service must notice."""
    client.delete_object(Bucket=bucket, Key=key)
