"""S3 blob backend: Object Lock, conditional put, server-side encryption.

What each part is defending against:

``IfNoneMatch="*"``       another writer, or a retry, replacing an object that is already there.
                          S3 answers ``412 PreconditionFailed`` instead of overwriting.
``ObjectLockMode``        deletion. ``COMPLIANCE`` by default, which nobody -- including the root
                          account -- can shorten or bypass until the retain-until date. Settings
                          can choose ``GOVERNANCE`` for environments that need an escape hatch,
                          and that choice is explicit rather than a default.
``ChecksumSHA256``        a corrupted upload. S3 rejects the put if the bytes do not hash to the
                          digest we sent, so a truncated body never becomes a stored blob.
``ServerSideEncryption``  the bytes at rest. ``AES256`` or ``aws:kms`` with a configured key.

There is no ``delete_object`` call in this file, and no code path that could add one.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from datetime import datetime
from typing import TYPE_CHECKING, Any, cast

from botocore.exceptions import BotoCoreError, ClientError

from esign.contracts import IntegrityFailure
from esign.logging import get_logger
from esign.storage.objectstore import BlobStoreUnavailable, PutOutcome, content_key

if TYPE_CHECKING:  # pragma: no cover - typing only
    from mypy_boto3_s3.client import S3Client
    from mypy_boto3_s3.literals import ObjectLockRetentionModeType
    from mypy_boto3_s3.type_defs import ObjectLockRetentionTypeDef

__all__ = ["S3ObjectStore"]

log = get_logger(__name__)

#: S3 answers one of these when the key already exists and ``IfNoneMatch: *`` was sent.
_ALREADY_EXISTS = frozenset({"PreconditionFailed", "ConditionalRequestConflict"})
#: Absence, spelled three ways depending on the operation and the implementation.
_NOT_FOUND = frozenset({"NoSuchKey", "NotFound", "404"})


class S3ObjectStore:
    """Write-once objects in one bucket. The bucket must have Object Lock enabled at creation."""

    backend_name = "s3"

    def __init__(
        self,
        client: S3Client,
        *,
        bucket: str,
        prefix: str = "",
        object_lock_mode: str = "COMPLIANCE",
        sse: str = "AES256",
        sse_kms_key_id: str | None = None,
    ) -> None:
        if not bucket:
            raise ValueError("the s3 blob backend needs BLOB_S3_BUCKET")
        self._client = client
        self._bucket = bucket
        self._prefix = prefix
        self._object_lock_mode = object_lock_mode
        self._sse = sse
        self._sse_kms_key_id = sse_kms_key_id

    def storage_key(self, sha256: bytes) -> str:
        return content_key(sha256, self._prefix)

    def put(self, key: str, data: bytes, *, sha256: bytes, retain_until: datetime) -> PutOutcome:
        params: dict[str, Any] = {
            "Bucket": self._bucket,
            "Key": key,
            "Body": data,
            "ContentType": "application/octet-stream",
            # Refuse to replace anything already at this key.
            "IfNoneMatch": "*",
            # Let S3 verify the upload against the digest the key is derived from.
            "ChecksumAlgorithm": "SHA256",
            "ChecksumSHA256": base64.b64encode(sha256).decode("ascii"),
            "ObjectLockMode": self._object_lock_mode,
            "ObjectLockRetainUntilDate": retain_until,
        }
        params.update(self._encryption_params())
        try:
            self._client.put_object(**params)
        except ClientError as exc:
            if _error_code(exc) in _ALREADY_EXISTS:
                return self._confirm_identical(key, sha256)
            raise _unavailable(exc, "put") from exc
        except BotoCoreError as exc:
            raise _unavailable(exc, "put") from exc

        log.debug("blob.written", backend=self.backend_name, sha256=sha256, size_bytes=len(data))
        return "created"

    def get(self, key: str) -> bytes | None:
        try:
            response = self._client.get_object(Bucket=self._bucket, Key=key)
            body: bytes = response["Body"].read()
        except ClientError as exc:
            if _error_code(exc) in _NOT_FOUND:
                return None
            raise _unavailable(exc, "get") from exc
        except BotoCoreError as exc:
            raise _unavailable(exc, "get") from exc
        return body

    def exists(self, key: str) -> bool:
        return self._head(key) is not None

    def extend_retention(self, key: str, retain_until: datetime) -> bool:
        head = self._head(key)
        if head is None:
            return False
        current = head.get("ObjectLockRetainUntilDate")
        if current is not None and current >= retain_until:
            return False
        retention: ObjectLockRetentionTypeDef = {
            "Mode": cast("ObjectLockRetentionModeType", self._object_lock_mode),
            "RetainUntilDate": retain_until,
        }
        try:
            self._client.put_object_retention(Bucket=self._bucket, Key=key, Retention=retention)
        except (ClientError, BotoCoreError) as exc:
            raise _unavailable(exc, "put_object_retention") from exc
        log.info("blob.retention_extended", backend=self.backend_name)
        return True

    # ------------------------------------------------------------------ internals

    def _encryption_params(self) -> dict[str, Any]:
        if self._sse.lower() in {"aws:kms", "kms"}:
            params: dict[str, Any] = {"ServerSideEncryption": "aws:kms"}
            if self._sse_kms_key_id:
                params["SSEKMSKeyId"] = self._sse_kms_key_id
            return params
        return {"ServerSideEncryption": self._sse}

    def _head(self, key: str) -> dict[str, Any] | None:
        try:
            response = self._client.head_object(Bucket=self._bucket, Key=key, ChecksumMode="ENABLED")
        except ClientError as exc:
            if _error_code(exc) in _NOT_FOUND:
                return None
            raise _unavailable(exc, "head") from exc
        except BotoCoreError as exc:
            raise _unavailable(exc, "head") from exc
        return dict(response)

    def _confirm_identical(self, key: str, sha256: bytes) -> PutOutcome:
        """The key is taken. Accept it only if what is there is exactly this content."""
        head = self._head(key)
        recorded = None if head is None else head.get("ChecksumSHA256")
        if isinstance(recorded, str):
            try:
                if base64.b64decode(recorded, validate=True) == sha256:
                    return "already_present"
            except (binascii.Error, ValueError):
                # A multipart checksum ("<digest>-<parts>") is not comparable; fall through and
                # settle it by downloading the bytes.
                pass
        body = self.get(key)
        if body is not None and hashlib.sha256(body).digest() == sha256:
            return "already_present"
        raise IntegrityFailure(
            f"blob {sha256.hex()} is already stored with different content",
            code="blob_content_mismatch",
        )


def _error_code(exc: ClientError) -> str:
    error = exc.response.get("Error", {})
    code = error.get("Code")
    if code:
        return str(code)
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return str(status) if status else ""


def _unavailable(exc: Exception, operation: str) -> BlobStoreUnavailable:
    """One error out, with no bucket, key or endpoint in the message."""
    log.warning("blob.store_error", backend="s3", method=operation, error_code=_safe_code(exc))
    return BlobStoreUnavailable(f"s3 blob store did not complete {operation}")


def _safe_code(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        return _error_code(exc)[:64]
    return type(exc).__name__
