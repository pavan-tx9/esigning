"""Content-addressed, write-once blob storage. See docs/SPEC.md section 7.

Blobs are addressed by the SHA-256 of their content, written once, re-hashed on every read, and
never deleted. There is no delete method on the service, on either backend, or anywhere in this
package -- that is the guarantee, expressed as missing code rather than as a rule.

Layout:

``objectstore.py``  the backend seam and the shared fan-out key function.
``fs.py``           development backend: exclusive create, read-only files, temp file + hard
                    link so a blob is never replaced and never half-written.
``s3.py``           production backend: Object Lock (COMPLIANCE by default), conditional put,
                    server-side encryption, and an upload checksum S3 verifies.
``service.py``      the :class:`~esign.contracts.BlobService`: the ``blobs`` row plus the bytes.

Usage::

    blobs = build_blob_service(settings, clock)
    ref = blobs.put(db, pdf_bytes, kind="sealed_pdf", retain_until=when)
    assert blobs.get(db, ref.sha256) == pdf_bytes
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from esign.config import Settings
from esign.contracts import BlobService, Clock
from esign.storage.fs import FileSystemObjectStore
from esign.storage.objectstore import BlobStoreUnavailable, ObjectStore, content_key
from esign.storage.s3 import S3ObjectStore
from esign.storage.service import ContentAddressedBlobService

if TYPE_CHECKING:  # pragma: no cover - typing only
    from mypy_boto3_s3.client import S3Client

__all__ = [
    "BlobStoreUnavailable",
    "ContentAddressedBlobService",
    "FileSystemObjectStore",
    "ObjectStore",
    "S3ObjectStore",
    "build_blob_service",
    "build_object_store",
    "content_key",
]


def build_object_store(settings: Settings, *, s3_client: S3Client | None = None) -> ObjectStore:
    """The backend ``BLOB_BACKEND`` selects. ``s3_client`` is for tests (moto) and for reuse."""
    if settings.blob_backend == "s3":
        client = s3_client if s3_client is not None else _default_s3_client(settings)
        return S3ObjectStore(
            client,
            bucket=settings.blob_s3_bucket,
            prefix=settings.blob_s3_prefix,
            object_lock_mode=settings.blob_s3_object_lock_mode,
            sse=settings.blob_s3_sse,
            sse_kms_key_id=settings.blob_s3_sse_kms_key_id,
        )
    return FileSystemObjectStore(settings.blob_fs_root)


def build_blob_service(settings: Settings, clock: Clock, *, s3_client: S3Client | None = None) -> BlobService:
    """The module's one factory (SPEC section 2)."""
    return ContentAddressedBlobService(build_object_store(settings, s3_client=s3_client), settings, clock)


def _default_s3_client(settings: Settings) -> S3Client:
    import boto3

    client: S3Client = boto3.client(
        "s3",
        region_name=settings.blob_s3_region,
        endpoint_url=settings.blob_s3_endpoint_url,
    )
    return client
