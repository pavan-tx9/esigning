"""S3 backend: Object Lock, conditional put, encryption, and what happens when S3 says no.

Against moto. One caveat worth knowing: moto does not verify the ``ChecksumSHA256`` we send on
upload, where real S3 does. That is why nothing here relies on the server-side checksum for
integrity -- ``BlobService.get`` re-hashes on the client, which is the check that must hold.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import boto3
import pytest
from botocore.exceptions import ClientError
from sqlalchemy import text
from sqlalchemy.orm import Session

from esign.clock import FixedClock
from esign.config import Settings
from esign.contracts import BlobService, IntegrityFailure
from esign.storage import build_blob_service, build_object_store
from esign.storage.objectstore import BlobStoreUnavailable
from esign.storage.s3 import S3ObjectStore
from tests.storage.conftest import BUCKET, REGION

if TYPE_CHECKING:  # pragma: no cover - typing only
    from mypy_boto3_s3.client import S3Client

DATA = b"%PDF-1.7\nsealed\n%%EOF\n"
SHA = hashlib.sha256(DATA).digest()
RETAIN = datetime(2036, 1, 1, tzinfo=UTC)


@pytest.fixture
def store(s3_client: S3Client) -> S3ObjectStore:
    return S3ObjectStore(s3_client, bucket=BUCKET, prefix="esign/")


def _head(client: S3Client, key: str) -> dict[str, object]:
    return dict(client.head_object(Bucket=BUCKET, Key=key, ChecksumMode="ENABLED"))


def test_the_key_carries_the_configured_prefix_and_the_fan_out(store: S3ObjectStore) -> None:
    key = store.storage_key(SHA)
    hexed = SHA.hex()
    assert key == f"esign/{hexed[:2]}/{hexed[2:4]}/{hexed}"


def test_a_bucket_must_be_configured(s3_client: S3Client) -> None:
    with pytest.raises(ValueError, match="BLOB_S3_BUCKET"):
        S3ObjectStore(s3_client, bucket="")


def test_an_object_is_written_under_a_compliance_lock_by_default(store: S3ObjectStore, s3_client: S3Client) -> None:
    key = store.storage_key(SHA)
    assert store.put(key, DATA, sha256=SHA, retain_until=RETAIN) == "created"
    head = _head(s3_client, key)
    assert head["ObjectLockMode"] == "COMPLIANCE"
    assert head["ObjectLockRetainUntilDate"] == RETAIN


def test_governance_mode_is_available_but_has_to_be_asked_for(s3_client: S3Client) -> None:
    store = S3ObjectStore(s3_client, bucket=BUCKET, object_lock_mode="GOVERNANCE")
    key = store.storage_key(SHA)
    store.put(key, DATA, sha256=SHA, retain_until=RETAIN)
    assert _head(s3_client, key)["ObjectLockMode"] == "GOVERNANCE"


def test_server_side_encryption_is_on(store: S3ObjectStore, s3_client: S3Client) -> None:
    key = store.storage_key(SHA)
    store.put(key, DATA, sha256=SHA, retain_until=RETAIN)
    assert _head(s3_client, key)["ServerSideEncryption"] == "AES256"


def test_kms_encryption_is_selected_by_configuration(s3_client: S3Client) -> None:
    store = S3ObjectStore(s3_client, bucket=BUCKET, sse="aws:kms", sse_kms_key_id="alias/esign")
    key = store.storage_key(SHA)
    store.put(key, DATA, sha256=SHA, retain_until=RETAIN)
    head = _head(s3_client, key)
    assert head["ServerSideEncryption"] == "aws:kms"
    assert head["SSEKMSKeyId"] == "alias/esign"


def test_the_upload_carries_the_sha256_so_real_s3_can_verify_it(store: S3ObjectStore, s3_client: S3Client) -> None:
    key = store.storage_key(SHA)
    store.put(key, DATA, sha256=SHA, retain_until=RETAIN)
    assert _head(s3_client, key)["ChecksumSHA256"] == base64.b64encode(SHA).decode("ascii")


def test_the_put_is_conditional_so_an_existing_key_is_never_replaced(store: S3ObjectStore, s3_client: S3Client) -> None:
    key = store.storage_key(SHA)
    s3_client.put_object(Bucket=BUCKET, Key=key, Body=b"someone else's bytes")
    with pytest.raises(IntegrityFailure) as caught:
        store.put(key, DATA, sha256=SHA, retain_until=RETAIN)
    assert caught.value.code == "blob_content_mismatch"
    assert s3_client.get_object(Bucket=BUCKET, Key=key)["Body"].read() == b"someone else's bytes"


def test_writing_the_same_content_twice_is_idempotent(store: S3ObjectStore) -> None:
    key = store.storage_key(SHA)
    assert store.put(key, DATA, sha256=SHA, retain_until=RETAIN) == "created"
    assert store.put(key, DATA, sha256=SHA, retain_until=RETAIN) == "already_present"
    assert store.get(key) == DATA


def test_identical_content_without_a_recorded_checksum_is_still_recognised(
    store: S3ObjectStore, s3_client: S3Client
) -> None:
    """An object written by something else, with no checksum header: settle it by the bytes."""
    key = store.storage_key(SHA)
    s3_client.put_object(Bucket=BUCKET, Key=key, Body=DATA)
    assert store.put(key, DATA, sha256=SHA, retain_until=RETAIN) == "already_present"


def test_a_missing_key_reads_as_absent_rather_than_failing(store: S3ObjectStore) -> None:
    key = store.storage_key(hashlib.sha256(b"absent").digest())
    assert store.get(key) is None
    assert store.exists(key) is False


def test_retention_can_be_pushed_out_but_never_pulled_in(store: S3ObjectStore, s3_client: S3Client) -> None:
    key = store.storage_key(SHA)
    store.put(key, DATA, sha256=SHA, retain_until=RETAIN)
    later = RETAIN + timedelta(days=365 * 5)

    assert store.extend_retention(key, later) is True
    assert _head(s3_client, key)["ObjectLockRetainUntilDate"] == later
    # Asking for an earlier date changes nothing at all.
    assert store.extend_retention(key, RETAIN) is False
    assert _head(s3_client, key)["ObjectLockRetainUntilDate"] == later


def test_a_later_put_of_the_same_content_extends_the_retention_through_the_service(
    db: Session, s3_settings: Settings, clock: FixedClock, s3_client: S3Client
) -> None:
    blobs: BlobService = build_blob_service(s3_settings, clock, s3_client=s3_client)
    ref = blobs.put(db, DATA, kind="sealed_pdf", retain_until=RETAIN)
    key = build_object_store(s3_settings, s3_client=s3_client).storage_key(ref.sha256)
    longer = RETAIN + timedelta(days=365 * 10)

    blobs.put(db, DATA, kind="sealed_pdf", retain_until=longer)
    assert _head(s3_client, key)["ObjectLockRetainUntilDate"] == longer


def test_an_unreachable_store_is_reported_as_unavailable_with_nothing_leaked(
    aws_credentials: None,
) -> None:
    """No bucket name, key or endpoint in the message: it may be logged and returned."""
    client: S3Client = boto3.client("s3", region_name=REGION)
    store = S3ObjectStore(client, bucket="a-bucket-that-does-not-exist", prefix="esign/")
    with pytest.raises(BlobStoreUnavailable) as caught:
        store.put(store.storage_key(SHA), DATA, sha256=SHA, retain_until=RETAIN)
    message = str(caught.value)
    assert caught.value.code == "blob_store_unavailable"
    assert caught.value.http_status == 503
    assert "a-bucket-that-does-not-exist" not in message
    assert SHA.hex() not in message


def test_an_s3_failure_is_never_swallowed_into_a_successful_put(
    db: Session, s3_settings: Settings, clock: FixedClock, aws_credentials: None
) -> None:
    client: S3Client = boto3.client("s3", region_name=REGION)
    blobs = build_blob_service(
        s3_settings.model_copy(update={"blob_s3_bucket": "no-such-bucket-here"}), clock, s3_client=client
    )
    with pytest.raises(BlobStoreUnavailable):
        blobs.put(db, DATA, kind="sealed_pdf")
    stored = db.execute(text("SELECT count(*) FROM blobs WHERE sha256 = :s"), {"s": SHA}).scalar_one()
    assert stored == 0


def test_the_backend_never_calls_delete() -> None:
    import esign.storage.s3 as module

    source = Path(module.__file__).read_text(encoding="utf-8")
    for call in ("delete_object", "delete_objects", "delete_bucket", "abort_multipart_upload"):
        assert f".{call}(" not in source


def test_the_backend_has_no_delete_method(store: S3ObjectStore) -> None:
    forbidden = {"delete", "remove", "purge", "destroy"}
    names = {name for name in dir(store) if not name.startswith("_")}
    assert not {name for name in names if any(word in name.lower() for word in forbidden)}


def test_object_lock_is_really_enforced_by_the_bucket(store: S3ObjectStore, s3_client: S3Client) -> None:
    """A locked version cannot be destroyed, which is the point of COMPLIANCE mode."""
    key = store.storage_key(SHA)
    store.put(key, DATA, sha256=SHA, retain_until=RETAIN)
    version = s3_client.head_object(Bucket=BUCKET, Key=key)["VersionId"]
    with pytest.raises(ClientError):
        s3_client.delete_object(Bucket=BUCKET, Key=key, VersionId=version)
    assert store.get(key) == DATA
