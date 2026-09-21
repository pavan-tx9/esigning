"""Fixtures for the storage tests: the two backends, and the service over each of them."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import boto3
import pytest
from moto import mock_aws

from esign.clock import FixedClock
from esign.config import Settings
from esign.contracts import BlobService
from esign.storage import build_blob_service
from tests.storage.helpers import corrupt_file, corrupt_object, delete_file, delete_object

if TYPE_CHECKING:  # pragma: no cover - typing only
    from mypy_boto3_s3.client import S3Client

BUCKET = "esign-blobs-test"
REGION = "us-east-1"


@dataclass(frozen=True)
class Backend:
    """A blob service plus the two things only someone behind it could do to what it stored."""

    name: str
    service: BlobService
    #: Replace the bytes at a storage key with something else.
    corrupt: Callable[[str], None]
    #: Make the object at a storage key go away.
    destroy: Callable[[str], None]


@pytest.fixture
def aws_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never let a test reach a real account, whatever is in the developer's environment."""
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SECURITY_TOKEN", "AWS_SESSION_TOKEN"):
        monkeypatch.setenv(name, "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.delenv("AWS_PROFILE", raising=False)


@pytest.fixture
def s3_client(aws_credentials: None) -> Iterator[S3Client]:
    """A moto-backed S3 with Object Lock enabled on the bucket, as production requires."""
    with mock_aws():
        client: S3Client = boto3.client("s3", region_name=REGION)
        client.create_bucket(Bucket=BUCKET, ObjectLockEnabledForBucket=True)
        yield client


@pytest.fixture
def s3_settings(settings: Settings) -> Settings:
    return settings.model_copy(update={"blob_backend": "s3", "blob_s3_bucket": BUCKET, "blob_s3_region": REGION})


@pytest.fixture
def fs_blobs(settings: Settings, clock: FixedClock) -> BlobService:
    return build_blob_service(settings, clock)


@pytest.fixture
def s3_blobs(s3_settings: Settings, clock: FixedClock, s3_client: S3Client) -> BlobService:
    return build_blob_service(s3_settings, clock, s3_client=s3_client)


@pytest.fixture(params=["fs", "s3"])
def backend(request: pytest.FixtureRequest) -> Backend:
    """Both backends, so every service-level guarantee is asserted against each of them."""
    if request.param == "s3":
        client: S3Client = request.getfixturevalue("s3_client")
        return Backend(
            name="s3",
            service=request.getfixturevalue("s3_blobs"),
            corrupt=lambda key: corrupt_object(client, BUCKET, key),
            destroy=lambda key: delete_object(client, BUCKET, key),
        )
    root: Path = request.getfixturevalue("blob_dir")
    return Backend(
        name="fs",
        service=request.getfixturevalue("fs_blobs"),
        corrupt=lambda key: corrupt_file(root / key),
        destroy=lambda key: delete_file(root / key),
    )


@pytest.fixture
def blobs(backend: Backend) -> BlobService:
    return backend.service
