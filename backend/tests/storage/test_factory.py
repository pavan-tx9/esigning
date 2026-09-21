"""The module's public seam: one factory, backend chosen by settings, contract-shaped."""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

import esign.storage
from esign.clock import FixedClock
from esign.config import Settings
from esign.contracts import BlobService
from esign.storage import build_blob_service, build_object_store
from esign.storage.fs import FileSystemObjectStore
from esign.storage.s3 import S3ObjectStore

if TYPE_CHECKING:  # pragma: no cover - typing only
    from mypy_boto3_s3.client import S3Client


def test_the_factory_is_named_and_shaped_as_the_spec_says() -> None:
    parameters = list(inspect.signature(build_blob_service).parameters)
    assert parameters[:2] == ["settings", "clock"]
    assert "build_blob_service" in esign.storage.__all__


def test_the_built_service_implements_every_method_the_protocol_declares(
    settings_no_db: Settings, clock: FixedClock
) -> None:
    blobs = build_blob_service(settings_no_db, clock)
    for name in ("put", "get", "exists"):
        assert callable(getattr(blobs, name))
        assert inspect.signature(getattr(blobs, name)).parameters.keys() == (
            inspect.signature(getattr(BlobService, name)).parameters.keys() - {"self"}
        )


def test_the_filesystem_backend_is_the_default(settings_no_db: Settings) -> None:
    assert isinstance(build_object_store(settings_no_db), FileSystemObjectStore)


def test_the_s3_backend_is_selected_by_settings(s3_settings: Settings, s3_client: S3Client) -> None:
    store = build_object_store(s3_settings, s3_client=s3_client)
    assert isinstance(store, S3ObjectStore)
    assert store.backend_name == "s3"


def test_an_s3_backend_without_a_bucket_fails_at_construction_not_at_the_first_put(
    settings_no_db: Settings, clock: FixedClock
) -> None:
    """A misconfiguration must not be discovered halfway through sealing a document."""
    broken = settings_no_db.model_copy(update={"blob_backend": "s3", "blob_s3_bucket": ""})
    with pytest.raises(ValueError, match="BLOB_S3_BUCKET"):
        build_blob_service(broken, clock, s3_client=None)


def test_the_module_imports_only_contracts_and_foundation() -> None:
    """SPEC section 2: "Modules depend on contracts.py and foundation files only"."""
    allowed = {
        "esign.contracts",
        "esign.config",
        "esign.clock",
        "esign.db",
        "esign.ids",
        "esign.logging",
        "esign.storage",
    }
    package = Path(esign.storage.__file__).parent
    for path in sorted(package.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            module = node.module if isinstance(node, ast.ImportFrom) else None
            if module is None or not module.startswith("esign"):
                continue
            root = module if module in allowed else module.rsplit(".", 1)[0]
            assert root in allowed or module.startswith("esign.storage."), f"{path.name} imports {module}"
