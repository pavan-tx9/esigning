"""Filesystem backend mechanics: the things that make a file on disk write-once.

No database: these are properties of the backend itself.
"""

from __future__ import annotations

import hashlib
import stat
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from esign.contracts import IntegrityFailure
from esign.storage import content_key
from esign.storage.fs import FileSystemObjectStore
from esign.storage.objectstore import BlobStoreUnavailable

DATA = b"the bytes of a document\n"
SHA = hashlib.sha256(DATA).digest()
RETAIN = datetime(2036, 1, 1, tzinfo=UTC)


@pytest.fixture
def store(blob_dir: Path) -> FileSystemObjectStore:
    return FileSystemObjectStore(blob_dir)


def test_the_key_is_the_content_hash_with_two_levels_of_fan_out(store: FileSystemObjectStore) -> None:
    key = store.storage_key(SHA)
    hexed = SHA.hex()
    assert key == f"{hexed[:2]}/{hexed[2:4]}/{hexed}"


def test_a_key_needs_a_real_digest() -> None:
    with pytest.raises(ValueError, match="32-byte"):
        content_key(b"too short")


def test_a_stored_file_is_read_only(store: FileSystemObjectStore, blob_dir: Path) -> None:
    key = store.storage_key(SHA)
    store.put(key, DATA, sha256=SHA, retain_until=RETAIN)
    mode = stat.S_IMODE((blob_dir / key).stat().st_mode)
    assert mode == 0o444


def test_a_stored_file_holds_exactly_the_bytes_and_reads_back(store: FileSystemObjectStore) -> None:
    key = store.storage_key(SHA)
    assert store.put(key, DATA, sha256=SHA, retain_until=RETAIN) == "created"
    assert store.get(key) == DATA
    assert store.exists(key)


def test_reading_a_key_that_was_never_written_is_none_not_an_error(store: FileSystemObjectStore) -> None:
    assert store.get(store.storage_key(hashlib.sha256(b"absent").digest())) is None
    assert not store.exists(store.storage_key(hashlib.sha256(b"absent").digest()))


def test_writing_the_same_content_twice_is_idempotent(store: FileSystemObjectStore) -> None:
    key = store.storage_key(SHA)
    assert store.put(key, DATA, sha256=SHA, retain_until=RETAIN) == "created"
    assert store.put(key, DATA, sha256=SHA, retain_until=RETAIN) == "already_present"
    assert store.get(key) == DATA


def test_a_key_already_holding_different_content_is_never_overwritten(
    store: FileSystemObjectStore, blob_dir: Path
) -> None:
    key = store.storage_key(SHA)
    path = blob_dir / key
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"someone else's bytes")

    with pytest.raises(IntegrityFailure) as caught:
        store.put(key, DATA, sha256=SHA, retain_until=RETAIN)
    assert caught.value.code == "blob_content_mismatch"
    assert path.read_bytes() == b"someone else's bytes"


def test_the_temporary_directory_is_left_empty(store: FileSystemObjectStore, blob_dir: Path) -> None:
    store.put(store.storage_key(SHA), DATA, sha256=SHA, retain_until=RETAIN)
    assert list((blob_dir / ".tmp").iterdir()) == []


def test_a_failed_link_leaves_no_temporary_file_behind(store: FileSystemObjectStore, blob_dir: Path) -> None:
    key = store.storage_key(SHA)
    path = blob_dir / key
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"different")
    with pytest.raises(IntegrityFailure):
        store.put(key, DATA, sha256=SHA, retain_until=RETAIN)
    assert list((blob_dir / ".tmp").iterdir()) == []


def test_concurrent_writers_of_the_same_content_all_succeed_with_one_file(
    store: FileSystemObjectStore, blob_dir: Path
) -> None:
    """The link is the race winner; everyone else confirms the content and moves on."""
    key = store.storage_key(SHA)
    start = threading.Barrier(6)
    outcomes: list[str] = []
    failures: list[BaseException] = []
    lock = threading.Lock()

    def worker() -> None:
        try:
            start.wait(timeout=30)
            result = store.put(key, DATA, sha256=SHA, retain_until=RETAIN)
            with lock:
                outcomes.append(result)
        except BaseException as exc:
            with lock:
                failures.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert failures == []
    assert len(outcomes) == 6
    assert outcomes.count("created") == 1
    assert (blob_dir / key).read_bytes() == DATA


def test_the_store_cannot_extend_a_retention_it_does_not_have(store: FileSystemObjectStore) -> None:
    key = store.storage_key(SHA)
    store.put(key, DATA, sha256=SHA, retain_until=RETAIN)
    assert store.extend_retention(key, RETAIN + timedelta(days=365)) is False


def test_an_unwritable_root_is_reported_as_the_store_being_unavailable(blob_dir: Path) -> None:
    """Not as a validation error and not as success: nothing may believe the blob was stored."""
    root = blob_dir / "locked"
    store = FileSystemObjectStore(root)
    root.chmod(0o500)
    try:
        with pytest.raises(BlobStoreUnavailable):
            store.put(store.storage_key(SHA), DATA, sha256=SHA, retain_until=RETAIN)
    finally:
        root.chmod(0o700)


def test_the_backend_has_no_delete_method(store: FileSystemObjectStore) -> None:
    forbidden = {"delete", "remove", "unlink", "purge", "destroy", "rename", "replace"}
    names = {name for name in dir(store) if not name.startswith("_")}
    assert not {name for name in names if any(word in name.lower() for word in forbidden)}


def test_the_backend_source_never_renames_over_a_path() -> None:
    """A rename would silently replace a stored blob. A hard link cannot."""
    import esign.storage.fs as module

    source = Path(module.__file__).read_text(encoding="utf-8")
    assert "os.rename" not in source
    assert "os.replace" not in source
    assert ".rename(" not in source
    assert "hardlink_to" in source
