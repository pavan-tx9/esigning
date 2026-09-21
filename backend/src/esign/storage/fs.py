"""Filesystem blob backend. Development and tests; production uses S3 with Object Lock.

Writing a blob has to survive a crash, a concurrent writer and a retry without ever producing a
file whose contents are not the bytes its name promises. So:

1. the bytes go to a uniquely named temporary file, opened ``O_CREAT | O_EXCL``;
2. the file is flushed and ``fsync``-ed, so the data is on the disk before anything points at it;
3. it is made read-only (``0o444``) *before* it is linked into place;
4. it is hard-linked to its final path. ``link`` fails if the target exists -- it can never
   replace a blob. ``rename`` is not used anywhere in this file, because rename overwrites;
5. the containing directory is ``fsync``-ed, so the link itself is durable;
6. the temporary name is unlinked, leaving one read-only file with two-level fan-out.

A crash at any step leaves either no final file or a complete one. It never leaves a truncated
file at the final path, which is the failure mode that would make a blob quietly wrong.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime
from pathlib import Path
from secrets import token_hex

from esign.contracts import IntegrityFailure
from esign.logging import get_logger
from esign.storage.objectstore import BlobStoreUnavailable, PutOutcome, content_key

__all__ = ["FileSystemObjectStore"]

log = get_logger(__name__)

#: Blobs are read-only to everyone, including the process that wrote them.
_BLOB_MODE = 0o444
#: Directories are private to the service account.
_DIR_MODE = 0o700


class FileSystemObjectStore:
    """Content-addressed files under ``root``, created read-only and never replaced.

    The filesystem cannot enforce a retain-until date the way S3 Object Lock can. That is the
    reason this backend is documented as development-only: ``retain_until`` is recorded in the
    ``blobs`` row, and the file mode stops accidents, but nothing here stops a determined
    ``root``. Production storage is ``s3``.
    """

    backend_name = "fs"

    def __init__(self, root: Path) -> None:
        self._root = Path(root)
        self._tmp = self._root / ".tmp"
        self._root.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
        self._tmp.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)

    @property
    def root(self) -> Path:
        return self._root

    def storage_key(self, sha256: bytes) -> str:
        return content_key(sha256)

    def path_for(self, key: str) -> Path:
        return self._root / key

    def put(
        self,
        key: str,
        data: bytes,
        *,
        sha256: bytes,
        retain_until: datetime,  # noqa: ARG002 - a filesystem cannot hold a retention lock; see the class docstring
    ) -> PutOutcome:
        path = self.path_for(key)
        if path.exists():
            return self._confirm_identical(path, sha256)

        try:
            path.parent.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
            tmp = self._tmp / f"{sha256.hex()}.{os.getpid()}.{token_hex(8)}.part"
            descriptor = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
            except BaseException:
                tmp.unlink(missing_ok=True)
                raise

            try:
                tmp.chmod(_BLOB_MODE)
                try:
                    # Hard link, not rename: link refuses to replace an existing blob.
                    path.hardlink_to(tmp)
                except FileExistsError:
                    return self._confirm_identical(path, sha256)
                _fsync_directory(path.parent)
            finally:
                tmp.unlink(missing_ok=True)
        except OSError as exc:
            raise BlobStoreUnavailable(f"filesystem blob store cannot write ({exc.errno})") from exc

        log.debug("blob.written", backend=self.backend_name, sha256=sha256, size_bytes=len(data))
        return "created"

    def get(self, key: str) -> bytes | None:
        path = self.path_for(key)
        try:
            return path.read_bytes()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise BlobStoreUnavailable(f"filesystem blob store cannot read ({exc.errno})") from exc

    def exists(self, key: str) -> bool:
        return self.path_for(key).is_file()

    def extend_retention(self, key: str, retain_until: datetime) -> bool:  # noqa: ARG002
        """No-op: a filesystem has no retention lock to extend."""
        return False

    def _confirm_identical(self, path: Path, sha256: bytes) -> PutOutcome:
        """A file is already there. It is only acceptable if it is byte-for-byte this content."""
        try:
            existing = path.read_bytes()
        except OSError as exc:
            raise BlobStoreUnavailable(f"filesystem blob store cannot read ({exc.errno})") from exc
        if hashlib.sha256(existing).digest() != sha256:
            raise IntegrityFailure(
                f"blob {sha256.hex()} is already stored with different content",
                code="blob_content_mismatch",
            )
        return "already_present"


def _fsync_directory(path: Path) -> None:
    """Make a newly created directory entry durable. Best effort on platforms that refuse it."""
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    except OSError:  # pragma: no cover - some filesystems do not allow fsync on a directory
        pass
    finally:
        os.close(descriptor)
