"""The guarantees ``BlobService`` makes, asserted against both backends.

Every test in this file runs twice, once on ``fs`` and once on ``s3`` (moto), because a guarantee
that only holds in development is not a guarantee.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from esign.contracts import BlobRef, BlobService, IntegrityFailure, NotFound, ValidationFailed
from tests.conftest import FROZEN_NOW
from tests.storage.conftest import Backend
from tests.storage.helpers import blob_count, blob_row, digest

PDF = b"%PDF-1.7\nnot really a pdf, but distinct bytes\n%%EOF\n"
OTHER = b"%PDF-1.7\nsomething else entirely\n%%EOF\n"


def test_put_returns_the_content_hash_size_and_kind(db: Session, blobs: BlobService) -> None:
    ref = blobs.put(db, PDF, kind="sealed_pdf")
    assert ref == BlobRef(sha256=digest(PDF), size_bytes=len(PDF), kind="sealed_pdf")


def test_put_records_a_row_with_a_storage_key_and_a_retention_date(db: Session, blobs: BlobService) -> None:
    ref = blobs.put(db, PDF, kind="presented_pdf")
    row = blob_row(db, ref.sha256)
    assert row is not None
    assert bytes(row.sha256) == ref.sha256
    assert row.size_bytes == len(PDF)
    assert row.kind == "presented_pdf"
    assert row.storage_key.endswith(ref.sha256.hex())
    assert row.retain_until is not None


def test_the_default_retention_is_the_configured_floor_measured_from_the_clock(db: Session, blobs: BlobService) -> None:
    ref = blobs.put(db, PDF, kind="sealed_pdf")
    row = blob_row(db, ref.sha256)
    assert row.retain_until == FROZEN_NOW + timedelta(days=365 * 10)


def test_an_explicit_retention_date_is_recorded(db: Session, blobs: BlobService) -> None:
    when = FROZEN_NOW + timedelta(days=365 * 25)
    ref = blobs.put(db, PDF, kind="sealed_pdf", retain_until=when)
    assert blob_row(db, ref.sha256).retain_until == when


def test_get_returns_exactly_what_was_put(db: Session, blobs: BlobService) -> None:
    ref = blobs.put(db, PDF, kind="revision_pdf")
    assert blobs.get(db, ref.sha256) == PDF


def test_get_of_an_unknown_digest_is_not_found(db: Session, blobs: BlobService) -> None:
    with pytest.raises(NotFound):
        blobs.get(db, digest(b"never stored"))


def test_exists_answers_for_stored_and_unstored_content(db: Session, blobs: BlobService) -> None:
    ref = blobs.put(db, PDF, kind="revision_pdf")
    assert blobs.exists(db, ref.sha256)
    assert not blobs.exists(db, digest(b"never stored"))


def test_putting_the_same_bytes_twice_is_one_blob_and_one_row(db: Session, blobs: BlobService) -> None:
    first = blobs.put(db, PDF, kind="revision_pdf")
    second = blobs.put(db, PDF, kind="revision_pdf")
    assert first == second
    assert blob_count(db, first.sha256) == 1


def test_a_repeat_put_under_a_different_kind_returns_the_recorded_kind(db: Session, blobs: BlobService) -> None:
    """Identical bytes are one blob. The row that exists is the truth, and it is append-only."""
    first = blobs.put(db, PDF, kind="presented_pdf")
    second = blobs.put(db, PDF, kind="revision_pdf")
    assert second.kind == first.kind == "presented_pdf"
    assert blob_count(db, first.sha256) == 1


def test_two_different_documents_are_two_blobs(db: Session, blobs: BlobService) -> None:
    one = blobs.put(db, PDF, kind="revision_pdf")
    two = blobs.put(db, OTHER, kind="revision_pdf")
    assert one.sha256 != two.sha256
    assert blobs.get(db, one.sha256) == PDF
    assert blobs.get(db, two.sha256) == OTHER


def test_an_empty_blob_is_refused(db: Session, blobs: BlobService) -> None:
    with pytest.raises(ValidationFailed) as caught:
        blobs.put(db, b"", kind="sealed_pdf")
    assert caught.value.code == "blob_empty"


def test_an_unknown_kind_is_refused(db: Session, blobs: BlobService) -> None:
    with pytest.raises(ValidationFailed):
        blobs.put(db, PDF, kind="chart_note")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "when",
    [
        FROZEN_NOW - timedelta(days=1),
        FROZEN_NOW,
        datetime(2050, 1, 1),
    ],
)
def test_a_retention_date_that_is_not_a_future_aware_instant_is_refused(
    db: Session, blobs: BlobService, when: datetime
) -> None:
    with pytest.raises(ValidationFailed) as caught:
        blobs.put(db, PDF, kind="sealed_pdf", retain_until=when)
    assert caught.value.code == "blob_retention_invalid"


@pytest.mark.parametrize("bad", [b"", b"short", bytes(31), bytes(33)])
def test_a_digest_of_the_wrong_length_is_refused(db: Session, blobs: BlobService, bad: bytes) -> None:
    with pytest.raises(ValidationFailed):
        blobs.get(db, bad)
    with pytest.raises(ValidationFailed):
        blobs.exists(db, bad)


def test_the_service_has_no_delete_method(blobs: BlobService) -> None:
    forbidden = {"delete", "remove", "unlink", "purge", "destroy", "expire", "overwrite"}
    names = {name for name in dir(blobs) if not name.startswith("_")}
    assert not {name for name in names if any(word in name.lower() for word in forbidden)}


def test_put_does_not_commit(db: Session, blobs: BlobService) -> None:
    ref = blobs.put(db, PDF, kind="sealed_pdf")
    db.rollback()
    # The row went with the transaction. The bytes are still in the store, which is harmless:
    # content-addressed, so the next put of the same bytes adopts them.
    assert blob_row(db, ref.sha256) is None


def test_a_rolled_back_put_can_be_repeated(db: Session, blobs: BlobService) -> None:
    blobs.put(db, PDF, kind="sealed_pdf")
    db.rollback()
    ref = blobs.put(db, PDF, kind="sealed_pdf")
    assert blobs.get(db, ref.sha256) == PDF
    assert blob_count(db, ref.sha256) == 1


def test_a_large_blob_round_trips(db: Session, blobs: BlobService) -> None:
    data = bytes(range(256)) * 8192  # 2 MiB
    ref = blobs.put(db, data, kind="sealed_pdf")
    assert ref.size_bytes == len(data)
    assert blobs.get(db, ref.sha256) == data


def test_a_corrupted_blob_raises_integrity_failure_not_a_wrong_answer(db: Session, backend: Backend) -> None:
    """SPEC section 12: "corrupted blob raises IntegrityFailure"."""
    ref = backend.service.put(db, PDF, kind="sealed_pdf")
    backend.corrupt(_storage_key(db, ref.sha256))
    with pytest.raises(IntegrityFailure) as caught:
        backend.service.get(db, ref.sha256)
    assert caught.value.code == "blob_corrupt"


def test_a_destroyed_blob_is_an_integrity_failure_not_a_miss(db: Session, backend: Backend) -> None:
    """Reporting "not found" would let a caller treat destroyed evidence as "not ready yet"."""
    ref = backend.service.put(db, PDF, kind="sealed_pdf")
    backend.destroy(_storage_key(db, ref.sha256))
    with pytest.raises(IntegrityFailure) as caught:
        backend.service.get(db, ref.sha256)
    assert caught.value.code == "blob_missing"
    with pytest.raises(IntegrityFailure):
        backend.service.exists(db, ref.sha256)


def test_a_repeat_put_over_destroyed_evidence_is_refused_rather_than_healed(db: Session, backend: Backend) -> None:
    ref = backend.service.put(db, PDF, kind="sealed_pdf")
    backend.destroy(_storage_key(db, ref.sha256))
    with pytest.raises(IntegrityFailure):
        backend.service.put(db, PDF, kind="sealed_pdf")


def test_content_at_a_key_that_is_not_its_content_is_refused(db: Session, backend: Backend) -> None:
    """Overwrite refused: the store already holds something else where this content would go."""
    ref = backend.service.put(db, PDF, kind="sealed_pdf")
    key = _storage_key(db, ref.sha256)
    backend.corrupt(key)
    db.rollback()  # forget the row, so put takes the "write it" path again
    with pytest.raises(IntegrityFailure) as caught:
        backend.service.put(db, PDF, kind="sealed_pdf")
    assert caught.value.code == "blob_content_mismatch"


def _storage_key(db: Session, sha256: bytes) -> str:
    return str(blob_row(db, sha256).storage_key)
