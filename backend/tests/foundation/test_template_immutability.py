"""A published template version is what the signer saw. It does not change afterwards."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from tests.foundation.helpers import RAISE_EXCEPTION, insert_template_version, sqlstate


def _publish(db: Session, version_id: object) -> None:
    db.execute(
        text("UPDATE template_versions SET status = 'published', published_at = now() WHERE id = :id"),
        {"id": version_id},
    )


def test_a_draft_version_can_still_be_edited(db: Session) -> None:
    version_id = insert_template_version(db)
    db.execute(
        text('UPDATE template_versions SET fields = \'[{"id": "sig"}]\'::jsonb WHERE id = :id'),
        {"id": version_id},
    )
    fields = db.execute(text("SELECT fields FROM template_versions WHERE id = :id"), {"id": version_id}).scalar_one()
    assert fields == [{"id": "sig"}]


def test_a_draft_version_can_be_published(db: Session) -> None:
    version_id = insert_template_version(db)
    _publish(db, version_id)
    status = db.execute(text("SELECT status FROM template_versions WHERE id = :id"), {"id": version_id}).scalar_one()
    assert status == "published"


def test_a_published_version_cannot_be_edited(db: Session) -> None:
    version_id = insert_template_version(db)
    _publish(db, version_id)
    with pytest.raises(DBAPIError) as caught, db.begin_nested():
        db.execute(
            text('UPDATE template_versions SET fields = \'[{"id": "sneaky"}]\'::jsonb WHERE id = :id'),
            {"id": version_id},
        )
    assert sqlstate(caught.value) == RAISE_EXCEPTION
    assert "immutable" in str(caught.value.orig)


def test_a_published_version_cannot_be_deleted(db: Session) -> None:
    version_id = insert_template_version(db)
    _publish(db, version_id)
    with pytest.raises(DBAPIError) as caught, db.begin_nested():
        db.execute(text("DELETE FROM template_versions WHERE id = :id"), {"id": version_id})
    assert sqlstate(caught.value) == RAISE_EXCEPTION
    assert "cannot be deleted" in str(caught.value.orig)


def test_a_published_version_may_be_retired_and_nothing_else(db: Session) -> None:
    version_id = insert_template_version(db)
    _publish(db, version_id)
    db.execute(
        text("UPDATE template_versions SET status = 'retired' WHERE id = :id"),
        {"id": version_id},
    )
    status = db.execute(text("SELECT status FROM template_versions WHERE id = :id"), {"id": version_id}).scalar_one()
    assert status == "retired"


def test_retiring_cannot_smuggle_another_change_through(db: Session) -> None:
    """`status -> retired` is allowed only when every other column is untouched."""
    version_id = insert_template_version(db)
    _publish(db, version_id)
    with pytest.raises(DBAPIError) as caught, db.begin_nested():
        db.execute(
            text(
                "UPDATE template_versions SET status = 'retired', "
                'fields = \'[{"id": "sneaky"}]\'::jsonb WHERE id = :id'
            ),
            {"id": version_id},
        )
    assert sqlstate(caught.value) == RAISE_EXCEPTION
    assert "immutable" in str(caught.value.orig)
