"""Row factories for the identity tests.

The identity module owns hosts, sessions, attestations and consent texts, but every session hangs
off a signer, which hangs off an envelope, a template version and a blob. These helpers build that
chain with plain SQL so the tests depend on the schema rather than on another module's code.

Timestamps come from the test's ``Clock``: the fixtures' frozen time is nowhere near the database
server's ``now()``, and a test that mixed the two would pass or fail depending on the date.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import timedelta
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from esign.clock import FixedClock
from esign.ids import new_id

#: Deliberately recognisable: several tests assert this string never reaches a log line.
SIGNER_DISPLAY_NAME = "Wanda Q Testpatient"


@dataclass(frozen=True)
class SignerFixture:
    """One host, envelope and signer, ready for a session."""

    host_id: UUID
    envelope_id: UUID
    signer_id: UUID


def digest(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()


def insert_host_row(db: Session, clock: FixedClock, *, name: str = "Test EHR", key_hash: bytes | None = None) -> UUID:
    host_id = new_id()
    db.execute(
        text(
            "INSERT INTO hosts (id, name, api_key_hash, allowed_origins, created_at) "
            "VALUES (:id, :name, :key, ARRAY['https://ehr.example.org'], :created_at)"
        ),
        {"id": host_id, "name": name, "key": key_hash or digest(f"key:{host_id}"), "created_at": clock.now()},
    )
    return host_id


def make_signer(
    db: Session,
    clock: FixedClock,
    *,
    host_id: UUID | None = None,
    display_name: str = SIGNER_DISPLAY_NAME,
    requires_reauth: bool = False,
    role_key: str = "patient",
    envelope_id: UUID | None = None,
) -> SignerFixture:
    """A signer on a live envelope. Reuse ``envelope_id`` to put two signers on one envelope."""
    now = clock.now()
    if envelope_id is None:
        host_id = host_id or insert_host_row(db, clock)
        blob_sha = digest(f"template:{new_id()}")
        db.execute(
            text(
                "INSERT INTO blobs (sha256, size_bytes, kind, storage_key, created_at) "
                "VALUES (:sha, 1024, 'template_pdf', :key, :created_at) ON CONFLICT DO NOTHING"
            ),
            {"sha": blob_sha, "key": f"t/{blob_sha.hex()}", "created_at": now},
        )
        template_id = new_id()
        db.execute(
            text(
                "INSERT INTO templates (id, host_id, key, name, document_type, created_at) "
                "VALUES (:id, :host, :key, 'Consent', 'patient_consent', :created_at)"
            ),
            {"id": template_id, "host": host_id, "key": f"tpl_{template_id.hex[:8]}", "created_at": now},
        )
        version_id = new_id()
        db.execute(
            text(
                "INSERT INTO template_versions (id, template_id, version, status, pdf_sha256, fields, signer_roles, "
                " created_at, published_at) "
                "VALUES (:id, :tpl, 1, 'published', :sha, '[]'::jsonb, '[]'::jsonb, :created_at, :created_at)"
            ),
            {"id": version_id, "tpl": template_id, "sha": blob_sha, "created_at": now},
        )
        envelope_id = new_id()
        db.execute(
            text(
                "INSERT INTO envelopes (id, host_id, template_version_id, document_type, patient_ref, "
                " signing_order, status, expires_at, created_at) "
                "VALUES (:id, :host, :tv, 'patient_consent', 'patient-ref-1', 'parallel', 'created', "
                "        :expires_at, :created_at)"
            ),
            {
                "id": envelope_id,
                "host": host_id,
                "tv": version_id,
                "expires_at": now + timedelta(days=14),
                "created_at": now,
            },
        )
    else:
        host_id = (
            host_id
            or db.execute(text("SELECT host_id FROM envelopes WHERE id = :id"), {"id": envelope_id}).scalar_one()
        )

    signer_id = new_id()
    db.execute(
        text(
            "INSERT INTO signers (id, envelope_id, role_key, host_user_id, display_name, capacity, order_index, "
            " requires_reauth, status) "
            "VALUES (:id, :env, :role_key, :host_user, :display_name, 'self', 0, :requires_reauth, 'pending')"
        ),
        {
            "id": signer_id,
            "env": envelope_id,
            "role_key": role_key,
            "host_user": f"host-user-{signer_id.hex[:8]}",
            "display_name": display_name,
            "requires_reauth": requires_reauth,
        },
    )
    assert host_id is not None
    return SignerFixture(host_id=host_id, envelope_id=envelope_id, signer_id=signer_id)


def live_session_count(db: Session, signer_id: UUID) -> int:
    return int(
        db.execute(
            text("SELECT count(*) FROM signing_sessions WHERE signer_id = :id AND revoked_at IS NULL"),
            {"id": signer_id},
        ).scalar_one()
    )
