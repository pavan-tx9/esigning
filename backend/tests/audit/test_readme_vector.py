"""``audit/README.md`` promises someone can re-verify a chain by hand. This keeps that promise true.

The worked example in the README is recomputed here from the live code. If the encoding changes,
or someone edits the document, this fails -- which is the point: a hand-verification guide that
has silently drifted is worse than none.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import esign.audit
from esign.audit.canonical import ZERO_HASH, compute_event_hash, hash_input
from esign.audit.events import validate_event_data
from esign.contracts import EventType

README = Path(esign.audit.__file__).parent / "README.md"

#: Exactly the row the README tabulates.
VECTOR_FIELDS: dict[str, Any] = {
    "actor_capacity": "self",
    "actor_role": "patient",
    "actor_user_id": "host-user-1187",
    "auth_method": "portal_otp",
    "data": validate_event_data(
        EventType.SIGNER_SIGNED,
        {
            "signer_id": UUID("7c3f1d2e-5a64-4b8f-9c10-2e4a6b8d0f31"),
            "role_key": "patient",
            "capacity": "self",
            "consent_version": "2026-09",
            "reauth_used": False,
            "presented_sha256": bytes.fromhex("3b1f8c2d4e5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e"),
            "revision_no": 2,
            "revision_sha256": bytes.fromhex("9a8b7c6d5e4f30211203f4e5d6c7b8a9f0e1d2c3b4a59687786950413223145f"),
            "capture_count": 1,
            "captures": [{"field_id": "patient_sig", "kind": "drawn"}],
        },
    ),
    "document_sha256": bytes.fromhex("9a8b7c6d5e4f30211203f4e5d6c7b8a9f0e1d2c3b4a59687786950413223145f"),
    "event_type": "signer.signed",
    "id": UUID("0f2c9a44-1d3b-4e57-8a66-b1c2d3e4f5a6"),
    "ip": "198.51.100.24",
    "occurred_at": datetime(2026, 3, 17, 14, 31, 2, 481073, tzinfo=UTC),
    "on_behalf_of": None,
    "prev_event_hash": bytes.fromhex("5d41402abc4b2a76b9719d911017c592a1b2c3d4e5f60718293a4b5c6d7e8f90"),
    "sequence": 7,
    "session_id": UUID("b4d5e6f7-8a9b-4c0d-9e1f-2a3b4c5d6e7f"),
    "stream_id": UUID("1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9"),
    "stream_type": "envelope",
    "user_agent": "Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X)",
}


def test_the_readme_exists_and_documents_the_field_list() -> None:
    text = README.read_text(encoding="utf-8")
    for field in esign.audit.HASHED_FIELDS:
        assert f"`{field}`" in text, field
    assert "`event_hash` is not in the list" in text


def test_the_worked_canonical_json_in_the_readme_is_byte_for_byte_correct() -> None:
    encoded = hash_input(VECTOR_FIELDS).decode("utf-8")
    assert encoded in README.read_text(encoding="utf-8")


def test_the_worked_digest_in_the_readme_is_correct() -> None:
    digest = compute_event_hash(VECTOR_FIELDS).hex()
    assert digest in README.read_text(encoding="utf-8")


def test_the_readme_states_the_byte_length_of_the_worked_example() -> None:
    length = len(hash_input(VECTOR_FIELDS))
    assert f"{length} bytes" in README.read_text(encoding="utf-8")


def test_the_readme_quotes_the_genesis_prev_hash() -> None:
    assert ZERO_HASH.hex() in README.read_text(encoding="utf-8")
