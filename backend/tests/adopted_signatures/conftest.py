"""Fixtures and helpers for the adopted-signature tests (Addendum 1 B).

These run against the real HTTP app over the real modules -- the ``world``/``ehr`` fixtures the
end-to-end suite builds -- because the feature only exists as the sum of its parts: identity holds
the row, the envelope service resolves it under the envelope lock, and the API layer offers it,
saves it and writes the trail. A test with a fake in the middle of that could pass while the real
thing offered one signer's signature to another.

The fixtures are imported rather than copied, so there is one definition of "the real stack".
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from sqlalchemy import text

from tests.e2e.conftest import (  # noqa: F401 - re-exported pytest fixtures
    Ehr,
    Signer,
    World,
    e2e_pki,
    e2e_settings,
    ehr,
    world,
)

#: The patient of the sample envelopes, as the host identifies them. Saved signatures are keyed on
#: ``(host_id, host_user_id)``, so the tests vary exactly this to test "a different user".
PATIENT = "pt-100482"
OTHER_PATIENT = "pt-778931"

#: A kiosk context: staff at a clinic tablet vouching for the patient in front of them.
KIOSK = {"staff_user_id": "staff-3310", "identity_check": "photo_id"}


@pytest.fixture
def other_ehr(world: World) -> Ehr:  # noqa: F811 - the fixture, not the function
    """A second EHR with the same templates: the "different host" of the rules below."""
    host = world.host()
    host.publish_template("hipaa_acknowledgement")
    return host


def envelope_for(
    ehr: Ehr,  # noqa: F811
    *,
    host_user_id: str = PATIENT,
    template_key: str = "hipaa_acknowledgement",
) -> dict[str, Any]:
    """One envelope for this user, so a second session for the same person can be opened."""
    body = ehr.envelope_body(template_key)
    for signer in body["signers"]:
        if signer["role_key"] == "patient":
            signer["host_user_id"] = host_user_id
    response = ehr.post("/envelopes", body)
    assert response.status_code == 201, response.text
    payload: dict[str, Any] = response.json()
    return payload


def sign_body(
    signer: Signer,
    payload: dict[str, Any],
    *,
    kind: str = "drawn",
    save: bool = False,
    captures: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "intent_confirmed": True,
        "captures": signer.captures(payload, kind=kind) if captures is None else captures,
    }
    if save:
        body["save_adopted_signature"] = True
    return body


def sign(signer: Signer, payload: dict[str, Any], *, key: str, **kwargs: Any) -> httpx.Response:
    return signer.post("/sign", sign_body(signer, payload, **kwargs), **{"Idempotency-Key": key})


def adopt(
    ehr: Ehr,  # noqa: F811
    *,
    host_user_id: str = PATIENT,
    kind: str = "drawn",
    key: str = "adopt-1",
) -> dict[str, Any]:
    """Sign one envelope and keep the signature: the "session A" of every test below.

    Returns the envelope, so a test can read the trail of the session the signature was saved in.
    """
    envelope = envelope_for(ehr, host_user_id=host_user_id)
    signer = ehr.open_session(envelope, "patient")
    payload = signer.review_and_consent()
    response = sign(signer, payload, key=f"{key}-{envelope['id']}", kind=kind, save=True)
    assert response.status_code == 200, response.text
    return envelope


def offered(ehr: Ehr, *, host_user_id: str = PATIENT) -> dict[str, Any] | None:  # noqa: F811
    """What a fresh session for this user is offered: the ``adopted_signature`` payload, or None."""
    envelope = envelope_for(ehr, host_user_id=host_user_id)
    signer = ehr.open_session(envelope, "patient")
    adopted: dict[str, Any] | None = signer.session()["adopted_signature"]
    return adopted


def adopted_capture(payload: dict[str, Any], adopted_signature_id: str) -> list[dict[str, Any]]:
    """The wire shape of an ``adopted`` capture: the id, and nothing else."""
    return [
        {"field_id": field["id"], "kind": "adopted", "adopted_signature_id": adopted_signature_id}
        for field in payload["fields"]
        if field["type"] in ("signature", "initials")
    ]


def stored_image_hex(world: World, adopted_signature_id: str) -> str:  # noqa: F811
    """The saved signature's image hash, as the database holds it.

    The trail's capture digest is compared against *this*, not against a digest recomputed from
    the test's own bytes: what has to be true is that the stamped mark was the stored one.
    """
    with world.sessions() as db:
        stored = db.execute(
            text("SELECT image_sha256 FROM adopted_signatures WHERE id = :id"),
            {"id": adopted_signature_id},
        ).scalar_one()
    return bytes(stored).hex()


def adopted_rows(world: World, host_user_id: str = PATIENT) -> list[Any]:  # noqa: F811
    """Every saved-signature row for a user, oldest first, revoked ones included."""
    with world.sessions() as db:
        return list(
            db.execute(
                text(
                    "SELECT id, kind, image_sha256, typed_text, revoked_at, revoke_reason, created_at "
                    "FROM adopted_signatures WHERE host_user_id = :user ORDER BY created_at"
                ),
                {"user": host_user_id},
            ).all()
        )


def capture_rows(world: World, signer_id: str) -> list[Any]:  # noqa: F811
    with world.sessions() as db:
        return list(
            db.execute(
                text(
                    "SELECT field_id, kind, image_sha256, typed_text, adopted_signature_id "
                    "FROM signature_captures WHERE signer_id = :id ORDER BY field_id"
                ),
                {"id": signer_id},
            ).all()
        )


def system_events(world: World) -> list[Any]:  # noqa: F811
    with world.sessions() as db:
        return list(
            db.execute(
                text(
                    "SELECT event_type, actor_user_id, data FROM audit_events "
                    "WHERE stream_type = 'system' ORDER BY sequence"
                )
            ).all()
        )
