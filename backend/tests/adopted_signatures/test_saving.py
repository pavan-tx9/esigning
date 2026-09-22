"""Saving a signature: who may, when, and what is written (Addendum 1 B).

Only the signer, from inside their own live session, and only once their signature has actually
been applied -- a saved signature that never signed anything is a signature nobody adopted. Never
from a kiosk, and never through the host API: staff cannot create a doctor's signature.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import text

from tests.adopted_signatures.conftest import (
    KIOSK,
    OTHER_PATIENT,
    PATIENT,
    adopt,
    adopted_rows,
    envelope_for,
    offered,
    sign,
    sign_body,
    system_events,
)
from tests.e2e.conftest import Ehr, World


def _adopted_events(ehr: Ehr, envelope_id: str) -> list[dict[str, Any]]:
    return [e for e in ehr.audit(envelope_id) if e["event_type"] == "signature.adopted"]


def test_saving_writes_one_live_row_and_records_it_on_the_envelope_stream(ehr: Ehr, world: World) -> None:
    envelope = adopt(ehr)

    rows = adopted_rows(world)
    assert len(rows) == 1
    assert rows[0].kind == "drawn"
    assert rows[0].revoked_at is None
    assert rows[0].typed_text is None

    # The event lives on the stream of the session that saved it, one step after the signature it
    # was adopted from, and carries the digest rather than the ink.
    events = _adopted_events(ehr, envelope["id"])
    assert len(events) == 1
    data = events[0]["data"]
    assert data["adopted_signature_id"] == str(rows[0].id)
    assert data["kind"] == "drawn"
    assert data["image_sha256"] == bytes(rows[0].image_sha256).hex()
    assert data["typed_text_sha256"] is None
    assert events[0]["actor"]["user_id"] == PATIENT


def test_the_saved_image_is_the_one_that_was_stamped(ehr: Ehr, world: World) -> None:
    adopt(ehr)
    row = adopted_rows(world)[0]

    with world.sessions() as db:
        kind = db.execute(
            text("SELECT kind FROM blobs WHERE sha256 = :sha"), {"sha": bytes(row.image_sha256)}
        ).scalar_one()

    # The row names a blob the sign path stored, of the kind only a sanitised signature gets: the
    # client's original bytes are not what is kept and not what is offered next time.
    assert kind == "signature_image"


def test_a_typed_signature_is_saved_as_the_text_that_was_stamped(ehr: Ehr, world: World) -> None:
    adopt(ehr, kind="typed")

    row = adopted_rows(world)[0]
    assert row.kind == "typed"
    assert row.image_sha256 is None
    assert row.typed_text


def test_saving_again_revokes_the_earlier_row(ehr: Ehr, world: World) -> None:
    adopt(ehr, key="first")
    adopt(ehr, kind="typed", key="second")

    rows = adopted_rows(world)
    assert len(rows) == 2
    # Rows are never deleted: a capture may point at the old one. It is revoked and stays.
    assert rows[0].revoke_reason == "replaced"
    assert rows[0].revoked_at is not None
    assert rows[1].revoked_at is None

    offered_now = offered(ehr)
    assert offered_now is not None
    assert offered_now["id"] == str(rows[1].id)
    assert offered_now["kind"] == "typed"

    revocations = [e for e in system_events(world) if e.event_type == "signature.adoption_revoked"]
    assert [e.data["reason"] for e in revocations] == ["replaced"]
    assert revocations[0].data["adopted_signature_id"] == str(rows[0].id)
    assert revocations[0].data["host_user_id"] == PATIENT


def test_a_kiosk_session_saves_nothing_and_signs_nothing(ehr: Ehr, world: World) -> None:
    envelope = envelope_for(ehr)
    kiosk = ehr.open_session(envelope, "patient", method="staff_verified", kiosk=KIOSK)
    payload = kiosk.review_and_consent()

    response = kiosk.post(
        "/sign", sign_body(kiosk, payload, save=True), **{"Idempotency-Key": f"kiosk-save-{envelope['id']}"}
    )

    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "adoption_not_allowed"
    assert adopted_rows(world) == []
    # The refusal rolls the whole request back: the signature is not applied either, so nobody is
    # left having signed a document while being told they had not.
    assert ehr.envelope(envelope["id"])["signers"][0]["status"] == "consented"


def test_saving_needs_a_drawn_or_typed_signature_to_save(ehr: Ehr, world: World) -> None:
    envelope = envelope_for(ehr)
    signer = ehr.open_session(envelope, "patient")
    payload = signer.review_and_consent()

    response = signer.post(
        "/sign",
        sign_body(signer, payload, kind="click", save=True),
        **{"Idempotency-Key": f"click-save-{envelope['id']}"},
    )

    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "no_signature_to_save"
    assert adopted_rows(world) == []
    assert ehr.envelope(envelope["id"])["signers"][0]["status"] == "consented"


def test_a_replayed_signature_saves_one_signature(ehr: Ehr, world: World) -> None:
    envelope = envelope_for(ehr)
    signer = ehr.open_session(envelope, "patient")
    payload = signer.review_and_consent()
    key = f"replay-{envelope['id']}"

    first = sign(signer, payload, key=key, save=True)
    second = sign(signer, payload, key=key, save=True)

    assert first.status_code == 200, first.text
    assert second.json() == first.json()
    assert len(adopted_rows(world)) == 1
    assert len(_adopted_events(ehr, envelope["id"])) == 1


def test_a_host_cannot_create_a_saved_signature(ehr: Ehr, world: World) -> None:
    # There is no route: the whole point of the feature is that only the signer, inside their own
    # authenticated session, can decide what their signature looks like.
    assert (
        ehr.post(f"/users/{OTHER_PATIENT}/adopted-signature", {"kind": "typed", "typed_text": "Dr Who"}).status_code
        == 404
    )
    assert adopted_rows(world, OTHER_PATIENT) == []
