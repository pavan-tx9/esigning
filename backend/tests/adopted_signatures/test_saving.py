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
    capture_rows,
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


def test_an_initials_field_earlier_in_the_document_is_not_what_gets_saved(ehr: Ehr, world: World) -> None:
    """The saved signature is the *signature*, whatever order the fields come in.

    ``procedure_consent`` asks the patient to initial the risks on page 2 before signing on page 3,
    and the UI builds its captures in reading order. Saving the first drawn-or-typed capture would
    keep the two-letter initials and offer them back as "your saved signature" -- and the document
    the next session stamps would carry "MO" in the signature box.
    """
    envelope = envelope_for(ehr, template_key="procedure_consent")
    signer = ehr.open_session(envelope, "patient")
    payload = signer.review_and_consent()
    field_types = {field["id"]: field["type"] for field in payload["fields"]}
    assert list(field_types.values())[:2] == ["initials", "signature"], "the initials must come first"

    response = sign(signer, payload, key=f"initials-first-{envelope['id']}", save=True)

    assert response.status_code == 200, response.text
    row = adopted_rows(world)[0]
    assert row.kind == "drawn"
    assert row.typed_text is None
    # And it is the ink from the signature field, not from an initials field that happens to be drawn.
    event = _adopted_events(ehr, envelope["id"])[0]
    assert event["data"]["image_sha256"] == bytes(row.image_sha256).hex()
    signature_capture = next(c for c in capture_rows(world, signer.signer_id) if c.field_id == "patient_signature")
    assert bytes(signature_capture.image_sha256) == bytes(row.image_sha256)


def test_a_typed_signature_saved_from_a_document_with_initials_keeps_the_name(ehr: Ehr, world: World) -> None:
    envelope = envelope_for(ehr, template_key="procedure_consent")
    signer = ehr.open_session(envelope, "patient")
    payload = signer.review_and_consent()

    response = sign(signer, payload, key=f"typed-initials-{envelope['id']}", kind="typed", save=True)

    assert response.status_code == 200, response.text
    row = adopted_rows(world)[0]
    assert row.kind == "typed"
    # The name that was stamped into the signature box, not the initials from page 2.
    assert row.typed_text == payload["signer"]["display_name"]


def test_saving_needs_a_signature_field_not_just_initials(ehr: Ehr, world: World) -> None:
    """Initials alone are not a signature to save: the refusal comes before anything is applied."""
    envelope = envelope_for(ehr, template_key="procedure_consent")
    signer = ehr.open_session(envelope, "patient")
    payload = signer.review_and_consent()
    captures = [
        {"field_id": field["id"], "kind": "typed", "typed_text": "MO"}
        if field["type"] == "initials"
        else {"field_id": field["id"], "kind": "click"}
        for field in payload["fields"]
        if field["type"] in ("signature", "initials")
    ]

    response = signer.post(
        "/sign",
        sign_body(signer, payload, save=True, captures=captures),
        **{"Idempotency-Key": f"only-initials-{envelope['id']}"},
    )

    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "no_signature_to_save"
    assert adopted_rows(world) == []
    assert ehr.envelope(envelope["id"])["signers"][0]["status"] == "consented"


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


def _blob_files(world: World) -> set[str]:
    root = world.settings.blob_fs_root
    return {str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()}


def test_a_kiosk_save_is_refused_before_the_signature_is_applied(ehr: Ehr, world: World) -> None:
    """The refusal is a pre-flight, not a rollback.

    ``save_adopted_signature`` in ``api/adopted.py`` runs *after* ``EnvelopeService.sign``, so on
    its own it means a kiosk client that sets the flag has its whole signature applied -- revision
    stamped, blobs written, ``signer.signed`` appended -- and then rolled back. The database
    rollback is clean, but the blob store is not transactional: the sanitised PNG and the stamped
    revision PDF are written to it before the row that records them, and they stay behind. So the
    blob store is what this test watches, alongside the trail.
    """
    envelope = envelope_for(ehr)
    kiosk = ehr.open_session(envelope, "patient", method="staff_verified", kiosk=KIOSK)
    payload = kiosk.review_and_consent()
    before = _blob_files(world)

    response = kiosk.post(
        "/sign", sign_body(kiosk, payload, save=True), **{"Idempotency-Key": f"kiosk-preflight-{envelope['id']}"}
    )

    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "adoption_not_allowed"
    assert _blob_files(world) == before
    assert "signer.signed" not in [e["event_type"] for e in ehr.audit(envelope["id"])]
    assert adopted_rows(world) == []
    assert ehr.envelope(envelope["id"])["signers"][0]["status"] == "consented"
