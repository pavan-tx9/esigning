"""Applying a saved signature to a later document (Addendum 1 B).

What the signer sends is an id. What is stamped, stored and hashed is the signature they saved --
resolved server-side, under the envelope row lock, from their own live row. The trail says the
mark was ``adopted`` and which row it came from, so "this looks like their signature because they
drew it once, months ago" is a statement the record supports rather than an assumption.
"""

from __future__ import annotations

import io
import re
from typing import Any

from pypdf import PdfReader

from tests.adopted_signatures.conftest import (
    KIOSK,
    PATIENT,
    adopt,
    adopted_capture,
    capture_rows,
    envelope_for,
    offered,
    sign,
    stored_image_hex,
)
from tests.e2e.conftest import Ehr, World


def _signed_event(ehr: Ehr, envelope_id: str) -> dict[str, Any]:
    return next(e for e in ehr.audit(envelope_id) if e["event_type"] == "signer.signed")


def test_an_adopted_capture_stamps_the_stored_image_and_names_it_in_the_trail(ehr: Ehr, world: World) -> None:
    adopt(ehr)
    saved = offered(ehr)
    assert saved is not None

    envelope = envelope_for(ehr)
    signer = ehr.open_session(envelope, "patient")
    payload = signer.review_and_consent()
    response = sign(signer, payload, key=f"apply-{envelope['id']}", captures=adopted_capture(payload, saved["id"]))
    assert response.status_code == 200, response.text

    rows = capture_rows(world, signer.signer_id)
    assert [(r.kind, str(r.adopted_signature_id)) for r in rows] == [("adopted", saved["id"])]
    # One place holds the ink: the capture row points at the saved signature instead of keeping a
    # second copy of the image or the text (migration 0700).
    assert rows[0].image_sha256 is None
    assert rows[0].typed_text is None

    signed = _signed_event(ehr, envelope["id"])
    assert signed["data"]["adopted_signature_id"] == saved["id"]
    capture = signed["data"]["captures"][0]
    assert capture["kind"] == "adopted"
    # The digest in the trail is the digest of what was stamped, and it is the saved image's:
    # nothing else could have been applied.
    assert capture["image_sha256"] == stored_image_hex(world, saved["id"])
    assert capture["typed_text_sha256"] is None


def test_an_adopted_typed_signature_carries_its_text_digest(ehr: Ehr, world: World) -> None:
    adopt(ehr, kind="typed")
    saved = offered(ehr)
    assert saved is not None and saved["kind"] == "typed"

    envelope = envelope_for(ehr)
    signer = ehr.open_session(envelope, "patient")
    payload = signer.review_and_consent()
    applied = sign(signer, payload, key=f"typed-{envelope['id']}", captures=adopted_capture(payload, saved["id"]))
    assert applied.status_code == 200, applied.text

    signed = _signed_event(ehr, envelope["id"])
    capture = signed["data"]["captures"][0]
    assert capture["kind"] == "adopted"
    assert capture["image_sha256"] is None
    assert capture["typed_text_sha256"] is not None
    assert capture["typed_text_sha256"] != saved["typed_text"]  # a digest, never the name


def test_a_signature_without_a_saved_one_records_no_adopted_id(ehr: Ehr) -> None:
    envelope = envelope_for(ehr)
    signer = ehr.open_session(envelope, "patient")
    payload = signer.review_and_consent()
    applied = sign(signer, payload, key=f"plain-{envelope['id']}")
    assert applied.status_code == 200, applied.text

    assert _signed_event(ehr, envelope["id"])["data"]["adopted_signature_id"] is None


def test_the_certificate_says_the_signature_was_a_saved_one(ehr: Ehr) -> None:
    adopt(ehr)
    saved = offered(ehr)
    assert saved is not None

    envelope = envelope_for(ehr)
    signer = ehr.open_session(envelope, "patient")
    payload = signer.review_and_consent()
    applied = sign(signer, payload, key=f"cert-{envelope['id']}", captures=adopted_capture(payload, saved["id"]))
    assert applied.status_code == 200, applied.text

    sealed = ehr.get(f"/envelopes/{envelope['id']}/document")
    assert sealed.status_code == 200, sealed.text
    text = re.sub(
        r"\s+", " ", "".join(page.extract_text() or "" for page in PdfReader(io.BytesIO(sealed.content)).pages)
    )
    day = str(saved["created_at"])[:10]
    assert f"signed with a saved signature adopted on {day}" in text


def test_a_revoked_saved_signature_cannot_be_applied(ehr: Ehr) -> None:
    adopt(ehr)
    saved = offered(ehr)
    assert saved is not None
    assert ehr.post(f"/users/{PATIENT}/adopted-signature/revoke").status_code == 200

    envelope = envelope_for(ehr)
    signer = ehr.open_session(envelope, "patient")
    payload = signer.review_and_consent()
    response = sign(signer, payload, key=f"revoked-{envelope['id']}", captures=adopted_capture(payload, saved["id"]))

    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "adopted_signature_unavailable"


def test_a_kiosk_session_cannot_apply_a_saved_signature(ehr: Ehr) -> None:
    adopt(ehr)
    saved = offered(ehr)
    assert saved is not None

    envelope = envelope_for(ehr)
    kiosk = ehr.open_session(envelope, "patient", method="staff_verified", kiosk=KIOSK)
    payload = kiosk.review_and_consent()
    response = sign(kiosk, payload, key=f"kiosk-{envelope['id']}", captures=adopted_capture(payload, saved["id"]))

    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "adopted_signature_unavailable"


def test_an_adopted_capture_may_not_carry_a_payload(ehr: Ehr) -> None:
    adopt(ehr)
    saved = offered(ehr)
    assert saved is not None

    envelope = envelope_for(ehr)
    signer = ehr.open_session(envelope, "patient")
    payload = signer.review_and_consent()
    captures = adopted_capture(payload, saved["id"])
    captures[0]["typed_text"] = "Somebody Else"

    response = sign(signer, payload, key=f"payload-{envelope['id']}", captures=captures)

    # Refused at the edge: an image or a name beside the id would be the client deciding what a
    # saved signature looks like.
    assert response.status_code == 422, response.text


def test_an_unknown_saved_signature_is_refused_like_somebody_elses(ehr: Ehr) -> None:
    adopt(ehr)
    envelope = envelope_for(ehr)
    signer = ehr.open_session(envelope, "patient")
    payload = signer.review_and_consent()

    response = sign(
        signer,
        payload,
        key=f"unknown-{envelope['id']}",
        captures=adopted_capture(payload, "00000000-0000-4000-8000-000000000000"),
    )

    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "adopted_signature_unavailable"
