"""Who is offered a saved signature, and who is not (Addendum 1 B).

The rule the whole feature rests on: a saved signature belongs to one
``(host_id, host_user_id)`` pair, and that pair is read from the session's own rows. A session is
therefore offered the signature of the person whose session it is, or nothing at all.
"""

from __future__ import annotations

import base64
import json

from tests.adopted_signatures.conftest import (
    KIOSK,
    OTHER_PATIENT,
    PATIENT,
    adopt,
    adopted_capture,
    envelope_for,
    offered,
    sign,
)
from tests.e2e.conftest import Ehr


def test_a_signature_saved_in_one_session_is_offered_in_the_next(ehr: Ehr) -> None:
    adopt(ehr)

    adopted = offered(ehr)

    assert adopted is not None
    assert adopted["kind"] == "drawn"
    assert adopted["typed_text"] is None
    # The image the next session is offered is the one that was stamped: the sanitised PNG the
    # sign path stored, not the bytes the browser sent.
    assert base64.b64decode(adopted["image_png_base64"]) != b""
    assert adopted["created_at"] is not None


def test_a_typed_signature_is_offered_as_its_text(ehr: Ehr) -> None:
    adopt(ehr, kind="typed")

    adopted = offered(ehr)

    assert adopted is not None
    assert adopted["kind"] == "typed"
    assert adopted["image_png_base64"] is None
    assert adopted["typed_text"]


def test_nothing_is_offered_before_anything_is_saved(ehr: Ehr) -> None:
    assert offered(ehr) is None


def test_a_signature_is_not_offered_to_a_different_user(ehr: Ehr) -> None:
    adopt(ehr)

    assert offered(ehr, host_user_id=OTHER_PATIENT) is None


def test_a_signature_is_not_offered_to_the_same_user_on_a_different_host(ehr: Ehr, other_ehr: Ehr) -> None:
    adopt(ehr)

    # Same ``host_user_id``, different host: two EHRs' "pt-100482" are two different people, and
    # the partial unique index is on the pair for exactly that reason.
    assert offered(other_ehr, host_user_id=PATIENT) is None


def test_a_kiosk_session_is_offered_nothing(ehr: Ehr) -> None:
    adopt(ehr)

    envelope = envelope_for(ehr)
    kiosk = ehr.open_session(envelope, "patient", method="staff_verified", kiosk=KIOSK)
    payload = kiosk.session()

    # A patient on a shared tablet must not be handed the last patient's signature -- nor their
    # own, on a device somebody else is holding.
    assert payload["session"]["kiosk"] is True
    assert payload["adopted_signature"] is None


def test_the_saved_image_reaches_only_its_own_user(ehr: Ehr) -> None:
    adopt(ehr)
    mine = offered(ehr)
    assert mine is not None and mine["image_png_base64"]

    envelope = envelope_for(ehr, host_user_id=OTHER_PATIENT)
    signer = ehr.open_session(envelope, "patient")
    payload = signer.review_and_consent()

    # The session payload is the only route that ever serves the image, and it is built from the
    # session's own pair: another user's session is served nothing of it, anywhere.
    assert payload["adopted_signature"] is None
    assert mine["image_png_base64"] not in json.dumps(payload)

    # ...and naming somebody else's saved signature outright is refused rather than resolved.
    response = sign(
        signer,
        payload,
        key=f"borrow-{envelope['id']}",
        captures=adopted_capture(payload, mine["id"]),
    )
    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "adopted_signature_unavailable"
