"""Removing a saved signature (Addendum 1 B).

Either side may revoke: the signer from their own session (``user``), the host from the Host API
(``host``). Neither deletes anything -- the row is revoked once, and stays, because a signature
already applied points at it. Both are recorded on the ``system`` stream, which is where a fact
about a user that outlives any one envelope belongs.
"""

from __future__ import annotations

from typing import Any

from tests.adopted_signatures.conftest import (
    KIOSK,
    OTHER_PATIENT,
    PATIENT,
    adopt,
    adopted_rows,
    envelope_for,
    offered,
    system_events,
)
from tests.e2e.conftest import Ehr, World


def _revocations(world: World) -> list[Any]:
    return [e for e in system_events(world) if e.event_type == "signature.adoption_revoked"]


def test_a_signer_removes_their_own_saved_signature(ehr: Ehr, world: World) -> None:
    adopt(ehr)
    envelope = envelope_for(ehr)
    signer = ehr.open_session(envelope, "patient")

    response = signer.post("/adopted-signature/revoke", {})

    assert response.status_code == 200, response.text
    assert response.json() == {"revoked": True}
    row = adopted_rows(world)[0]
    assert row.revoke_reason == "user"
    assert row.revoked_at is not None
    # Nothing is offered afterwards, in this session or the next.
    assert signer.session()["adopted_signature"] is None
    assert offered(ehr) is None

    events = _revocations(world)
    assert [e.data["reason"] for e in events] == ["user"]
    assert events[0].data["adopted_signature_id"] == str(row.id)
    assert events[0].actor_user_id == PATIENT


def test_revoking_twice_is_honest_about_the_second_time(ehr: Ehr, world: World) -> None:
    adopt(ehr)
    envelope = envelope_for(ehr)
    signer = ehr.open_session(envelope, "patient")

    assert signer.post("/adopted-signature/revoke", {}).json() == {"revoked": True}
    assert signer.post("/adopted-signature/revoke", {}).json() == {"revoked": False}

    # One revocation, recorded once: the second call changed nothing and says nothing.
    assert len(_revocations(world)) == 1
    assert len(adopted_rows(world)) == 1


def test_a_signer_with_nothing_saved_may_still_ask(ehr: Ehr) -> None:
    envelope = envelope_for(ehr)
    signer = ehr.open_session(envelope, "patient")

    response = signer.post("/adopted-signature/revoke", {})

    assert response.status_code == 200, response.text
    assert response.json() == {"revoked": False}


def test_the_host_removes_a_users_saved_signature(ehr: Ehr, world: World) -> None:
    adopt(ehr)

    response = ehr.post(f"/users/{PATIENT}/adopted-signature/revoke", {"reason": "left the practice"})

    assert response.status_code == 200, response.text
    assert response.json() == {"revoked": True}
    row = adopted_rows(world)[0]
    # The host's own words are not kept: the trail records that the host did it, and nothing else.
    assert row.revoke_reason == "host"
    events = _revocations(world)
    assert [e.data["reason"] for e in events] == ["host"]
    assert "left the practice" not in str(events[0].data)
    assert offered(ehr) is None


def test_the_host_route_answers_the_same_for_a_user_it_does_not_have(ehr: Ehr, world: World) -> None:
    adopt(ehr)

    unknown = ehr.post(f"/users/{OTHER_PATIENT}/adopted-signature/revoke")
    not_an_id = ehr.post("/users/not%20an%20id/adopted-signature/revoke")

    # A user of another host and a user with nothing saved are one answer, so the route confirms
    # nothing about who exists where.
    assert unknown.status_code == 200
    assert unknown.json() == {"revoked": False}
    assert not_an_id.status_code == 200
    assert not_an_id.json() == {"revoked": False}
    assert _revocations(world) == []


def test_one_host_cannot_revoke_another_hosts_users_signature(ehr: Ehr, other_ehr: Ehr, world: World) -> None:
    adopt(ehr)

    response = other_ehr.post(f"/users/{PATIENT}/adopted-signature/revoke")

    assert response.status_code == 200
    assert response.json() == {"revoked": False}
    assert adopted_rows(world)[0].revoked_at is None
    assert offered(ehr) is not None


def test_a_revoked_row_stays(ehr: Ehr, world: World) -> None:
    adopt(ehr)
    assert ehr.post(f"/users/{PATIENT}/adopted-signature/revoke").status_code == 200

    # Revocation is an update, not a delete: the row a ``signature_captures`` row may point at is
    # still there, with the reason and the moment it stopped being offered.
    rows = adopted_rows(world)
    assert len(rows) == 1
    assert rows[0].revoked_at is not None


def test_a_kiosk_session_cannot_revoke_the_signers_saved_signature(ehr: Ehr, world: World) -> None:
    """A shared tablet is untrusted for saved signatures everywhere else -- it is offered none,
    may save none, and the identity module refuses it a third time -- and revocation is the one
    irreversible door: ``0700``'s trigger permits exactly one revocation and forbids DELETE, so
    the row can never be brought back.

    The false attribution is the lasting damage. ``signature.adoption_revoked`` would go onto the
    append-only ``system`` stream with ``reason: "user"`` and the signer as the actor -- a claim
    that the person themselves asked for it -- when what happened is that staff holding a clinic
    tablet asked, for a signature that same tablet is not even allowed to be shown.
    """
    adopt(ehr)
    envelope = envelope_for(ehr)
    kiosk = ehr.open_session(envelope, "patient", method="staff_verified", kiosk=KIOSK)
    assert kiosk.session()["adopted_signature"] is None

    response = kiosk.post("/adopted-signature/revoke", {})

    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "adoption_not_allowed"
    row = adopted_rows(world)[0]
    assert row.revoked_at is None and row.revoke_reason is None
    assert _revocations(world) == []
    # And it is still there for the person whose signature it is.
    assert offered(ehr) is not None
