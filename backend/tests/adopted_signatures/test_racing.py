"""Two signatures by the same user at the same time (Addendum 1 B).

A clinician working a signing queue can have two documents open in two tabs and tick "save this
signature" on both. The rows survive that already -- the partial unique index and the per-user
advisory lock see to it -- but the *record* has to survive it too: ``signature.adoption_revoked``
goes on the ``system`` stream, which is append-only and can never be corrected, so it has to name
the row that actually stopped being offered.

The test drives the interleaving rather than hoping for it: the first request is held still
between reading the row it means to replace and replacing it, and the second runs in that gap.
"""

from __future__ import annotations

import threading
from typing import Any

import httpx
import pytest

from tests.adopted_signatures.conftest import (
    adopt,
    adopted_rows,
    envelope_for,
    sign,
    system_events,
)
from tests.e2e.conftest import Ehr, World


def _revocations(world: World) -> list[str]:
    return [
        str(event.data["adopted_signature_id"])
        for event in system_events(world)
        if event.event_type == "signature.adoption_revoked"
    ]


def test_each_replacement_names_the_row_it_actually_revoked(
    ehr: Ehr, world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    adopt(ehr, key="first")  # the row both racers find live and both mean to replace

    signers = []
    for index in (1, 2):
        signer = ehr.open_session(envelope_for(ehr), "patient")
        signers.append((signer, signer.review_and_consent(), f"race-{index}"))

    read = threading.Event()
    resume = threading.Event()
    held: list[bool] = []
    original = world.rt.identity.get_adopted_signature

    def hold_after_reading(*args: Any, **kwargs: Any) -> Any:
        """Stop the first request between its read and its write, and let the second one past."""
        row = original(*args, **kwargs)
        if not held:
            held.append(True)
            read.set()
            # Bounded: once the read is serialised behind the lock the second request cannot get
            # in front of it at all, so nothing will ever set this.
            resume.wait(timeout=3.0)
        return row

    monkeypatch.setattr(world.rt.identity, "get_adopted_signature", hold_after_reading)

    first_signer, first_payload, first_key = signers[0]
    answers: dict[str, httpx.Response] = {}
    thread = threading.Thread(
        target=lambda: answers.update(first=sign(first_signer, first_payload, key=first_key, save=True))
    )
    thread.start()
    try:
        assert read.wait(timeout=20), "the first request never read the row it meant to replace"
        second_signer, second_payload, second_key = signers[1]
        answers["second"] = sign(second_signer, second_payload, key=second_key, kind="typed", save=True)
    finally:
        resume.set()
        thread.join(timeout=30)

    assert not thread.is_alive()
    assert answers["first"].status_code == 200, answers["first"].text
    assert answers["second"].status_code == 200, answers["second"].text

    rows = adopted_rows(world)
    assert len(rows) == 3
    assert len([row for row in rows if row.revoked_at is None]) == 1
    revoked = sorted(str(row.id) for row in rows if row.revoked_at is not None)
    # One event per row that stopped being offered, naming that row: not the same row twice while
    # the other disappears from the trail.
    assert sorted(_revocations(world)) == revoked
