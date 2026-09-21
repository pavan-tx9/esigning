"""Deliveries are queued only for hosts that asked for them, and stop after the last attempt."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import text

from esign.worker import run_once
from tests.e2e.conftest import World


def test_a_host_without_a_webhook_gets_no_delivery_rows(world: World) -> None:
    quiet = world.host("No webhook EHR")
    quiet.publish_template("hipaa_acknowledgement")
    envelope = quiet.create_envelope("hipaa_acknowledgement")
    assert quiet.post(f"/envelopes/{envelope['id']}/void", {"reason_code": "entered_in_error"}).status_code == 200
    with world.sessions() as db:
        assert db.execute(text("SELECT count(*) FROM webhook_deliveries")).scalar_one() == 0


def test_delivery_gives_up_after_the_configured_number_of_attempts(world: World) -> None:
    ehr = world.host(webhook=True)
    ehr.publish_template("hipaa_acknowledgement")
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    assert ehr.post(f"/envelopes/{envelope['id']}/void", {"reason_code": "entered_in_error"}).status_code == 200

    calls = 0

    def always_down(url: str, body: bytes, headers: dict[str, str]) -> int:
        nonlocal calls
        calls += 1
        return 500

    for _ in range(world.settings.webhook_max_attempts + 5):
        run_once(world.rt, send=always_down)
        world.clock.advance(timedelta(hours=2))
    assert calls == world.settings.webhook_max_attempts
    with world.sessions() as db:
        row = db.execute(text("SELECT attempts, delivered_at, last_status FROM webhook_deliveries")).one()
    assert (row.attempts, row.delivered_at, row.last_status) == (world.settings.webhook_max_attempts, None, 500)
