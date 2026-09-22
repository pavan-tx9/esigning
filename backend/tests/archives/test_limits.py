"""Metering ``POST /v1/archives`` without turning a retry into a duplicate filing.

The limiter is real -- filing a scan stores a blob, appends two audit events and queues a seal
job, none of which has a delete path -- but it runs *after* the idempotency replay check, as
``POST /v1/signing/sign`` does and for the same reason: a retry of a filing that already
succeeded must get its first answer back, not a 429, however many times the connection drops.

It matters more here than for signing. Signing has a second line of defence: the envelope service
refuses a second signature whatever key is used. Archives have none -- ``host_document_ref`` is a
plain nullable column, nothing is unique on the scan hash, and ``Idempotency-Key`` is optional on
this route -- so a host bulk-filing scanned consents whose retry got a 429 and then re-filed under
a fresh key would end up with two sealed paper archives of one piece of paper in the chart.
"""

from __future__ import annotations

from uuid import UUID

import pytest
from sqlalchemy import text

from esign.contracts import RateLimited
from esign.identity import RateLimits, host_key
from tests.archives.conftest import error_code, file_archive, filed
from tests.e2e.conftest import Ehr, World


def _exhaust(host: Ehr, world: World) -> None:
    """Spend this host's archive-filing allowance, as a bulk import would."""
    limit = RateLimits.SESSION_CREATE
    key = host_key("archive_create", UUID(host.host_id))
    with pytest.raises(RateLimited):
        for _ in range(limit.limit + 1):
            world.rt.limiter.hit(key, limit=limit.limit, window_seconds=limit.window_seconds)


def test_a_retry_of_a_filing_that_succeeded_replays_instead_of_meeting_the_limiter(host: Ehr, world: World) -> None:
    first = filed(host, key="bulk-import-0041")
    _exhaust(host, world)

    replay = file_archive(host, key="bulk-import-0041")

    assert replay.status_code == 201, replay.text
    assert replay.json()["id"] == first["id"]
    # One archive in the chart, not two: the retry was answered from the stored key.
    with world.sessions() as db:
        filings = db.execute(
            text("SELECT count(*) FROM envelopes WHERE host_id = :id AND kind = 'paper_archive'"),
            {"id": host.host_id},
        ).scalar_one()
    assert filings == 1


def test_a_new_filing_still_meets_the_limiter(host: Ehr, world: World) -> None:
    """The meter is not weakened, only reordered: a filing that is not a replay is still refused."""
    _exhaust(host, world)

    refused = file_archive(host, key="bulk-import-0042")

    assert refused.status_code == 429, refused.text
    assert error_code(refused) == "rate_limited"
