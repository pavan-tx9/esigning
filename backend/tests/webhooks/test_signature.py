"""The signature scheme of SPEC section 9, pinned with a vector a host can check by hand."""

from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime, timedelta

from esign.webhooks import WEBHOOK_BACKOFF_SCHEDULE, sign, verify_signature, webhook_backoff

SECRET = bytes(range(32))
BODY = b'{"envelope_id":"1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9","event":"envelope.sealed"}'
SENT = datetime(2026, 3, 17, 14, 30, tzinfo=UTC)


def test_the_header_is_hmac_sha256_over_timestamp_dot_body() -> None:
    header = sign(SECRET, BODY, 1773757800)
    expected = hmac.new(SECRET, b"1773757800." + BODY, hashlib.sha256).hexdigest()
    assert header == f"t=1773757800,v1={expected}"
    assert int(SENT.timestamp()) == 1773757800
    assert verify_signature(SECRET, BODY, header, now=SENT)


def test_verification_refuses_anything_that_is_not_exactly_right() -> None:
    header = sign(SECRET, BODY, int(SENT.timestamp()))
    assert not verify_signature(SECRET, BODY + b"x", header, now=SENT)
    assert not verify_signature(b"another secret", BODY, header, now=SENT)
    assert not verify_signature(SECRET, BODY, header, now=SENT + timedelta(minutes=6))  # replayed later
    assert not verify_signature(SECRET, BODY, header, now=SENT - timedelta(minutes=6))
    assert verify_signature(SECRET, BODY, header, now=SENT + timedelta(minutes=4))
    for malformed in ("", "v1=abc", "t=abc,v1=abc", "t=1773757800", "garbage"):
        assert not verify_signature(SECRET, BODY, malformed, now=SENT)


def test_backoff_grows_and_then_holds_at_an_hour() -> None:
    delays = [webhook_backoff(n) for n in range(1, 9)]
    assert delays[: len(WEBHOOK_BACKOFF_SCHEDULE)] == list(WEBHOOK_BACKOFF_SCHEDULE)
    assert delays == sorted(delays) and delays[-1] == timedelta(hours=1)
    assert webhook_backoff(0) == WEBHOOK_BACKOFF_SCHEDULE[0]
