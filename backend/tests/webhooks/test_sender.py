"""``HttpSender``: the status code is all we want, and all we are prepared to wait for."""

from __future__ import annotations

from collections.abc import Iterator

import httpx

from esign.config import Settings
from esign.webhooks import HttpSender


def test_only_the_status_is_read_not_the_body(settings_no_db: Settings) -> None:
    """``Client.post`` reads the whole response body before it returns, and only the status is used.

    A host endpoint that answers with gigabytes, or with one chunk every few seconds, would
    otherwise hold the worker's single delivery loop -- delaying seal retries and expiries for every
    host in the same tick -- and grow its heap while doing it.
    """
    chunks_read = 0

    def endless() -> Iterator[bytes]:
        nonlocal chunks_read
        while True:
            chunks_read += 1
            yield b"x" * 64_000

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(204, content=endless())

    sender = HttpSender(settings_no_db, transport=httpx.MockTransport(handler))
    try:
        assert sender("https://ehr.example/hooks", b"{}", {"Content-Type": "application/json"}) == 204
    finally:
        sender.close()
    # The generator was never pulled, so a body with no end costs nothing.
    assert chunks_read == 0


def test_a_transport_failure_is_raised_for_the_caller_to_count(settings_no_db: Settings) -> None:
    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    sender = HttpSender(settings_no_db, transport=httpx.MockTransport(refused))
    try:
        raised = False
        try:
            sender("https://ehr.example/hooks", b"{}", {})
        except httpx.ConnectError:
            raised = True
        assert raised
    finally:
        sender.close()
