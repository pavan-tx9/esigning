"""Checking the signature on an incoming webhook.

This is written out here rather than imported from the service, because it is the one piece of the
integration a customer has to implement themselves, and a stand-in EHR that imported the service's
own helper would prove nothing. ``esign.webhooks.verify_signature`` is the normative version; if
the two ever disagree the end-to-end run fails at the webhook, which is exactly where it should.

The header is ``X-Esign-Signature: t=<unix seconds>,v1=<hex hmac-sha256 of "t.body">``. Two rules
matter and both are easy to get wrong:

* compare with :func:`hmac.compare_digest`, never ``==``;
* refuse a timestamp outside the tolerance, or a delivery captured today can be replayed forever.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime

__all__ = ["SIGNATURE_HEADER", "verify_signature"]

SIGNATURE_HEADER = "X-Esign-Signature"

TOLERANCE_SECONDS = 300


def verify_signature(
    secret: bytes, body: bytes, header: str, *, now: datetime, tolerance_seconds: int = TOLERANCE_SECONDS
) -> bool:
    """True when ``body`` really came from the service, recently."""
    if not secret or not header:
        return False
    parts = dict(part.split("=", 1) for part in header.split(",") if "=" in part)
    try:
        timestamp = int(parts.get("t", ""))
    except ValueError:
        return False
    if abs(int(now.timestamp()) - timestamp) > tolerance_seconds:
        return False
    expected = hmac.new(secret, f"{timestamp}.".encode("ascii") + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, parts.get("v1", ""))
