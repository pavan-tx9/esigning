"""SPEC section 12: no log line from a run may contain a name, a token or a key.

The allowlist in ``esign.logging`` is the mechanism; this is the proof that this module uses it.
The flow below is everything identity does in a signing session, run against a signer whose name
and staff contact are deliberately distinctive strings.
"""

from __future__ import annotations

import json
from datetime import timedelta

import pytest
from sqlalchemy.orm import Session

from esign.clock import FixedClock
from esign.contracts import AuthContext, KioskContext, RequestContext, Unauthorized
from esign.identity import SqlIdentityService, add_consent_text, create_host
from esign.logging import configure_logging
from tests.identity.factories import SIGNER_DISPLAY_NAME, make_signer

STAFF_ID = "nurse-priya-raman"


def test_a_full_identity_flow_logs_no_name_token_or_key(
    db: Session, clock: FixedClock, identity: SqlIdentityService, capsys: pytest.CaptureFixture[str]
) -> None:
    signer = make_signer(db, clock, display_name=SIGNER_DISPLAY_NAME, requires_reauth=True)
    add_consent_text(db, version="2026-03", locale="en-US", body="Disclosure body.", effective_at=clock.now())

    configure_logging(level="DEBUG", json_output=True, app_env="test")
    capsys.readouterr()  # discard anything the setup above wrote

    key, _host = create_host(db, "Northside EHR", ["https://ehr.example.org"], None, clock=clock)
    identity.authenticate_host(db, key)
    token, info = identity.create_session(
        db,
        signer_id=signer.signer_id,
        auth=AuthContext(method="staff_verified", auth_time=clock.now() - timedelta(seconds=10)),
        kiosk=KioskContext(staff_user_id=STAFF_ID, identity_check="photo_id"),
        ctx=RequestContext(ip="203.0.113.9", user_agent="Mozilla/5.0 (iPad)"),
    )
    identity.authenticate_session(db, token)
    identity.attest_reauth(db, session_id=info.id, auth=AuthContext("password+mfa", clock.now()))
    identity.fresh_reauth(db, info.id)
    identity.current_consent(db, "en-US")
    with pytest.raises(Unauthorized):
        identity.authenticate_session(db, "est_" + "a" * 43)
    identity.revoke_sessions(db, signer.signer_id)

    output = capsys.readouterr().out
    assert output.strip(), "the flow logged nothing at all, so this proves nothing"

    forbidden = [SIGNER_DISPLAY_NAME, "Wanda", "Testpatient", STAFF_ID, key, token, key[4:], token[4:]]
    for secret in forbidden:
        assert secret not in output, f"{secret[:12]!r} reached the logs"

    for line in output.strip().splitlines():
        parsed = json.loads(line)
        assert "dropped_fields" not in parsed, f"a log call passed an unlistable key: {parsed}"


def test_an_error_message_from_this_module_never_echoes_input(
    db: Session, clock: FixedClock, identity: SqlIdentityService
) -> None:
    """Messages are returned to callers, so they may not repeat what the caller sent."""
    bad_token = "est_" + "W" * 43
    with pytest.raises(Unauthorized) as caught:
        identity.authenticate_session(db, bad_token)
    assert bad_token not in str(caught.value)
    assert str(caught.value) == "invalid credentials"

    with pytest.raises(Unauthorized) as host_failure:
        identity.authenticate_host(db, "esk_" + "W" * 43)
    assert "W" * 43 not in str(host_failure.value)
