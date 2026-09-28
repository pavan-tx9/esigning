"""CORS on ``/v1/signing/*``: preflight by any host origin, actual requests only for SDK sessions."""

from __future__ import annotations

from tests.e2e.conftest import Ehr

ALLOWED = "https://ehr.example"
FOREIGN = "https://other.example"
SDK_CLIENT = "esign-sdk/0.1.0"


def test_preflight_is_answered_for_an_origin_any_host_has_allowed(ehr: Ehr) -> None:
    response = ehr.client.options(
        "/v1/signing/session",
        headers={
            "Origin": ALLOWED,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization,content-type,x-esign-client",
        },
    )
    assert response.status_code == 204, response.text
    assert response.headers["access-control-allow-origin"] == ALLOWED
    assert "X-Esign-Client" in response.headers["access-control-allow-headers"]


def test_preflight_from_an_unknown_origin_is_refused(ehr: Ehr) -> None:
    response = ehr.client.options(
        "/v1/signing/session",
        headers={"Origin": FOREIGN, "Access-Control-Request-Method": "GET"},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "origin_not_allowed"


def test_an_sdk_session_from_the_host_origin_is_allowed(ehr: Ehr) -> None:
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    signer = ehr.open_session(envelope, "patient", client="sdk")
    response = signer.get("/session", **{"Origin": ALLOWED, "X-Esign-Client": SDK_CLIENT})
    assert response.status_code == 200, response.text
    assert response.headers["access-control-allow-origin"] == ALLOWED


def test_an_sdk_session_from_another_origin_is_refused(ehr: Ehr) -> None:
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    signer = ehr.open_session(envelope, "patient", client="sdk")
    response = signer.get("/session", **{"Origin": FOREIGN, "X-Esign-Client": SDK_CLIENT})
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "origin_not_allowed"


def test_an_iframe_session_is_unchanged_when_an_origin_is_sent(ehr: Ehr) -> None:
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    signer = ehr.open_session(envelope, "patient")
    response = signer.get("/session", **{"Origin": ALLOWED})
    assert response.status_code == 200, response.text
    assert "access-control-allow-origin" not in response.headers


def test_an_sdk_session_requires_the_library_header(ehr: Ehr) -> None:
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    signer = ehr.open_session(envelope, "patient", client="sdk")
    response = signer.get("/session", **{"Origin": ALLOWED})
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "client_required"


def test_a_session_created_as_sdk_is_recorded_that_way(ehr: Ehr) -> None:
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    ehr.open_session(envelope, "patient", client="sdk")
    created = next(e for e in ehr.audit(envelope["id"]) if e["event_type"] == "session.created")
    assert created["data"]["client_mode"] == "sdk"


def test_host_api_routes_do_not_grow_cors_headers(ehr: Ehr) -> None:
    response = ehr.client.get("/v1/templates", headers={**ehr.headers, "Origin": ALLOWED})
    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers
