"""SPEC sections 9 and 10 at the HTTP boundary: the error envelope, size limits, headers, the
per-host CSP on /sign, rate limits, and where the recorded IP comes from."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from esign.api import check_production_settings, create_app
from esign.clock import FixedClock
from esign.config import Settings
from esign.identity import RateLimits
from esign.runtime import ConfigurationError, build_runtime
from tests.e2e.conftest import PATIENT_NAME, Ehr, Sessions, World, build_world


def test_errors_use_one_envelope_and_never_echo_input(ehr: Ehr, world: World) -> None:
    body = ehr.envelope_body("procedure_consent")
    body["signers"][0]["capacity"] = f"friend of {PATIENT_NAME}"
    invalid = ehr.post("/envelopes", body)
    assert invalid.status_code == 422
    assert set(invalid.json()) == {"error"}
    assert set(invalid.json()["error"]) == {"code", "message"}
    assert invalid.json()["error"]["code"] == "validation_failed"
    assert PATIENT_NAME not in invalid.text

    missing = world.client.get("/v1/nothing-here")
    assert missing.status_code == 404 and missing.json()["error"]["code"] == "not_found"
    wrong_method = world.client.delete("/v1/envelopes")
    assert wrong_method.status_code == 405 and wrong_method.json()["error"]["code"] == "method_not_allowed"
    not_an_id = ehr.get("/envelopes/not-a-uuid")
    assert not_an_id.status_code == 422 and "not-a-uuid" not in not_an_id.text

    unauthenticated = world.client.get("/v1/templates")
    assert unauthenticated.status_code == 401
    assert unauthenticated.headers["www-authenticate"] == "Bearer"
    assert unauthenticated.json()["error"]["code"] == "unauthorized"


def test_there_is_no_delete_path_anywhere(world: World) -> None:
    routes = [route for route in world.client.app.routes if hasattr(route, "methods")]  # type: ignore[attr-defined]
    assert routes
    for route in routes:
        assert "DELETE" not in route.methods and "PUT" not in route.methods and "PATCH" not in route.methods


def test_out_of_scope_requests_are_refused_with_a_clear_code(ehr: Ehr) -> None:
    for path in ("/envelopes/bulk", "/envelopes/7f1c0e7e-3f59-4e4e-9a53-0f6f1a2b3c4d/email-links"):
        response = ehr.post(path, {})
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "out_of_scope"


def test_every_response_carries_the_security_headers(ehr: Ehr, world: World) -> None:
    for response in (ehr.get("/templates"), world.client.get("/v1/nothing-here"), world.client.get("/healthz")):
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert response.headers["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        assert "default-src 'none'" in response.headers["content-security-policy"]


def test_oversized_bodies_are_refused_before_they_are_read(
    e2e_settings: Settings, clock: FixedClock, app_engine: Engine, db_factory: Sessions
) -> None:
    small = e2e_settings.model_copy(update={"max_request_bytes": 2_000})
    world = build_world(small, clock, app_engine, db_factory)
    ehr = world.host()

    declared = ehr.post("/envelopes", {"padding": "x" * 5_000})
    assert declared.status_code == 413
    assert declared.json()["error"]["code"] == "payload_too_large"
    assert declared.headers["x-content-type-options"] == "nosniff"

    def chunks() -> object:  # chunked: no Content-Length to check up front
        for _ in range(10):
            yield b"x" * 500

    streamed = world.client.post("/v1/envelopes", content=chunks(), headers=ehr.headers)
    assert streamed.status_code == 413

    assert ehr.post("/envelopes", {"padding": "x"}).status_code == 422  # small enough to be looked at


def test_the_signing_ui_is_framed_only_by_the_hosts_origins(
    e2e_settings: Settings, clock: FixedClock, app_engine: Engine, db_factory: Sessions, tmp_path: Path
) -> None:
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text(
        '<!doctype html><html><head><title>Sign</title></head><body><div id="root"></div>'
        '<script type="module" src="/assets/index-abc.js"></script></body></html>',
        encoding="utf-8",
    )
    (dist / "assets" / "index-abc.js").write_text("console.log('ui')", encoding="utf-8")
    world = build_world(e2e_settings.model_copy(update={"frontend_dist_dir": dist}), clock, app_engine, db_factory)
    ehr = world.host()

    page = world.client.get(f"/sign?host={ehr.host_id}")
    assert page.status_code == 200
    csp = page.headers["content-security-policy"]
    assert "frame-ancestors https://ehr.example" in csp and "script-src 'self'" in csp
    assert "x-frame-options" not in page.headers  # frame-ancestors governs; DENY would forbid embedding
    assert '<meta name="esign-allowed-origins" content="https://ehr.example">' in page.text
    assert page.headers["cache-control"] == "no-store"

    # No host, an unknown host, or garbage: not embeddable, and the UI trusts nobody.
    for url in ("/sign", "/sign?host=5f0d4e7e-3f59-4e4e-9a53-0f6f1a2b3c4d", "/sign?host=%22%3E%3Cscript%3E"):
        anonymous = world.client.get(url)
        assert anonymous.status_code == 200
        assert "frame-ancestors 'none'" in anonymous.headers["content-security-policy"]
        assert '<meta name="esign-allowed-origins" content="">' in anonymous.text
        assert "<script>" not in anonymous.text.replace('<script type="module"', "")

    asset = world.client.get("/assets/index-abc.js")
    assert asset.status_code == 200 and "console.log" in asset.text


def test_without_a_built_ui_there_is_no_sign_route(world: World) -> None:
    assert world.client.get("/sign").status_code == 404


def test_session_creation_is_rate_limited_per_host_with_a_retry_hint(ehr: Ehr, world: World) -> None:
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    statuses = [ehr.open_session_response(envelope, "patient").status_code for _ in range(61)]
    assert statuses[:60] == [201] * 60
    assert statuses[60] == 429
    limited = ehr.open_session_response(envelope, "patient")
    assert limited.json()["error"]["code"] == "rate_limited"
    assert 1 <= int(limited.headers["retry-after"]) <= 60

    # Another host is not affected, and the window passes.
    assert world.host("Lakeside EHR").get("/templates").status_code == 200
    world.clock.advance(61)
    assert ehr.open_session_response(envelope, "patient").status_code == 201


def test_presenting_the_document_is_rate_limited_per_session(ehr: Ehr, world: World) -> None:
    """``GET /v1/signing/document`` appends ``document.presented`` and re-hashes the revision.

    ``audit_events`` has no delete path, so a loop with one live token used to grow the trail
    without bound -- and every later ``audit.verify``, which ``seal_pending`` runs, with it.
    """
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    patient = ehr.open_session(envelope, "patient")
    limit = RateLimits.PRESENT.limit
    statuses = [patient.get("/document").status_code for _ in range(limit + 1)]
    assert statuses[:limit] == [200] * limit
    assert statuses[limit] == 429
    limited = patient.get("/document")
    assert limited.json()["error"]["code"] == "rate_limited"
    assert 1 <= int(limited.headers["retry-after"]) <= RateLimits.PRESENT.window_seconds

    world.clock.advance(RateLimits.PRESENT.window_seconds + 1)
    assert patient.get("/document").status_code == 200


def test_reporting_the_document_viewed_is_rate_limited_per_session(ehr: Ehr, world: World) -> None:
    """``POST /v1/signing/viewed`` was the one mutating signer endpoint with no limit at all.

    VIEW is legal repeatedly (a signer who has consented may re-read), and every call re-fetches the
    revision, re-hashes it, re-parses the PDF for its page count and appends ``document.viewed`` --
    which has no delete path. A token holder could add thousands of events in a 30-minute session,
    bloating ``audit_event_count`` on the certificate and slowing every later ``audit.verify``,
    including the one ``seal_pending`` runs.
    """
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    patient = ehr.open_session(envelope, "patient")
    pages = patient.session()["envelope"]["page_count"]
    assert patient.get("/document").status_code == 200

    limit = RateLimits.PRESENT.limit
    statuses = [patient.post("/viewed", {"pages_viewed": pages}).status_code for _ in range(limit + 1)]
    assert statuses[:limit] == [200] * limit
    assert statuses[limit] == 429
    limited = patient.post("/viewed", {"pages_viewed": pages})
    assert limited.json()["error"]["code"] == "rate_limited"
    assert 1 <= int(limited.headers["retry-after"]) <= RateLimits.PRESENT.window_seconds

    world.clock.advance(RateLimits.PRESENT.window_seconds + 1)
    assert patient.post("/viewed", {"pages_viewed": pages}).status_code == 200


def test_running_a_verification_is_rate_limited_per_host(ehr: Ehr, world: World) -> None:
    """Every call re-hashes every revision, validates the seal and appends an audit event."""
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    limit = RateLimits.VERIFY.limit
    statuses = [ehr.get(f"/envelopes/{envelope['id']}/verification").status_code for _ in range(limit + 1)]
    assert statuses[:limit] == [200] * limit
    assert statuses[limit] == 429

    # Another host is unaffected, and the window passes.
    world.clock.advance(RateLimits.VERIFY.window_seconds + 1)
    assert ehr.get(f"/envelopes/{envelope['id']}/verification").status_code == 200


def test_guessing_tokens_is_rate_limited_per_ip(world: World) -> None:
    headers = {"Authorization": "Bearer est_" + "A" * 43}
    statuses = [world.client.get("/v1/signing/session", headers=headers).status_code for _ in range(21)]
    assert statuses[:20] == [401] * 20
    assert statuses[20] == 429


def test_the_recorded_ip_honours_trusted_proxies_only(
    e2e_settings: Settings, clock: FixedClock, app_engine: Engine, db_factory: Sessions
) -> None:
    def recorded_ip(settings: Settings, peer: str) -> str | None:
        rt = build_runtime(settings, clock=clock, engine=app_engine)
        client = TestClient(create_app(runtime=rt), raise_server_exceptions=False, client=(peer, 50000))
        world = World(client=client, rt=rt, clock=clock, sessions=db_factory, settings=settings)
        ehr = world.host(f"EHR behind {peer}")
        ehr.publish_template("hipaa_acknowledgement")
        forwarded = {"X-Forwarded-For": "203.0.113.77, 10.0.0.9", "User-Agent": "EhrBackend/4.2"}
        created = client.post(
            "/v1/envelopes", json=ehr.envelope_body("hipaa_acknowledgement"), headers={**ehr.headers, **forwarded}
        )
        assert created.status_code == 201, created.text
        events = ehr.get(f"/envelopes/{created.json()['id']}/audit").json()["events"]
        assert events[0]["context"]["user_agent"] == "EhrBackend/4.2"
        assert events[0]["context"]["auth_method"] == "api_key"
        ip: str | None = events[0]["context"]["ip"]
        return ip

    # A client can send any X-Forwarded-For it likes; it is believed only from a configured proxy.
    assert recorded_ip(e2e_settings, "198.51.100.10") == "198.51.100.10"
    behind_proxy = e2e_settings.model_copy(update={"trusted_proxy_cidrs": ("10.0.0.0/8",)})
    assert recorded_ip(behind_proxy, "10.0.0.5") == "203.0.113.77"
    assert recorded_ip(behind_proxy, "198.51.100.10") == "198.51.100.10"


def test_production_refuses_to_start_half_configured(e2e_settings: Settings) -> None:
    check_production_settings(e2e_settings)  # test/dev: nothing to insist on
    prod = e2e_settings.model_copy(update={"app_env": "prod", "seal_profile": "PAdES-B-T"})
    with pytest.raises(ConfigurationError) as refused:
        check_production_settings(prod)
    message = str(refused.value)
    assert "SEAL_PROFILE" in message and "BLOB_BACKEND" in message and "SEAL_KEY_BACKEND" in message
    with pytest.raises(ValueError, match="does not appear to be"):
        check_production_settings(e2e_settings.model_copy(update={"trusted_proxy_cidrs": ("not-a-network",)}))

    # The s3 backend with no bucket is refused in *any* environment: left to the backend it was a
    # bare ValueError at the first blob write, and ``esign worker`` / ``esign verify`` catch
    # ConfigurationError and EsignError only, so it reached the operator as a traceback.
    with pytest.raises(ConfigurationError) as no_bucket:
        check_production_settings(e2e_settings.model_copy(update={"blob_backend": "s3", "blob_s3_bucket": ""}))
    assert "BLOB_S3_BUCKET" in str(no_bucket.value)

    # And a production key or bucket with the default environment is a deployment that forgot
    # APP_ENV -- every rule above is keyed on it, the timestamp authority most of all.
    with pytest.raises(ConfigurationError) as forgot:
        check_production_settings(e2e_settings.model_copy(update={"app_env": "dev", "seal_key_backend": "aws_kms"}))
    assert "APP_ENV" in str(forgot.value)


def test_production_refuses_dev_database_credentials_and_sql_echo(e2e_settings: Settings, tmp_path: Path) -> None:
    """The seal and the blob store were covered; the database was not.

    ``DATABASE_URL`` and ``DATABASE_OWNER_URL`` default to DSNs carrying the passwords
    ``0002_roles.sql`` sets when it has to create the roles itself, and ``DB_ECHO`` would log every
    statement -- with its bound parameters: display names, prefill, typed signatures -- through the
    stdlib logger. SPEC section 10.
    """
    roots = tmp_path / "roots.pem"
    roots.write_text("-- not a real bundle\n")
    prod = e2e_settings.model_copy(
        update={
            "app_env": "prod",
            "seal_profile": "PAdES-B-LT",
            "seal_key_backend": "aws_kms",
            "seal_kms_key_id": "alias/esign-seal",
            "seal_cert_path": roots,
            "blob_backend": "s3",
            "blob_s3_bucket": "esign-documents",
            "trust_roots_path": roots,
            "tsa_url": "https://tsa.example/rfc3161",
            "database_url": "postgresql+psycopg://esign_app:esign_app_dev@db/esign",
            "database_owner_url": "postgresql+psycopg://esign_owner:esign_owner_dev@db/esign",
            "db_echo": True,
        }
    )
    with pytest.raises(ConfigurationError) as refused:
        check_production_settings(prod)
    message = str(refused.value)
    assert "DATABASE_URL" in message and "DATABASE_OWNER_URL" in message and "DB_ECHO" in message

    # With real credentials and the echo off, that configuration is accepted.
    check_production_settings(
        prod.model_copy(
            update={
                "database_url": "postgresql+psycopg://esign_app:s3cret@db/esign",
                "database_owner_url": "postgresql+psycopg://esign_owner:0ther@db/esign",
                "db_echo": False,
            }
        )
    )


def test_production_refuses_a_kms_backend_with_no_key_or_certificate(e2e_settings: Settings, tmp_path: Path) -> None:
    """``keys.py`` only noticed these at the first seal, by which time a document is signed and
    waiting and the failure looks like an outage rather than a misconfiguration."""
    roots = tmp_path / "roots.pem"
    roots.write_text("-- not a real bundle\n")
    prod = e2e_settings.model_copy(
        update={
            "app_env": "prod",
            "seal_profile": "PAdES-B-LT",
            "seal_key_backend": "aws_kms",
            "blob_backend": "s3",
            "blob_s3_bucket": "esign-documents",
            "trust_roots_path": roots,
            "tsa_url": "https://tsa.example/rfc3161",
            "database_url": "postgresql+psycopg://esign_app:s3cret@db/esign",
            "database_owner_url": "postgresql+psycopg://esign_owner:0ther@db/esign",
        }
    )
    with pytest.raises(ConfigurationError) as refused:
        check_production_settings(prod)
    message = str(refused.value)
    assert "SEAL_KMS_KEY_ID" in message and "SEAL_CERT_PATH" in message
