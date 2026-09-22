"""``esign``: the commands an operator runs. Driven through ``main`` with the test runtime."""

from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path

import pytest
from sqlalchemy import text

from esign.cli import main
from esign.clock import FixedClock
from esign.config import Settings
from esign.runtime import ConfigurationError, build_runtime
from tests.conftest import FROZEN_NOW
from tests.e2e.conftest import PATIENT_NAME, Ehr, World


def test_hosts_consent_and_templates_set_up_a_working_host(world: World, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["hosts", "create", "--name", "Riverside EHR", "--origin", "https://ehr.example",
                 "--webhook-url", "https://ehr.example/hooks"], runtime=world.rt) == 0  # fmt: skip
    out = capsys.readouterr().out
    host_id = re.search(r"host id:\s+(\S+)", out).group(1)  # type: ignore[union-attr]
    api_key = re.search(r"api key:\s+(esk_\S+)", out).group(1)  # type: ignore[union-attr]
    assert re.search(r"webhook secret: [0-9a-f]{64}", out)

    # The key is shown once and only its hash is stored.
    with world.sessions() as db:
        stored = db.execute(text("SELECT api_key_hash, name FROM hosts WHERE id = :id"), {"id": host_id}).one()
    assert api_key.encode() not in bytes(stored.api_key_hash) and len(bytes(stored.api_key_hash)) == 32

    assert main(["consent", "add", "--default"], runtime=world.rt) == 0  # idempotent: already seeded
    assert "2026-09" in capsys.readouterr().out

    assert main(["templates", "import", "--host", host_id], runtime=world.rt) == 0
    imported = capsys.readouterr().out
    assert "procedure_consent v1 published" in imported and "hipaa_acknowledgement v1 published" in imported

    headers = {"Authorization": f"Bearer {api_key}"}
    listed = world.client.get("/v1/templates", headers=headers).json()["templates"]
    assert sorted(t["key"] for t in listed) == [
        "clinical_order",
        "hipaa_acknowledgement",
        "patient_consent",
        "procedure_consent",
    ]

    # Importing again adds a new published version rather than touching the immutable one.
    assert main(["templates", "import", "--host", host_id], runtime=world.rt) == 0
    assert "procedure_consent v2 published" in capsys.readouterr().out

    assert main(["hosts", "rotate-key", host_id], runtime=world.rt) == 0
    new_key = re.search(r"api key: (esk_\S+)", capsys.readouterr().out).group(1)  # type: ignore[union-attr]
    assert world.client.get("/v1/templates", headers=headers).status_code == 401
    assert world.client.get("/v1/templates", headers={"Authorization": f"Bearer {new_key}"}).status_code == 200

    assert main(["templates", "import", "--host", "5f0d4e7e-3f59-4e4e-9a53-0f6f1a2b3c4d"], runtime=world.rt) == 2
    assert "host_not_found" in capsys.readouterr().err


def test_a_custom_consent_text_can_be_added_from_a_file(
    world: World, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    body = tmp_path / "es.txt"
    body.write_text("Acuerdo para firmar electronicamente.\n\nPuede firmar en papel si lo prefiere.", encoding="utf-8")
    args = ["consent", "add", "--version", "2026-10", "--locale", "es-US", "--file", str(body)]
    assert main([*args, "--effective-at", "2026-01-01T00:00:00+00:00"], runtime=world.rt) == 0
    assert "2026-10 (es-US)" in capsys.readouterr().out
    assert main([*args, "--effective-at", "2026-01-01T00:00:00"], runtime=world.rt) == 2  # naive time refused
    assert main(["consent", "add", "--version", "x"], runtime=world.rt) == 2


def test_verify_and_worker(ehr: Ehr, world: World, capsys: pytest.CaptureFixture[str]) -> None:
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    assert main(["verify", envelope["id"]], runtime=world.rt) == 0
    assert "NOT complete" in capsys.readouterr().out

    ehr.sign_everyone(envelope, ("patient",))
    assert main(["verify", envelope["id"]], runtime=world.rt) == 0
    out = capsys.readouterr().out
    assert "RESULT: verified" in out and "PASSED  seal_trusted" in out and PATIENT_NAME not in out

    assert main(["verify", envelope["id"], "--json"], runtime=world.rt) == 0
    assert json.loads(capsys.readouterr().out)["complete"] is True
    assert ehr.audit_types(envelope["id"]).count("verification.performed") == 3

    assert main(["verify", "5f0d4e7e-3f59-4e4e-9a53-0f6f1a2b3c4d"], runtime=world.rt) == 2
    assert "not_found" in capsys.readouterr().err

    # A wrong trust store is a failed verification (exit 1), never a pass.
    untrusting = build_runtime(
        world.settings.model_copy(update={"trust_roots_path": world.settings.blob_fs_root / "missing.pem"}),
        clock=world.clock,
        engine=world.rt.engine,
    )
    assert main(["verify", envelope["id"]], runtime=untrusting) == 1
    assert "FAILED" in capsys.readouterr().out

    # `esign worker --once` would POST to the host's real URL, so the host here has no webhook.
    quiet = world.host("No webhook EHR")
    quiet.publish_template("hipaa_acknowledgement")
    quiet.create_envelope(
        "hipaa_acknowledgement", expires_at=(world.clock.now().replace(year=2026, month=3, day=18)).isoformat()
    )
    with world.sessions() as db:
        db.execute(
            text("UPDATE webhook_deliveries SET delivered_at = :now WHERE delivered_at IS NULL"),
            {"now": world.clock.now()},
        )
        db.commit()
    world.clock.advance(60 * 60 * 24 * 2)
    assert main(["worker", "--once"], runtime=world.rt) == 0
    assert "expired 1" in capsys.readouterr().out


def test_dev_pki_refuses_to_overwrite_and_refuses_production(
    tmp_path: Path, settings_no_db: Settings, capsys: pytest.CaptureFixture[str]
) -> None:
    target = settings_no_db.model_copy(update={"dev_pki_dir": tmp_path / "pki"})
    rt = build_runtime(target, clock=FixedClock(FROZEN_NOW))
    assert main(["dev-pki"], runtime=rt) == 0
    assert (tmp_path / "pki" / "trust-roots.pem").is_file()
    assert main(["dev-pki"], runtime=rt) == 2
    assert "already holds a dev PKI" in capsys.readouterr().err
    assert main(["dev-pki", "--force"], runtime=rt) == 0

    # A prod runtime cannot even be built with a dev profile and the local key backend, so the
    # settings have to be swapped onto an existing one to reach the dev-pki refusal itself.
    prod = replace(rt, settings=target.model_copy(update={"app_env": "prod"}))
    assert main(["dev-pki", "--force"], runtime=prod) == 2


def test_the_worker_refuses_a_production_configuration_before_touching_the_database(
    settings_no_db: Settings, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The worker is the process that seals, and it used to be gated by nothing at all.

    ``check_production_settings`` ran only in ``create_app``, so a prod worker with ``TSA_URL`` set
    but ``SEAL_PROFILE``/``SEAL_KEY_BACKEND`` left at their defaults and a ``.dev-pki`` directory
    present would seal real documents at B-T with the dev key while the API container beside it
    refused to start. SPEC section 5: B-T is an explicit setting, never a silent downgrade.
    """
    prod = settings_no_db.model_copy(
        update={
            "app_env": "prod",
            "seal_profile": "PAdES-B-T",
            "seal_key_backend": "local",
            "tsa_url": "https://tsa.example/rfc3161",
            # A DSN that would not connect from here anyway; the point is that nothing tries.
            "database_url": "postgresql+psycopg://esign_app:nope@127.0.0.1:1/esign",
        }
    )
    monkeypatch.setattr("esign.cli.get_settings", lambda: prod)

    assert main(["worker", "--once"]) == 2
    message = capsys.readouterr().err
    assert "SEAL_PROFILE" in message
    assert "SEAL_KEY_BACKEND" in message


def test_building_a_runtime_refuses_a_production_dev_profile(settings_no_db: Settings) -> None:
    """Every entry point goes through ``build_runtime``; every one of them is gated by it."""
    prod = settings_no_db.model_copy(update={"app_env": "prod", "seal_profile": "PAdES-B-T"})
    with pytest.raises(ConfigurationError) as refused:
        build_runtime(prod, clock=FixedClock(FROZEN_NOW))
    assert "SEAL_PROFILE" in str(refused.value)


def test_serve_does_not_let_uvicorn_install_its_own_loggers(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    """``esign serve`` must not hand logging back to uvicorn's defaults.

    ``uvicorn.LOGGING_CONFIG`` gives ``uvicorn`` and ``uvicorn.access`` their own stdout handlers
    with ``propagate: False``, so their records never reach the root handler ``configure_logging``
    installs and never pass ``drop_unlisted_keys``. The access line carries the raw path and query
    string -- which the ``AccessLog`` middleware deliberately avoids, logging the route template
    only -- inside the reserved ``event`` key, where it could not be sanitised even if it did
    propagate. So the log config is dropped and the access log is off.
    """
    import uvicorn

    captured: dict[str, object] = {}

    def fake_run(app: str, **kwargs: object) -> None:
        captured["app"] = app
        captured.update(kwargs)

    monkeypatch.setattr(uvicorn, "run", fake_run)
    assert main(["serve", "--port", "8123"], runtime=world.rt) == 0

    assert captured["app"] == "esign.api:app"
    assert captured["log_config"] is None
    assert captured["access_log"] is False
    # And the app still owns the peer address and the server header (TRUSTED_PROXY_CIDRS).
    assert captured["proxy_headers"] is False
    assert captured["server_header"] is False
    assert captured["reload"] is False


def test_serve_reloads_only_when_asked_and_still_drops_the_log_config(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``make dev-api`` runs the development server through ``esign serve --reload``.

    It used to call uvicorn itself with ``--no-access-log``, which silences the raw-URL access line
    but leaves uvicorn's error logger on its own non-propagating handler. Reloading is the only
    reason that invocation existed, so it is a flag here and the logging is the same either way.
    """
    import uvicorn

    captured: dict[str, object] = {}

    def fake_run(app: str, **kwargs: object) -> None:
        captured["app"] = app
        captured.update(kwargs)

    monkeypatch.setattr(uvicorn, "run", fake_run)
    assert main(["serve", "--port", "8123", "--reload"], runtime=world.rt) == 0

    assert captured["reload"] is True
    assert captured["log_config"] is None
    assert captured["access_log"] is False
