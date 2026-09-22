"""The names on a paper archive stay in the database and inside the sealed PDF.

An archive carries more names than an electronic envelope does -- the staff member who attested to
the copy, and everyone whose signature is on the paper -- and none of them is a signer in this
system, so none of them has a row the audit allowlist would have refused. The names are therefore
the thing to watch: ``archive.attested`` records a *count* of paper signers, and the cover page and
the certificate, both inside the seal, are the only places a name is written.
"""

from __future__ import annotations

import io
import json
from typing import Any

import structlog
from sqlalchemy import text

from esign.logging import LOGGABLE_KEYS, RESERVED_KEYS, configure_logging
from esign.worker import run_once
from tests.archives.conftest import (
    PAPER_SIGNER_NAME,
    SECOND_PAPER_SIGNER_NAME,
    STAFF_NAME,
    attestation,
    file_archive,
    filed,
)
from tests.e2e.conftest import Ehr, World

#: Everything that must not appear outside the database and the sealed bytes.
NAMES = (STAFF_NAME, PAPER_SIGNER_NAME, SECOND_PAPER_SIGNER_NAME, "Quillfeather", "Vandenbrouck", "Thistlewood")


def two_signers() -> dict[str, Any]:
    return attestation(
        paper_signers=[
            {"display_name": PAPER_SIGNER_NAME, "capacity": "self"},
            {"display_name": SECOND_PAPER_SIGNER_NAME, "capacity": "witness"},
        ]
    )


def test_no_log_line_from_filing_a_scan_carries_a_name(host: Ehr, world: World) -> None:
    """SPEC 12, for the archive path: the real logging pipeline renders into a buffer while a scan
    is filed, sealed, refused, read back, verified and delivered."""
    buffer = io.StringIO()
    configure_logging(level="DEBUG", json_output=True, app_env="test", stream=buffer)
    try:
        view = filed(host, attestation=two_signers())
        assert host.get(f"/envelopes/{view['id']}/document").status_code == 200
        host.audit_types(view["id"])
        assert host.verification(view["id"])["complete"] is True
        run_once(world.rt, send=host.receive)
        # A refusal must not quote the value it refused, either.
        refused = file_archive(host, attestation=attestation(staff_user_id=STAFF_NAME))
        assert refused.status_code == 422
    finally:
        structlog.reset_defaults()
        configure_logging(level="INFO", app_env="test")

    rendered = buffer.getvalue()
    lines = [json.loads(line) for line in rendered.splitlines() if line.startswith("{")]
    events = {str(line["event"]) for line in lines}
    assert {"archive.created", "document.sealed", "verification.performed", "webhook.delivered"} <= events, events
    for name in NAMES:
        assert name not in rendered, f"a log line carried {name}"
    for line in lines:
        assert "dropped_fields" not in line, line  # nothing even *tried* to log an unlisted key
        assert set(line) <= LOGGABLE_KEYS | RESERVED_KEYS, line


def test_no_name_reaches_audit_data(host: Ehr) -> None:
    view = filed(host, attestation=two_signers())
    trail = json.dumps(host.audit(view["id"]))
    for name in NAMES:
        assert name not in trail
    attested = next(e for e in host.audit(view["id"]) if e["event_type"] == "archive.attested")
    # A count, and nothing that could be a name. The date on the paper stays out too: it is a
    # date, and the trail holds no date-shaped values about a person.
    assert attested["data"]["paper_signer_count"] == 2
    assert "paper_signers" not in attested["data"]
    assert "2026-03-10" not in trail


def test_no_name_reaches_a_webhook_payload(host: Ehr, world: World) -> None:
    filed(host, attestation=two_signers())
    run_once(world.rt, send=host.receive)
    assert host.deliveries
    for _url, body, _headers in host.deliveries:
        for name in NAMES:
            assert name.encode() not in body
        payload = json.loads(body)
        # Ids, statuses and hashes only: no patient_ref and no host_document_ref either.
        assert "patient_ref" not in payload and "host_document_ref" not in payload


def test_the_names_are_kept_where_they_belong(host: Ehr, world: World) -> None:
    """The other half of the rule. A signature nobody can attribute is not evidence, so the names
    are written -- in the database, and on the cover page and certificate inside the seal."""
    view = filed(host, attestation=two_signers())
    with world.sessions() as db:
        stored = db.execute(
            text("SELECT attestation::text FROM envelopes WHERE id = :id"), {"id": view["id"]}
        ).scalar_one()
    assert STAFF_NAME in stored and PAPER_SIGNER_NAME in stored and SECOND_PAPER_SIGNER_NAME in stored

    sealed = host.get(f"/envelopes/{view['id']}/document")
    assert sealed.status_code == 200
    assert sealed.content.startswith(b"%PDF")
