"""``POST /v1/envelopes`` at the HTTP boundary: two request shapes on one route (Addendum 2).

The JSON shape is the base spec's and must be untouched; the multipart shape is new. What these
test is the seam between them -- which body is parsed, which size limit applies, what a malformed
request gets back -- rather than the envelope service behind it, which has its own tests.
"""

from __future__ import annotations

import json

from fastapi.testclient import TestClient
from sqlalchemy import Engine

from esign.clock import FixedClock
from esign.config import Settings
from tests.documents.helpers import NamedWidget, generated_report
from tests.e2e.conftest import CLINICIAN_NAME, Ehr, Sessions, World, build_world

PAGES = 6


def _report(pages: int = PAGES, *, widgets: bool = True) -> bytes:
    block = (
        (
            NamedWidget(name="clinician_signature", rect=(54, 96, 294, 146), page=pages),
            NamedWidget(name="clinician_date", rect=(320, 96, 500, 146), page=pages),
        )
        if widgets
        else ()
    )
    return generated_report(pages=pages, widgets=block)


def test_the_json_shape_still_creates_a_template_envelope(ehr: Ehr) -> None:
    envelope = ehr.create_envelope("patient_consent")
    assert envelope["source"] == "template"
    assert envelope["template_key"] == "patient_consent"
    assert envelope["template_version"] == 1


def test_the_multipart_shape_creates_a_host_document_envelope(ehr: Ehr) -> None:
    envelope = ehr.create_host_document_envelope(_report())
    assert envelope["source"] == "host_document"
    assert envelope["template_key"] is None
    assert envelope["signers"][0]["display_name"] == CLINICIAN_NAME
    # The same route answers the same shape, so a host can read both with one parser.
    assert set(envelope) == set(ehr.create_envelope("patient_consent"))


def test_a_multipart_request_missing_a_part_is_refused(ehr: Ehr) -> None:
    only_body = ehr.client.post(
        "/v1/envelopes",
        headers=ehr.headers,
        data={"body": json.dumps(ehr.host_document_body())},
        files={"notes": ("notes.txt", b"hello", "text/plain")},
    )
    assert only_body.status_code == 422
    assert only_body.json()["error"]["code"] == "validation_failed"

    only_document = ehr.client.post(
        "/v1/envelopes",
        headers=ehr.headers,
        files={"document": ("report.pdf", _report(), "application/pdf")},
    )
    assert only_document.status_code == 422
    assert only_document.json()["error"]["code"] == "validation_failed"


def test_a_body_part_that_is_not_json_is_refused(ehr: Ehr) -> None:
    refused = ehr.client.post(
        "/v1/envelopes",
        headers=ehr.headers,
        files={"document": ("report.pdf", _report(), "application/pdf")},
        data={"body": "not json at all"},
    )
    assert refused.status_code == 422
    assert refused.json()["error"]["code"] == "validation_failed"


def test_a_json_body_that_is_not_an_object_is_refused(ehr: Ehr) -> None:
    refused = ehr.client.post("/v1/envelopes", headers=ehr.headers, json=["not", "an", "object"])
    assert refused.status_code == 422
    assert refused.json()["error"]["code"] == "validation_failed"


def test_an_unauthenticated_multipart_request_is_refused_before_anything_is_created(world: World, ehr: Ehr) -> None:
    anonymous = world.client.post(
        "/v1/envelopes",
        files={"document": ("report.pdf", _report(), "application/pdf")},
        data={"body": json.dumps(ehr.host_document_body())},
    )
    assert anonymous.status_code == 401
    assert anonymous.headers["www-authenticate"] == "Bearer"


def test_uploading_a_pdf_at_signing_time_is_still_out_of_scope(ehr: Ehr) -> None:
    """A host document is a multipart ``POST /v1/envelopes``. A route that sounds like "upload a
    PDF to this envelope" stays refused: that is the signer-side upload section 1 excludes."""
    envelope = ehr.create_host_document_envelope(_report())
    refused = ehr.post(f"/envelopes/{envelope['id']}/documents", {})
    assert refused.status_code == 422
    assert refused.json()["error"]["code"] == "out_of_scope"


def test_the_multipart_route_gets_the_supplied_document_limit_not_the_request_limit(
    e2e_settings: Settings, clock: FixedClock, app_engine: Engine, db_factory: Sessions
) -> None:
    """SPEC section 9: a 30-page report is bigger than ``MAX_REQUEST_BYTES``, and the raise
    applies to the multipart shape of this route alone -- the JSON shape keeps the small limit."""
    tight = e2e_settings.model_copy(update={"max_request_bytes": 2_000, "max_supplied_document_bytes": 5 * 1024 * 1024})
    world = build_world(tight, clock, app_engine, db_factory)
    ehr = world.host()

    # A JSON body over the request limit is still 413.
    assert ehr.post("/envelopes", {"padding": "x" * 5_000}).status_code == 413

    # The same number of bytes as a multipart document is admitted and reaches the handler.
    document = _report()
    assert len(document) > tight.max_request_bytes
    created = ehr.post_host_document(document)
    assert created.status_code == 201, created.text


def test_a_document_over_the_supplied_limit_is_refused_as_such(
    e2e_settings: Settings, clock: FixedClock, app_engine: Engine, db_factory: Sessions
) -> None:
    small = e2e_settings.model_copy(update={"max_supplied_document_bytes": 4_000})
    world = build_world(small, clock, app_engine, db_factory)
    ehr = world.host()

    refused = ehr.post_host_document(_report())
    # 413 from the middleware or ``supplied_too_large`` from the route, depending on where the
    # bytes were counted first. Either way the host is told it was the document, not the envelope.
    assert refused.status_code in (413, 422)
    assert refused.json()["error"]["code"] in ("payload_too_large", "supplied_too_large")


def test_the_multipart_route_meters_the_host_but_a_retry_still_replays(ehr: Ehr) -> None:
    """Creating one of these stores two blobs with no delete path and runs a whole PDF through
    hygiene, so it is metered like the other calls that create evidence. The meter runs *after*
    the replay check, so a retry of a creation that already succeeded gets its first answer back
    and not a 429, however many times the connection dropped."""
    from esign.identity import RateLimits

    first = ehr.post_host_document(_report(pages=2), **{"Idempotency-Key": "report-001"})
    assert first.status_code == 201, first.text

    limit = RateLimits.SESSION_CREATE.limit
    statuses = [ehr.post_host_document(_report(pages=2)).status_code for _ in range(limit)]
    assert statuses.count(201) == limit - 1
    assert statuses[-1] == 429

    replayed = ehr.post_host_document(_report(pages=2), **{"Idempotency-Key": "report-001"})
    assert replayed.status_code == 201, replayed.text
    assert replayed.json()["id"] == first.json()["id"]


def test_a_signer_token_cannot_create_a_host_document_envelope(ehr: Ehr) -> None:
    envelope = ehr.create_host_document_envelope(_report())
    signer = ehr.open_session(envelope, "clinician", method="password+mfa")
    refused = ehr.client.post(
        "/v1/envelopes",
        headers=signer.headers,
        files={"document": ("report.pdf", _report(), "application/pdf")},
        data={"body": json.dumps(ehr.host_document_body())},
    )
    assert refused.status_code == 401
    assert refused.json()["error"]["code"] == "unauthorized"


def test_the_response_carries_the_security_headers_like_every_other(ehr: Ehr) -> None:
    created = ehr.post_host_document(_report())
    assert created.status_code == 201
    assert created.headers["cache-control"] == "no-store"
    assert created.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in created.headers["content-security-policy"]


def test_the_error_envelope_never_echoes_the_report(ehr: Ehr) -> None:
    body = ehr.host_document_body(patient_ref="Marguerite Okonkwo-Vasquez")
    refused = ehr.post_host_document(_report(), body)
    assert refused.status_code == 422
    assert refused.json()["error"]["code"] == "patient_ref_invalid"
    assert "Marguerite" not in refused.text


def test_an_unknown_client_is_not_told_which_part_of_the_world_it_got_wrong(world: World, ehr: Ehr) -> None:
    """A TestClient that sends a multipart body with a bogus content type is a 422, not a 500."""
    response: TestClient = world.client
    broken = response.post(
        "/v1/envelopes",
        headers={**ehr.headers, "Content-Type": "multipart/form-data"},
        content=b"not a multipart body at all",
    )
    assert broken.status_code in (400, 422), broken.text
    assert set(broken.json()) == {"error"}
