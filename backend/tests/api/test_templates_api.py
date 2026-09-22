"""The template lifecycle over the Host API."""

from __future__ import annotations

import json
from typing import Any

import httpx

from tests.documents.test_content_streams import over_cap_pdf
from tests.e2e.conftest import TEMPLATES_DIR, Ehr, World


def _upload(
    ehr: Ehr, path: str, key: str, *, definitions: dict[str, Any] | None = None, pdf: bytes | None = None
) -> httpx.Response:
    document = definitions or json.loads((TEMPLATES_DIR / f"{key}.json").read_text(encoding="utf-8"))
    content = pdf if pdf is not None else (TEMPLATES_DIR / f"{key}.pdf").read_bytes()
    response: httpx.Response = ehr.client.post(
        f"/v1{path}",
        headers=ehr.headers,
        files={"pdf": ("template.pdf", content, "application/pdf")},
        data={"definitions": json.dumps(document)},
    )
    return response


def test_draft_publish_new_version_retire(world: World) -> None:
    ehr = world.host()
    created = _upload(ehr, "/templates", "patient_consent")
    assert created.status_code == 201, created.text
    assert [(v["version"], v["status"]) for v in created.json()["versions"]] == [(1, "draft")]

    # A draft cannot be used: envelopes come from published versions only.
    unpublished = ehr.post("/envelopes", ehr.envelope_body("patient_consent"))
    assert unpublished.status_code in (404, 409)

    assert ehr.post("/templates/patient_consent/versions/1/publish").status_code == 200
    assert ehr.post("/templates/patient_consent/versions/1/publish").status_code == 409  # immutable from here
    assert _upload(ehr, "/templates", "patient_consent").status_code == 409  # the key is taken

    second = _upload(ehr, "/templates/patient_consent/versions", "patient_consent")
    assert second.status_code == 201
    assert [(v["version"], v["status"]) for v in second.json()["versions"]] == [(1, "published"), (2, "draft")]

    # "Latest published" is still version 1 until version 2 is published.
    assert ehr.create_envelope("patient_consent")["template_version"] == 1
    assert ehr.post("/templates/patient_consent/versions/2/publish").status_code == 200
    assert ehr.create_envelope("patient_consent")["template_version"] == 2
    assert ehr.create_envelope("patient_consent", template_version=1)["template_version"] == 1

    assert ehr.post("/templates/patient_consent/versions/1/retire").status_code == 200
    retired = ehr.post("/envelopes", ehr.envelope_body("patient_consent", template_version=1))
    assert retired.status_code == 409
    assert ehr.post("/templates/patient_consent/versions/9/publish").status_code == 404

    listing = ehr.get("/templates").json()["templates"]
    assert [(t["key"], [v["status"] for v in t["versions"]]) for t in listing] == [
        ("patient_consent", ["retired", "published"])
    ]
    detail = ehr.get("/templates/patient_consent").json()
    assert detail["name"] == "Consent to treatment" and len(detail["versions"][1]["pdf_sha256"]) == 64


def test_bad_uploads_are_refused(world: World) -> None:
    ehr = world.host()
    definitions = json.loads((TEMPLATES_DIR / "patient_consent.json").read_text(encoding="utf-8"))

    not_a_pdf = _upload(ehr, "/templates", "patient_consent", pdf=b"GIF89a not a pdf at all")
    assert not_a_pdf.status_code == 422

    unapproved = _upload(
        ehr, "/templates", "patient_consent", definitions={**definitions, "document_type": "dea_form_222"}
    )
    assert unapproved.status_code == 422
    assert unapproved.json()["error"]["code"] == "document_type_not_approved"

    bad_key = _upload(ehr, "/templates", "patient_consent", definitions={**definitions, "key": "Patient Consent!"})
    assert bad_key.json()["error"]["code"] == "template_key_invalid"

    outside = json.loads(json.dumps(definitions))
    outside["fields"][0]["rect"]["x"] = 5000
    assert _upload(ehr, "/templates", "patient_consent", definitions=outside).status_code == 422

    garbage = ehr.client.post(
        "/v1/templates",
        headers=ehr.headers,
        files={"pdf": ("t.pdf", (TEMPLATES_DIR / "patient_consent.pdf").read_bytes(), "application/pdf")},
        data={"definitions": "{not json"},
    )
    assert garbage.status_code == 422 and garbage.json()["error"]["code"] == "definitions_invalid"
    assert ehr.get("/templates").json() == {"templates": []}


def test_a_template_whose_content_cannot_be_decoded_is_refused_at_upload(world: World) -> None:
    """It used to publish cleanly and then 500 at ``POST /v1/envelopes``.

    ``inspect_template_pdf`` never decoded a page's content stream, so a file whose FlateDecode
    content inflates past pypdf's output cap passed inspection; stamping is the first thing that
    decodes it, and ``draw_overlay`` had no ``except`` of its own.
    """
    ehr = world.host()
    refused = _upload(ehr, "/templates", "patient_consent", pdf=over_cap_pdf())
    assert refused.status_code == 422, refused.text
    assert refused.json()["error"]["code"] == "template_content_unreadable"
    assert ehr.get("/templates").json()["templates"] == []
