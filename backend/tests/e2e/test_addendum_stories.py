"""The addenda, end to end over the real HTTP app: the stories the features exist for.

Each feature has its own test package (``tests/archives``, ``tests/adopted_signatures``,
``tests/reauth_span``, ``tests/consent_span``) that takes it apart rule by rule. These are the
stories told whole, the way the demo host tells them: a member of staff files a scan and somebody
later swaps it on disk; a clinician saves a signature on one order and is offered it on the next;
a queue confirmed once and signed three times with the span lapsing in between; a shared tablet
that is never offered what the patient saved; a host that takes a saved signature away; and
(Addendum 3 C) a patient at the front desk who reads the disclosure once and signs three forms.
"""

from __future__ import annotations

import io
import os
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pypdf import PdfReader
from sqlalchemy import Engine

from esign.clock import FixedClock
from esign.config import Settings
from esign.storage import content_key
from tests.adopted_signatures.conftest import adopted_capture, sign_body
from tests.archives.conftest import filed, scan_pdf
from tests.e2e.conftest import Ehr, Sessions, Signer, World, build_world

#: The demo's queue configuration: both windows five minutes, so the span is what lapses.
QUEUE_SPAN_SECONDS = 300
QUEUE_MAX_AGE_SECONDS = 300

CLINICIAN = "dr-0311"


def pdf_text(pdf: bytes) -> str:
    return "".join(page.extract_text() or "" for page in PdfReader(io.BytesIO(pdf)).pages)


def signed_event(ehr: Ehr, envelope_id: str) -> dict[str, Any]:
    events = [e for e in ehr.audit(envelope_id) if e["event_type"] == "signer.signed"]
    assert len(events) == 1, [e["event_type"] for e in ehr.audit(envelope_id)]
    data: dict[str, Any] = events[0]["data"]
    return data


def order(ehr: Ehr) -> dict[str, Any]:
    """A clinical order sign-off for the clinician: one signer, re-authentication required."""
    return ehr.create_envelope("clinical_order", signing_order="parallel")


def clinician_session(ehr: Ehr, envelope: dict[str, Any]) -> tuple[Signer, dict[str, Any]]:
    signer = ehr.open_session(envelope, "clinician", method="password+mfa")
    payload = signer.review_and_consent()
    assert payload["signer"]["requires_reauth"] is True
    return signer, payload


# --------------------------------------------------------------------------- A. a paper document


def test_a_paper_document_is_filed_sealed_and_verified_and_a_swapped_scan_is_caught(ehr: Ehr, world: World) -> None:
    scan = scan_pdf(pages=2, text="Consent to treatment, signed in ink")
    view = filed(ehr, scan)
    assert view["kind"] == "paper_archive"
    assert view["template_key"] is None and view["signers"] == []

    # Filed, sealed inline, and the sealed bytes open with the cover page that says what this is.
    sealed = ehr.envelope(view["id"])
    assert sealed["status"] == "sealed"
    assert ehr.audit_types(view["id"]) == [
        "archive.created",
        "archive.attested",
        "document.finalized",
        "document.sealed",
        "document.stored",
    ]
    document = ehr.get(f"/envelopes/{view['id']}/document")
    assert document.status_code == 200
    text = pdf_text(document.content)
    assert "Scanned copy of a document signed on paper" in text
    assert "Certificate of completion" in text
    assert view["id"] in text

    report = ehr.verification(view["id"])
    assert report["ok"] and report["complete"], report["problems"]

    # Somebody with access to the disk replaces the stored scan with another document. The store
    # is content-addressed, so the file under the scan's hash now holds bytes that do not hash to
    # it, and the seal proves exactly this: the scan is not what was filed.
    path = world.settings.blob_fs_root / content_key(bytes.fromhex(str(view["presented_sha256"])))
    os.chmod(path, 0o644)  # noqa: PTH101 - the file is deliberately read-only
    path.write_bytes(scan_pdf(pages=2, text="A different document altogether"))

    caught = ehr.verification(view["id"])
    assert caught["ok"] is False
    failed = {c["name"]: c["detail"] for c in caught["checks"] if c["status"] == "failed"}
    assert "revision_1_scan_hash" in failed, failed
    assert "integrity_failure" in failed["revision_1_scan_hash"]
    # The check that failed is itself on the record.
    assert ehr.audit_types(view["id"])[-1] == "verification.performed"


# --------------------------------------------------------------------------- B. a saved signature


@pytest.fixture
def orders(ehr: Ehr) -> Ehr:
    ehr.publish_template("clinical_order")
    return ehr


def test_a_clinician_saves_a_signature_on_one_order_and_uses_it_on_the_next(orders: Ehr) -> None:
    ehr = orders
    first = order(ehr)
    signer, payload = clinician_session(ehr, first)
    assert payload["adopted_signature"] is None
    assert ehr.reauth(signer).status_code == 200
    kept = signer.post("/sign", sign_body(signer, payload, kind="drawn", save=True), **{"Idempotency-Key": "keep-1"})
    assert kept.status_code == 200, kept.text
    assert "signature.adopted" in ehr.audit_types(first["id"])

    # The next order offers it back: the same person, the same host, the image the trail vouches for.
    second = order(ehr)
    signer2, payload2 = clinician_session(ehr, second)
    offered = payload2["adopted_signature"]
    assert offered is not None and offered["kind"] == "drawn"
    assert offered["image_png_base64"] and offered["typed_text"] is None
    assert ehr.reauth(signer2).status_code == 200
    applied = signer2.post(
        "/sign",
        sign_body(signer2, payload2, captures=adopted_capture(payload2, offered["id"])),
        **{"Idempotency-Key": "use-1"},
    )
    assert applied.status_code == 200, applied.text

    data = signed_event(ehr, second["id"])
    assert data["adopted_signature_id"] == offered["id"]
    assert [c["kind"] for c in data["captures"]] == ["adopted"]
    sealed = ehr.get(f"/envelopes/{second['id']}/document")
    assert sealed.status_code == 200
    assert "signed with a saved signature adopted on" in pdf_text(sealed.content)
    report = ehr.verification(second["id"])
    assert report["complete"] is True, (report["problems"], [c for c in report["checks"] if c["status"] != "passed"])


# --------------------------------------------------------------------------- C. the signing queue


@pytest.fixture
def queue_world(e2e_settings: Settings, clock: FixedClock, app_engine: Engine, db_factory: Sessions) -> World:
    """The whole stack with the demo's queue configuration: span and maximum age both 300 s."""
    settings = e2e_settings.model_copy(
        update={"reauth_span_seconds": QUEUE_SPAN_SECONDS, "reauth_max_age_seconds": QUEUE_MAX_AGE_SECONDS}
    )
    return build_world(settings, clock, app_engine, db_factory)


@pytest.fixture
def queue_ehr(queue_world: World) -> Ehr:
    host = queue_world.host(webhook=True)
    host.publish_template("clinical_order")
    return host


def test_a_queue_is_confirmed_once_and_the_third_document_is_refused_after_the_span_lapses(
    queue_world: World, queue_ehr: Ehr, clock: FixedClock
) -> None:
    with queue_world.client:
        ehr = queue_ehr
        # 1. The first order: the hand-off happens here, exactly once.
        first = order(ehr)
        signer1, payload1 = clinician_session(ehr, first)
        assert payload1["signer"]["reauth_scope"] is None and payload1["signer"]["reauth_at"] is None
        attested = ehr.reauth(signer1)
        assert attested.status_code == 200
        confirmed_at = clock.now()
        assert signer1.sign(payload1, key="q-1").status_code == 200
        assert signed_event(ehr, first["id"])["reauth_scope"] == "session"

        # 2. The second, two minutes later: no hand-off. The session says what it rests on.
        clock.advance(timedelta(seconds=120))
        second = order(ehr)
        signer2, payload2 = clinician_session(ehr, second)
        assert payload2["signer"]["reauth_scope"] == "span"
        assert datetime.fromisoformat(payload2["signer"]["reauth_at"]).astimezone(UTC) == confirmed_at
        valid_until = datetime.fromisoformat(payload2["signer"]["reauth_valid_until"]).astimezone(UTC)
        assert valid_until == confirmed_at + timedelta(seconds=QUEUE_SPAN_SECONDS)
        assert signer2.sign(payload2, key="q-2").status_code == 200
        borrowed = signed_event(ehr, second["id"])
        assert borrowed["reauth_scope"] == "span"
        assert borrowed["reauth_age_seconds"] == 120
        assert borrowed["reauth_attestation_id"] == signed_event(ehr, first["id"])["reauth_attestation_id"]
        certificate = pdf_text(ehr.get(f"/envelopes/{second['id']}/document").content)
        assert "in an earlier session, 120 seconds before signing" in certificate
        assert ehr.verification(second["id"])["complete"] is True

        # 3. The third, after the span has lapsed: refused until the clinician confirms again.
        clock.advance(timedelta(seconds=QUEUE_SPAN_SECONDS))
        third = order(ehr)
        signer3, payload3 = clinician_session(ehr, third)
        assert payload3["signer"]["reauth_valid_until"] is None
        assert payload3["signer"]["reauth_scope"] is None
        refused = signer3.sign(payload3, key="q-3")
        assert refused.status_code == 403, refused.text
        assert refused.json()["error"]["code"] == "reauth_required"
        assert ehr.reauth(signer3).status_code == 200
        assert signer3.sign(payload3, key="q-3b").status_code == 200
        assert signed_event(ehr, third["id"])["reauth_scope"] == "session"


# --------------------------------------------------------------------------- B. kiosk and host revoke

KIOSK = {"staff_user_id": "staff-3310", "identity_check": "photo_id"}


def with_adopted(signer: Signer, payload: dict[str, Any], adopted_signature_id: str) -> list[dict[str, Any]]:
    """This signer's captures with every signature field filled by the saved signature, and the
    checkbox and text fields as they would be anyway."""
    return [c for c in signer.captures(payload) if c.get("kind") not in ("drawn", "typed", "click")] + adopted_capture(
        payload, adopted_signature_id
    )


def patient_saves_a_signature(ehr: Ehr) -> dict[str, Any]:
    envelope = ehr.create_envelope("hipaa_acknowledgement")
    signer = ehr.open_session(envelope, "patient")
    payload = signer.review_and_consent()
    kept = signer.post("/sign", sign_body(signer, payload, kind="drawn", save=True), **{"Idempotency-Key": "keep-p"})
    assert kept.status_code == 200, kept.text
    return envelope


def test_a_kiosk_session_is_never_offered_the_patients_saved_signature(ehr: Ehr) -> None:
    patient_saves_a_signature(ehr)
    # The same patient, on a shared clinic tablet, with staff vouching for who they are.
    envelope = ehr.create_envelope("patient_consent")
    tablet = ehr.open_session(envelope, "patient", method="staff_verified", kiosk=KIOSK)
    payload = tablet.review_and_consent()
    assert payload["session"]["kiosk"] is True
    assert payload["adopted_signature"] is None

    # Neither can the tablet use the saved signature by guessing its id, nor leave a new one behind.
    with_saved = ehr.open_session(ehr.create_envelope("hipaa_acknowledgement"), "patient").session()
    saved_id = with_saved["adopted_signature"]["id"]
    used = tablet.post(
        "/sign",
        sign_body(tablet, payload, captures=with_adopted(tablet, payload, saved_id)),
        **{"Idempotency-Key": "k-1"},
    )
    assert used.status_code == 403 and used.json()["error"]["code"] == "adopted_signature_unavailable"
    left_behind = tablet.post(
        "/sign", sign_body(tablet, payload, kind="drawn", save=True), **{"Idempotency-Key": "k-2"}
    )
    assert left_behind.status_code == 403 and left_behind.json()["error"]["code"] == "adoption_not_allowed"
    # ...and a plain signature from the tablet still goes through.
    assert (
        tablet.post("/sign", sign_body(tablet, payload, kind="drawn"), **{"Idempotency-Key": "k-3"}).status_code == 200
    )


def test_a_host_revoke_removes_the_saved_signature_from_the_next_session(ehr: Ehr, world: World) -> None:
    patient_saves_a_signature(ehr)
    before = ehr.open_session(ehr.create_envelope("hipaa_acknowledgement"), "patient").session()
    assert before["adopted_signature"] is not None

    revoked = ehr.post("/users/pt-100482/adopted-signature/revoke", {"reason": "left the practice"})
    assert revoked.status_code == 200 and revoked.json() == {"revoked": True}

    after = ehr.open_session(ehr.create_envelope("hipaa_acknowledgement"), "patient").session()
    assert after["adopted_signature"] is None
    # Idempotent, and silent about whose user this is: a second revoke and another host's user
    # both answer the same thing.
    again = ehr.post("/users/pt-100482/adopted-signature/revoke", {})
    assert again.status_code == 200 and again.json() == {"revoked": False}
    stranger = world.host("Another EHR").post("/users/pt-100482/adopted-signature/revoke", {})
    assert stranger.status_code == 200 and stranger.json() == {"revoked": False}


# --------------------------------------------------------------------------- D. one sitting, three forms

#: What the front desk runs with: long enough for the forms one patient signs at one visit.
SITTING_SECONDS = 900


@pytest.fixture
def sitting_world(e2e_settings: Settings, clock: FixedClock, app_engine: Engine, db_factory: Sessions) -> World:
    """The whole stack with consent standing for fifteen minutes (Addendum 3 C)."""
    return build_world(
        e2e_settings.model_copy(update={"consent_span_seconds": SITTING_SECONDS}), clock, app_engine, db_factory
    )


@pytest.fixture
def sitting_ehr(sitting_world: World) -> Ehr:
    host = sitting_world.host(webhook=True)
    host.publish_template("hipaa_acknowledgement")
    return host


def read_and_sign(ehr: Ehr, envelope: dict[str, Any], *, key: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """One form, exactly as the UI does it (Addendum 3 A): read every page, agree -- relying on the
    standing acceptance when the payload offers one -- and sign.

    Returns the session payload, which is where the standing line comes from, and this envelope's
    own ``consent.accepted`` event.
    """
    signer = ehr.open_session(envelope, "patient")
    payload = signer.session()
    assert signer.get("/document").status_code == 200
    assert signer.post("/viewed", {"pages_viewed": payload["envelope"]["page_count"]}).status_code == 200
    body: dict[str, Any] = {"consent_version": payload["consent"]["version"], "accepted": True}
    standing = payload["consent"]["standing"]
    if standing is not None:
        body["relies_on_envelope_id"] = standing["envelope_id"]
    agreed = signer.post("/consent", body)
    assert agreed.status_code == 200, agreed.text
    assert signer.sign(payload, key=key).status_code == 200
    consent = next(e for e in ehr.audit(envelope["id"]) if e["event_type"] == "consent.accepted")
    return payload, consent


def test_a_patient_reads_the_disclosure_once_and_signs_three_forms(
    sitting_world: World, sitting_ehr: Ehr, clock: FixedClock
) -> None:
    with sitting_world.client:
        ehr = sitting_ehr
        # 1. The first form: the disclosure is displayed and agreed to, as it always is.
        first = ehr.create_envelope("hipaa_acknowledgement")
        agreed_at = clock.now()
        payload, consent = read_and_sign(ehr, first, key="s-1")
        assert payload["consent"]["standing"] is None
        assert consent["data"]["relied_on_envelope_id"] is None

        # 2 and 3. The rest of the forms: the notice is still there to re-read, but the agreement
        # already given stands, and each form records which one it stood on -- the most recent,
        # which is the previous form once there is one.
        stood_on, stood_at = str(first["id"]), agreed_at
        for index, minutes in enumerate((2, 5), start=2):
            clock.advance(timedelta(minutes=minutes))
            form = ehr.create_envelope("hipaa_acknowledgement")
            payload, consent = read_and_sign(ehr, form, key=f"s-{index}")
            standing = payload["consent"]["standing"]
            assert standing is not None
            assert standing["envelope_id"] == stood_on
            assert datetime.fromisoformat(standing["accepted_at"]).astimezone(UTC) == stood_at
            assert consent["data"]["relied_on_envelope_id"] == stood_on
            stood_on, stood_at = str(form["id"]), clock.now()
            # The acceptance is recorded on this form too: the signer is `consented` here.
            assert [s["status"] for s in ehr.envelope(form["id"])["signers"]] == ["signed"]
            # ...and the sealed copy says where the agreement came from.
            certificate = pdf_text(ehr.get(f"/envelopes/{form['id']}/document").content)
            assert "given for an earlier document in the same sitting" in certificate
            report = ehr.verification(form["id"])
            assert report["complete"] is True, (report["problems"],)

        # 4. Back in the afternoon: the sitting is over -- a second past the span, counted from
        # the most recent agreement -- and the notice is shown again.
        clock.advance(timedelta(seconds=SITTING_SECONDS + 1))
        later = ehr.create_envelope("hipaa_acknowledgement")
        signer = ehr.open_session(later, "patient")
        payload = signer.session()
        assert payload["consent"]["standing"] is None
        assert signer.get("/document").status_code == 200
        assert signer.post("/viewed", {"pages_viewed": payload["envelope"]["page_count"]}).status_code == 200
        refused = signer.post(
            "/consent",
            {
                "consent_version": payload["consent"]["version"],
                "accepted": True,
                "relies_on_envelope_id": str(first["id"]),
            },
        )
        assert refused.status_code == 409
        assert refused.json()["error"]["code"] == "consent_not_standing"
        assert (
            signer.post("/consent", {"consent_version": payload["consent"]["version"], "accepted": True}).status_code
            == 200
        )
