"""Fixtures for standing consent (Addendum 3 C, SPEC sections 8, 9 and 16 C).

Two levels, because the feature has two halves that can be wrong independently:

* ``standing`` -- the envelope service over real rows, for the rule itself: whose acceptance may
  stand for another document, of which disclosure, for how long, and from which session.
* ``sitting`` -- the whole stack over HTTP (``tests.e2e.conftest``'s world), for what a person
  signing two documents in one go actually gets: the session payload, the audit data, the
  certificate and the verification report.

The span is configuration, so every fixture here says which span it runs with. Nothing defaults to
"on": a test that does not ask for a span is testing the shipped behaviour, which is consent
collected once per envelope.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx
import pytest
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from esign.clock import FixedClock
from esign.config import Settings
from esign.contracts import EnvelopeView, Host, KioskContext, NewSigner, SessionInfo
from esign.sealing import generate_dev_pki
from tests.conftest import FROZEN_NOW
from tests.e2e.conftest import Ehr, Sessions, Signer, World, build_world
from tests.envelopes.conftest import CONSENT_VERSION, CTX, PAGES, PATIENT_CONSENT, Bench

#: What a clinic's sitting looks like: long enough for a queue of forms at one desk, far short of
#: the one-hour cap. Nothing in the code knows this number; it is the tests' own choice.
SITTING_SECONDS = 900

#: The patient every test means when it says "the same person".
PATIENT = "pt-100482"
#: ...and somebody else at the same practice.
SOMEBODY_ELSE = "pt-993317"


# --------------------------------------------------------------------------- service level


#: The envelope service with the consent span set to a given number of seconds.
Standing = Callable[[int], Bench]


@pytest.fixture
def standing(settings: Settings, clock: FixedClock, blob_dir: Path) -> Standing:
    """A bench whose consent span is whatever the test says it is.

    A factory rather than a fixture with a fixed value: "off" and "on" are two configurations of
    one piece of code, and each test has to be able to name the one it means.
    """

    def build(span_seconds: int) -> Bench:
        return Bench(settings.model_copy(update={"consent_span_seconds": span_seconds}), clock, blob_dir)

    return build


def patient(host_user_id: str) -> tuple[NewSigner, ...]:
    """One patient signer, identified as a named user of the host."""
    return (
        NewSigner(
            role_key="patient",
            host_user_id=host_user_id,
            display_name="Patient Person",
            capacity="self",
        ),
    )


@dataclass(frozen=True)
class Document:
    """One envelope, one signer, one session: what a person is looking at right now."""

    envelope: EnvelopeView
    signer_id: UUID
    session: SessionInfo


def open_document(
    bench: Bench,
    db: Session,
    host: Host,
    *,
    host_user_id: str = PATIENT,
    kiosk: KioskContext | None = None,
) -> Document:
    """A fresh patient consent for this person, presented and read but not yet agreed to."""
    view = bench.create(db, host, PATIENT_CONSENT, signers=patient(host_user_id))
    signer_id = bench.signer_id(view, "patient")
    session = bench.session(db, signer_id, method="staff_verified" if kiosk else "password", kiosk=kiosk)
    bench.service.present(db, session, CTX)
    bench.service.record_viewed(db, session, PAGES, CTX)
    return Document(envelope=view, signer_id=signer_id, session=session)


def already_agreed(
    bench: Bench,
    db: Session,
    host: Host,
    *,
    host_user_id: str = PATIENT,
    kiosk: KioskContext | None = None,
) -> Document:
    """...and the same, agreed to: the first document of the sitting."""
    document = open_document(bench, db, host, host_user_id=host_user_id, kiosk=kiosk)
    bench.service.accept_consent(db, document.session, CONSENT_VERSION, CTX)
    return document


def practice(bench: Bench, db: Session, name: str = "Test EHR") -> Host:
    """A host with the patient consent template published and the disclosure seeded."""
    host = bench.host(db, name)
    bench.template(db, host, PATIENT_CONSENT)
    return host


# --------------------------------------------------------------------------- HTTP level


@pytest.fixture(scope="session")
def sitting_pki(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One development PKI for the whole run; generating RSA keys per test would dominate it."""
    directory = tmp_path_factory.mktemp("sitting-dev-pki")
    generate_dev_pki(directory, FixedClock(FROZEN_NOW))
    return directory


@pytest.fixture
def sitting_settings(settings: Settings, sitting_pki: Path, tmp_path: Path) -> Settings:
    """``tests.e2e.conftest``'s settings, without a consent span: each test names its own."""
    return settings.model_copy(
        update={
            "dev_pki_dir": sitting_pki,
            "trust_roots_path": sitting_pki / "trust-roots.pem",
            "seal_profile": "PAdES-B-LT",
            "seal_key_backend": "local",
            "tsa_url": "",  # the in-process authority from the dev PKI
            "frontend_dist_dir": tmp_path / "no-ui-built",
            "log_level": "INFO",
        }
    )


@dataclass
class Sitting:
    """A practice whose patients sign more than one form at a time, and the world it lives in."""

    world: World
    ehr: Ehr

    def form(self, *, host_user_id: str = PATIENT, ehr: Ehr | None = None) -> dict[str, Any]:
        """A patient consent for one named patient: the shape of every document in a sitting."""
        host = ehr or self.ehr
        body = host.envelope_body("patient_consent")
        for signer in body["signers"]:
            signer["host_user_id"] = host_user_id
        response = host.post("/envelopes", body)
        assert response.status_code == 201, response.text
        created: dict[str, Any] = response.json()
        return created

    def consent_block(self, signer: Signer) -> dict[str, Any]:
        block: dict[str, Any] = signer.session()["consent"]
        return block

    def signers_row(self, envelope_id: str) -> Any:
        """The ``signers`` row as the database holds it -- what the certificate cross-checks."""
        with self.world.rt.transaction() as db:
            return db.execute(
                text("SELECT status, consent_text_id, consented_at FROM signers WHERE envelope_id = :id"),
                {"id": envelope_id},
            ).one()

    def consent_events(self, envelope_id: str) -> list[dict[str, Any]]:
        return [e for e in self.ehr.audit(envelope_id) if e["event_type"] == "consent.accepted"]


#: Build the whole stack with the consent span set to a given number of seconds.
SittingFactory = Callable[[int], Sitting]


@pytest.fixture
def sitting(
    sitting_settings: Settings, clock: FixedClock, app_engine: Engine, db_factory: Sessions
) -> Iterator[SittingFactory]:
    stack = ExitStack()

    def build(span_seconds: int) -> Sitting:
        settings = sitting_settings.model_copy(update={"consent_span_seconds": span_seconds})
        world = build_world(settings, clock, app_engine, db_factory)
        stack.enter_context(world.client)
        ehr = world.host()
        ehr.publish_template("patient_consent")
        return Sitting(world=world, ehr=ehr)

    with stack:
        yield build


def review(signer: Signer) -> dict[str, Any]:
    """Everything the UI does before the consent block: fetch, display every page.

    Deliberately not ``Signer.review_and_consent``: what happens at the consent step is this
    suite's whole subject, so it is spelled out in every test rather than hidden in a helper.
    """
    payload = signer.session()
    assert signer.get("/document").status_code == 200
    viewed = signer.post("/viewed", {"pages_viewed": payload["envelope"]["page_count"]})
    assert viewed.status_code == 200, viewed.text
    return payload


def agree(
    signer: Signer, payload: dict[str, Any], *, relies_on: str | None = None, version: str | None = None
) -> httpx.Response:
    """``POST /signing/consent``, with or without the standing acceptance it relies on."""
    body: dict[str, Any] = {"consent_version": version or payload["consent"]["version"], "accepted": True}
    if relies_on is not None:
        body["relies_on_envelope_id"] = relies_on
    response: httpx.Response = signer.post("/consent", body)
    return response
