"""Fixtures for the re-authentication span (Addendum 1 C, SPEC sections 8, 9 and 14 C).

Two levels, because the feature has two halves that can be wrong independently:

* ``identity`` / ``spanning`` -- ``SqlIdentityService`` over real rows, for the resolution order
  itself: whose attestation may be borrowed, for how long, and by which session.
* ``queue`` -- the whole stack over HTTP (``tests.e2e.conftest``'s world), for what a clinician
  signing several documents in a row actually gets: the session payload, the audit data, the
  certificate and the verification report.

The span is configuration, so every fixture here says which span it runs with. Nothing defaults to
"on": a test that does not ask for a span is testing the shipped behaviour.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from esign.clock import FixedClock
from esign.config import Settings
from esign.contracts import AuthContext, Host, RequestContext
from esign.identity import SqlIdentityService
from esign.sealing import generate_dev_pki
from tests.conftest import FROZEN_NOW
from tests.e2e.conftest import Ehr, Sessions, World, build_world
from tests.identity.factories import make_signer

#: What the demo runs with: long enough for a queue of documents, far short of the 900 second cap.
DEMO_SPAN_SECONDS = 300

CTX = RequestContext(ip="203.0.113.9", user_agent="test-agent")


# --------------------------------------------------------------------------- identity level


@dataclass(frozen=True)
class Clinician:
    """One user of one host, with a signer row of their own on an envelope of their own.

    The span is keyed on ``(host_id, host_user_id)``, so every test here needs to be able to say
    "the same person, a different document" and "a different person, the same host" without the
    two being confusable.
    """

    host_id: UUID
    host_user_id: str
    envelope_id: UUID
    signer_id: UUID

    @property
    def host(self) -> Host:
        return Host(id=self.host_id, name="Test EHR", allowed_origins=())


def make_clinician(db: Session, clock: FixedClock, *, host_user_id: str, host_id: UUID | None = None) -> Clinician:
    """A re-authenticating signer on a fresh envelope, for a named user of a named host.

    Built on the identity module's own factories rather than a second copy of the row chain; only
    ``host_user_id`` is set afterwards, because that is the column this feature turns on and the
    factory generates a unique one per signer.
    """
    fixture = make_signer(db, clock, host_id=host_id, requires_reauth=True, role_key="clinician")
    db.execute(
        text("UPDATE signers SET host_user_id = :user WHERE id = :id"),
        {"user": host_user_id, "id": fixture.signer_id},
    )
    return Clinician(
        host_id=fixture.host_id,
        host_user_id=host_user_id,
        envelope_id=fixture.envelope_id,
        signer_id=fixture.signer_id,
    )


#: The identity service with the span set to a given number of seconds.
Spanning = Callable[[int], SqlIdentityService]


@pytest.fixture
def identity(settings: Settings, clock: FixedClock) -> SqlIdentityService:
    """The shipped configuration: ``REAUTH_SPAN_SECONDS`` is zero and nothing is ever borrowed."""
    return SqlIdentityService(settings, clock)


@pytest.fixture
def spanning(settings: Settings, clock: FixedClock) -> Spanning:
    def build(span_seconds: int) -> SqlIdentityService:
        return SqlIdentityService(settings.model_copy(update={"reauth_span_seconds": span_seconds}), clock)

    return build


def open_session(identity: SqlIdentityService, db: Session, clinician: Clinician, clock: FixedClock) -> UUID:
    _, info = identity.create_session(
        db,
        signer_id=clinician.signer_id,
        auth=AuthContext(method="password+mfa", auth_time=clock.now()),
        kiosk=None,
        ctx=CTX,
    )
    return info.id


def attest(
    identity: SqlIdentityService, db: Session, clinician: Clinician, session_id: UUID, clock: FixedClock
) -> None:
    identity.attest_reauth(
        db, host=clinician.host, session_id=session_id, auth=AuthContext("password+mfa", clock.now())
    )


# --------------------------------------------------------------------------- HTTP level


@pytest.fixture(scope="session")
def span_pki(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One development PKI for the whole run; generating RSA keys per test would dominate it."""
    directory = tmp_path_factory.mktemp("span-dev-pki")
    generate_dev_pki(directory, FixedClock(FROZEN_NOW))
    return directory


@pytest.fixture
def span_settings(settings: Settings, span_pki: Path, tmp_path: Path) -> Settings:
    """``tests.e2e.conftest``'s settings, without its span: each test names its own."""
    return settings.model_copy(
        update={
            "dev_pki_dir": span_pki,
            "trust_roots_path": span_pki / "trust-roots.pem",
            "seal_profile": "PAdES-B-LT",
            "seal_key_backend": "local",
            "tsa_url": "",  # the in-process authority from the dev PKI
            "frontend_dist_dir": tmp_path / "no-ui-built",
            "log_level": "INFO",
        }
    )


@dataclass
class Queue:
    """A host that files procedure consents, and the world it lives in."""

    world: World
    ehr: Ehr

    def attestation_ids(self) -> list[UUID]:
        with self.world.rt.transaction() as db:
            return [
                row.id for row in db.execute(text("SELECT id FROM reauth_attestations ORDER BY attested_at, id")).all()
            ]


#: Build the whole stack with the span set to a given number of seconds.
QueueFactory = Callable[[int], Queue]


@pytest.fixture
def queue(
    span_settings: Settings, clock: FixedClock, app_engine: Engine, db_factory: Sessions
) -> Iterator[QueueFactory]:
    """Build the whole stack with the span set to a given number of seconds.

    A factory rather than a fixture with a fixed value: "off", "on" and "on, but longer than the
    maximum age" are three different configurations of the same code, and each test has to be able
    to name the one it means.
    """
    stack = ExitStack()

    def build(span_seconds: int) -> Queue:
        settings = span_settings.model_copy(update={"reauth_span_seconds": span_seconds})
        world = build_world(settings, clock, app_engine, db_factory)
        stack.enter_context(world.client)
        ehr = world.host()
        ehr.publish_template("procedure_consent")
        return Queue(world=world, ehr=ehr)

    with stack:
        yield build
