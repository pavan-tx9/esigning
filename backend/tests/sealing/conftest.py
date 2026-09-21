"""Fixtures for the sealing tests.

None of these need Postgres: ``Sealer`` is a pure bytes-in, bytes-out component. They do need a
PKI, and generating four RSA keys per test would dominate the run, so two hierarchies are built
once per session -- the real one, and an unrelated one used to prove that a seal from a foreign
CA is not trusted.
"""

from __future__ import annotations

import io
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import pytest
from reportlab.lib.pagesizes import LETTER
from reportlab.pdfgen import canvas

from esign.clock import FixedClock
from esign.config import SealKeyBackend, SealProfileName, Settings
from esign.contracts import Sealer
from esign.sealing import build_sealer, generate_dev_pki
from esign.sealing.dev_pki import DevPki
from tests.conftest import FROZEN_NOW

#: A name a sceptical reviewer would grep the logs for. Used by the PHI tests.
PATIENT_NAME = "Marguerite Okonkwo-Vasquez"


@dataclass(frozen=True)
class Pki:
    """A generated hierarchy plus the directory it lives in."""

    directory: Path
    trust_roots: Path
    pki: DevPki


def _build_pki(directory: Path) -> Pki:
    pki = generate_dev_pki(directory, FixedClock(FROZEN_NOW))
    return Pki(directory=directory, trust_roots=directory / "trust-roots.pem", pki=pki)


@pytest.fixture(scope="session")
def dev_pki(tmp_path_factory: pytest.TempPathFactory) -> Pki:
    """The hierarchy the sealer signs with and validates against."""
    return _build_pki(tmp_path_factory.mktemp("dev-pki"))


@pytest.fixture(scope="session")
def foreign_pki(tmp_path_factory: pytest.TempPathFactory) -> Pki:
    """A second, unrelated hierarchy. Its seals must never validate against the first."""
    return _build_pki(tmp_path_factory.mktemp("foreign-pki"))


@pytest.fixture
def clock() -> FixedClock:
    """A stopped clock, at the same instant the session PKIs were generated at."""
    return FixedClock(FROZEN_NOW)


def make_settings(
    pki: Pki | None = None,
    *,
    app_env: Literal["dev", "test", "prod"] = "test",
    seal_profile: SealProfileName = "PAdES-B-LT",
    seal_key_backend: SealKeyBackend = "local",
    tsa_url: str = "",
    tsa_timeout_seconds: float = 2.0,
    dev_pki_dir: Path | None = None,
    trust_roots_path: Path | None = None,
    seal_kms_key_id: str = "",
    seal_kms_endpoint_url: str | None = None,
    seal_cert_path: Path | None = None,
    seal_chain_path: Path | None = None,
) -> Settings:
    """Settings for a sealer. Defaults: local key backend, in-process TSA, this PKI's roots."""
    if dev_pki_dir is None:
        dev_pki_dir = pki.directory if pki else Path("/nonexistent-dev-pki")
    if trust_roots_path is None:
        trust_roots_path = pki.trust_roots if pki else Path("/nonexistent-dev-pki/trust-roots.pem")
    return Settings(
        app_env=app_env,
        seal_profile=seal_profile,
        seal_key_backend=seal_key_backend,
        tsa_url=tsa_url,
        tsa_timeout_seconds=tsa_timeout_seconds,
        dev_pki_dir=dev_pki_dir,
        trust_roots_path=trust_roots_path,
        seal_kms_key_id=seal_kms_key_id,
        seal_kms_endpoint_url=seal_kms_endpoint_url,
        seal_cert_path=seal_cert_path,
        seal_chain_path=seal_chain_path,
    )


@pytest.fixture
def settings(dev_pki: Pki) -> Settings:
    return make_settings(dev_pki)


@pytest.fixture
def sealer(settings: Settings, clock: FixedClock) -> Sealer:
    return build_sealer(settings, clock)


@pytest.fixture
def foreign_sealer(foreign_pki: Pki, clock: FixedClock) -> Sealer:
    """A sealer holding a key from the other hierarchy entirely."""
    return build_sealer(make_settings(foreign_pki), clock)


def make_pdf(*, pages: int = 1, text: str = "Certificate of completion") -> bytes:
    """A small, flat PDF with no form fields -- the shape the documents module produces."""
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=LETTER)
    for page in range(pages):
        pdf.drawString(72, 720, f"{text} (page {page + 1})")
        pdf.showPage()
    pdf.save()
    return buffer.getvalue()


@pytest.fixture
def pdf() -> bytes:
    return make_pdf()


@pytest.fixture
def pdf_factory() -> Callable[..., bytes]:
    return make_pdf
