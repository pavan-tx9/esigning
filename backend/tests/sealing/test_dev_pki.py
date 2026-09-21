"""The development PKI: shape, permissions, and refusal to destroy itself."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from esign.clock import FixedClock
from esign.sealing import DevPkiMissing, dev_pki_paths, generate_dev_pki, issue_seal_certificate, load_dev_pki
from tests.conftest import FROZEN_NOW
from tests.sealing.conftest import Pki


def test_generates_every_file(dev_pki: Pki) -> None:
    for role, path in dev_pki_paths(dev_pki.directory).items():
        assert path.exists(), role


def test_private_keys_are_not_world_readable(dev_pki: Pki) -> None:
    paths = dev_pki_paths(dev_pki.directory)
    for role in ("root_key", "intermediate_key", "seal_key", "tsa_key"):
        mode = paths[role].stat().st_mode & 0o777
        assert mode == 0o600, f"{role} is {oct(mode)}"
    assert dev_pki.directory.stat().st_mode & 0o777 == 0o700


def test_trust_roots_hold_the_root_and_nothing_else(dev_pki: Pki) -> None:
    """The intermediate and the seal certificate must not be trust anchors."""
    roots = x509.load_pem_x509_certificates(dev_pki.trust_roots.read_bytes())
    assert len(roots) == 1
    assert roots[0].subject == dev_pki.pki.root_cert.subject
    assert roots[0].fingerprint(hashes.SHA256()) == dev_pki.pki.root_cert.fingerprint(hashes.SHA256())


def test_chain_actually_chains(dev_pki: Pki) -> None:
    pki = dev_pki.pki
    _assert_issued_by(pki.intermediate_cert, pki.root_cert)
    _assert_issued_by(pki.seal_cert, pki.intermediate_cert)
    _assert_issued_by(pki.tsa_cert, pki.intermediate_cert)


def test_seal_certificate_can_be_used_for_non_repudiation(dev_pki: Pki) -> None:
    usage = dev_pki.pki.seal_cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert usage.content_commitment is True
    assert usage.digital_signature is True
    assert usage.key_cert_sign is False
    basic = dev_pki.pki.seal_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert basic.ca is False


def test_tsa_certificate_is_marked_for_timestamping(dev_pki: Pki) -> None:
    extension = dev_pki.pki.tsa_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert list(extension.value) == [ExtendedKeyUsageOID.TIME_STAMPING]
    assert extension.critical is True


def test_certificate_authorities_are_constrained(dev_pki: Pki) -> None:
    root = dev_pki.pki.root_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    intermediate = dev_pki.pki.intermediate_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert root.ca and root.path_length == 1
    assert intermediate.ca and intermediate.path_length == 0


def test_crls_are_current_at_the_clock(dev_pki: Pki) -> None:
    """B-LT needs revocation data offline, so both CAs publish a CRL that is valid now."""
    assert len(dev_pki.pki.crls) == 2
    for der in dev_pki.pki.crls:
        crl = x509.load_der_x509_crl(der)
        assert crl.next_update_utc is not None
        assert crl.last_update_utc <= FROZEN_NOW <= crl.next_update_utc
        assert len(list(crl)) == 0


def test_certificates_are_valid_at_the_clock(dev_pki: Pki) -> None:
    for cert in (dev_pki.pki.root_cert, dev_pki.pki.intermediate_cert, dev_pki.pki.seal_cert, dev_pki.pki.tsa_cert):
        assert cert.not_valid_before_utc <= FROZEN_NOW <= cert.not_valid_after_utc


def test_refuses_to_overwrite_an_existing_pki(tmp_path: Path) -> None:
    """Regenerating in place would invalidate every document already sealed with the old key."""
    clock = FixedClock(FROZEN_NOW)
    first = generate_dev_pki(tmp_path / "pki", clock)
    with pytest.raises(FileExistsError):
        generate_dev_pki(tmp_path / "pki", clock)
    assert load_dev_pki(tmp_path / "pki").seal_cert.fingerprint(hashes.SHA256()) == first.seal_cert.fingerprint(
        hashes.SHA256()
    )


def test_force_replaces_the_pki(tmp_path: Path) -> None:
    clock = FixedClock(FROZEN_NOW)
    first = generate_dev_pki(tmp_path / "pki", clock)
    second = generate_dev_pki(tmp_path / "pki", clock, force=True)
    assert first.seal_cert.fingerprint(hashes.SHA256()) != second.seal_cert.fingerprint(hashes.SHA256())
    assert dev_pki_paths(tmp_path / "pki")["seal_key"].stat().st_mode & 0o777 == 0o600


def test_loading_an_incomplete_pki_says_what_is_missing(tmp_path: Path) -> None:
    generate_dev_pki(tmp_path / "pki", FixedClock(FROZEN_NOW))
    dev_pki_paths(tmp_path / "pki")["seal_key"].unlink()
    with pytest.raises(DevPkiMissing, match=r"seal\.key\.pem"):
        load_dev_pki(tmp_path / "pki")


def test_loading_an_absent_pki_raises(tmp_path: Path) -> None:
    with pytest.raises(DevPkiMissing):
        load_dev_pki(tmp_path / "never-generated")


def test_generation_uses_the_injected_clock_not_the_wall_clock(tmp_path: Path) -> None:
    """Certificate validity is evidence too: it must be reproducible from the clock."""
    past = datetime(2021, 6, 1, 12, tzinfo=UTC)
    pki = generate_dev_pki(tmp_path / "pki", FixedClock(past))
    assert pki.seal_cert.not_valid_before_utc == past - timedelta(days=1)
    assert pki.seal_cert.not_valid_after_utc == past + timedelta(days=365 * 5)


def test_issue_seal_certificate_chains_to_the_same_root(dev_pki: Pki) -> None:
    """The KMS backend needs a certificate for a key this process does not hold."""
    external = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = issue_seal_certificate(dev_pki.pki, external.public_key(), FixedClock(FROZEN_NOW))
    _assert_issued_by(cert, dev_pki.pki.intermediate_cert)
    issued = cert.public_key()
    assert isinstance(issued, rsa.RSAPublicKey)
    assert issued.public_numbers() == external.public_key().public_numbers()


def _assert_issued_by(subject: x509.Certificate, issuer: x509.Certificate) -> None:
    assert subject.issuer == issuer.subject
    public_key = issuer.public_key()
    assert isinstance(public_key, rsa.RSAPublicKey)
    public_key.verify(
        subject.signature,
        subject.tbs_certificate_bytes,
        padding.PKCS1v15(),
        subject.signature_hash_algorithm,  # type: ignore[arg-type]
    )
