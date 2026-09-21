"""The KMS key backend.

In production the private key never leaves KMS; the service holds only a certificate. These
tests stand a KMS up with ``moto``, mint a certificate for the key it generated, and then put the
same seal through the same code path -- including the failure path, because a KMS that cannot be
reached must never produce anything but ``SealUnavailable``.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path
from uuid import uuid4

import boto3
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_der_public_key
from moto import mock_aws
from mypy_boto3_kms.literals import KeySpecType

from esign.clock import FixedClock
from esign.config import SealProfileName, Settings
from esign.contracts import SealUnavailable
from esign.sealing import build_sealer, issue_seal_certificate
from tests.conftest import FROZEN_NOW
from tests.sealing.conftest import Pki, make_pdf, make_settings


@pytest.fixture(autouse=True)
def aws_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """moto refuses to run against real credentials; make sure there are none."""
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SECURITY_TOKEN", "AWS_SESSION_TOKEN"):
        monkeypatch.setenv(name, "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture
def aws() -> Iterator[None]:
    with mock_aws():
        yield


def write_chain(directory: Path, pki: Pki, cert_pem: bytes) -> tuple[Path, Path]:
    cert_path = directory / "seal.cert.pem"
    chain_path = directory / "seal-chain.pem"
    cert_path.write_bytes(cert_pem)
    chain_path.write_bytes(b"".join(cert.public_bytes(serialization.Encoding.PEM) for cert in pki.pki.chain))
    return cert_path, chain_path


def provision_key(
    dev_pki: Pki,
    tmp_path: Path,
    *,
    key_spec: KeySpecType,
    profile: SealProfileName = "PAdES-B-T",
) -> Settings:
    """Create a KMS key, issue it a certificate from the dev CA, and point settings at both."""
    client = boto3.client("kms", region_name="us-east-1")
    key_id = client.create_key(KeyUsage="SIGN_VERIFY", KeySpec=key_spec)["KeyMetadata"]["KeyId"]
    public_key = load_der_public_key(client.get_public_key(KeyId=key_id)["PublicKey"])
    assert isinstance(public_key, RSAPublicKey | EllipticCurvePublicKey)
    certificate = issue_seal_certificate(dev_pki.pki, public_key, FixedClock(FROZEN_NOW))
    cert_path, chain_path = write_chain(tmp_path, dev_pki, certificate.public_bytes(serialization.Encoding.PEM))

    return make_settings(
        dev_pki,
        seal_key_backend="aws_kms",
        seal_profile=profile,
        seal_kms_key_id=key_id,
        seal_cert_path=cert_path,
        seal_chain_path=chain_path,
    )


@pytest.mark.parametrize("key_spec", ["RSA_2048", "ECC_NIST_P256"])
def test_seals_with_a_key_held_in_kms(aws: None, dev_pki: Pki, tmp_path: Path, key_spec: KeySpecType) -> None:
    settings = provision_key(dev_pki, tmp_path, key_spec=key_spec)
    sealer = build_sealer(settings, FixedClock(FROZEN_NOW))

    result = sealer.seal(make_pdf(), reason="Envelope completed", envelope_id=uuid4())

    report = sealer.validate(result.sealed_pdf)
    assert report.problems == ()
    assert report.ok is True
    assert report.signer_cert_sha256 == result.signer_cert_sha256


def test_signing_happens_exactly_once_per_seal(
    aws: None, dev_pki: Pki, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """pyHanko asks for a dry run to size the container; that must not become a KMS call."""
    from esign.sealing import kms

    calls: list[str] = []
    original: Callable[..., bytes] = kms.KmsSigner._sign

    def counting(self: kms.KmsSigner, message: bytes, message_type: str) -> bytes:
        calls.append(message_type)
        return original(self, message, message_type)

    monkeypatch.setattr(kms.KmsSigner, "_sign", counting)

    settings = provision_key(dev_pki, tmp_path, key_spec="RSA_2048")
    build_sealer(settings, FixedClock(FROZEN_NOW)).seal(make_pdf(), reason="done", envelope_id=uuid4())

    assert calls == ["RAW"]


def test_an_unreachable_kms_is_seal_unavailable(dev_pki: Pki, tmp_path: Path) -> None:
    """No KMS means no seal. It does not mean a document that claims to be complete."""
    with mock_aws():
        settings = provision_key(dev_pki, tmp_path, key_spec="RSA_2048")

    # Outside the mock, and pointed at a port nothing is listening on.
    offline = make_settings(
        dev_pki,
        seal_key_backend="aws_kms",
        seal_profile="PAdES-B-T",
        seal_kms_key_id=settings.seal_kms_key_id,
        seal_kms_endpoint_url="http://127.0.0.1:9",
        seal_cert_path=settings.seal_cert_path,
        seal_chain_path=settings.seal_chain_path,
    )
    sealer = build_sealer(offline, FixedClock(FROZEN_NOW))
    with pytest.raises(SealUnavailable):
        sealer.seal(make_pdf(), reason="Envelope completed", envelope_id=uuid4())


def test_a_key_kms_will_not_sign_with_is_seal_unavailable(aws: None, dev_pki: Pki, tmp_path: Path) -> None:
    """An error from KMS -- missing key, denied, throttled -- is never a reason to skip the seal."""
    settings = provision_key(dev_pki, tmp_path, key_spec="RSA_2048")
    unknown = make_settings(
        dev_pki,
        seal_key_backend="aws_kms",
        seal_profile="PAdES-B-T",
        seal_kms_key_id="00000000-0000-4000-8000-000000000000",
        seal_cert_path=settings.seal_cert_path,
        seal_chain_path=settings.seal_chain_path,
    )
    sealer = build_sealer(unknown, FixedClock(FROZEN_NOW))
    with pytest.raises(SealUnavailable):
        sealer.seal(make_pdf(), reason="Envelope completed", envelope_id=uuid4())


def test_an_unsupported_key_algorithm_is_refused(dev_pki: Pki, tmp_path: Path) -> None:
    """Only RSA PKCS#1 v1.5 SHA-256 and ECDSA P-256 are supported; nothing is approximated."""
    key = ed25519.Ed25519PrivateKey.generate()
    certificate = issue_seal_certificate(dev_pki.pki, key.public_key(), FixedClock(FROZEN_NOW))
    cert_path, chain_path = write_chain(tmp_path, dev_pki, certificate.public_bytes(serialization.Encoding.PEM))
    settings = make_settings(
        dev_pki,
        seal_key_backend="aws_kms",
        seal_profile="PAdES-B-T",
        seal_kms_key_id="does-not-matter",
        seal_cert_path=cert_path,
        seal_chain_path=chain_path,
    )
    sealer = build_sealer(settings, FixedClock(FROZEN_NOW))
    with pytest.raises(SealUnavailable) as caught:
        sealer.seal(make_pdf(), reason="Envelope completed", envelope_id=uuid4())
    assert caught.value.code == "seal_key_unavailable"


def test_missing_kms_configuration_is_refused(dev_pki: Pki, tmp_path: Path) -> None:
    for key_id, cert_path in (("", tmp_path / "seal.cert.pem"), ("abc", None)):
        settings = make_settings(dev_pki, seal_key_backend="aws_kms", seal_kms_key_id=key_id, seal_cert_path=cert_path)
        sealer = build_sealer(settings, FixedClock(FROZEN_NOW))
        with pytest.raises(SealUnavailable) as caught:
            sealer.seal(make_pdf(), reason="Envelope completed", envelope_id=uuid4())
        assert caught.value.code == "seal_key_unavailable"


@pytest.mark.slow
def test_long_term_profile_without_reachable_revocation_data_refuses_to_seal(
    aws: None, dev_pki: Pki, tmp_path: Path
) -> None:
    """A B-LT seal that could not gather revocation data is not a B-T seal. It is no seal."""
    settings = provision_key(dev_pki, tmp_path, key_spec="RSA_2048", profile="PAdES-B-LT")
    sealer = build_sealer(settings, FixedClock(FROZEN_NOW))
    with pytest.raises(SealUnavailable):
        sealer.seal(make_pdf(), reason="Envelope completed", envelope_id=uuid4())
