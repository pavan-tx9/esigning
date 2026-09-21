"""A throwaway PKI for development and tests.

Production signs with a key held in KMS and a certificate issued by a real CA. Neither exists on
a laptop, and neither may ever be committed, so ``esign dev-pki`` generates a self-contained
hierarchy into a git-ignored directory:

``root-ca`` -> ``intermediate-ca`` -> ``seal`` (the document seal) and ``tsa`` (the timestamp
authority used by the in-process test TSA).

Both CAs also publish a CRL, so ``PAdES-B-LT`` -- which has to embed revocation information --
can be produced with no network at all. ``trust-roots.pem`` holds the root certificate alone: it
is the only thing ``Sealer.validate`` is ever allowed to trust.

Private keys are written ``0600`` into a ``0700`` directory, and the directory is in
``.gitignore``. Nothing here is a secret worth protecting -- that is exactly the point.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Final

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from esign.contracts import Clock

__all__ = [
    "DevPki",
    "DevPkiMissing",
    "dev_pki_paths",
    "generate_dev_pki",
    "issue_seal_certificate",
    "load_dev_pki",
]

#: RSA everywhere. The dummy timestamp authority pyHanko ships is RSA-only, and 2048 bits keeps
#: key generation fast enough that every test can afford its own PKI.
_KEY_BITS: Final = 2048

#: Dev certificates are short-lived on purpose: a stale ``.dev-pki`` should fail loudly.
_ROOT_YEARS: Final = 20
_INTERMEDIATE_YEARS: Final = 10
_LEAF_YEARS: Final = 5

#: Clock-skew allowance on ``not_valid_before``.
_BACKDATE: Final = timedelta(days=1)

#: How long a generated CRL claims to be current. Well beyond any test's clock movement.
_CRL_VALIDITY: Final = timedelta(days=365)

_FILE_NAMES: Final[dict[str, str]] = {
    "root_key": "root-ca.key.pem",
    "root_cert": "root-ca.cert.pem",
    "root_crl": "root-ca.crl.pem",
    "intermediate_key": "intermediate-ca.key.pem",
    "intermediate_cert": "intermediate-ca.cert.pem",
    "intermediate_crl": "intermediate-ca.crl.pem",
    "seal_key": "seal.key.pem",
    "seal_cert": "seal.cert.pem",
    "seal_chain": "seal-chain.pem",
    "tsa_key": "tsa.key.pem",
    "tsa_cert": "tsa.cert.pem",
    "trust_roots": "trust-roots.pem",
}

#: CRL distribution points. Never fetched -- ``validate`` runs with fetching disabled -- but real
#: certificates carry one, and their presence keeps the dev chain shaped like a production chain.
_ROOT_CRL_URL: Final = "http://pki.esign.invalid/root-ca.crl"
_INTERMEDIATE_CRL_URL: Final = "http://pki.esign.invalid/intermediate-ca.crl"


class DevPkiMissing(RuntimeError):
    """The dev PKI directory does not hold a usable hierarchy. Run ``esign dev-pki``."""


@dataclass(frozen=True)
class DevPki:
    """The generated hierarchy, loaded from disk."""

    directory: Path
    root_cert: x509.Certificate
    intermediate_cert: x509.Certificate
    #: The issuing key. Present so that ``esign dev-pki`` can mint further dev certificates --
    #: a certificate for a KMS-held public key, for instance -- without a second hierarchy.
    intermediate_key: RSAPrivateKey
    seal_cert: x509.Certificate
    seal_key: RSAPrivateKey
    tsa_cert: x509.Certificate
    tsa_key: RSAPrivateKey
    crls: tuple[bytes, ...]  # DER-encoded, root CRL then intermediate CRL

    @property
    def chain(self) -> tuple[x509.Certificate, ...]:
        """Intermediates between the seal certificate and the trust root, root included.

        The root is present so that a validator that insists on seeing it can build a path; it
        confers no trust, which comes from ``trust-roots.pem`` alone.
        """
        return (self.intermediate_cert, self.root_cert)


def dev_pki_paths(directory: Path) -> dict[str, Path]:
    """Every file ``generate_dev_pki`` writes, by role."""
    return {role: directory / name for role, name in _FILE_NAMES.items()}


# --------------------------------------------------------------------------- generation


def generate_dev_pki(directory: Path, clock: Clock, *, force: bool = False) -> DevPki:
    """Generate root CA, intermediate CA, seal certificate, TSA certificate and CRLs.

    Refuses to overwrite an existing PKI unless ``force`` is set: regenerating silently would
    invalidate every document sealed with the previous key, which is exactly the surprise this
    codebase exists to prevent.
    """
    paths = dev_pki_paths(directory)
    existing = [path for path in paths.values() if path.exists()]
    if existing and not force:
        raise FileExistsError(
            f"{directory} already holds a dev PKI ({len(existing)} files). "
            "Pass force=True to replace it; every document sealed with the old key stops validating."
        )

    now = _require_utc(clock.now())
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o700)

    root_key = _generate_key()
    root_cert = _self_signed_ca(root_key, now)

    intermediate_key = _generate_key()
    intermediate_cert = _issue_intermediate(intermediate_key.public_key(), root_key, root_cert, now)

    seal_key = _generate_key()
    seal_cert = _issue_leaf(
        seal_key.public_key(),
        intermediate_key,
        intermediate_cert,
        now,
        common_name="esign document seal (dev)",
        serial=0x5EA1,
        extended_key_usage=None,
    )

    tsa_key = _generate_key()
    tsa_cert = _issue_leaf(
        tsa_key.public_key(),
        intermediate_key,
        intermediate_cert,
        now,
        common_name="esign dev timestamp authority",
        serial=0x715A,
        extended_key_usage=[ExtendedKeyUsageOID.TIME_STAMPING],
    )

    root_crl = _empty_crl(root_cert, root_key, now)
    intermediate_crl = _empty_crl(intermediate_cert, intermediate_key, now)

    _write_public(paths["root_cert"], _pem_cert(root_cert))
    _write_public(paths["intermediate_cert"], _pem_cert(intermediate_cert))
    _write_public(paths["seal_cert"], _pem_cert(seal_cert))
    _write_public(paths["tsa_cert"], _pem_cert(tsa_cert))
    _write_public(paths["seal_chain"], _pem_cert(intermediate_cert) + _pem_cert(root_cert))
    _write_public(paths["trust_roots"], _pem_cert(root_cert))
    _write_public(paths["root_crl"], root_crl.public_bytes(serialization.Encoding.PEM))
    _write_public(paths["intermediate_crl"], intermediate_crl.public_bytes(serialization.Encoding.PEM))

    _write_private(paths["root_key"], _pem_key(root_key))
    _write_private(paths["intermediate_key"], _pem_key(intermediate_key))
    _write_private(paths["seal_key"], _pem_key(seal_key))
    _write_private(paths["tsa_key"], _pem_key(tsa_key))

    return load_dev_pki(directory)


def load_dev_pki(directory: Path) -> DevPki:
    """Read a previously generated hierarchy. Raises ``DevPkiMissing`` if anything is absent."""
    paths = dev_pki_paths(directory)
    missing = sorted(name for role, name in _FILE_NAMES.items() if not paths[role].exists())
    if missing:
        raise DevPkiMissing(f"{directory} is missing {', '.join(missing)}; run `esign dev-pki`")

    return DevPki(
        directory=directory,
        root_cert=x509.load_pem_x509_certificate(paths["root_cert"].read_bytes()),
        intermediate_cert=x509.load_pem_x509_certificate(paths["intermediate_cert"].read_bytes()),
        intermediate_key=_load_rsa_key(paths["intermediate_key"]),
        seal_cert=x509.load_pem_x509_certificate(paths["seal_cert"].read_bytes()),
        seal_key=_load_rsa_key(paths["seal_key"]),
        tsa_cert=x509.load_pem_x509_certificate(paths["tsa_cert"].read_bytes()),
        tsa_key=_load_rsa_key(paths["tsa_key"]),
        crls=(
            x509.load_pem_x509_crl(paths["root_crl"].read_bytes()).public_bytes(serialization.Encoding.DER),
            x509.load_pem_x509_crl(paths["intermediate_crl"].read_bytes()).public_bytes(serialization.Encoding.DER),
        ),
    )


# --------------------------------------------------------------------------- certificate builders


def _generate_key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=_KEY_BITS)


def _name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "esign development"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _self_signed_ca(key: RSAPrivateKey, now: datetime) -> x509.Certificate:
    subject = _name("esign dev root CA")
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(0x0001)
        .not_valid_before(now - _BACKDATE)
        .not_valid_after(now + timedelta(days=365 * _ROOT_YEARS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(_ca_key_usage(), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )


def _issue_intermediate(
    public_key: rsa.RSAPublicKey,
    issuer_key: RSAPrivateKey,
    issuer_cert: x509.Certificate,
    now: datetime,
) -> x509.Certificate:
    return (
        x509.CertificateBuilder()
        .subject_name(_name("esign dev intermediate CA"))
        .issuer_name(issuer_cert.subject)
        .public_key(public_key)
        .serial_number(0x0002)
        .not_valid_before(now - _BACKDATE)
        .not_valid_after(now + timedelta(days=365 * _INTERMEDIATE_YEARS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_ca_key_usage(), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()),  # type: ignore[arg-type]
            critical=False,
        )
        .add_extension(_crl_distribution_points(_ROOT_CRL_URL), critical=False)
        .sign(issuer_key, hashes.SHA256())
    )


def issue_seal_certificate(
    pki: DevPki,
    public_key: CertificatePublicKeyTypes,
    clock: Clock,
    *,
    common_name: str = "esign document seal (dev, external key)",
    serial: int = 0x5EA2,
) -> x509.Certificate:
    """Issue a seal certificate for a key this process does not hold.

    The ``aws_kms`` backend needs a certificate whose public key matches a key inside KMS. In
    development -- and in the KMS tests -- the dev intermediate CA issues it, so the result chains
    to the same ``trust-roots.pem`` as everything else.
    """
    return _issue_leaf(
        public_key,
        pki.intermediate_key,
        pki.intermediate_cert,
        _require_utc(clock.now()),
        common_name=common_name,
        serial=serial,
        extended_key_usage=None,
    )


def _issue_leaf(
    public_key: CertificatePublicKeyTypes,
    issuer_key: RSAPrivateKey,
    issuer_cert: x509.Certificate,
    now: datetime,
    *,
    common_name: str,
    serial: int,
    extended_key_usage: list[x509.ObjectIdentifier] | None,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(issuer_cert.subject)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(now - _BACKDATE)
        .not_valid_after(now + timedelta(days=365 * _LEAF_YEARS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            # non_repudiation is what pyHanko requires of a document signer by default.
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()),  # type: ignore[arg-type]
            critical=False,
        )
        .add_extension(_crl_distribution_points(_INTERMEDIATE_CRL_URL), critical=False)
    )
    if extended_key_usage:
        # RFC 3161 requires the timestamping EKU to be present and critical, and to stand alone.
        builder = builder.add_extension(x509.ExtendedKeyUsage(extended_key_usage), critical=True)
    return builder.sign(issuer_key, hashes.SHA256())


def _ca_key_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )


def _crl_distribution_points(url: str) -> x509.CRLDistributionPoints:
    return x509.CRLDistributionPoints(
        [
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(url)],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
        ]
    )


def _empty_crl(
    issuer_cert: x509.Certificate, issuer_key: RSAPrivateKey, now: datetime
) -> x509.CertificateRevocationList:
    """A CRL revoking nothing. Its value is that it exists: B-LT needs revocation data offline."""
    return (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_cert.subject)
        .last_update(now - _BACKDATE)
        .next_update(now + _CRL_VALIDITY)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()),  # type: ignore[arg-type]
            critical=False,
        )
        .add_extension(x509.CRLNumber(1), critical=False)
        .sign(issuer_key, hashes.SHA256())
    )


# --------------------------------------------------------------------------- file helpers


def _pem_cert(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _pem_key(key: RSAPrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _write_public(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    path.chmod(0o644)


def _write_private(path: Path, data: bytes) -> None:
    """Create the file with 0600 already set, rather than widening then narrowing it."""
    path.unlink(missing_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def _load_rsa_key(path: Path) -> RSAPrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, RSAPrivateKey):
        raise DevPkiMissing(f"{path} is not an RSA private key")
    return key


def _require_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("Clock returned a naive datetime; all times in this system are UTC-aware")
    return value
