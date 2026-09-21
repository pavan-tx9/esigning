"""Where the signing key lives, behind one interface.

Two backends, chosen by ``SEAL_KEY_BACKEND``:

``local``     the dev PKI on disk (``esign dev-pki``). Development and tests only.
``aws_kms``   a key held in KMS that never leaves it; the certificate chain comes from PEM files.

Both hand back a :class:`SigningMaterial`, which is a pyHanko ``Signer`` plus the certificates a
validator will need to build a path. No private key material is ever read for the KMS backend, and
none of it is ever logged.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from asn1crypto import keys as asn1_keys  # type: ignore[import-untyped]
from asn1crypto import x509 as asn1_x509
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from pyhanko.sign import signers
from pyhanko_certvalidator.registry import SimpleCertificateStore

from esign.config import Settings
from esign.contracts import SealUnavailable

from .dev_pki import DevPki, DevPkiMissing, load_dev_pki
from .kms import KmsSigner, kms_client

__all__ = [
    "SigningMaterial",
    "cert_sha256",
    "load_signing_material",
    "load_trust_roots",
    "to_asn1_cert",
    "to_asn1_key",
]


@dataclass(frozen=True)
class SigningMaterial:
    """Everything needed to produce one seal, and nothing else."""

    signer: signers.Signer
    signing_cert: asn1_x509.Certificate
    chain: tuple[asn1_x509.Certificate, ...]
    backend: str
    #: Present for the ``local`` backend only: the in-process TSA needs the dev PKI's TSA key.
    dev_pki: DevPki | None = None

    @property
    def signing_cert_sha256(self) -> bytes:
        return cert_sha256(self.signing_cert)


def load_signing_material(settings: Settings) -> SigningMaterial:
    """Resolve the configured key backend, or raise ``SealUnavailable``.

    Missing or unreadable key material is an infrastructure failure, not a signing failure: the
    envelope stays ``completed_pending_seal`` and the job retries once an operator has fixed it.
    Falling back to some other key, or to no seal at all, is never an option.
    """
    if settings.seal_key_backend == "local":
        return _local_material(settings)
    return _kms_material(settings)


# --------------------------------------------------------------------------- local (dev PKI)


def _local_material(settings: Settings) -> SigningMaterial:
    try:
        pki = load_dev_pki(settings.dev_pki_dir)
    except DevPkiMissing as exc:
        raise SealUnavailable(str(exc), code="seal_key_unavailable") from exc
    except (OSError, ValueError) as exc:
        raise SealUnavailable("dev PKI could not be read", code="seal_key_unavailable") from exc

    chain = tuple(to_asn1_cert(cert) for cert in pki.chain)
    registry = SimpleCertificateStore()  # type: ignore[no-untyped-call]
    registry.register_multiple(chain)
    signer = signers.SimpleSigner(
        signing_cert=to_asn1_cert(pki.seal_cert),
        signing_key=to_asn1_key(pki.seal_key),
        cert_registry=registry,
        # Embedding the dev root is harmless and makes hand-inspection of a sealed file easier;
        # trust still comes only from trust-roots.pem at validation time.
        embed_roots=True,
    )
    return SigningMaterial(
        signer=signer,
        signing_cert=to_asn1_cert(pki.seal_cert),
        chain=chain,
        backend="local",
        dev_pki=pki,
    )


# --------------------------------------------------------------------------- aws_kms


def _kms_material(settings: Settings) -> SigningMaterial:
    if not settings.seal_kms_key_id:
        raise SealUnavailable("SEAL_KMS_KEY_ID is not configured", code="seal_key_unavailable")
    if settings.seal_cert_path is None:
        raise SealUnavailable("SEAL_CERT_PATH is not configured", code="seal_key_unavailable")

    signing_cert = _load_single_cert(settings.seal_cert_path)
    chain = _load_cert_bundle(settings.seal_chain_path) if settings.seal_chain_path else ()

    registry = SimpleCertificateStore()  # type: ignore[no-untyped-call]
    if chain:
        registry.register_multiple(chain)

    signer = KmsSigner(
        client=kms_client(settings),
        key_id=settings.seal_kms_key_id,
        signing_cert=signing_cert,
        cert_registry=registry,
    )
    return SigningMaterial(signer=signer, signing_cert=signing_cert, chain=chain, backend="aws_kms")


# --------------------------------------------------------------------------- trust roots


def load_trust_roots(path: Path) -> tuple[asn1_x509.Certificate, ...]:
    """Read the PEM bundle of roots ``validate`` may trust.

    Raises ``FileNotFoundError``/``ValueError`` rather than returning an empty tuple: an empty
    trust store would make every document untrusted for a reason nobody could diagnose, and a
    missing file must never be read as "trust whatever is embedded in the document".
    """
    data = path.read_bytes()
    roots = tuple(
        asn1_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))
        for cert in crypto_x509.load_pem_x509_certificates(data)
    )
    if not roots:
        raise ValueError(f"{path} contains no certificates")
    return roots


# --------------------------------------------------------------------------- conversions


def to_asn1_cert(cert: crypto_x509.Certificate) -> asn1_x509.Certificate:
    return asn1_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))


def to_asn1_key(key: RSAPrivateKey) -> asn1_keys.PrivateKeyInfo:
    return asn1_keys.PrivateKeyInfo.load(
        key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def cert_sha256(cert: asn1_x509.Certificate) -> bytes:
    """SHA-256 over the certificate's DER encoding -- the usual certificate fingerprint."""
    return hashlib.sha256(cert.dump()).digest()


def _load_single_cert(path: Path) -> asn1_x509.Certificate:
    certs = _load_cert_bundle(path)
    if len(certs) != 1:
        raise SealUnavailable(
            f"{path} must hold exactly one certificate, found {len(certs)}",
            code="seal_key_unavailable",
        )
    return certs[0]


def _load_cert_bundle(path: Path) -> tuple[asn1_x509.Certificate, ...]:
    try:
        loaded = crypto_x509.load_pem_x509_certificates(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise SealUnavailable(f"{path} could not be read as PEM certificates", code="seal_key_unavailable") from exc
    return tuple(asn1_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER)) for cert in loaded)
