"""A pyHanko ``Signer`` whose private key lives in AWS KMS and never leaves it.

pyHanko builds the CMS ``SignedData`` and asks for one raw signature over the signed attributes.
That is the only operation KMS performs: we hash locally and call ``kms:Sign`` with
``MessageType=DIGEST``, so no document bytes are sent to AWS either.

Every failure to reach or use KMS becomes ``SealUnavailable``. There is no path in this module
that returns an unsigned or differently-signed result.
"""

from __future__ import annotations

import asyncio
import hashlib
from typing import TYPE_CHECKING, Any, Final

from asn1crypto import x509 as asn1_x509  # type: ignore[import-untyped]
from asn1crypto.algos import SignedDigestAlgorithm  # type: ignore[import-untyped]
from botocore.exceptions import BotoCoreError, ClientError
from pyhanko.sign.signers.pdf_cms import Signer
from pyhanko_certvalidator.registry import CertificateStore

from esign.config import Settings
from esign.contracts import SealUnavailable

if TYPE_CHECKING:  # pragma: no cover - typing only
    from mypy_boto3_kms.client import KMSClient

__all__ = ["KmsSigner", "kms_client"]

#: ``kms:Sign`` algorithm per key type. Only what SPEC section 5 asks for: RSA PKCS#1 v1.5
#: SHA-256 and ECDSA P-256 SHA-256. Anything else is refused rather than approximated.
_RSA_ALGORITHM: Final = "RSASSA_PKCS1_V1_5_SHA_256"
_ECDSA_ALGORITHM: Final = "ECDSA_SHA_256"

#: Maximum DER length of an ECDSA P-256 signature (two 32-byte integers, worst-case padding).
_ECDSA_P256_MAX_DER: Final = 72

#: ``kms:Sign`` accepts at most 4096 bytes when ``MessageType`` is ``RAW``.
_MAX_RAW_MESSAGE_BYTES: Final = 4096

_DIGESTS: Final[dict[str, Any]] = {"sha256": hashlib.sha256}


def kms_client(settings: Settings) -> KMSClient:
    """A boto3 KMS client from settings. Credentials come from the environment, never the repo."""
    import boto3  # imported lazily: nothing but the KMS backend needs botocore's import cost

    client: KMSClient = boto3.client(
        "kms",
        region_name=settings.seal_kms_region,
        endpoint_url=settings.seal_kms_endpoint_url,
    )
    return client


class KmsSigner(Signer):
    """Signs with ``kms:Sign``. The key id is configuration; the certificate is on disk."""

    def __init__(
        self,
        *,
        client: KMSClient,
        key_id: str,
        signing_cert: asn1_x509.Certificate,
        cert_registry: CertificateStore,
    ) -> None:
        self._client = client
        self._key_id = key_id
        self._kms_algorithm, mechanism, self._placeholder_len = _describe_key(signing_cert)
        super().__init__(
            signing_cert=signing_cert,
            cert_registry=cert_registry,
            signature_mechanism=SignedDigestAlgorithm({"algorithm": mechanism}),
            embed_roots=False,
        )

    async def async_sign_raw(self, data: bytes, digest_algorithm: str, dry_run: bool = False) -> bytes:
        if dry_run:
            # Size estimation only. Never spend a KMS call, and never let a dry run look like a
            # real signature: these bytes are placeholders pyHanko overwrites.
            return bytes(self._placeholder_len)

        digest_name = digest_algorithm.lower()
        hasher = _DIGESTS.get(digest_name)
        if hasher is None:
            raise SealUnavailable(
                f"digest {digest_name} is not supported by the KMS backend",
                code="seal_key_unavailable",
            )

        # CMS signed attributes are a few hundred bytes, comfortably inside the RAW limit, so we
        # normally hand KMS the bytes and let it hash them: one less place for our hashing and
        # AWS's to disagree. A payload that somehow exceeds the limit is hashed here instead.
        if len(data) <= _MAX_RAW_MESSAGE_BYTES:
            message, message_type = data, "RAW"
        else:
            message, message_type = hasher(data).digest(), "DIGEST"

        return await asyncio.to_thread(self._sign, message, message_type)

    def _sign(self, message: bytes, message_type: str) -> bytes:
        try:
            response = self._client.sign(
                KeyId=self._key_id,
                Message=message,
                MessageType=message_type,  # type: ignore[arg-type]
                SigningAlgorithm=self._kms_algorithm,  # type: ignore[arg-type]
            )
        except (BotoCoreError, ClientError, OSError) as exc:
            # Unreachable endpoint, throttling, a disabled key, denied permissions: all of them
            # mean "we did not seal", and all of them are retryable by the seal job.
            raise SealUnavailable("KMS signing failed", code="seal_unavailable") from exc

        signature = response.get("Signature")
        if not signature:
            raise SealUnavailable("KMS returned an empty signature", code="seal_unavailable")
        if len(signature) > self._placeholder_len:
            # pyHanko sized the signature container from the dry run. A longer real signature
            # would be truncated into the container, producing a file that looks sealed and is
            # not. Refuse instead.
            raise SealUnavailable(
                "KMS signature is longer than the reserved container",
                code="seal_unavailable",
            )
        return bytes(signature)


def _describe_key(cert: asn1_x509.Certificate) -> tuple[str, str, int]:
    """(kms signing algorithm, CMS mechanism name, placeholder signature length)."""
    public_key = cert.public_key
    algorithm = public_key.algorithm
    if algorithm == "rsa":
        return _RSA_ALGORITHM, "sha256_rsa", (public_key.bit_size + 7) // 8
    if algorithm == "ec":
        curve = public_key.curve
        if curve[0] != "named" or curve[1] not in {"secp256r1", "prime256v1"}:
            raise SealUnavailable(
                f"unsupported EC curve for the KMS backend: {curve[1]}",
                code="seal_key_unavailable",
            )
        return _ECDSA_ALGORITHM, "sha256_ecdsa", _ECDSA_P256_MAX_DER
    raise SealUnavailable(
        f"unsupported seal key algorithm: {algorithm}",
        code="seal_key_unavailable",
    )
