"""Test-only signing helpers.

The sealer deliberately produces exactly one kind of signature. To prove that ``validate``
rejects every *other* kind -- an approval signature, a second signature, a certification that
still permits form filling -- the tests have to produce those themselves, with pyHanko directly.
"""

from __future__ import annotations

import io
from datetime import datetime, timedelta

from asn1crypto import crl as asn1_crl  # type: ignore[import-untyped]
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers
from pyhanko.sign.fields import MDPPerm, SigSeedSubFilter
from pyhanko.sign.timestamps import DummyTimeStamper
from pyhanko.sign.validation.dss import DocumentSecurityStore
from pyhanko_certvalidator.registry import SimpleCertificateStore

from esign.clock import FixedClock
from esign.sealing.keys import to_asn1_cert, to_asn1_key
from tests.conftest import FROZEN_NOW
from tests.sealing.conftest import Pki

__all__ = ["revoke_seal_certificate", "sign_with"]


def sign_with(
    pki: Pki,
    pdf: bytes,
    *,
    field_name: str = "EsignSeal",
    certify: bool = True,
    permissions: MDPPerm = MDPPerm.NO_CHANGES,
    timestamp: bool = True,
) -> bytes:
    """Apply one signature to ``pdf`` using the given hierarchy's seal key."""
    chain = [to_asn1_cert(cert) for cert in pki.pki.chain]
    registry = SimpleCertificateStore()  # type: ignore[no-untyped-call]
    registry.register_multiple(chain)
    signer = signers.SimpleSigner(
        signing_cert=to_asn1_cert(pki.pki.seal_cert),
        signing_key=to_asn1_key(pki.pki.seal_key),
        cert_registry=registry,
    )

    timestamper = None
    if timestamp:
        embed = SimpleCertificateStore()  # type: ignore[no-untyped-call]
        embed.register_multiple(chain)
        timestamper = DummyTimeStamper(
            tsa_cert=to_asn1_cert(pki.pki.tsa_cert),
            tsa_key=to_asn1_key(pki.pki.tsa_key),
            certs_to_embed=embed,
            fixed_dt=FixedClock(FROZEN_NOW).now(),
        )

    meta = signers.PdfSignatureMetadata(
        field_name=field_name,
        md_algorithm="sha256",
        reason="test fixture",
        subfilter=SigSeedSubFilter.PADES,
        certify=certify,
        docmdp_permissions=permissions,
    )
    writer = IncrementalPdfFileWriter(io.BytesIO(pdf), strict=False)
    output = signers.sign_pdf(writer, meta, signer, timestamper=timestamper)
    result: bytes = output.getvalue()
    return result


def revoke_seal_certificate(pki: Pki, sealed: bytes, *, revoked_at: datetime) -> bytes:
    """The same sealed document, with a CRL revoking its seal certificate in the DSS.

    This is how a compromised or superseded seal key reaches a verifier years later: the CA issues
    a CRL, and an archival system folds the fresher revocation data into the document's own
    security store as an incremental update (which is what the store is for, and what DocMDP
    permits). The document is otherwise untouched -- intact, covering itself, chaining to the
    configured root -- so the only thing that can refuse it is a validator that actually reads the
    revocation data.
    """
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(pki.pki.intermediate_cert.subject)
        .last_update(revoked_at - timedelta(hours=2))
        .next_update(revoked_at + timedelta(days=365 * 10))
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(pki.pki.intermediate_cert.public_key()),  # type: ignore[arg-type]
            critical=False,
        )
        .add_extension(x509.CRLNumber(2), critical=False)
        .add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(pki.pki.seal_cert.serial_number)
            .revocation_date(revoked_at)
            .add_extension(x509.CRLReason(x509.ReasonFlags.key_compromise), critical=False)
            .build()
        )
        .sign(pki.pki.intermediate_key, hashes.SHA256())
    )
    loaded = asn1_crl.CertificateList.load(crl.public_bytes(serialization.Encoding.DER))
    writer = IncrementalPdfFileWriter(io.BytesIO(sealed), strict=False)
    DocumentSecurityStore.supply_dss_in_writer(writer, None, crls=[loaded])
    output = io.BytesIO()
    writer.write(output)  # type: ignore[no-untyped-call]
    return output.getvalue()
