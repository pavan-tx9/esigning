"""Test-only signing helpers.

The sealer deliberately produces exactly one kind of signature. To prove that ``validate``
rejects every *other* kind -- an approval signature, a second signature, a certification that
still permits form filling -- the tests have to produce those themselves, with pyHanko directly.
"""

from __future__ import annotations

import io

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers
from pyhanko.sign.fields import MDPPerm, SigSeedSubFilter
from pyhanko.sign.timestamps import DummyTimeStamper
from pyhanko_certvalidator.registry import SimpleCertificateStore

from esign.clock import FixedClock
from esign.sealing.keys import to_asn1_cert, to_asn1_key
from tests.conftest import FROZEN_NOW
from tests.sealing.conftest import Pki

__all__ = ["sign_with"]


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
