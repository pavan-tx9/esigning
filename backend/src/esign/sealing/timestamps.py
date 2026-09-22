"""Choosing a timestamp authority.

Production points ``TSA_URL`` at a real RFC 3161 authority. Development and tests have no such
thing reachable, so the dev PKI's TSA certificate drives an in-process authority instead.

The rule that matters, and it is enforced below rather than merely stated: the in-process authority
is only ever reachable from a non-production environment running on the local dev key, or from the
test environment (where the offline KMS tests exercise the KMS path). A production deployment with
no TSA configured does not quietly seal without a trusted time -- it refuses, and the envelope
stays pending. Neither does a deployment holding a real key that forgot to set ``APP_ENV``.
"""

from __future__ import annotations

from pyhanko.sign.timestamps import DummyTimeStamper, HTTPTimeStamper, TimeStamper
from pyhanko_certvalidator.registry import SimpleCertificateStore

from esign.config import Settings
from esign.contracts import Clock, SealUnavailable

from .dev_pki import DevPkiMissing, load_dev_pki
from .keys import SigningMaterial, to_asn1_cert, to_asn1_key

__all__ = ["build_timestamper"]


def build_timestamper(settings: Settings, clock: Clock, material: SigningMaterial) -> TimeStamper:
    """A timestamper for one sealing attempt.

    Built per attempt rather than cached: the in-process authority stamps at ``clock.now()``, and
    a cached one would keep stamping the time it was created.
    """
    if settings.tsa_url:
        return HTTPTimeStamper(settings.tsa_url, timeout=settings.tsa_timeout_seconds)

    if settings.app_env == "prod":
        raise SealUnavailable(
            "TSA_URL is not configured; refusing to seal without a trusted timestamp",
            code="tsa_not_configured",
        )

    if material.backend != "local" and settings.app_env != "test":
        # ``APP_ENV`` defaults to ``dev``, so keying the refusal above on ``prod`` alone meant a
        # deployment with a real KMS key, a real bucket and a missing or misspelled ``APP_ENV``
        # sealed real documents whose RFC 3161 time was asserted by a throwaway dev certificate --
        # and ``document.sealed`` records no TSA identity, so the trail could not show it. The
        # in-process authority is reachable only on the local dev key, or under the test
        # environment, which is where the offline KMS tests run.
        raise SealUnavailable(
            "TSA_URL is required when the seal key is not the local dev PKI",
            code="tsa_not_configured",
        )

    # Outside production, the dev PKI's authority stands in -- including when the key itself lives
    # in KMS under APP_ENV=test, which is how the KMS path is exercised without a network.
    pki = material.dev_pki
    if pki is None:
        try:
            pki = load_dev_pki(settings.dev_pki_dir)
        except (DevPkiMissing, OSError, ValueError) as exc:
            raise SealUnavailable(
                "TSA_URL is not configured and no dev PKI is available to stand in for one",
                code="tsa_not_configured",
            ) from exc

    embed = SimpleCertificateStore()  # type: ignore[no-untyped-call]
    embed.register_multiple(to_asn1_cert(cert) for cert in pki.chain)
    return DummyTimeStamper(
        tsa_cert=to_asn1_cert(pki.tsa_cert),
        tsa_key=to_asn1_key(pki.tsa_key),
        certs_to_embed=embed,
        fixed_dt=clock.now(),
    )
