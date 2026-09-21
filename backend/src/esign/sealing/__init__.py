"""PAdES sealing and validation via pyHanko. See docs/SPEC.md section 5.

The module exposes one factory. Everything else in here is an implementation detail that other
modules must not reach into:

    sealer = build_sealer(settings, clock)
    result = sealer.seal(pdf, reason="Envelope completed", envelope_id=envelope_id)
    report = sealer.validate(result.sealed_pdf)

``dev_pki`` is re-exported because the ``esign dev-pki`` command in the CLI needs it; it generates
throwaway development key material and has no production role.
"""

from __future__ import annotations

from esign.config import Settings
from esign.contracts import Clock, Sealer

from .dev_pki import (
    DevPki,
    DevPkiMissing,
    dev_pki_paths,
    generate_dev_pki,
    issue_seal_certificate,
    load_dev_pki,
)
from .problems import PROBLEMS, Problem
from .sealer import SEAL_FIELD_NAME, PadesSealer

__all__ = [
    "PROBLEMS",
    "SEAL_FIELD_NAME",
    "DevPki",
    "DevPkiMissing",
    "PadesSealer",
    "Problem",
    "build_sealer",
    "dev_pki_paths",
    "generate_dev_pki",
    "issue_seal_certificate",
    "load_dev_pki",
]


def build_sealer(settings: Settings, clock: Clock) -> Sealer:
    """The module factory named in SPEC section 2.

    Key material is resolved on first use rather than here, so that a process which never seals
    (the API, say) starts even when the dev PKI has not been generated. A missing or unreadable
    key surfaces as ``SealUnavailable`` at the moment it is needed, which leaves the envelope in
    ``completed_pending_seal`` -- the fail-closed outcome -- instead of reporting a document as
    complete.
    """
    return PadesSealer(settings, clock)
