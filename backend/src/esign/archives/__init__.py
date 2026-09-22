"""Paper archives: a scan of a document signed in ink, filed by the host (Addendum 1 A).

``service``     creation -- hygiene, write-once storage as revision 1, the attestation, the trail
``repository``  the rows a paper archive is made of

An archive is an envelope with ``kind = paper_archive``: no template, no signers, no sessions.
Everything from ``completed_pending_seal`` onwards -- the seal job, the cover page, the archive
variant of the certificate, the webhook, verification and the void rules -- belongs to the
envelopes, documents and verification modules, which handle both kinds.

This module imports ``esign.contracts`` and the foundation files only, like every other module.
``esign.runtime`` builds it and injects it into the envelope service, whose ``create_archive``
delegates here.
"""

from __future__ import annotations

from esign.archives.service import ArchiveService, build_archive_service

__all__ = ["ArchiveService", "build_archive_service"]
