"""Verification: re-check everything the stored record claims. See docs/SPEC.md section 3, step 9.

``verify_envelope`` trusts nothing it can recompute:

* every stored revision is fetched and re-hashed (``BlobService.get`` does the hashing);
* the envelope's pointers are compared with the revisions table;
* the audit chain is re-verified link by link;
* the hashes recorded in the audit trail are compared with the revisions they describe;
* the seal is validated against the *configured* trust roots (never the embedded certificates),
  and the certificate that signed is compared with the one recorded when it was sealed;
* the head hash the certificate of completion recorded is compared with the chain as it stands,
  and looked for in the text of the sealed certificate page.

Then it records ``verification.performed``, so the fact that someone checked -- and what they
found -- is itself part of the trail.

The report says exactly what was checked, what was skipped and why, and what failed. A check that
could not be run is ``skipped``, never silently ``passed``; an envelope that is not sealed yet can
be internally consistent (``ok``) but is never ``complete``.
"""

from __future__ import annotations

import hashlib
import io
import re
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Final, Literal
from uuid import UUID

from pyhanko.pdf_utils.reader import PdfFileReader
from pypdf import PdfReader
from sqlalchemy import text
from sqlalchemy.orm import Session

from esign.contracts import (
    Actor,
    AuditEvent,
    AuditLog,
    BlobService,
    EsignError,
    EventType,
    Host,
    IntegrityFailure,
    NotFound,
    RequestContext,
    Sealer,
    SealValidation,
)
from esign.logging import get_logger

__all__ = ["Check", "VerificationReport", "Verifier"]

log = get_logger(__name__)

CheckStatus = Literal["passed", "failed", "skipped"]

#: How far a mutable row's timestamp may sit from the event that recorded the same fact. They are
#: written in one transaction but from two ``Clock`` reads. Matches the envelope service's own
#: tolerance, so the seal and this report cannot disagree about what counts as drift.
_ROW_EVENT_TOLERANCE: Final = timedelta(seconds=60)


@dataclass(frozen=True)
class Check:
    name: str
    status: CheckStatus
    detail: str = ""  # machine-ish and PHI-free: hashes, numbers, problem strings

    def to_json(self) -> dict[str, str]:
        return {"name": self.name, "status": self.status, "detail": self.detail}


@dataclass(frozen=True)
class VerificationReport:
    envelope_id: UUID
    envelope_status: str
    checks: tuple[Check, ...]
    audit_event_count: int
    audit_head_hash: bytes | None
    blobs_checked: int
    seal: SealValidation | None = None
    recorded: bool = False  # verification.performed was appended

    @property
    def problems(self) -> tuple[str, ...]:
        return tuple(f"{c.name}: {c.detail}" if c.detail else c.name for c in self.checks if c.status == "failed")

    @property
    def ok(self) -> bool:
        """Nothing that was checked failed."""
        return not self.problems

    @property
    def complete(self) -> bool:
        """``ok``, sealed, and every seal check actually ran."""
        return (
            self.ok
            and self.envelope_status == "sealed"
            and self.seal is not None
            and self.seal.ok
            and not any(c.status == "skipped" for c in self.checks)
        )

    def to_json(self) -> dict[str, Any]:
        seal = self.seal
        return {
            "envelope_id": str(self.envelope_id),
            "envelope_status": self.envelope_status,
            "ok": self.ok,
            "complete": self.complete,
            "checks": [c.to_json() for c in self.checks],
            "problems": list(self.problems),
            "audit": {
                "event_count": self.audit_event_count,
                "head_hash": None if self.audit_head_hash is None else self.audit_head_hash.hex(),
            },
            "blobs_checked": self.blobs_checked,
            "seal": None
            if seal is None
            else {
                "ok": seal.ok,
                "intact": seal.intact,
                "covers_whole_document": seal.covers_whole_document,
                "trusted": seal.trusted,
                "timestamp_valid": seal.timestamp_valid,
                "profile": seal.profile,
                "signer_cert_sha256": None if seal.signer_cert_sha256 is None else seal.signer_cert_sha256.hex(),
                "signing_time": None if seal.signing_time is None else seal.signing_time.isoformat(),
                "problems": list(seal.problems),
            },
            "recorded": self.recorded,
        }


@dataclass
class _Run:
    checks: list[Check] = field(default_factory=list)

    def passed(self, name: str, detail: str = "") -> None:
        self.checks.append(Check(name, "passed", detail))

    def failed(self, name: str, detail: str) -> None:
        self.checks.append(Check(name, "failed", detail))

    def skipped(self, name: str, detail: str) -> None:
        self.checks.append(Check(name, "skipped", detail))

    def expect(self, name: str, condition: bool, detail: str) -> None:
        if condition:
            self.passed(name)
        else:
            self.failed(name, detail)


def _hex(value: bytes | None) -> str:
    return "none" if value is None else value.hex()


class Verifier:
    def __init__(self, *, audit: AuditLog, blobs: BlobService, sealer: Sealer) -> None:
        self._audit = audit
        self._blobs = blobs
        self._sealer = sealer

    def verify_envelope(
        self,
        db: Session,
        envelope_id: UUID,
        *,
        host: Host | None = None,
        actor: Actor | None = None,
        ctx: RequestContext | None = None,
    ) -> VerificationReport:
        """``host`` scopes the lookup for the Host API (another host's envelope is ``not_found``);
        the CLI passes ``None``."""
        envelope = db.execute(
            text(
                "SELECT id, host_id, status, presented_sha256, current_revision_sha256, sealed_sha256 "
                # A shared row lock: signing and sealing wait, so the envelope, its revisions and
                # its trail are read as one consistent state and a seal landing mid-check cannot
                # show up as a false finding. Other verifications are not blocked.
                "FROM envelopes WHERE id = :id FOR SHARE"
            ),
            {"id": envelope_id},
        ).first()
        if envelope is None or (host is not None and envelope.host_id != host.id):
            raise NotFound("no such envelope", code="not_found")
        status = str(envelope.status)
        run = _Run()

        revisions = db.execute(
            text(
                "SELECT revision_no, kind, sha256 FROM document_revisions WHERE envelope_id = :id ORDER BY revision_no"
            ),
            {"id": envelope_id},
        ).all()
        blobs_checked, fetched = self._check_revisions(db, run, revisions)
        sealed_pdf = next(iter(fetched.get("sealed", [])), None)
        self._check_pointers(run, envelope, revisions)

        chain = self._audit.verify(db, "envelope", envelope_id)
        if chain.ok:
            run.passed("audit_chain", f"{chain.event_count} events")
        else:
            run.failed("audit_chain", "; ".join(chain.problems) or "chain did not verify")
        events = self._audit.list(db, "envelope", envelope_id)
        self._check_trail_against_revisions(run, events, revisions, status)

        self._check_signer_rows_against_trail(db, run, events, envelope_id)
        blobs_checked += self._check_capture_images(db, run, events, envelope_id)
        self._check_sealed_pages_match_final_revision(run, fetched, status)

        seal: SealValidation | None = None
        if status == "sealed":
            seal = self._check_seal(run, events, sealed_pdf)
            self._check_seal_binding(run, envelope_id, sealed_pdf)
            self._check_certificate_head(run, events, sealed_pdf)
        else:
            run.skipped("seal", f"envelope is {status}, not sealed")
            run.skipped("seal_bound_to_envelope", f"envelope is {status}, not sealed")
            run.skipped("certificate_head_hash", f"envelope is {status}, not sealed")

        report = VerificationReport(
            envelope_id=envelope_id,
            envelope_status=status,
            checks=tuple(run.checks),
            audit_event_count=chain.event_count,
            audit_head_hash=chain.head_hash,
            blobs_checked=blobs_checked,
            seal=seal,
        )
        self._audit.append(
            db,
            stream_type="envelope",
            stream_id=envelope_id,
            event_type=EventType.VERIFICATION_PERFORMED,
            actor=actor or Actor(role="system"),
            ctx=ctx or RequestContext(),
            document_sha256=None if envelope.sealed_sha256 is None else bytes(envelope.sealed_sha256),
            data={
                "ok": report.ok,
                "audit_ok": chain.ok,
                "audit_event_count": chain.event_count,
                "audit_head_hash": chain.head_hash,
                "seal_intact": None if seal is None else seal.intact,
                "seal_trusted": None if seal is None else seal.trusted,
                "seal_covers_whole_document": None if seal is None else seal.covers_whole_document,
                "seal_timestamp_valid": None if seal is None else seal.timestamp_valid,
                "seal_profile": None if seal is None else seal.profile,
                "blobs_checked": blobs_checked,
                "problem_count": len(report.problems),
            },
        )
        log.info(
            "verification.performed",
            envelope_id=envelope_id,
            ok=report.ok,
            event_count=chain.event_count,
            count=len(report.problems),
        )
        return VerificationReport(**{**report.__dict__, "recorded": True})

    # ----------------------------------------------------------------- checks

    def _check_revisions(self, db: Session, run: _Run, revisions: Any) -> tuple[int, dict[str, list[bytes]]]:
        """Fetch and re-hash every stored revision.

        Returns (how many matched, the fetched bytes by revision kind, in revision order).
        """
        fetched: dict[str, list[bytes]] = {}
        if not revisions:
            run.failed("revisions_present", "the envelope has no stored revisions")
            return 0, fetched
        run.expect(
            "revision_numbers_gapless",
            [int(r.revision_no) for r in revisions] == list(range(1, len(revisions) + 1)),
            "revision numbers are not 1..n",
        )
        checked = 0
        for revision in revisions:
            name = f"revision_{int(revision.revision_no)}_{revision.kind}_hash"
            try:
                data = self._blobs.get(db, bytes(revision.sha256))
            except EsignError as exc:
                # IntegrityFailure is the finding here, not an accident: report it, keep checking.
                kind = "integrity_failure" if isinstance(exc, IntegrityFailure) else "unreadable"
                run.failed(name, f"{kind} ({exc.code}) for {bytes(revision.sha256).hex()}")
                continue
            checked += 1
            run.passed(name, bytes(revision.sha256).hex())
            fetched.setdefault(str(revision.kind), []).append(data)
        return checked, fetched

    def _check_pointers(self, run: _Run, envelope: Any, revisions: Any) -> None:
        by_kind: dict[str, list[bytes]] = {}
        for revision in revisions:
            by_kind.setdefault(str(revision.kind), []).append(bytes(revision.sha256))
        presented = by_kind.get("presented", [None])[0]
        run.expect(
            "envelope_presented_pointer",
            presented is not None and _opt(envelope.presented_sha256) == presented,
            f"envelope says {_hex(_opt(envelope.presented_sha256))}, revision 1 is {_hex(presented)}",
        )
        signed = by_kind.get("signer_applied", [])
        expected_current = signed[-1] if signed else presented
        run.expect(
            "envelope_current_revision_pointer",
            _opt(envelope.current_revision_sha256) == expected_current,
            f"envelope says {_hex(_opt(envelope.current_revision_sha256))}, last signed revision is "
            f"{_hex(expected_current)}",
        )
        sealed = by_kind.get("sealed", [])
        if str(envelope.status) == "sealed":
            run.expect(
                "envelope_sealed_pointer",
                len(sealed) == 1 and _opt(envelope.sealed_sha256) == sealed[0],
                f"envelope says {_hex(_opt(envelope.sealed_sha256))}, sealed revisions: {len(sealed)}",
            )
        else:
            run.expect(
                "no_sealed_document_before_sealing",
                not sealed and envelope.sealed_sha256 is None,
                "a sealed document exists for an envelope that is not sealed",
            )

    def _check_trail_against_revisions(self, run: _Run, events: list[AuditEvent], revisions: Any, status: str) -> None:
        """The hashes the trail recorded must be the hashes of the revisions that are stored."""
        by_no = {int(r.revision_no): bytes(r.sha256) for r in revisions}
        by_kind = {str(r.kind): bytes(r.sha256) for r in revisions}

        prepared = [e for e in events if e.event_type == EventType.DOCUMENT_PREPARED]
        run.expect(
            "trail_presented_hash",
            len(prepared) == 1 and prepared[0].document_sha256 == by_kind.get("presented"),
            "document.prepared does not record the stored presented revision",
        )
        signed = [e for e in events if e.event_type == EventType.SIGNER_SIGNED]
        mismatched = [
            str(e.sequence) for e in signed if by_no.get(int(e.data.get("revision_no", 0))) != e.document_sha256
        ]
        stored_signed = sum(1 for r in revisions if r.kind == "signer_applied")
        run.expect(
            "trail_signed_revision_hashes",
            not mismatched and len(signed) == stored_signed,
            f"signer.signed events {', '.join(mismatched) or '-'} disagree with the stored revisions "
            f"({len(signed)} events, {stored_signed} revisions)",
        )
        if status != "sealed":
            return
        sealed_events = [e for e in events if e.event_type == EventType.DOCUMENT_SEALED]
        run.expect(
            "trail_sealed_hash",
            len(sealed_events) == 1 and sealed_events[0].document_sha256 == by_kind.get("sealed"),
            "document.sealed does not record the stored sealed document",
        )
        finalized = [e for e in events if e.event_type == EventType.DOCUMENT_FINALIZED]
        run.expect(
            "trail_final_unsealed_hash",
            len(finalized) == 1 and finalized[0].document_sha256 == by_kind.get("final_unsealed"),
            "document.finalized does not record the stored unsealed document",
        )

    def _check_seal(self, run: _Run, events: list[AuditEvent], sealed_pdf: bytes | None) -> SealValidation | None:
        if sealed_pdf is None:
            run.failed("seal", "the sealed document could not be read, so its seal was not validated")
            return None
        seal = self._sealer.validate(sealed_pdf)  # never raises; configured trust roots only
        for name, flag in (
            ("seal_intact", seal.intact),
            ("seal_covers_whole_document", seal.covers_whole_document),
            ("seal_trusted", seal.trusted),
            ("seal_timestamp_valid", seal.timestamp_valid),
        ):
            run.expect(name, flag, "; ".join(seal.problems) or "validation flag is false")
        run.expect("seal_no_problems", not seal.problems, "; ".join(seal.problems))

        recorded = next((e for e in events if e.event_type == EventType.DOCUMENT_SEALED), None)
        if recorded is None:
            run.failed("seal_matches_record", "there is no document.sealed event")
            return seal
        cert = None if seal.signer_cert_sha256 is None else seal.signer_cert_sha256.hex()
        run.expect(
            "seal_matches_record",
            cert == recorded.data.get("signer_cert_sha256") and seal.profile == recorded.data.get("seal_profile"),
            f"sealed with certificate {cert} as {seal.profile}; the trail recorded "
            f"{recorded.data.get('signer_cert_sha256')} as {recorded.data.get('seal_profile')}",
        )
        return seal

    def _check_seal_binding(self, run: _Run, envelope_id: UUID, sealed_pdf: bytes | None) -> None:
        """The envelope id written into the signature dictionary is this envelope's.

        SPEC section 5 and ``Sealer.seal``'s contract say the seal is bound to the envelope it
        completes by ``/Location = envelope:<id>``. Nothing used to read it back, so the binding
        was evidence only in the sense that it was written down. This is the one check a verifier
        holding just the sealed PDF and an envelope id can run.
        """
        if sealed_pdf is None:
            run.failed("seal_bound_to_envelope", "the sealed document could not be read")
            return
        expected = f"envelope:{envelope_id}"
        try:
            reader = PdfFileReader(io.BytesIO(sealed_pdf), strict=False)
            signatures = list(reader.embedded_regular_signatures)
            location = None if not signatures else signatures[0].sig_object.get("/Location")
        except Exception:
            run.failed("seal_bound_to_envelope", "the sealed document's signature could not be read")
            return
        found = None if location is None else str(location)
        run.expect(
            "seal_bound_to_envelope",
            found == expected,
            f"the seal names {found!r}; this envelope is {expected!r}",
        )

    def _check_signer_rows_against_trail(
        self, db: Session, run: _Run, events: list[AuditEvent], envelope_id: UUID
    ) -> None:
        """The ``signers`` rows must still say what the append-only trail says.

        ``signers`` is fully UPDATE-able by the runtime role, and it is where the certificate of
        completion's per-signer times come from. The seal refuses on a disagreement
        (``certificate_evidence_mismatch``); this reports the same comparison afterwards, for an
        envelope that was already sealed when the row was changed.
        """
        rows = db.execute(
            text("SELECT id, status, viewed_at, consented_at, signed_at FROM signers WHERE envelope_id = :id"),
            {"id": envelope_id},
        ).all()
        problems: list[str] = []
        for row in rows:
            signer_id = str(row.id)
            for event_type, column, value in (
                (EventType.DOCUMENT_VIEWED, "viewed_at", row.viewed_at),
                (EventType.CONSENT_ACCEPTED, "consented_at", row.consented_at),
                (EventType.SIGNER_SIGNED, "signed_at", row.signed_at),
            ):
                recorded = next(
                    (e for e in events if e.event_type == event_type and str(e.data.get("signer_id")) == signer_id),
                    None,
                )
                if value is None and recorded is None:
                    continue  # this signer never got that far; nothing claims otherwise
                if value is None or recorded is None:
                    problems.append(f"{column} and {event_type.value} disagree about whether it happened")
                elif abs(value - recorded.occurred_at) > _ROW_EVENT_TOLERANCE:
                    problems.append(f"{column} is not the time {event_type.value} recorded")
            signed = next(
                (
                    e
                    for e in events
                    if e.event_type == EventType.SIGNER_SIGNED and str(e.data.get("signer_id")) == signer_id
                ),
                None,
            )
            if (str(row.status) == "signed") != (signed is not None):
                problems.append("a signer's status does not match whether signer.signed is in the trail")
            if signed is not None and not _viewed_what_was_signed(events, signer_id, signed):
                # SPEC section 3 step 3: the server refuses signing before the document was viewed.
                # The bytes have to line up, not just the order of events: ``viewed`` is a
                # signer-level status carried across sessions.
                problems.append("no document.viewed covers the revision signer.signed was built on")
        run.expect("signer_rows_match_trail", not problems, "; ".join(sorted(set(problems))))

    def _check_sealed_pages_match_final_revision(self, run: _Run, fetched: dict[str, list[bytes]], status: str) -> None:
        """The pages inside the seal are the pages of the last signer-applied revision.

        ``finalize`` rebuilds the document with pypdf rather than appending the certificate as an
        incremental update, so ``final_unsealed`` does not *contain* revision N's bytes. A verifier
        could prove the seal covers ``final_unsealed`` and that revision N re-hashes, but not that
        the pages inside the seal are revision N's pages -- the only link was the trail's word for
        it. This recomputes the link: same page count plus the certificate's, and the same content
        streams and page boxes for the leading pages.
        """
        if status != "sealed":
            run.skipped("sealed_pages_match_final_revision", f"envelope is {status}, not sealed")
            return
        signed = fetched.get("signer_applied", [])
        final = next(iter(fetched.get("final_unsealed", [])), None)
        if not signed or final is None:
            run.failed(
                "sealed_pages_match_final_revision",
                "the last signed revision or the finalized document could not be read",
            )
            return
        try:
            source = PdfReader(io.BytesIO(signed[-1])).pages
            target = PdfReader(io.BytesIO(final)).pages
        except Exception:
            run.failed("sealed_pages_match_final_revision", "a revision's pages could not be read")
            return
        if len(target) < len(source):
            run.failed(
                "sealed_pages_match_final_revision",
                f"the finalized document has {len(target)} pages, fewer than the {len(source)} that were signed",
            )
            return
        problems = [
            f"page {index + 1}"
            for index, (before, after) in enumerate(zip(source, target, strict=False))
            if not _same_page(before, after)
        ]
        run.expect(
            "sealed_pages_match_final_revision",
            not problems,
            f"the finalized document differs from the last signed revision at {', '.join(problems)}",
        )

    def _check_capture_images(self, db: Session, run: _Run, events: list[AuditEvent], envelope_id: UUID) -> int:
        """The raw signer input still matches what the trail recorded of it.

        ``signature_captures`` holds the ink as it was drawn, before it was scaled into the page.
        The stamped revision covers how the mark *appears* in the document; this covers the input
        itself. Two things are checked: every stored image still re-hashes (``BlobService.get`` does
        the hashing), and every digest ``signer.signed`` recorded is the digest of a capture that is
        still there. Returns how many blobs were read.
        """
        rows = db.execute(
            text(
                "SELECT c.signer_id, c.field_id, c.kind, c.image_sha256, c.typed_text "
                "FROM signature_captures c JOIN signers s ON s.id = c.signer_id "
                "WHERE s.envelope_id = :id ORDER BY c.created_at, c.id"
            ),
            {"id": envelope_id},
        ).all()

        checked = 0
        problems: list[str] = []
        for row in rows:
            if row.image_sha256 is None:
                continue
            sha = bytes(row.image_sha256)
            try:
                self._blobs.get(db, sha)
            except EsignError as exc:
                kind = "integrity_failure" if isinstance(exc, IntegrityFailure) else "unreadable"
                problems.append(f"{kind} ({exc.code}) for {sha.hex()}")
                continue
            checked += 1
        if not rows:
            # Passed, not skipped: the check ran and found nothing it could not reach. A click-only
            # signature stores no capture row at all, so this is an ordinary outcome.
            run.passed("capture_images_intact", "no drawn or typed signature was captured")
        else:
            run.expect("capture_images_intact", not problems, "; ".join(problems))

        stored = {
            (str(row.signer_id), str(row.field_id)): (
                None if row.image_sha256 is None else bytes(row.image_sha256).hex(),
                None if row.typed_text is None else hashlib.sha256(str(row.typed_text).encode("utf-8")).hexdigest(),
            )
            for row in rows
        }
        drift: list[str] = []
        for event in events:
            if event.event_type != EventType.SIGNER_SIGNED:
                continue
            signer_id = str(event.data.get("signer_id"))
            for ref in event.data.get("captures") or []:
                recorded = (ref.get("image_sha256"), ref.get("typed_text_sha256"))
                if recorded == (None, None):
                    continue  # click-to-sign, a checkbox or a text field: nothing to tie
                found = stored.get((signer_id, str(ref.get("field_id"))))
                if found is None:
                    drift.append(f"{ref.get('field_id')}: the capture the trail records is gone")
                elif found != recorded:
                    drift.append(f"{ref.get('field_id')}: the stored capture is not the one the trail records")
        run.expect("captures_match_trail", not drift, "; ".join(sorted(set(drift))))
        return checked

    def _check_certificate_head(self, run: _Run, events: list[AuditEvent], sealed_pdf: bytes | None) -> None:
        """The certificate of completion records the chain head at the moment it was written."""
        finalized = next((e for e in events if e.event_type == EventType.DOCUMENT_FINALIZED), None)
        if finalized is None:
            run.failed("certificate_head_hash", "there is no document.finalized event")
            return
        count = int(finalized.data.get("audit_event_count", 0))
        head = str(finalized.data.get("audit_head_hash", ""))
        at_count = next((e for e in events if e.sequence == count), None)
        covered = sum(1 for e in events if e.sequence <= count)
        run.expect(
            "certificate_head_hash",
            at_count is not None and at_count.event_hash.hex() == head and covered == count,
            f"the certificate was written over {count} events ending {head}; {covered} of them are still there "
            f"and event {count} now hashes to {_hex(None if at_count is None else at_count.event_hash)}",
        )
        if sealed_pdf is None:
            run.failed("certificate_head_hash_in_document", "the sealed document could not be read")
            return
        try:
            reader = PdfReader(io.BytesIO(sealed_pdf))
            # Every page, not a guess at how long the certificate is. ``build_certificate``
            # paginates freely -- ten signers with long role labels already run to five pages --
            # and the head hash is printed in the "Audit trail" section near the *top* of the
            # certificate's first page. Searching a fixed tail failed genuine documents, which is
            # the worst possible answer from a verifier: an append-only ``verification.performed``
            # recording ``ok: false`` for a sound seal. ``max_template_pages`` bounds the work.
            printed = re.sub(r"\s+", "", "".join(page.extract_text() or "" for page in reader.pages)).lower()
        except Exception:
            run.failed("certificate_head_hash_in_document", "the sealed document's text could not be read")
            return
        run.expect(
            "certificate_head_hash_in_document",
            bool(head) and head in printed,
            "the head hash in the trail is not the one printed on the sealed certificate page",
        )


def _opt(value: Any) -> bytes | None:
    return None if value is None else bytes(value)


def _same_page(before: Any, after: Any) -> bool:
    """Whether two pages draw the same thing in the same place.

    The content stream is compared decoded, because ``finalize`` re-writes the file and may choose a
    different compression; the boxes and rotation are compared because the same ink at a different
    offset is a different page.
    """
    try:
        first = before.get_contents()
        second = after.get_contents()
        if (first is None) != (second is None):
            return False
        if first is not None and second is not None and first.get_data() != second.get_data():
            return False
        for key in ("/MediaBox", "/CropBox", "/Rotate"):
            if str(before.get(key)) != str(after.get(key)):
                return False
    except Exception:
        return False
    return True


def _viewed_what_was_signed(events: list[AuditEvent], signer_id: str, signed: AuditEvent) -> bool:
    """Whether a ``document.viewed`` for these exact bytes precedes this signature."""
    presented = str(signed.data.get("presented_sha256", ""))
    return any(
        e.event_type == EventType.DOCUMENT_VIEWED
        and str(e.data.get("signer_id")) == signer_id
        and e.document_sha256 is not None
        and e.document_sha256.hex() == presented
        and e.sequence < signed.sequence
        for e in events
    )
