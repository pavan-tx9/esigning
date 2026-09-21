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

import io
import re
from dataclasses import dataclass, field
from typing import Any, Literal
from uuid import UUID

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
        blobs_checked, sealed_pdf = self._check_revisions(db, run, revisions)
        self._check_pointers(run, envelope, revisions)

        chain = self._audit.verify(db, "envelope", envelope_id)
        if chain.ok:
            run.passed("audit_chain", f"{chain.event_count} events")
        else:
            run.failed("audit_chain", "; ".join(chain.problems) or "chain did not verify")
        events = self._audit.list(db, "envelope", envelope_id)
        self._check_trail_against_revisions(run, events, revisions, status)

        seal: SealValidation | None = None
        if status == "sealed":
            seal = self._check_seal(run, events, sealed_pdf)
            self._check_certificate_head(run, events, sealed_pdf)
        else:
            run.skipped("seal", f"envelope is {status}, not sealed")
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

    def _check_revisions(self, db: Session, run: _Run, revisions: Any) -> tuple[int, bytes | None]:
        """Fetch and re-hash every stored revision. Returns (how many matched, the sealed bytes)."""
        if not revisions:
            run.failed("revisions_present", "the envelope has no stored revisions")
            return 0, None
        run.expect(
            "revision_numbers_gapless",
            [int(r.revision_no) for r in revisions] == list(range(1, len(revisions) + 1)),
            "revision numbers are not 1..n",
        )
        checked = 0
        sealed_pdf: bytes | None = None
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
            if revision.kind == "sealed":
                sealed_pdf = data
        return checked, sealed_pdf

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
            pages = reader.pages[-4:]  # the certificate is the tail of the document
            printed = re.sub(r"\s+", "", "".join(page.extract_text() or "" for page in pages)).lower()
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
