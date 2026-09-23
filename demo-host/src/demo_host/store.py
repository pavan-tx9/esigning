"""The EHR's own state: people, charts, the worklist, and what came back from the service.

All of it is in memory. This is a test harness, not a product: restarting it forgets everything,
which is the behaviour you want when a demo goes sideways.

Two rules from the service's spec are honoured here even though nobody would check:

* a chart identifier, a task identifier and a document identifier are opaque UUIDs, so no name,
  medical record number or date of birth ever reaches a URL;
* the identifiers handed to the signing service (``host_user_id``, ``patient_ref``, the kiosk
  ``staff_user_id``) are opaque too, because they end up in an audit trail that refuses anything
  that looks like a fact about a person.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from demo_host.reports import Report, SignatureBlock, render

__all__ = [
    "ArchiveFiling",
    "ChartDocument",
    "Login",
    "Patient",
    "QueueReauth",
    "QueueRun",
    "Store",
    "Task",
    "TaskSigner",
    "User",
    "WebhookRecord",
    "build_store",
]

UserRole = Literal["patient", "guardian", "witness", "clinician", "staff"]
IdentityCheck = Literal["photo_id", "dob_and_name", "known_to_staff", "wristband"]

IDENTITY_CHECK_LABELS: dict[str, str] = {
    "photo_id": "Photo ID",
    "dob_and_name": "Date of birth and name",
    "known_to_staff": "Known to staff",
    "wristband": "Wristband",
}


@dataclass(frozen=True)
class User:
    """Somebody who can log in here. ``id`` is what the signing service sees."""

    id: str  # opaque host_user_id
    username: str
    display_name: str
    role: UserRole
    #: The chart this person *is* (patients) or looks after (guardians).
    patient_id: str | None = None
    job_title: str = ""

    @property
    def is_staff(self) -> bool:
        return self.role == "staff"


@dataclass(frozen=True)
class Patient:
    id: str  # opaque chart id; appears in URLs
    mrn: str  # opaque patient_ref handed to the signing service
    name: str
    date_of_birth: str


@dataclass(frozen=True)
class TaskSigner:
    """One row of the envelope this task will create."""

    role_key: str
    role_label: str
    user_id: str
    capacity: str
    on_behalf_of: str | None = None


@dataclass
class Task:
    """A document somebody has to sign. The EHR's side of an envelope.

    Addendum 2 gave it a second shape. ``source == "template"`` is everything the base spec
    describes: the service renders a published template version with the prefill below.
    ``source == "host_document"`` is a report *this* system generates per patient and uploads;
    there is no template and no prefill, and the fields come from the PDF's own widget names.
    """

    id: str
    title: str
    patient_id: str
    signing_order: Literal["sequential", "parallel"]
    signers: tuple[TaskSigner, ...]
    source: Literal["template", "host_document"] = "template"
    #: ``source == "template"`` only: the published template to render, and what to merge into it.
    template_key: str | None = None
    prefill: dict[str, str] = field(default_factory=dict)
    #: ``source == "host_document"`` only: what to render, and the type compliance has to have
    #: approved for it. A template envelope takes its document type from the template version.
    report: Report | None = None
    document_type: str | None = None
    note: str = ""
    #: Set once the envelope exists in the signing service.
    envelope_id: str | None = None
    #: role_key -> the signer id the service assigned.
    signer_ids: dict[str, str] = field(default_factory=dict)
    #: Last status the service told us about, by webhook or by polling.
    envelope_status: str = "not_started"
    #: role_key -> status, as last seen.
    signer_status: dict[str, str] = field(default_factory=dict)
    #: The live signing session per role_key: (session_id, token).
    sessions: dict[str, tuple[str, str]] = field(default_factory=dict)
    #: When each of those sessions was started, so one that is still good can be reused: creating
    #: a new session revokes the previous one, and a re-authentication attested on a revoked
    #: session covers nothing (SPEC section 8), which would break the signing queue.
    session_started: dict[str, datetime] = field(default_factory=dict)
    #: Set while a member of staff is running this task on the clinic tablet.
    kiosk: tuple[str, str] | None = None  # (staff_user_id, identity_check)
    #: The report as it was uploaded, kept because ``Idempotency-Key`` on this route hashes the
    #: document bytes: a retry has to send the same document or it is a different request.
    upload: bytes | None = None
    #: The hash of those bytes, so the page can show what was sent and a reader can hold it
    #: against the ``document.supplied`` event and the certificate.
    upload_sha256: str | None = None

    def signer_for(self, user_id: str) -> TaskSigner | None:
        return next((s for s in self.signers if s.user_id == user_id), None)

    @property
    def is_finished(self) -> bool:
        return self.envelope_status in {"sealed", "declined", "voided", "expired", "completed_pending_seal"}


@dataclass(frozen=True)
class ChartDocument:
    """A sealed PDF filed in a patient's chart: signed electronically from a template, generated
    here and supplied to the service (Addendum 2), or a scan of a paper original that staff filed
    and the service sealed (Addendum 1 A)."""

    id: str
    patient_id: str
    title: str
    envelope_id: str
    template_key: str | None
    sealed_sha256: str
    filed_at: datetime
    pdf: bytes
    kind: str = "electronic"
    #: The date on the paper, for a paper archive.
    paper_signed_on: str | None = None
    #: For a host document: the reference this system gave it and the hash of what it uploaded,
    #: which is what the ``document.supplied`` event and the certificate name.
    host_document_ref: str | None = None
    upload_sha256: str | None = None
    page_count: int | None = None


@dataclass
class ArchiveFiling:
    """A scan of a paper-signed document that staff filed with the service, until the sealed
    copy comes back by webhook and lands in the chart."""

    envelope_id: str
    patient_id: str
    title: str
    document_type: str
    paper_signed_on: str
    filed_by: str  # user id of the attesting member of staff
    filed_at: datetime
    envelope_status: str


@dataclass
class QueueReauth:
    """The one re-authentication a clinician made for their signing queue, as the service answered
    it. The service is the authority on whether it still covers anything; this is for the page."""

    at: datetime
    valid_until: str
    session_id: str


@dataclass
class QueueRun:
    """A clinician working through their queue (Addendum 3 B).

    The host owns the queue and its tokens, so the host owns the order too: the list is fixed when
    the run starts, and ``position`` walks it. Fixing it is the point -- a list recomputed after
    each signature would shrink as documents left it, and "3 of 8" would count down towards
    "1 of 1" while the clinician was still working.
    """

    #: Task ids, in the order they will open. Only documents that were ready when the run started.
    tasks: tuple[str, ...]
    #: Which of them is open now, zero-based.
    position: int = 0

    @property
    def current(self) -> str | None:
        return self.tasks[self.position] if 0 <= self.position < len(self.tasks) else None

    def index_of(self, task_id: str) -> int | None:
        return self.tasks.index(task_id) if task_id in self.tasks else None


@dataclass(frozen=True)
class WebhookRecord:
    received_at: datetime
    event: str
    envelope_id: str
    delivery_id: str
    verified: bool
    note: str


@dataclass
class Login:
    user_id: str
    since: datetime


class Store:
    """Every mutable thing the demo host knows, behind one lock."""

    def __init__(
        self,
        users: tuple[User, ...],
        patients: tuple[Patient, ...],
        tasks: tuple[Task, ...],
    ) -> None:
        self._lock = threading.RLock()
        self.users = {u.id: u for u in users}
        self.patients = {p.id: p for p in patients}
        self.tasks = {t.id: t for t in tasks}
        self.logins: dict[str, Login] = {}
        self.documents: dict[str, ChartDocument] = {}
        self.archives: dict[str, ArchiveFiling] = {}
        self.queue_reauth: dict[str, QueueReauth] = {}
        #: user id -> the run they are part-way through, if any (Addendum 3 B).
        self.queue_runs: dict[str, QueueRun] = {}
        self.webhooks: list[WebhookRecord] = []
        self._seen_deliveries: set[str] = set()

    # ------------------------------------------------------------------ people
    def user_by_username(self, username: str) -> User | None:
        return next((u for u in self.users.values() if u.username == username), None)

    def user_by_id(self, user_id: str) -> User | None:
        return self.users.get(user_id)

    def start_login(self, user: User, now: datetime) -> str:
        key = secrets.token_urlsafe(24)
        with self._lock:
            self.logins[key] = Login(user_id=user.id, since=now)
        return key

    def end_login(self, key: str) -> None:
        with self._lock:
            self.logins.pop(key, None)

    def login(self, key: str | None) -> Login | None:
        return None if key is None else self.logins.get(key)

    # ------------------------------------------------------------------ tasks
    def tasks_for(self, user: User) -> list[Task]:
        """The worklist: documents rendered from a template. Reports have a page of their own."""
        return [t for t in self.tasks.values() if t.source == "template" and t.signer_for(user.id) is not None]

    def tasks_for_patient(self, patient_id: str) -> list[Task]:
        return [t for t in self.tasks.values() if t.patient_id == patient_id]

    def task_by_envelope(self, envelope_id: str) -> Task | None:
        return next((t for t in self.tasks.values() if t.envelope_id == envelope_id), None)

    def queue_for(self, user: User) -> list[Task]:
        """The documents waiting on this clinician's signature, in seed order.

        Order sign-offs, not reports: the queue exists to show one confirmation of identity
        covering a run of short, near-identical documents (Addendum 1 C). A twenty-five page
        report is read, not run through, and it has its own page.
        """
        return [
            t
            for t in self.tasks.values()
            if t.source == "template" and any(s.user_id == user.id and s.capacity == "clinician" for s in t.signers)
        ]

    # ------------------------------------------------------------------ reports (Addendum 2)
    def reports_for(self, user: User) -> list[Task]:
        """The host-document reports this clinician has a part in, in seed order."""
        return [t for t in self.tasks.values() if t.source == "host_document" and t.signer_for(user.id) is not None]

    def upload_for(self, task: Task) -> bytes:
        """Render this task's report, once, and remember the bytes.

        Once, because the same task must upload the same document: the ``Idempotency-Key`` on
        ``POST /v1/envelopes`` hashes the document as well as the body, so a second attempt with a
        freshly rendered PDF would be a different request rather than a replay of this one. The
        renderer is deterministic anyway; this makes it true even if it ever stops being.
        """
        if task.report is None:
            raise ValueError("this task has no report to render")
        with self._lock:
            if task.upload is None:
                pdf = render(task.report)
                task.upload = pdf
                task.upload_sha256 = hashlib.sha256(pdf).hexdigest()
            return task.upload

    # ------------------------------------------------------------------ paper archives
    def record_archive(self, filing: ArchiveFiling) -> None:
        with self._lock:
            self.archives[filing.envelope_id] = filing

    def archives_for(self, patient_id: str) -> list[ArchiveFiling]:
        return [a for a in self.archives.values() if a.patient_id == patient_id]

    # ------------------------------------------------------------------ chart
    def file_document(self, document: ChartDocument) -> None:
        with self._lock:
            self.documents[document.id] = document

    def document_for_envelope(self, envelope_id: str) -> ChartDocument | None:
        return next((d for d in self.documents.values() if d.envelope_id == envelope_id), None)

    def documents_for(self, patient_id: str) -> list[ChartDocument]:
        found = [d for d in self.documents.values() if d.patient_id == patient_id]
        return sorted(found, key=lambda d: d.filed_at, reverse=True)

    # ------------------------------------------------------------------ webhooks
    def record_webhook(self, record: WebhookRecord) -> bool:
        """Store the delivery. False when this delivery id has already been handled -- delivery is
        at-least-once, so a repeat is normal and must not file a second copy of anything."""
        with self._lock:
            self.webhooks.insert(0, record)
            del self.webhooks[50:]
            if record.delivery_id in self._seen_deliveries:
                return False
            self._seen_deliveries.add(record.delivery_id)
            return True


# --------------------------------------------------------------------------- the seed


def build_store() -> Store:
    """Two patients, a guardian, a witness, two clinicians and a member of the front desk, with
    one worklist item per sample template, a queue of orders waiting on each clinician, and two
    generated reports for them to sign as host documents (Addendum 2)."""
    maria = Patient(id=str(uuid4()), mrn="mrn-100234", name="Maria Alvarez", date_of_birth="1971-04-02")
    sam = Patient(id=str(uuid4()), mrn="mrn-100907", name="Sam Okafor", date_of_birth="2017-11-19")

    users = (
        User(id="u-maria", username="maria", display_name="Maria Alvarez", role="patient", patient_id=maria.id),
        User(id="u-sam", username="sam", display_name="Sam Okafor", role="patient", patient_id=sam.id),
        User(
            id="u-grace",
            username="grace",
            display_name="Grace Okafor",
            role="guardian",
            patient_id=sam.id,
            job_title="Parent of Sam Okafor",
        ),
        User(id="u-ben", username="ben", display_name="Ben Doyle", role="witness", job_title="Clinic volunteer"),
        User(
            id="u-priya",
            username="priya",
            display_name="Dr. Priya Raman",
            role="clinician",
            job_title="Consultant surgeon",
        ),
        User(id="u-tomas", username="tomas", display_name="Dr. Tomas Silva", role="clinician", job_title="Registrar"),
        User(id="u-alice", username="alice", display_name="Alice Wu", role="staff", job_title="Front desk"),
    )

    tasks = (
        Task(
            id=str(uuid4()),
            title="Acknowledgement of privacy practices",
            template_key="hipaa_acknowledgement",
            patient_id=maria.id,
            signing_order="parallel",
            signers=(TaskSigner(role_key="patient", role_label="Patient", user_id="u-maria", capacity="self"),),
            prefill={"patient_name": maria.name, "notice_version": "2026-03"},
            note="One signer. Signs, seals, and the copy is ready straight away.",
        ),
        Task(
            id=str(uuid4()),
            title="Consent to treatment",
            template_key="patient_consent",
            patient_id=sam.id,
            signing_order="parallel",
            signers=(
                TaskSigner(
                    role_key="patient",
                    role_label="Patient or guardian",
                    user_id="u-grace",
                    capacity="guardian",
                    on_behalf_of=sam.mrn,
                ),
            ),
            prefill={
                "patient_name": sam.name,
                "date_of_birth": sam.date_of_birth,
                "treatment_summary": (
                    "A course of six weeks of physiotherapy for the left ankle, with a review "
                    "appointment at the end of it."
                ),
            },
            note="A guardian signs on behalf of a child. The signature is attributed to the guardian, in that capacity.",
        ),
        Task(
            id=str(uuid4()),
            title="Consent to a procedure",
            template_key="procedure_consent",
            patient_id=maria.id,
            signing_order="sequential",
            signers=(
                TaskSigner(role_key="patient", role_label="Patient", user_id="u-maria", capacity="self"),
                TaskSigner(role_key="witness", role_label="Witness", user_id="u-ben", capacity="witness"),
                TaskSigner(role_key="clinician", role_label="Clinician", user_id="u-priya", capacity="clinician"),
            ),
            prefill={
                "patient_name": maria.name,
                "date_of_birth": maria.date_of_birth,
                "procedure_name": "Right knee arthroscopy",
                "procedure_description": (
                    "A camera is passed into the knee joint through two small cuts so the cartilage "
                    "can be looked at and trimmed where it is torn. It is done under a general "
                    "anaesthetic and takes about forty minutes."
                ),
                "known_risks": (
                    "Bleeding or bruising around the knee. Infection, which is uncommon and is "
                    "usually treated with antibiotics. A blood clot in the leg. Stiffness that "
                    "takes several weeks of physiotherapy to settle. Numbness in a small patch of "
                    "skin near the cuts, which is usually temporary."
                ),
            },
            note="Three signers in order: the patient, then the witness, then the clinician, who has to confirm who they are again before signing.",
        ),
        Task(
            id=str(uuid4()),
            title="Consent to treatment (physiotherapy)",
            template_key="patient_consent",
            patient_id=maria.id,
            signing_order="parallel",
            signers=(TaskSigner(role_key="patient", role_label="Patient", user_id="u-maria", capacity="self"),),
            prefill={
                "patient_name": maria.name,
                "date_of_birth": maria.date_of_birth,
                "treatment_summary": (
                    "Eight weeks of physiotherapy for the right knee after the arthroscopy, twice a "
                    "week, with a review at the end."
                ),
            },
            note="The one to run on the clinic tablet: the front desk starts it, the patient signs it there, and the tablet comes back.",
        ),
        # Sam's own documents (he is old enough to have a portal login of his own in this demo):
        # one to sign on the portal, one for the clinic tablet, one for afterwards. Together they
        # show that a signature saved on the portal is never offered on a shared tablet, and that
        # the front desk can take a saved signature away.
        Task(
            id=str(uuid4()),
            title="Acknowledgement of privacy practices (annual)",
            template_key="hipaa_acknowledgement",
            patient_id=sam.id,
            signing_order="parallel",
            signers=(TaskSigner(role_key="patient", role_label="Patient", user_id="u-sam", capacity="self"),),
            prefill={"patient_name": sam.name, "notice_version": "2026-03"},
            note="Sam signs this one himself. Tick 'Save this signature for next time' to keep it.",
        ),
        Task(
            id=str(uuid4()),
            title="Consent to treatment (hydrotherapy)",
            template_key="patient_consent",
            patient_id=sam.id,
            signing_order="parallel",
            signers=(TaskSigner(role_key="patient", role_label="Patient", user_id="u-sam", capacity="self"),),
            prefill={
                "patient_name": sam.name,
                "date_of_birth": sam.date_of_birth,
                "treatment_summary": "Six sessions of hydrotherapy for the left ankle, weekly.",
            },
            note="For the clinic tablet. A shared tablet is never offered a saved signature, whatever Sam kept on the portal.",
        ),
        Task(
            id=str(uuid4()),
            title="Consent to treatment (review appointment)",
            template_key="patient_consent",
            patient_id=sam.id,
            signing_order="parallel",
            signers=(TaskSigner(role_key="patient", role_label="Patient", user_id="u-sam", capacity="self"),),
            prefill={
                "patient_name": sam.name,
                "date_of_birth": sam.date_of_birth,
                "treatment_summary": "A review of the ankle at the end of the physiotherapy course.",
            },
            note="Open this after the front desk has removed Sam's saved signature from 'People': it is no longer offered.",
        ),
        *_orders(
            "u-priya",
            (
                (maria, "ORD-4471", "Physiotherapy, right knee: eight weeks, twice weekly, review at the end."),
                (sam, "ORD-4472", "Ankle X-ray, left, two views, before the physiotherapy review."),
                (maria, "ORD-4473", "Pre-operative bloods: full blood count, clotting screen, group and save."),
                (sam, "ORD-4474", "Physiotherapy, left ankle: six weeks, weekly, with a home programme."),
                (maria, "ORD-4475", "Knee brace, right, off-the-shelf, to be fitted at the next appointment."),
            ),
        ),
        *_orders(
            "u-tomas",
            (
                (sam, "ORD-4480", "Paediatric physiotherapy referral, left ankle, six weeks."),
                (maria, "ORD-4481", "Repeat prescription review: analgesia for the right knee, four weeks."),
            ),
        ),
        *_reports(maria, sam),
    )
    return Store(users=users, patients=(maria, sam), tasks=tasks)


def _orders(clinician_id: str, orders: tuple[tuple[Patient, str, str], ...]) -> tuple[Task, ...]:
    """A clinician's queue: one ``clinical_order`` sign-off per order, each its own envelope with
    the clinician as its only signer. Re-authentication is required for every one; with the span
    on (Addendum 1 C) one confirmation covers the run."""
    return tuple(
        Task(
            id=str(uuid4()),
            title=f"Order sign-off {reference}",
            template_key="clinical_order",
            patient_id=patient.id,
            signing_order="parallel",
            signers=(
                TaskSigner(role_key="clinician", role_label="Clinician", user_id=clinician_id, capacity="clinician"),
            ),
            prefill={"patient_name": patient.name, "order_reference": reference, "order_summary": summary},
            note="A clinician's sign-off. One of the signing queue: confirm your identity once, then sign each in turn.",
        )
        for patient, reference, summary in orders
    )


#: The document type a generated report is filed under. It has to be on the signing service's
#: approved list before any of this works -- compliance decides what may be signed electronically,
#: whoever rendered the PDF -- so `demo.sh` adds it to APPROVED_DOCUMENT_TYPES.
REPORT_DOCUMENT_TYPE = "clinical_report"


def _reports(maria: Patient, sam: Patient) -> tuple[Task, ...]:
    """Addendum 2: two reports this records system generates itself and supplies to the service.

    A long one signed by the clinician who wrote it, and a shorter one a registrar co-signs after
    the consultant, in that order. Both carry a named signature block on the last page and no
    template anywhere.
    """
    today = datetime.now(UTC).date().isoformat()
    priya = "Dr. Priya Raman"
    tomas = "Dr. Tomas Silva"
    return (
        Task(
            id=str(uuid4()),
            title="Annual care summary",
            patient_id=maria.id,
            signing_order="parallel",
            signers=(
                TaskSigner(
                    role_key="clinician",
                    role_label="Responsible clinician",
                    user_id="u-priya",
                    capacity="clinician",
                ),
            ),
            source="host_document",
            document_type=REPORT_DOCUMENT_TYPE,
            report=Report(
                title="Annual care summary",
                reference="RPT-2291",
                pages=30,
                patient_name=maria.name,
                patient_dob=maria.date_of_birth,
                patient_ref=maria.mrn,
                prepared_on=today,
                prepared_by=priya,
                blocks=(SignatureBlock(role_key="clinician", caption="Responsible clinician", expected_name=priya),),
            ),
            note=(
                "Thirty pages of this patient's own record, generated here and uploaded to the signing "
                "service as the document itself. No template exists for it and none could."
            ),
        ),
        Task(
            id=str(uuid4()),
            title="Multidisciplinary case review",
            patient_id=sam.id,
            signing_order="sequential",
            signers=(
                TaskSigner(
                    role_key="clinician",
                    role_label="Responsible clinician",
                    user_id="u-priya",
                    capacity="clinician",
                ),
                TaskSigner(
                    role_key="cosigner",
                    role_label="Co-signing clinician",
                    user_id="u-tomas",
                    capacity="clinician",
                ),
            ),
            source="host_document",
            document_type=REPORT_DOCUMENT_TYPE,
            report=Report(
                title="Multidisciplinary case review",
                reference="RPT-2292",
                pages=25,
                patient_name=sam.name,
                patient_dob=sam.date_of_birth,
                patient_ref=sam.mrn,
                prepared_on=today,
                prepared_by=priya,
                blocks=(
                    SignatureBlock(role_key="clinician", caption="Responsible clinician", expected_name=priya),
                    SignatureBlock(role_key="cosigner", caption="Co-signing clinician", expected_name=tomas),
                ),
            ),
            note=(
                "Two signature blocks on the last page, so two roles: the consultant signs, then the "
                "registrar co-signs. Both confirm who they are before signing."
            ),
        ),
    )
