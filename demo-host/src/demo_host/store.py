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

import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal
from uuid import uuid4

__all__ = [
    "ArchiveFiling",
    "ChartDocument",
    "Login",
    "Patient",
    "QueueReauth",
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
    """A document somebody has to sign. The EHR's side of an envelope."""

    id: str
    title: str
    template_key: str
    patient_id: str
    signing_order: Literal["sequential", "parallel"]
    signers: tuple[TaskSigner, ...]
    prefill: dict[str, str]
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

    def signer_for(self, user_id: str) -> TaskSigner | None:
        return next((s for s in self.signers if s.user_id == user_id), None)

    @property
    def is_finished(self) -> bool:
        return self.envelope_status in {"sealed", "declined", "voided", "expired", "completed_pending_seal"}


@dataclass(frozen=True)
class ChartDocument:
    """A sealed PDF filed in a patient's chart: signed electronically, or a scan of a paper
    original that staff filed and the service sealed (Addendum 1 A)."""

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
        return [t for t in self.tasks.values() if t.signer_for(user.id) is not None]

    def tasks_for_patient(self, patient_id: str) -> list[Task]:
        return [t for t in self.tasks.values() if t.patient_id == patient_id]

    def task_by_envelope(self, envelope_id: str) -> Task | None:
        return next((t for t in self.tasks.values() if t.envelope_id == envelope_id), None)

    def queue_for(self, user: User) -> list[Task]:
        """The documents waiting on this clinician's signature, in seed order."""
        return [
            t for t in self.tasks.values() if any(s.user_id == user.id and s.capacity == "clinician" for s in t.signers)
        ]

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
    one worklist item per sample template and a queue of orders waiting on each clinician."""
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
            ),
        ),
        *_orders(
            "u-tomas",
            (
                (sam, "ORD-4480", "Paediatric physiotherapy referral, left ankle, six weeks."),
                (maria, "ORD-4481", "Repeat prescription review: analgesia for the right knee, four weeks."),
            ),
        ),
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
