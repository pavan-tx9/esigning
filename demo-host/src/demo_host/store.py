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
    "ChartDocument",
    "Login",
    "Patient",
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
    #: Set while a member of staff is running this task on the clinic tablet.
    kiosk: tuple[str, str] | None = None  # (staff_user_id, identity_check)

    def signer_for(self, user_id: str) -> TaskSigner | None:
        return next((s for s in self.signers if s.user_id == user_id), None)


@dataclass(frozen=True)
class ChartDocument:
    """A sealed PDF filed in a patient's chart."""

    id: str
    patient_id: str
    title: str
    envelope_id: str
    template_key: str
    sealed_sha256: str
    filed_at: datetime
    pdf: bytes


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
    one worklist item per sample template."""
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
    )
    return Store(users=users, patients=(maria, sam), tasks=tasks)
