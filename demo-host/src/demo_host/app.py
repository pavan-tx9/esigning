"""A stand-in EHR.

It exists to prove the signing service works from the outside: it logs people in, shows them a
worklist, creates envelopes over the Host API, embeds the signing UI in an iframe and speaks the
parent half of the embedding protocol, runs a clinic tablet in kiosk mode, receives and verifies
webhooks, and files the sealed PDF in a chart where anybody can re-verify it.

It is deliberately plain. Server-rendered HTML, one small stylesheet, no build step, no framework
on the page beyond the twenty lines of JavaScript the embedding protocol actually needs. Nothing
here is a pattern to copy into a product except those twenty lines and the webhook check.

Two things it does copy from a real host, because getting them wrong would invalidate the demo:

* the API key and the session token never reach the browser as anything but a ``postMessage``
  payload -- in particular, no token is ever put in a URL;
* no name, medical record number or date of birth appears in a path or a query string.
"""

from __future__ import annotations

import json
import secrets
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any
from uuid import uuid4

from fastapi import Cookie, FastAPI, File, Form, Request, Response, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from demo_host.config import Config, load_config
from demo_host.esign_api import EsignApiError, EsignClient
from demo_host.signatures import SIGNATURE_HEADER, verify_signature
from demo_host.store import (
    IDENTITY_CHECK_LABELS,
    ArchiveFiling,
    ChartDocument,
    QueueReauth,
    QueueRun,
    Store,
    Task,
    TaskSigner,
    User,
    WebhookRecord,
    build_store,
)

__all__ = ["create_app"]

_HERE = Path(__file__).resolve().parent
SESSION_COOKIE = "demo_session"

#: What a clinic tablet says it did to check the person in front of it.
IDENTITY_CHECKS = tuple(IDENTITY_CHECK_LABELS)

#: A signing session lasts 30 minutes on the service; one younger than this is reused rather than
#: replaced, because replacing it revokes it and a re-authentication attested on it with it.
SESSION_REUSE = timedelta(minutes=25)

#: Where a page may send somebody back to after signing. A closed list, so a return address can
#: never be a link somebody else chose.
RETURN_URLS = {
    "/worklist": "Back to the worklist",
    "/queue": "Back to the signing queue",
    "/reports": "Back to the reports",
}

#: The paper documents staff can file (Addendum 1 A). The document type is what the service's
#: retention and approval rules key on; the title is this EHR's own label for the chart.
ARCHIVE_DOCUMENT_TYPES = {
    "patient_consent": "Consent to treatment",
    "hipaa_acknowledgement": "Acknowledgement of privacy practices",
    "procedure_consent": "Consent to a procedure",
    "clinical_order": "Clinical order sign-off",
}
DISPOSITIONS = {
    "retained": "The paper original is kept on file",
    "returned_to_signer": "The paper original was returned to the signer",
    "destroyed_per_policy": "The paper original was destroyed under the retention policy",
}
PAPER_CAPACITIES = ("self", "guardian", "proxy", "witness", "interpreter", "clinician")
MAX_SCAN_BYTES = 20 * 1024 * 1024


def _now() -> datetime:
    return datetime.now(UTC)


def _is_date(value: str) -> bool:
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def create_app(
    config: Config | None = None, *, store: Store | None = None, client: EsignClient | None = None
) -> FastAPI:
    settings = config or load_config()
    state = store or build_store()
    esign = client or EsignClient(settings.api_url, settings.api_key)

    app = FastAPI(title="Demo EHR", docs_url=None, redoc_url=None)
    app.mount("/static", StaticFiles(directory=_HERE / "static"), name="static")
    pages = Jinja2Templates(directory=str(_HERE / "templates"))
    pages.env.globals["identity_check_labels"] = IDENTITY_CHECK_LABELS
    pages.env.globals["archive_document_types"] = ARCHIVE_DOCUMENT_TYPES
    pages.env.globals["dispositions"] = DISPOSITIONS
    pages.env.globals["paper_capacities"] = PAPER_CAPACITIES

    # ------------------------------------------------------------------ helpers

    def render(request: Request, name: str, context: dict[str, Any], status_code: int = 200) -> HTMLResponse:
        user = context.get("user")
        return pages.TemplateResponse(
            request,
            name,
            {**context, "config": settings, "signed_in": user is not None},
            status_code=status_code,
            headers={"Cache-Control": "no-store"},
        )

    def current_user(key: str | None) -> User | None:
        login = state.login(key)
        return None if login is None else state.user_by_id(login.user_id)

    def login_time(key: str | None) -> datetime:
        login = state.login(key)
        return _now() if login is None else login.since

    def to_login() -> RedirectResponse:
        return RedirectResponse("/", status_code=303)

    def problem(request: Request, user: User | None, title: str, detail: str, status_code: int = 400) -> HTMLResponse:
        return render(request, "problem.html", {"user": user, "title": title, "detail": detail}, status_code)

    def may_see_chart(user: User, patient_id: str) -> bool:
        return user.role in {"clinician", "staff"} or user.patient_id == patient_id

    def signers_body(task: Task) -> list[dict[str, Any]]:
        """The signers of this task's envelope, as the host API takes them.

        ``on_behalf_of`` is the patient's MRN, because it has to be opaque -- it reaches the audit
        trail. ``on_behalf_of_display`` is the same person in the words a parent would use, and it
        is the patient's own name rather than a second field on the task: a guardian's
        ``on_behalf_of`` is required to equal the envelope's ``patient_ref``, so there is exactly
        one person it can name, and writing it twice is one more place for them to disagree.
        """
        return [
            {
                "role_key": signer.role_key,
                "host_user_id": state.users[signer.user_id].id,
                "display_name": state.users[signer.user_id].display_name,
                "capacity": signer.capacity,
                "on_behalf_of": signer.on_behalf_of,
                "on_behalf_of_display": None if signer.on_behalf_of is None else state.patients[task.patient_id].name,
            }
            for signer in task.signers
        ]

    def signer_roles_body(task: Task) -> list[dict[str, Any]]:
        """The roles a host document is signed by, in the shape a template version carries them.

        A template publishes these once; a generated report has no template, so the request says
        them. They are derived from the task's own signers rather than written out twice: the
        capacity each role allows is the capacity that role signs in, and a clinician's signature
        always needs a fresh confirmation of who they are.
        """
        return [
            {
                "key": signer.role_key,
                "label": signer.role_label,
                "allowed_capacities": [signer.capacity],
                "requires_reauth": signer.capacity == "clinician",
                "order_index": index,
                "required": True,
            }
            for index, signer in enumerate(task.signers)
        ]

    def ensure_envelope(task: Task) -> dict[str, Any]:
        """Create the envelope the first time somebody opens this task, then reuse it.

        The idempotency key is the task id, so two people opening the same task at the same moment
        get one envelope rather than two. Addendum 2: a report takes the other path through the
        same route -- multipart, with the PDF this system generated.
        """
        if task.envelope_id is not None:
            return esign.envelope(task.envelope_id)
        patient = state.patients[task.patient_id]
        if task.source == "host_document":
            assert task.report is not None and task.document_type is not None
            view = esign.create_document_envelope(
                document=state.upload_for(task),
                filename=f"{task.report.reference}.pdf",
                document_type=task.document_type,
                patient_ref=patient.mrn,
                host_document_ref=f"report-{task.id}",
                signing_order=task.signing_order,
                signers=signers_body(task),
                signer_roles=signer_roles_body(task),
                idempotency_key=task.id,
            )
        else:
            assert task.template_key is not None
            view = esign.create_envelope(
                template_key=task.template_key,
                patient_ref=patient.mrn,
                host_document_ref=f"task-{task.id}",
                signing_order=task.signing_order,
                signers=signers_body(task),
                prefill=task.prefill,
                idempotency_key=task.id,
            )
        absorb(task, view)
        return view

    def absorb(task: Task, view: dict[str, Any]) -> None:
        """Take what the service says about an envelope as the truth about the task."""
        task.envelope_id = str(view["id"])
        task.envelope_status = str(view["status"])
        for signer in view.get("signers", []):
            role = str(signer["role_key"])
            task.signer_ids[role] = str(signer["id"])
            task.signer_status[role] = str(signer["status"])

    def refresh(task: Task) -> str | None:
        """Ask the service where the task has got to. Returns an error code if it could not."""
        if task.envelope_id is None:
            return None
        try:
            absorb(task, esign.envelope(task.envelope_id))
        except EsignApiError as exc:
            return exc.code
        return None

    def signer_for(task: Task, user: User) -> TaskSigner | None:
        """Who is about to sign. On the clinic tablet that is the patient, never the member of
        staff holding it (SPEC section 8)."""
        if task.kiosk is not None and user.is_staff:
            return next((s for s in task.signers if s.role_key == "patient"), None)
        return task.signer_for(user.id)

    def waiting_for(task: Task, signer: TaskSigner) -> str | None:
        """For a sequential task, the role this one is waiting on."""
        if task.signing_order != "sequential":
            return None
        for other in task.signers:
            if other.role_key == signer.role_key:
                return None
            if task.signer_status.get(other.role_key, "pending") != "signed":
                return other.role_label
        return None

    # ------------------------------------------------------------------ login

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request, demo_session: Annotated[str | None, Cookie()] = None) -> Response:
        if current_user(demo_session) is not None:
            return RedirectResponse("/worklist", status_code=303)
        return render(
            request,
            "login.html",
            {"user": None, "users": list(state.users.values()), "patients": state.patients, "failed": False},
        )

    @app.post("/login")
    def login(
        request: Request,
        username: Annotated[str, Form()],
        password: Annotated[str, Form()],
        demo_session: Annotated[str | None, Cookie()] = None,
    ) -> Response:
        user = state.user_by_username(username.strip())
        # A demo, not an authentication system: one shared password, compared in constant time so
        # nobody reads this and copies the wrong half.
        if user is None or not secrets.compare_digest(password, settings.password):
            return render(
                request,
                "login.html",
                {"user": None, "users": list(state.users.values()), "patients": state.patients, "failed": True},
                status_code=401,
            )
        if demo_session is not None:
            state.end_login(demo_session)
        key = state.start_login(user, _now())
        response = RedirectResponse("/worklist", status_code=303)
        response.set_cookie(SESSION_COOKIE, key, httponly=True, samesite="lax", path="/")
        return response

    @app.post("/logout")
    def logout(demo_session: Annotated[str | None, Cookie()] = None) -> Response:
        if demo_session is not None:
            state.end_login(demo_session)
        response = RedirectResponse("/", status_code=303)
        response.delete_cookie(SESSION_COOKIE, path="/")
        return response

    # ------------------------------------------------------------------ worklist

    @app.get("/worklist", response_class=HTMLResponse)
    def worklist(
        request: Request,
        problem_code: str | None = None,
        demo_session: Annotated[str | None, Cookie()] = None,
    ) -> Response:
        user = current_user(demo_session)
        if user is None:
            return to_login()
        rows = []
        unreachable: str | None = None
        for task in state.tasks_for(user):
            unreachable = refresh(task) or unreachable
            signer = task.signer_for(user.id)
            assert signer is not None
            rows.append(
                {
                    "task": task,
                    "signer": signer,
                    "patient": state.patients[task.patient_id],
                    "my_status": task.signer_status.get(signer.role_key, "pending"),
                    "waiting_for": waiting_for(task, signer),
                    "document": state.document_for_envelope(task.envelope_id or ""),
                }
            )
        return render(
            request,
            "worklist.html",
            {
                "user": user,
                "rows": rows,
                "problem_code": problem_code,
                "unreachable": unreachable,
                "chart": state.patients.get(user.patient_id or ""),
                "patients": list(state.patients.values()),
            },
        )

    @app.post("/tasks/{task_id}/open")
    def open_task(
        task_id: str,
        return_to: Annotated[str, Form()] = "/worklist",
        demo_session: Annotated[str | None, Cookie()] = None,
    ) -> Response:
        """Create the envelope if it does not exist, start a signing session for this person, and
        send them to the page that embeds the signing UI. The token stays here."""
        user = current_user(demo_session)
        if user is None:
            return to_login()
        back = return_to if return_to in RETURN_URLS else "/worklist"
        task = state.tasks.get(task_id)
        if task is None or task.signer_for(user.id) is None:
            return RedirectResponse(f"{back}?problem_code=not_your_task", status_code=303)
        try:
            ensure_envelope(task)
            started = start_session(task, user, demo_session)
        except EsignApiError as exc:
            return RedirectResponse(f"{back}?problem_code={exc.code}", status_code=303)
        if started is None:
            return RedirectResponse(f"{back}?problem_code=no_signer", status_code=303)
        if back == "/queue":
            # Addendum 3 B: opening a document from the queue starts a run through it. From here
            # the documents open one after another in the same frame; the list is not come back to.
            start_queue_run(user, task)
        return RedirectResponse(
            f"/sign/{task.id}" + (f"?return_to={back}" if back != "/worklist" else ""), status_code=303
        )

    def start_session(task: Task, user: User, session_key: str | None) -> TaskSigner | None:
        """Start a signing session for this person on this task, or reuse the one already running.

        The service revokes a signer's previous session whenever a new one is created, and a
        re-authentication attested on a revoked session covers nothing. A queue confirms identity
        on the first document's session *before* that document is opened, so opening it has to
        keep that session rather than mint another.
        """
        signer = signer_for(task, user)
        if signer is None or task.envelope_id is None:
            return None
        signer_id = task.signer_ids.get(signer.role_key)
        if signer_id is None:
            return None
        started = task.session_started.get(signer.role_key)
        if signer.role_key in task.sessions and started is not None and _now() - started < SESSION_REUSE:
            return signer
        kiosk = task.kiosk
        created = esign.create_session(
            envelope_id=task.envelope_id,
            signer_id=signer_id,
            method="staff_verified" if kiosk is not None else "password",
            auth_time=login_time(session_key),
            kiosk=kiosk,
        )
        task.sessions[signer.role_key] = (str(created["session_id"]), str(created["token"]))
        task.session_started[signer.role_key] = _now()
        return signer

    # ------------------------------------------------------------------ the signing queue (Addendum 1 C)

    def queue_rows(user: User) -> tuple[list[dict[str, Any]], str | None]:
        rows: list[dict[str, Any]] = []
        unreachable: str | None = None
        for task in state.queue_for(user):
            unreachable = refresh(task) or unreachable
            signer = task.signer_for(user.id)
            assert signer is not None
            my_status = task.signer_status.get(signer.role_key, "pending")
            rows.append(
                {
                    "task": task,
                    "patient": state.patients[task.patient_id],
                    "my_status": my_status,
                    "ready": my_status not in {"signed", "declined"}
                    and not task.is_finished
                    and waiting_for(task, signer) is None,
                    "document": state.document_for_envelope(task.envelope_id or ""),
                }
            )
        return rows, unreachable

    @app.get("/queue", response_class=HTMLResponse)
    def queue(
        request: Request,
        problem_code: str | None = None,
        demo_session: Annotated[str | None, Cookie()] = None,
    ) -> Response:
        """A clinician's signing queue: the documents waiting on them, one confirmation of their
        identity, then each document in turn. The service is configured with a re-authentication
        span for the demo, so the confirmation made on the first document covers the rest for a
        few minutes; every signature still records which confirmation it rests on."""
        user = current_user(demo_session)
        if user is None:
            return to_login()
        if user.role != "clinician":
            return problem(request, user, "Clinicians only", "The signing queue is for clinicians' sign-offs.", 403)
        rows, unreachable = queue_rows(user)
        return render(
            request,
            "queue.html",
            {
                "user": user,
                "rows": rows,
                "problem_code": problem_code,
                "unreachable": unreachable,
                "reauth": state.queue_reauth.get(user.id),
                "now": _now(),
            },
        )

    @app.post("/queue/reauth")
    def queue_reauth(
        password: Annotated[str, Form()],
        demo_session: Annotated[str | None, Cookie()] = None,
    ) -> Response:
        """Confirm the clinician's identity once for the queue.

        The service has no "re-authenticate this user" call, on purpose: an attestation belongs to
        a session, and a session belongs to one signer of one document. So the first document in
        the queue gets its envelope and session here, the attestation is made on that session, and
        with the span on the service lets the clinician's other sessions borrow it. The password
        is checked by this EHR, and the attestation goes server to server, exactly as on the
        signing page.
        """
        user = current_user(demo_session)
        if user is None:
            return to_login()
        if user.role != "clinician":
            return RedirectResponse("/worklist?problem_code=clinicians_only", status_code=303)
        if not secrets.compare_digest(password, settings.password):
            return RedirectResponse("/queue?problem_code=wrong_password", status_code=303)
        rows, _ = queue_rows(user)
        first = next((row["task"] for row in rows if row["ready"]), None)
        if first is None:
            return RedirectResponse("/queue?problem_code=nothing_to_sign", status_code=303)
        try:
            ensure_envelope(first)
            started = start_session(first, user, demo_session)
            if started is None:
                return RedirectResponse("/queue?problem_code=no_signer", status_code=303)
            session_id = first.sessions[started.role_key][0]
            result = esign.reauth(session_id=session_id, method="password", auth_time=_now())
        except EsignApiError as exc:
            return RedirectResponse(f"/queue?problem_code={exc.code}", status_code=303)
        state.queue_reauth[user.id] = QueueReauth(
            at=_now(), valid_until=str(result.get("reauth_valid_until", "")), session_id=session_id
        )
        return RedirectResponse("/queue", status_code=303)

    # ------------------------------------------------------------ the run through it (Addendum 3 B)

    def still_to_sign(task: Task, user: User) -> bool:
        """Is this document still waiting for this person? Asked of the service, not remembered."""
        signer = signer_for(task, user)
        if signer is None:
            return False
        refresh(task)
        status = task.signer_status.get(signer.role_key, "pending")
        return status not in {"signed", "declined"} and not task.is_finished and waiting_for(task, signer) is None

    def start_queue_run(user: User, task: Task) -> None:
        """Fix the order of a run, starting at the document being opened.

        Fixed on purpose. A list recomputed after each signature would shrink as documents left
        it, and the counter the signing UI shows would walk from "3 of 5" towards "1 of 1" while
        the clinician was still working. Reports are not in it, because they are not in the queue.
        """
        ready = [row["task"].id for row in queue_rows(user)[0] if row["ready"]]
        if task.id not in ready:
            state.queue_runs.pop(user.id, None)
            return
        state.queue_runs[user.id] = QueueRun(tasks=tuple(ready), position=ready.index(task.id))

    def queue_position(user: User, task: Task) -> dict[str, Any] | None:
        """What the signing UI is told about the run: where this document sits and what follows.

        Just a counter and a title. The UI never fetches the next document itself -- it asks, with
        ``esign:next``, and this host decides what that means.
        """
        run = state.queue_runs.get(user.id)
        at = None if run is None else run.index_of(task.id)
        if run is None or at is None:
            return None
        run.position = at
        following = state.tasks.get(run.tasks[at + 1]) if at + 1 < len(run.tasks) else None
        return {
            "index": at + 1,
            "total": len(run.tasks),
            "next_title": None if following is None else following.title,
        }

    @app.post("/queue/next")
    async def queue_next(request: Request, demo_session: Annotated[str | None, Cookie()] = None) -> Response:
        """``esign:next``: the signer has finished one document and the host opens the next.

        The frame is asking, so nothing it says is taken on trust: the document it claims to have
        finished has to be the one this host has open in this person's run, and the envelope id it
        names has to be the envelope this host created for it. The next document gets an envelope
        and a session of its own here, exactly as opening it from the list would have.
        """
        user = current_user(demo_session)
        if user is None:
            return JSONResponse({"error": "not_signed_in"}, status_code=401)
        body = await request.json()
        run = state.queue_runs.get(user.id)
        finished = state.tasks.get(str(body.get("after", "")))
        if run is None or finished is None or run.current != finished.id:
            return JSONResponse({"error": "not_in_this_run"}, status_code=409)
        claimed = body.get("envelope_id")
        if claimed is not None and str(claimed) != (finished.envelope_id or ""):
            return JSONResponse({"error": "envelope_mismatch"}, status_code=409)

        # The next one still waiting on this person. Anything signed elsewhere, withdrawn, or now
        # waiting on somebody else is stepped over rather than opened on a stale idea of the list.
        following: Task | None = None
        for position in range(run.position + 1, len(run.tasks)):
            candidate = state.tasks.get(run.tasks[position])
            if candidate is not None and still_to_sign(candidate, user):
                run.position, following = position, candidate
                break
        if following is None:
            state.queue_runs.pop(user.id, None)
            return JSONResponse({"done": True, "total": len(run.tasks)}, headers={"Cache-Control": "no-store"})

        try:
            ensure_envelope(following)
            started = start_session(following, user, demo_session)
        except EsignApiError as exc:
            return JSONResponse({"error": exc.code}, status_code=502)
        if started is None:
            return JSONResponse({"error": "no_signer"}, status_code=409)
        after_that = state.tasks.get(run.tasks[run.position + 1]) if run.position + 1 < len(run.tasks) else None
        return JSONResponse(
            {
                "done": False,
                "task_id": following.id,
                "title": following.title,
                "index": run.position + 1,
                "total": len(run.tasks),
                "next_title": None if after_that is None else after_that.title,
            },
            headers={"Cache-Control": "no-store"},
        )

    # ------------------------------------------------------------------ reports (Addendum 2)

    @app.get("/reports", response_class=HTMLResponse)
    def reports(
        request: Request,
        problem_code: str | None = None,
        demo_session: Annotated[str | None, Cookie()] = None,
    ) -> Response:
        """The reports waiting on this clinician's signature.

        Each one is a document this records system generates for this patient -- twenty-five or
        thirty pages of their own record, different every time -- and hands to the signing service
        as the document itself. There is no template: the service is told the document type, who
        signs it and in what roles, and finds the fields from the names in the signature block on
        the last page. Everything after that is the ordinary signing flow.
        """
        user = current_user(demo_session)
        if user is None:
            return to_login()
        if user.role != "clinician":
            return problem(request, user, "Clinicians only", "Reports are signed off by clinicians.", 403)
        rows = []
        unreachable: str | None = None
        for task in state.reports_for(user):
            unreachable = refresh(task) or unreachable
            signer = task.signer_for(user.id)
            assert signer is not None
            my_status = task.signer_status.get(signer.role_key, "pending")
            rows.append(
                {
                    "task": task,
                    "report": task.report,
                    "signer": signer,
                    "patient": state.patients[task.patient_id],
                    "my_status": my_status,
                    "waiting_for": waiting_for(task, signer),
                    "ready": my_status not in {"signed", "declined"}
                    and not task.is_finished
                    and waiting_for(task, signer) is None,
                    "document": state.document_for_envelope(task.envelope_id or ""),
                }
            )
        return render(
            request,
            "reports.html",
            {"user": user, "rows": rows, "problem_code": problem_code, "unreachable": unreachable},
        )

    @app.get("/reports/{task_id}/generated.pdf")
    def report_generated(task_id: str, demo_session: Annotated[str | None, Cookie()] = None) -> Response:
        """What this system rendered, before the service saw it.

        Worth having in a demo: the bytes on this link are the ones whose SHA-256 the reports page
        shows, the ones ``document.supplied`` records as the upload hash, and the ones the service
        flattened the widgets out of to make revision 1. The sealed copy in the chart is the other
        end of that chain.
        """
        user = current_user(demo_session)
        task = state.tasks.get(task_id)
        if user is None or task is None or task.source != "host_document":
            return JSONResponse({"error": "not_found"}, status_code=404)
        if task.signer_for(user.id) is None:
            return JSONResponse({"error": "not_your_report"}, status_code=403)
        return Response(
            state.upload_for(task),
            media_type="application/pdf",
            headers={"Cache-Control": "no-store", "Content-Disposition": 'inline; filename="report.pdf"'},
        )

    # ------------------------------------------------------------------ the embedded signing page

    @app.get("/sign/{task_id}", response_class=HTMLResponse)
    def sign_page(
        request: Request,
        task_id: str,
        return_to: str = "/worklist",
        demo_session: Annotated[str | None, Cookie()] = None,
    ) -> Response:
        user = current_user(demo_session)
        if user is None:
            return to_login()
        back = return_to if return_to in RETURN_URLS else "/worklist"
        task = state.tasks.get(task_id)
        if task is None:
            return problem(request, user, "No such document", "That document is not on this worklist.", 404)
        signer = signer_for(task, user)
        if signer is None or signer.role_key not in task.sessions:
            return RedirectResponse(f"{back}?problem_code=session_missing", status_code=303)
        return render(
            request,
            "sign.html",
            {
                "user": user,
                "task": task,
                "signer": signer,
                "patient": state.patients[task.patient_id],
                "kiosk": task.kiosk is not None,
                "kiosk_check": None if task.kiosk is None else IDENTITY_CHECK_LABELS.get(task.kiosk[1], task.kiosk[1]),
                "needs_reauth": signer.capacity == "clinician",
                "esign_origin": settings.ui_url,
                "frame_src": settings.signing_ui_src,
                "return_url": back,
                "return_label": RETURN_URLS[back],
                # Addendum 3 B: present only while this document is part of a run through the queue.
                "queue": queue_position(user, task) if back == "/queue" else None,
            },
        )

    @app.post("/sign/{task_id}/token")
    def sign_token(task_id: str, demo_session: Annotated[str | None, Cookie()] = None) -> Response:
        """The page asks for the token once the iframe says it is ready. It arrives in a response
        body, is handed straight to the iframe by ``postMessage``, and is never written down."""
        user = current_user(demo_session)
        task = state.tasks.get(task_id)
        if user is None or task is None:
            return JSONResponse({"error": "not_signed_in"}, status_code=401)
        signer = signer_for(task, user)
        if signer is None:
            return JSONResponse({"error": "not_your_task"}, status_code=403)
        live = task.sessions.get(signer.role_key)
        if live is None:
            return JSONResponse({"error": "session_missing"}, status_code=409)
        session_id, token = live
        return JSONResponse({"session_id": session_id, "token": token}, headers={"Cache-Control": "no-store"})

    @app.post("/sign/{task_id}/reauth")
    async def sign_reauth(
        task_id: str, request: Request, demo_session: Annotated[str | None, Cookie()] = None
    ) -> Response:
        """The host half of step 5. The signing UI cannot re-authenticate anybody: it asks us, we
        ask for the password ourselves, and then *our backend* attests to the service that the
        person proved who they were. The browser never touches that call."""
        user = current_user(demo_session)
        task = state.tasks.get(task_id)
        if user is None or task is None:
            return JSONResponse({"error": "not_signed_in"}, status_code=401)
        signer = signer_for(task, user)
        if signer is None:
            return JSONResponse({"error": "not_your_task"}, status_code=403)
        live = task.sessions.get(signer.role_key)
        if live is None:
            return JSONResponse({"error": "session_missing"}, status_code=409)
        body = await request.json()
        password = str(body.get("password", ""))
        if not secrets.compare_digest(password, settings.password):
            return JSONResponse({"error": "wrong_password"}, status_code=401)
        # The UI told us which session it wants re-authenticated. We know which session we created;
        # if they disagree, the message is not about this signing and is refused.
        claimed = body.get("session_id")
        if claimed is not None and str(claimed) != live[0]:
            return JSONResponse({"error": "session_mismatch"}, status_code=409)
        try:
            result = esign.reauth(session_id=live[0], method="password", auth_time=_now())
        except EsignApiError as exc:
            return JSONResponse({"error": exc.code}, status_code=502)
        return JSONResponse({"ok": True, "reauth_valid_until": result.get("reauth_valid_until")})

    @app.get("/sign/{task_id}/status")
    def sign_status(task_id: str, demo_session: Annotated[str | None, Cookie()] = None) -> Response:
        """What the page polls after the UI reports a signature, so it can say when the sealed copy
        has actually been filed in the chart rather than claiming it early."""
        user = current_user(demo_session)
        task = state.tasks.get(task_id)
        if user is None or task is None:
            return JSONResponse({"error": "not_signed_in"}, status_code=401)
        refresh(task)
        document = state.document_for_envelope(task.envelope_id or "")
        return JSONResponse(
            {
                "envelope_status": task.envelope_status,
                "signers": task.signer_status,
                "filed": document is not None,
                "document_url": None if document is None else f"/chart/document/{document.id}",
                "chart_url": f"/chart/{task.patient_id}",
            },
            headers={"Cache-Control": "no-store"},
        )

    # ------------------------------------------------------------------ kiosk

    @app.get("/kiosk", response_class=HTMLResponse)
    def kiosk(
        request: Request,
        problem_code: str | None = None,
        demo_session: Annotated[str | None, Cookie()] = None,
    ) -> Response:
        user = current_user(demo_session)
        if user is None:
            return to_login()
        if not user.is_staff:
            return problem(request, user, "Staff only", "The clinic tablet is started by the front desk.", 403)
        rows = []
        for task in state.tasks.values():
            if not any(s.role_key == "patient" for s in task.signers):
                continue
            refresh(task)
            patient_signer = next(s for s in task.signers if s.role_key == "patient")
            rows.append(
                {
                    "task": task,
                    "patient": state.patients[task.patient_id],
                    "signs": state.users[patient_signer.user_id],
                    "status": task.signer_status.get("patient", "pending"),
                }
            )
        return render(
            request,
            "kiosk.html",
            {"user": user, "rows": rows, "checks": IDENTITY_CHECKS, "problem_code": problem_code},
        )

    @app.post("/kiosk/start")
    def kiosk_start(
        task_id: Annotated[str, Form()],
        identity_check: Annotated[str, Form()],
        demo_session: Annotated[str | None, Cookie()] = None,
    ) -> Response:
        """A member of staff hands the tablet over. They say how they checked who the patient is;
        that choice is part of the evidence, so it is recorded with the session."""
        user = current_user(demo_session)
        if user is None:
            return to_login()
        if not user.is_staff:
            return RedirectResponse("/kiosk?problem_code=staff_only", status_code=303)
        task = state.tasks.get(task_id)
        if task is None or identity_check not in IDENTITY_CHECKS:
            return RedirectResponse("/kiosk?problem_code=bad_request", status_code=303)
        task.kiosk = (user.id, identity_check)
        try:
            ensure_envelope(task)
            started = start_session(task, user, demo_session)
        except EsignApiError as exc:
            task.kiosk = None
            return RedirectResponse(f"/kiosk?problem_code={exc.code}", status_code=303)
        if started is None:
            task.kiosk = None
            return RedirectResponse("/kiosk?problem_code=no_signer", status_code=303)
        return RedirectResponse(f"/sign/{task.id}", status_code=303)

    @app.post("/kiosk/finish")
    def kiosk_finish(task_id: Annotated[str, Form()], demo_session: Annotated[str | None, Cookie()] = None) -> Response:
        """The tablet is back with the front desk. Everything about that patient goes away here."""
        user = current_user(demo_session)
        if user is None:
            return to_login()
        task = state.tasks.get(task_id)
        if task is not None:
            task.kiosk = None
            task.sessions.pop("patient", None)
        return RedirectResponse("/kiosk", status_code=303)

    # ------------------------------------------------------------------ paper documents (Addendum 1 A)

    @app.get("/archive", response_class=HTMLResponse)
    def archive_form(
        request: Request,
        problem_code: str | None = None,
        demo_session: Annotated[str | None, Cookie()] = None,
    ) -> Response:
        user = current_user(demo_session)
        if user is None:
            return to_login()
        if not user.is_staff:
            return problem(request, user, "Staff only", "Paper documents are filed by the front desk.", 403)
        return render(
            request,
            "archive.html",
            {
                "user": user,
                "patients": list(state.patients.values()),
                "problem_code": problem_code,
                "today": _now().date().isoformat(),
            },
        )

    @app.post("/archive")
    async def archive_file(
        patient_id: Annotated[str, Form()],
        title: Annotated[str, Form(max_length=120)],
        document_type: Annotated[str, Form()],
        paper_signed_on: Annotated[str, Form()],
        original_disposition: Annotated[str, Form()],
        signer_name: Annotated[list[str], Form()],
        signer_capacity: Annotated[list[str], Form()],
        scan: Annotated[UploadFile, File()],
        true_copy: Annotated[str | None, Form()] = None,
        demo_session: Annotated[str | None, Cookie()] = None,
    ) -> Response:
        """File a scan of a document signed on paper (Addendum 1 A).

        The member of staff is the attesting party: their opaque user id goes to the service and
        into the audit trail, their display name onto the cover page and the certificate. The
        people who signed the paper are named on the cover page and the certificate only. What
        the seal will prove is that this scan has not changed since this moment, and who said it
        was a true copy -- not that the ink is genuine.
        """
        user = current_user(demo_session)
        if user is None:
            return to_login()
        if not user.is_staff:
            return RedirectResponse("/worklist?problem_code=staff_only", status_code=303)
        patient = state.patients.get(patient_id)
        signers = [
            {"display_name": name.strip(), "capacity": capacity}
            for name, capacity in zip(signer_name, signer_capacity, strict=False)
            if name.strip()
        ]
        if (
            patient is None
            or document_type not in ARCHIVE_DOCUMENT_TYPES
            or original_disposition not in DISPOSITIONS
            or true_copy != "yes"
            or not signers
            or any(s["capacity"] not in PAPER_CAPACITIES for s in signers)
            or not _is_date(paper_signed_on)
        ):
            return RedirectResponse("/archive?problem_code=incomplete", status_code=303)
        data = await scan.read(MAX_SCAN_BYTES + 1)
        if not data.startswith(b"%PDF") or len(data) > MAX_SCAN_BYTES:
            return RedirectResponse("/archive?problem_code=not_a_pdf", status_code=303)
        filing_id = str(uuid4())
        try:
            view = esign.file_archive(
                scan=data,
                filename="scan.pdf",
                patient_ref=patient.mrn,
                document_type=document_type,
                host_document_ref=f"paper-{filing_id}",
                paper_signed_on=paper_signed_on,
                attestation={
                    "staff_user_id": user.id,
                    "staff_display_name": user.display_name,
                    "statement": "true_copy",
                    "original_disposition": original_disposition,
                    "paper_signers": signers,
                },
                idempotency_key=filing_id,
            )
        except EsignApiError as exc:
            return RedirectResponse(f"/archive?problem_code={exc.code}", status_code=303)
        state.record_archive(
            ArchiveFiling(
                envelope_id=str(view["id"]),
                patient_id=patient.id,
                title=title.strip() or ARCHIVE_DOCUMENT_TYPES[document_type],
                document_type=document_type,
                paper_signed_on=paper_signed_on,
                filed_by=user.id,
                filed_at=_now(),
                envelope_status=str(view["status"]),
            )
        )
        return RedirectResponse(f"/chart/{patient.id}?filed=1", status_code=303)

    def refresh_archive(filing: ArchiveFiling) -> None:
        """Ask the service where the filing has got to, and file the sealed copy if the webhook
        has not already: the inline seal usually finishes inside the filing request itself."""
        try:
            view = esign.envelope(filing.envelope_id)
        except EsignApiError:
            return
        filing.envelope_status = str(view["status"])
        if filing.envelope_status == "sealed":
            _file_archive_in_chart(filing, str(view.get("sealed_sha256") or ""))

    def _file_archive_in_chart(filing: ArchiveFiling, sealed_sha256: str) -> None:
        if state.document_for_envelope(filing.envelope_id) is not None:
            return
        try:
            pdf = esign.sealed_document(filing.envelope_id)
        except EsignApiError:
            return
        state.file_document(
            ChartDocument(
                id=str(uuid4()),
                patient_id=filing.patient_id,
                title=filing.title,
                envelope_id=filing.envelope_id,
                template_key=None,
                sealed_sha256=sealed_sha256,
                filed_at=_now(),
                pdf=pdf,
                kind="paper_archive",
                paper_signed_on=filing.paper_signed_on,
            )
        )

    # ------------------------------------------------------------------ people (Addendum 1 B)

    @app.get("/people", response_class=HTMLResponse)
    def people(
        request: Request,
        result: str | None = None,
        demo_session: Annotated[str | None, Cookie()] = None,
    ) -> Response:
        """Everybody who signs here, with the one thing a host may do to a saved signature:
        remove it. There is no host call to create or read one -- staff cannot make a doctor's
        signature -- so this page cannot say whether a person has one saved."""
        user = current_user(demo_session)
        if user is None:
            return to_login()
        if not user.is_staff:
            return problem(request, user, "Staff only", "Saved signatures are removed by the front desk.", 403)
        return render(request, "people.html", {"user": user, "people": list(state.users.values()), "result": result})

    @app.post("/people/{user_id}/revoke-signature")
    def revoke_signature(user_id: str, demo_session: Annotated[str | None, Cookie()] = None) -> Response:
        """``POST /v1/users/{host_user_id}/adopted-signature/revoke``, server to server. The
        service answers 200 either way and says whether there was one to remove."""
        user = current_user(demo_session)
        if user is None:
            return to_login()
        if not user.is_staff or user_id not in state.users:
            return RedirectResponse("/people?result=refused", status_code=303)
        try:
            revoked = esign.revoke_adopted_signature(user_id)
        except EsignApiError as exc:
            return RedirectResponse(f"/people?result={exc.code}", status_code=303)
        return RedirectResponse(f"/people?result={'revoked' if revoked else 'nothing_saved'}", status_code=303)

    # ------------------------------------------------------------------ the chart

    @app.get("/chart/{patient_id}", response_class=HTMLResponse)
    def chart(
        request: Request,
        patient_id: str,
        filed: str | None = None,
        demo_session: Annotated[str | None, Cookie()] = None,
    ) -> Response:
        user = current_user(demo_session)
        if user is None:
            return to_login()
        patient = state.patients.get(patient_id)
        if patient is None:
            return problem(request, user, "No such chart", "That chart does not exist here.", 404)
        if not may_see_chart(user, patient_id):
            return problem(request, user, "Not your chart", "You can only open your own chart.", 403)
        pending: list[dict[str, str]] = []
        for task in state.tasks_for_patient(patient_id):
            refresh(task)
            if task.envelope_id is not None and state.document_for_envelope(task.envelope_id) is None:
                pending.append({"title": task.title, "status": task.envelope_status})
        for filing in state.archives_for(patient_id):
            refresh_archive(filing)
            if state.document_for_envelope(filing.envelope_id) is None:
                pending.append({"title": f"{filing.title} (paper)", "status": filing.envelope_status})
        return render(
            request,
            "chart.html",
            {
                "user": user,
                "patient": patient,
                "documents": state.documents_for(patient_id),
                "pending": pending,
                "just_filed": filed is not None,
            },
        )

    @app.get("/chart/document/{document_id}", response_class=HTMLResponse)
    def chart_document(
        request: Request, document_id: str, demo_session: Annotated[str | None, Cookie()] = None
    ) -> Response:
        user = current_user(demo_session)
        if user is None:
            return to_login()
        document = state.documents.get(document_id)
        if document is None or not may_see_chart(user, document.patient_id):
            return problem(request, user, "Not available", "That document is not in a chart you can open.", 404)
        return render(
            request,
            "document.html",
            {
                "user": user,
                "document": document,
                "patient": state.patients[document.patient_id],
                "report": None,
            },
        )

    @app.get("/chart/document/{document_id}/pdf")
    def chart_document_pdf(document_id: str, demo_session: Annotated[str | None, Cookie()] = None) -> Response:
        user = current_user(demo_session)
        if user is None:
            return to_login()
        document = state.documents.get(document_id)
        if document is None or not may_see_chart(user, document.patient_id):
            return JSONResponse({"error": "not_found"}, status_code=404)
        return Response(
            document.pdf,
            media_type="application/pdf",
            headers={
                "Cache-Control": "no-store",
                "Content-Disposition": 'attachment; filename="signed-document.pdf"',
            },
        )

    @app.post("/chart/document/{document_id}/verify", response_class=HTMLResponse)
    def chart_document_verify(
        request: Request, document_id: str, demo_session: Annotated[str | None, Cookie()] = None
    ) -> Response:
        """Ask the service to re-check the seal, every stored hash and the audit chain, now."""
        user = current_user(demo_session)
        if user is None:
            return to_login()
        document = state.documents.get(document_id)
        if document is None or not may_see_chart(user, document.patient_id):
            return problem(request, user, "Not available", "That document is not in a chart you can open.", 404)
        try:
            report: dict[str, Any] | None = esign.verification(document.envelope_id)
            failure = None
        except EsignApiError as exc:
            report, failure = None, exc.code
        return render(
            request,
            "document.html",
            {
                "user": user,
                "document": document,
                "patient": state.patients[document.patient_id],
                "report": report,
                "failure": failure,
            },
        )

    # ------------------------------------------------------------------ webhooks

    @app.post("/webhooks/esign")
    async def receive_webhook(request: Request) -> Response:
        """Every delivery is verified before it is believed, and an unverified one changes nothing.

        Nothing is *read* out of an unverified body either, not even the event name: a body whose
        signature does not check out is a stranger's assertion, and putting its words in this log
        would show them as if they were facts. So a refusal records that a delivery arrived and
        failed the check, and no more. That is not hypothetical here -- the service has other
        hosts, and another host's delivery, signed with another host's secret, is exactly what
        arriving at this URL unverified looks like.

        Delivery is at-least-once, so the payload's ``id`` is what makes filing happen once.
        """
        body = await request.body()
        header = request.headers.get(SIGNATURE_HEADER, "")
        if not verify_signature(settings.webhook_secret, body, header, now=_now()):
            state.record_webhook(
                WebhookRecord(
                    received_at=_now(),
                    event="",
                    envelope_id="",
                    delivery_id=str(uuid4()),
                    verified=False,
                    note="signature did not check out; nothing was read and nothing was changed",
                )
            )
            return JSONResponse({"error": "bad_signature"}, status_code=401)

        try:
            payload = json.loads(body)
        except ValueError:
            payload = {}
        event = str(payload.get("event", "unknown"))
        envelope_id = str(payload.get("envelope_id", ""))
        delivery_id = str(payload.get("id", uuid4()))
        task = state.task_by_envelope(envelope_id)
        filing = state.archives.get(envelope_id)
        note = "no task here for that envelope" if task is None and filing is None else ""
        first_time = state.record_webhook(
            WebhookRecord(
                received_at=_now(),
                event=event,
                envelope_id=envelope_id,
                delivery_id=delivery_id,
                verified=True,
                note=note or "accepted",
            )
        )
        if task is not None and first_time:
            task.envelope_status = str(payload.get("status", task.envelope_status))
            for signer in payload.get("signers", []):
                task.signer_status[str(signer["role_key"])] = str(signer["status"])
            if event == "envelope.sealed":
                _file_in_chart(task, payload)
        if filing is not None and first_time:
            # A paper archive fires envelope.sealed and envelope.voided only (SPEC section 9).
            filing.envelope_status = str(payload.get("status", filing.envelope_status))
            if event == "envelope.sealed":
                _file_archive_in_chart(filing, str(payload.get("sealed_sha256", "")))
        return JSONResponse({"received": True})

    def _file_in_chart(task: Task, payload: dict[str, Any]) -> None:
        """Fetch the sealed PDF and put it in the chart. The webhook never carries the document --
        it carries ids and hashes -- so the host fetches it over the authenticated API."""
        if task.envelope_id is None or state.document_for_envelope(task.envelope_id) is not None:
            return
        try:
            pdf = esign.sealed_document(task.envelope_id)
        except EsignApiError:
            return
        report = task.report
        state.file_document(
            ChartDocument(
                id=str(uuid4()),
                patient_id=task.patient_id,
                title=task.title,
                envelope_id=task.envelope_id,
                template_key=task.template_key,
                sealed_sha256=str(payload.get("sealed_sha256", "")),
                filed_at=_now(),
                pdf=pdf,
                kind="electronic" if report is None else "host_document",
                host_document_ref=None if report is None else f"report-{task.id}",
                upload_sha256=task.upload_sha256,
                page_count=None if report is None else report.pages,
            )
        )

    @app.get("/webhooks", response_class=HTMLResponse)
    def webhook_log(request: Request, demo_session: Annotated[str | None, Cookie()] = None) -> Response:
        user = current_user(demo_session)
        if user is None:
            return to_login()
        return render(request, "webhooks.html", {"user": user, "records": list(state.webhooks)})

    # ------------------------------------------------------------------ health

    @app.get("/healthz")
    def healthz() -> JSONResponse:
        return JSONResponse({"status": "ok"})

    app.state.store = state
    app.state.esign = esign
    app.state.config = settings
    return app
