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
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any
from uuid import uuid4

from fastapi import Cookie, FastAPI, Form, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from demo_host.config import Config, load_config
from demo_host.esign_api import EsignApiError, EsignClient
from demo_host.signatures import SIGNATURE_HEADER, verify_signature
from demo_host.store import (
    IDENTITY_CHECK_LABELS,
    ChartDocument,
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


def _now() -> datetime:
    return datetime.now(UTC)


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

    def ensure_envelope(task: Task) -> dict[str, Any]:
        """Create the envelope the first time somebody opens this task, then reuse it.

        The idempotency key is the task id, so two people opening the same task at the same moment
        get one envelope rather than two.
        """
        if task.envelope_id is not None:
            return esign.envelope(task.envelope_id)
        patient = state.patients[task.patient_id]
        signers = []
        for signer in task.signers:
            person = state.users[signer.user_id]
            signers.append(
                {
                    "role_key": signer.role_key,
                    "host_user_id": person.id,
                    "display_name": person.display_name,
                    "capacity": signer.capacity,
                    "on_behalf_of": signer.on_behalf_of,
                }
            )
        view = esign.create_envelope(
            template_key=task.template_key,
            patient_ref=patient.mrn,
            host_document_ref=f"task-{task.id}",
            signing_order=task.signing_order,
            signers=signers,
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
    def open_task(task_id: str, demo_session: Annotated[str | None, Cookie()] = None) -> Response:
        """Create the envelope if it does not exist, start a signing session for this person, and
        send them to the page that embeds the signing UI. The token stays here."""
        user = current_user(demo_session)
        if user is None:
            return to_login()
        task = state.tasks.get(task_id)
        if task is None or task.signer_for(user.id) is None:
            return RedirectResponse("/worklist?problem_code=not_your_task", status_code=303)
        try:
            ensure_envelope(task)
            started = start_session(task, user, demo_session)
        except EsignApiError as exc:
            return RedirectResponse(f"/worklist?problem_code={exc.code}", status_code=303)
        if started is None:
            return RedirectResponse("/worklist?problem_code=no_signer", status_code=303)
        return RedirectResponse(f"/sign/{task.id}", status_code=303)

    def start_session(task: Task, user: User, session_key: str | None) -> TaskSigner | None:
        signer = signer_for(task, user)
        if signer is None or task.envelope_id is None:
            return None
        signer_id = task.signer_ids.get(signer.role_key)
        if signer_id is None:
            return None
        kiosk = task.kiosk
        created = esign.create_session(
            envelope_id=task.envelope_id,
            signer_id=signer_id,
            method="staff_verified" if kiosk is not None else "password",
            auth_time=login_time(session_key),
            kiosk=kiosk,
        )
        task.sessions[signer.role_key] = (str(created["session_id"]), str(created["token"]))
        return signer

    # ------------------------------------------------------------------ the embedded signing page

    @app.get("/sign/{task_id}", response_class=HTMLResponse)
    def sign_page(request: Request, task_id: str, demo_session: Annotated[str | None, Cookie()] = None) -> Response:
        user = current_user(demo_session)
        if user is None:
            return to_login()
        task = state.tasks.get(task_id)
        if task is None:
            return problem(request, user, "No such document", "That document is not on this worklist.", 404)
        signer = signer_for(task, user)
        if signer is None or signer.role_key not in task.sessions:
            return RedirectResponse("/worklist?problem_code=session_missing", status_code=303)
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
                "needs_reauth": signer.role_key == "clinician",
                "esign_origin": settings.ui_url,
                "frame_src": settings.signing_ui_src,
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

    # ------------------------------------------------------------------ the chart

    @app.get("/chart/{patient_id}", response_class=HTMLResponse)
    def chart(request: Request, patient_id: str, demo_session: Annotated[str | None, Cookie()] = None) -> Response:
        user = current_user(demo_session)
        if user is None:
            return to_login()
        patient = state.patients.get(patient_id)
        if patient is None:
            return problem(request, user, "No such chart", "That chart does not exist here.", 404)
        if not may_see_chart(user, patient_id):
            return problem(request, user, "Not your chart", "You can only open your own chart.", 403)
        pending = []
        for task in state.tasks_for_patient(patient_id):
            refresh(task)
            if task.envelope_id is not None and state.document_for_envelope(task.envelope_id) is None:
                pending.append(task)
        return render(
            request,
            "chart.html",
            {
                "user": user,
                "patient": patient,
                "documents": state.documents_for(patient_id),
                "pending": pending,
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

        Delivery is at-least-once, so the payload's ``id`` is what makes filing happen once.
        """
        body = await request.body()
        header = request.headers.get(SIGNATURE_HEADER, "")
        ok = verify_signature(settings.webhook_secret, body, header, now=_now())
        try:
            payload = json.loads(body)
        except ValueError:
            payload = {}
        event = str(payload.get("event", "unknown"))
        envelope_id = str(payload.get("envelope_id", ""))
        delivery_id = str(payload.get("id", uuid4()))
        if not ok:
            state.record_webhook(
                WebhookRecord(
                    received_at=_now(),
                    event=event,
                    envelope_id=envelope_id,
                    delivery_id=delivery_id,
                    verified=False,
                    note="signature rejected; nothing was changed",
                )
            )
            return JSONResponse({"error": "bad_signature"}, status_code=401)

        task = state.task_by_envelope(envelope_id)
        note = "no task here for that envelope" if task is None else ""
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
