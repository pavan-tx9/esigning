"""The EHR's client for the Host API.

Server to server, ``Authorization: Bearer esk_...``, and never from the browser: the API key is
the thing that lets this host create an envelope for any of its patients, so it stays on the
server exactly like a database password would.

Errors come back as ``{"error": {"code", "message"}}``; :class:`EsignApiError` carries the code,
because the code is the part worth branching on and the part that is safe to show.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

import httpx

__all__ = ["EsignApiError", "EsignClient"]


class EsignApiError(RuntimeError):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(f"{status} {code}: {message}")
        self.status = status
        self.code = code
        self.api_message = message


def _timestamp(value: datetime) -> str:
    return value.astimezone().isoformat()


class EsignClient:
    def __init__(self, base_url: str, api_key: str, *, transport: httpx.BaseTransport | None = None) -> None:
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {api_key}", "User-Agent": "demo-host/1"},
            timeout=30.0,
            follow_redirects=False,
            transport=transport,
        )

    def close(self) -> None:
        self._client.close()

    # ------------------------------------------------------------------ plumbing
    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        try:
            response = self._client.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise EsignApiError(503, "service_unreachable", f"the signing service did not answer ({exc!r})") from exc
        if response.status_code >= 400:
            code, message = "error", response.text[:200]
            if response.headers.get("content-type", "").startswith("application/json"):
                body = response.json()
                if isinstance(body, dict) and isinstance(body.get("error"), dict):
                    code = str(body["error"].get("code", "error"))
                    message = str(body["error"].get("message", ""))
            raise EsignApiError(response.status_code, code, message)
        return response

    def _json(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        body: Any = self._request(method, path, **kwargs).json()
        if not isinstance(body, dict):  # pragma: no cover - the API always answers with an object
            raise EsignApiError(502, "unexpected_body", "the signing service answered with something unexpected")
        return body

    # ------------------------------------------------------------------ templates
    def templates(self) -> list[dict[str, Any]]:
        body = self._json("GET", "/v1/templates")
        listed = body.get("templates", [])
        return [item for item in listed if isinstance(item, dict)]

    # ------------------------------------------------------------------ envelopes
    def create_envelope(
        self,
        *,
        template_key: str,
        patient_ref: str,
        host_document_ref: str,
        signing_order: str,
        signers: list[dict[str, Any]],
        prefill: dict[str, str],
        idempotency_key: str,
    ) -> dict[str, Any]:
        return self._json(
            "POST",
            "/v1/envelopes",
            headers={"Idempotency-Key": idempotency_key},
            json={
                "template_key": template_key,
                "template_version": None,
                "patient_ref": patient_ref,
                "host_document_ref": host_document_ref,
                "signing_order": signing_order,
                "signers": signers,
                "prefill": prefill,
            },
        )

    def envelope(self, envelope_id: str | UUID) -> dict[str, Any]:
        return self._json("GET", f"/v1/envelopes/{envelope_id}")

    def void_envelope(self, envelope_id: str | UUID, reason_code: str) -> dict[str, Any]:
        return self._json("POST", f"/v1/envelopes/{envelope_id}/void", json={"reason_code": reason_code})

    # ------------------------------------------------------------------ sessions
    def create_session(
        self,
        *,
        envelope_id: str,
        signer_id: str,
        method: str,
        auth_time: datetime,
        kiosk: tuple[str, str] | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"auth": {"method": method, "auth_time": _timestamp(auth_time)}}
        if kiosk is not None:
            body["kiosk"] = {"staff_user_id": kiosk[0], "identity_check": kiosk[1]}
        return self._json("POST", f"/v1/envelopes/{envelope_id}/signers/{signer_id}/sessions", json=body)

    def reauth(self, *, session_id: str, method: str, auth_time: datetime) -> dict[str, Any]:
        return self._json(
            "POST",
            f"/v1/sessions/{session_id}/reauth",
            json={"method": method, "auth_time": _timestamp(auth_time)},
        )

    # ------------------------------------------------------------------ evidence
    def sealed_document(self, envelope_id: str) -> bytes:
        return self._request("GET", f"/v1/envelopes/{envelope_id}/document").content

    def verification(self, envelope_id: str) -> dict[str, Any]:
        return self._json("GET", f"/v1/envelopes/{envelope_id}/verification")

    def audit(self, envelope_id: str) -> list[dict[str, Any]]:
        body = self._json("GET", f"/v1/envelopes/{envelope_id}/audit")
        events = body.get("events", [])
        return [event for event in events if isinstance(event, dict)]
