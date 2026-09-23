"""The error envelope: ``{"error": {"code": "...", "message": "..."}}`` (SPEC section 9).

Messages never echo input, so none of them are built from an exception's text: a module's message
may quote a template key, a driver error may quote a row. The ``code`` is the specific, stable part
(it comes from the ``EsignError``); the ``message`` is a fixed sentence chosen here by code or, for
everything else, by status. The signing UI may show a message to a patient, so they are written for
that reader: calm, plain, second person.
"""

from __future__ import annotations

from typing import Final

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from esign.contracts import EsignError, IntegrityFailure, RateLimited
from esign.logging import get_logger

__all__ = ["error_response", "install_error_handlers"]

log = get_logger(__name__)

_BY_CODE: Final[dict[str, str]] = {
    "unauthorized": "Your session has ended. Please return to where you started and open the document again.",
    "reauth_required": "Please confirm it is you before signing.",
    "envelope_expired": "This document has expired and can no longer be signed.",
    "envelope_voided": "This document was withdrawn and can no longer be signed.",
    "envelope_declined": "This document can no longer be signed.",
    "envelope_sealed": "This document has already been completed.",
    "envelope_already_complete": "This document has already been signed.",
    "pages_not_all_viewed": "Please look through every page before you continue.",
    "not_viewed": "The document has changed. Please look through every page again before you sign.",
    "not_presented": "Please open the document before you continue.",
    "consent_version_stale": "The disclosure has been updated. Please read it again before you continue.",
    # Addendum 3 C. The signer is not being refused: they are being asked to agree here, on this
    # document, because the earlier agreement the page was showing no longer stands.
    "consent_not_standing": "Please agree to sign this document electronically before you continue.",
    "signer_finished": "This signer has already finished; there is nothing left to re-authenticate for.",
    "reauth_not_required": "This signer's role does not need re-authentication.",
    "envelope_not_live": "This document is no longer being signed.",
    "captures_invalid": "Please check the entries on the form and try again.",
    "typed_signature_too_long": "That typed signature is too long.",
    "text_value_too_long": "That entry is too long.",
    "not_sealed": "The document is not sealed yet.",
    "envelope_not_complete": "Your signed copy will be available when everyone has signed.",
    "idempotency_key_reused": "That idempotency key was already used with a different request.",
    "idempotency_key_required": "This request needs an Idempotency-Key header.",
    "out_of_scope": "This service does not support that kind of signing.",
    # Addendum 2, the host-supplied document path. These reach an integrator wiring up an EHR, not
    # a patient, and every one of them is about the file that was just sent -- so the sentence says
    # which class of problem it is. None of them names a role, a widget or anything else out of the
    # request: the `code` is the stable, specific part, exactly as SPEC section 9 has it.
    "fields_unresolved": "The document has no signature block for one of the signer roles you declared.",
    "supplied_definitions_invalid": "The field or signer-role definitions for that document were refused.",
    "supplied_too_large": "That document is larger than this service accepts.",
    "supplied_too_many_pages": "That document has more pages than this service accepts.",
    "supplied_no_pages": "That document has no pages.",
    "supplied_encrypted": "That document is encrypted; supply it unencrypted.",
    "supplied_already_signed": "That document already carries a signature.",
    "supplied_signature_field": (
        "That document contains an AcroForm signature field. Place the signature block as an "
        "ordinary text widget named <role_key>_signature instead."
    ),
    "supplied_annotation_not_removable": (
        "That document contains a visible annotation. Draw the mark into the page content before "
        "supplying it, because annotations are removed."
    ),
    "supplied_javascript": "That document contains JavaScript or an action trigger.",
    "supplied_xfa": "That document contains an XFA form.",
    "supplied_forbidden_action": "That document contains an action this service does not accept.",
    "supplied_embedded_file": "That document contains an embedded file.",
    "supplied_embedded_stream": "That document contains an embedded file.",
    "supplied_forbidden_annotation": "That document contains a multimedia or attachment annotation.",
    "supplied_unreadable_object": "That document could not be read.",
    "supplied_content_unreadable": "That document has a page whose content could not be read.",
    "supplied_too_complex": "That document is too large to inspect.",
    "supplied_flatten_changed_pages": "That document could not be prepared without changing its page count.",
    "field_page_out_of_range": "A field names a page the document does not have.",
    "document_type_not_approved": "That document type cannot be signed here.",
    "signer_roles_required": "A supplied document needs at least one signer role.",
    "duplicate_role": "Two signer roles share a key.",
}

_BY_STATUS: Final[dict[int, str]] = {
    400: "The request could not be understood.",
    401: "The credentials are missing or not valid.",
    403: "That is not allowed.",
    404: "Nothing was found at that address.",
    405: "That method is not allowed here.",
    409: "That is not possible right now.",
    413: "The request is too large.",
    415: "That content type is not supported.",
    422: "The request is not valid.",
    429: "Too many requests. Please wait a moment and try again.",
    500: "Something went wrong on our side. Nothing was completed.",
    503: "The service is temporarily unavailable. Nothing was completed; please try again shortly.",
}


def error_response(status: int, code: str, *, headers: dict[str, str] | None = None) -> JSONResponse:
    message = _BY_CODE.get(code) or _BY_STATUS.get(status) or _BY_STATUS[500 if status >= 500 else 400]
    return JSONResponse(status_code=status, content={"error": {"code": code, "message": message}}, headers=headers)


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(EsignError)
    def _esign_error(_request: Request, exc: EsignError) -> JSONResponse:
        headers: dict[str, str] = {}
        if isinstance(exc, RateLimited) and exc.retry_after_seconds:
            headers["Retry-After"] = str(exc.retry_after_seconds)
        if exc.http_status == 401:
            headers["WWW-Authenticate"] = "Bearer"
        if isinstance(exc, IntegrityFailure):
            # Stored evidence does not match its hash. Never swallowed: loud here, 500 to the caller.
            log.error("api.integrity_failure", error_code=exc.code)
        return error_response(exc.http_status, exc.code, headers=headers or None)

    @app.exception_handler(RequestValidationError)
    def _request_invalid(_request: Request, _exc: RequestValidationError) -> JSONResponse:
        # Pydantic's detail quotes the offending input. It is not returned and not logged.
        return error_response(422, "validation_failed")

    @app.exception_handler(StarletteHTTPException)
    def _http_error(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        codes = {404: "not_found", 405: "method_not_allowed", 413: "payload_too_large", 415: "unsupported_media_type"}
        status = exc.status_code
        return error_response(status, codes.get(status, "error" if status < 500 else "internal_error"))

    @app.exception_handler(Exception)
    def _unexpected(_request: Request, exc: Exception) -> JSONResponse:
        # The class name only. An exception's text can carry a row, a path or a parameter.
        log.error("api.unhandled_error", error_code="internal_error", problem=type(exc).__name__)
        return error_response(500, "internal_error")
