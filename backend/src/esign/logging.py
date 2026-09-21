"""Structured logging with a key allowlist.

The database and the blob store hold PHI. Logs do not. Every other defence in this codebase is a
rule someone has to remember; this one is mechanical: a log event carries a key or it does not get
written. Anything not on :data:`LOGGABLE_KEYS` is dropped before the line is rendered, and the
names of the dropped keys are reported under ``dropped_fields`` so a mistake is visible in dev
without the value ever reaching the log.

Usage::

    from esign.logging import get_logger
    log = get_logger(__name__)
    log.info("envelope.sealed", envelope_id=str(envelope_id), seal_profile=profile)

Request and response bodies are never logged. Neither are display names, prefill values, dates of
birth, free text, tokens or API keys -- none of which have a key on the list.
"""

from __future__ import annotations

import logging
import sys
from typing import Any, Final
from uuid import UUID

import structlog
from structlog.typing import EventDict, WrappedLogger

__all__ = [
    "LOGGABLE_KEYS",
    "RESERVED_KEYS",
    "configure_logging",
    "drop_unlisted_keys",
    "get_logger",
]

#: Keys structlog itself owns. They describe the line, not its subject, and always survive.
RESERVED_KEYS: Final[frozenset[str]] = frozenset(
    {
        "event",
        "level",
        "logger",
        "timestamp",
        "exc_info",
        "stack_info",
        "stack",
        "exception",
        "dropped_fields",
    }
)

#: Everything the service is allowed to say about what it did.
#:
#: The test is: could this value ever be, or contain, something about a patient? Ids that are
#: opaque to anyone without database access are fine. Names, dates, addresses, free text, prefill
#: values, tokens, PDF bytes and request bodies are not, and deliberately have no key here.
LOGGABLE_KEYS: Final[frozenset[str]] = frozenset(
    {
        # identity of the thing being acted on -- all opaque uuids or host-chosen keys
        "host_id",
        "envelope_id",
        "signer_id",
        "session_id",
        "template_id",
        "template_key",
        "template_version",
        "template_version_id",
        "revision_id",
        "revision_no",
        "job_id",
        "delivery_id",
        "stream_type",
        "stream_id",
        "sequence",
        "event_id",
        # classifications and states -- closed enums from the schema
        "document_type",
        "event_type",
        "envelope_status",
        "signer_status",
        "signer_role",
        "role_key",
        "capacity",
        "blob_kind",
        "revision_kind",
        "signing_order",
        "capture_kind",
        "webhook_event",
        "auth_method",
        "reauth_method",
        "identity_check",
        "consent_version",
        "locale",
        "reason_code",
        "decline_reason_code",
        "seal_profile",
        "key_backend",
        "blob_backend",
        # hashes and counts -- evidence, not content
        "sha256",
        "document_sha256",
        "presented_sha256",
        "sealed_sha256",
        "event_hash",
        "prev_event_hash",
        "head_hash",
        "cert_sha256",
        "size_bytes",
        "page_count",
        "pages_viewed",
        "event_count",
        "signer_count",
        "field_count",
        "capture_count",
        "attempts",
        "count",
        # outcome and operations
        "error_code",
        "code",
        "problem",
        "problems",
        "http_status",
        "method",
        "path",
        "route",
        "duration_ms",
        "retry_in_seconds",
        "ok",
        "intact",
        "trusted",
        "covers_whole_document",
        "timestamp_valid",
        # request provenance -- taken server-side, required by the audit rules
        "ip",
        "user_agent",
        "kiosk",
        # process
        "app_env",
        "component",
        "migration",
        "backend",
    }
)


def _scalarize(value: Any) -> Any:
    """Render the few types that show up in log values without surprising the JSON encoder."""
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, bytes | bytearray | memoryview):
        return bytes(value).hex()
    if isinstance(value, list | tuple):
        return [_scalarize(item) for item in value]
    return value


def drop_unlisted_keys(_logger: WrappedLogger, _method: str, event_dict: EventDict) -> EventDict:
    """Remove every key that is not on the allowlist. The last processor before rendering."""
    kept: EventDict = {}
    dropped: list[str] = []
    for key, value in event_dict.items():
        if key in RESERVED_KEYS:
            kept[key] = value
        elif key in LOGGABLE_KEYS:
            kept[key] = _scalarize(value)
        else:
            dropped.append(key)
    if dropped:
        kept["dropped_fields"] = sorted(dropped)
    return kept


def configure_logging(
    *,
    level: str = "INFO",
    json_output: bool = True,
    app_env: str = "dev",
) -> None:
    """Configure structlog and the stdlib root logger. Idempotent; call once at startup."""
    numeric_level = logging.getLevelNamesMapping().get(level.upper(), logging.INFO)

    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=numeric_level, force=True)

    renderer: Any = structlog.processors.JSONRenderer() if json_output else structlog.dev.ConsoleRenderer()

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            # Last: nothing may add a key after the allowlist has run.
            drop_unlisted_keys,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )
    structlog.contextvars.bind_contextvars(app_env=app_env)


def get_logger(name: str = "esign") -> Any:
    """A bound logger. Keys must be on :data:`LOGGABLE_KEYS` or they are dropped."""
    return structlog.get_logger(name)
