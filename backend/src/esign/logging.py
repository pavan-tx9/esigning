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
from typing import Any, Final, Protocol, TextIO, cast
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
        # Addendum 2: `template` or `host_document`, the `envelopes.source` enum itself. Named for
        # its column rather than a bare `source`, which is the kind of key a later caller fills
        # with free text without noticing the allowlist was meant to stop exactly that.
        "envelope_source",
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


class LogStream(Protocol):
    """The two methods a log sink needs. ``sys.stdout``, a ``StringIO`` and a test capture all fit."""

    def write(self, value: str, /) -> int: ...

    def flush(self) -> None: ...


class _StreamLoggerFactory:
    """Builds print loggers against an explicit stream, or against ``sys.stdout`` as it is *now*.

    structlog's own default captures ``sys.stdout`` when the library is imported, and a logger
    cached on first use keeps whatever stream was current then -- both outlive test capture and
    redirection, and surface much later as "I/O operation on closed file" in an unrelated module.
    So nothing is cached and the stream is resolved per log call unless one was given.
    """

    def __init__(self, stream: LogStream | None, *, stderr: bool = False) -> None:
        self._stream = stream
        self._stderr = stderr

    def __call__(self, *_args: Any) -> structlog.PrintLogger:
        if self._stream is not None:
            return structlog.PrintLogger(file=cast(TextIO, self._stream))
        return structlog.PrintLogger(file=sys.stderr if self._stderr else sys.stdout)


def configure_logging(
    *,
    level: str = "INFO",
    json_output: bool = True,
    app_env: str = "dev",
    stream: LogStream | None = None,
    stderr: bool = False,
) -> None:
    """Configure structlog and the stdlib root logger. Idempotent; call once at startup.

    ``stream`` pins the output (tests that read rendered lines pass a buffer); left as ``None``
    every line goes to the current ``sys.stdout`` -- or ``sys.stderr`` with ``stderr=True``, which
    is what the CLI uses so that its own output on stdout stays parseable.

    Records that reach the *stdlib* root logger -- SQLAlchemy, httpx, pypdf -- are formatted
    through the same processor chain, so the key allowlist covers them too rather than only this
    module's own callers. uvicorn is covered only when it is started *without* its default log
    config: ``uvicorn.LOGGING_CONFIG`` gives ``uvicorn`` and ``uvicorn.access`` their own stdout
    handlers with ``propagate: False``, and nothing here can reach a record that never arrives. So
    ``esign serve`` passes ``log_config=None, access_log=False``, and it is the only way the server
    is started: ``make dev-api`` (with ``--reload``) and ``demo-host/demo.sh`` both go through it
    rather than calling uvicorn themselves, where ``--no-access-log`` would drop the raw-URL access
    line but leave uvicorn's error logger writing past the allowlist.
    """
    numeric_level = logging.getLevelNamesMapping().get(level.upper(), logging.INFO)

    renderer: Any = structlog.processors.JSONRenderer() if json_output else structlog.dev.ConsoleRenderer()

    shared: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    structlog.configure(
        processors=[
            *shared,
            # Last: nothing may add a key after the allowlist has run.
            drop_unlisted_keys,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        logger_factory=_StreamLoggerFactory(stream, stderr=stderr),
        cache_logger_on_first_use=False,
    )

    # The stdlib root logger goes through the same allowlist. SQLAlchemy, httpx, pypdf and uvicorn
    # all write there, and ``logging.basicConfig(format="%(message)s")`` rendered whatever they said
    # verbatim -- so a single ``DB_ECHO=true`` would have printed every statement's bound parameters
    # (display names, prefill values, typed signatures) straight past this module's one defence.
    handler = logging.StreamHandler(cast(TextIO, stream) if stream is not None else None)
    handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            # ``ExtraAdder`` lifts a stdlib record's ``extra=`` fields into the event dict, which is
            # what puts them in front of the allowlist instead of inside a pre-rendered message.
            foreign_pre_chain=[*shared, structlog.stdlib.ExtraAdder()],
            processors=[
                structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                drop_unlisted_keys,
                renderer,
            ],
        )
    )
    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(numeric_level)
    # Even allowlisted, these are noise at INFO and the echo is the one that would carry PHI.
    for chatty in ("sqlalchemy.engine", "httpx", "httpcore", "pypdf", "botocore", "boto3", "urllib3"):
        logging.getLogger(chatty).setLevel(logging.WARNING)

    structlog.contextvars.bind_contextvars(app_env=app_env)


def get_logger(name: str = "esign") -> Any:
    """A bound logger. Keys must be on :data:`LOGGABLE_KEYS` or they are dropped."""
    return structlog.get_logger(name)


# Safe by default. structlog's own default prints every key it is given, so a process that forgot
# to call ``configure_logging`` would have no allowlist at all. Importing this module is enough to
# have one; an entry point calls ``configure_logging`` again to choose level and format.
if not structlog.is_configured():
    configure_logging()
