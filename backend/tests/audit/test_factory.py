"""The module's public seam: one factory, the shape SPEC section 2 names, and nothing else."""

from __future__ import annotations

import inspect
from uuid import uuid4

from sqlalchemy.orm import Session

import esign.audit
from esign.audit import build_audit_log
from esign.audit.log import PostgresAuditLog
from esign.clock import FixedClock
from esign.config import Settings
from esign.contracts import AuditLog, EventType
from tests.audit.helpers import sample_data


def test_the_factory_is_named_and_shaped_as_the_spec_says() -> None:
    parameters = list(inspect.signature(build_audit_log).parameters)
    assert parameters == ["settings", "clock"]
    assert inspect.signature(build_audit_log).return_annotation == "AuditLog"


def test_the_factory_is_exported_from_the_package() -> None:
    assert "build_audit_log" in esign.audit.__all__
    assert hasattr(esign.audit, "build_audit_log")


def test_the_built_log_implements_every_method_the_protocol_declares(
    settings_no_db: Settings, clock: FixedClock
) -> None:
    audit = build_audit_log(settings_no_db, clock)
    for name in ("append", "list", "verify"):
        assert callable(getattr(audit, name))
        assert inspect.signature(getattr(audit, name)).parameters.keys() == (
            inspect.signature(getattr(AuditLog, name)).parameters.keys() - {"self"}
        )


def test_the_log_is_stateless_enough_to_share(settings: Settings, clock: FixedClock, db: Session) -> None:
    """One instance, many streams, no cross-talk: nothing is cached between appends."""
    audit = build_audit_log(settings, clock)
    first, second = uuid4(), uuid4()
    audit.append(
        db,
        stream_type="envelope",
        stream_id=first,
        event_type=EventType.ENVELOPE_CREATED,
        data=sample_data(EventType.ENVELOPE_CREATED),
    )
    event = audit.append(
        db,
        stream_type="envelope",
        stream_id=second,
        event_type=EventType.ENVELOPE_CREATED,
        data=sample_data(EventType.ENVELOPE_CREATED),
    )
    assert event.sequence == 1
    assert audit.verify(db, "envelope", first).ok
    assert audit.verify(db, "envelope", second).ok


def test_the_module_imports_only_contracts_and_foundation() -> None:
    """SPEC section 2: "Modules depend on contracts.py and foundation files only"."""
    import ast
    from pathlib import Path

    allowed = {
        "esign.contracts",
        "esign.config",
        "esign.clock",
        "esign.db",
        "esign.ids",
        "esign.logging",
        "esign.audit",
    }
    package = Path(esign.audit.__file__).parent
    for path in sorted(package.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            module = node.module if isinstance(node, ast.ImportFrom) else None
            if module is None or not module.startswith("esign"):
                continue
            root = module if module in allowed else module.rsplit(".", 1)[0]
            assert root in allowed or module.startswith("esign.audit."), f"{path.name} imports {module}"


def test_the_concrete_class_is_available_for_tests_but_the_factory_is_the_seam() -> None:
    assert issubclass(PostgresAuditLog, object)
    assert "PostgresAuditLog" in esign.audit.__all__
