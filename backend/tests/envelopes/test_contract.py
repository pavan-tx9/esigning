"""The module's side of ``contracts.py``.

Cheap tests, but they are the ones that catch a signature drifting away from the contract that
lets six agents build six modules in parallel. Most of the work here is done by mypy: the
assignment below fails type checking the moment ``EnvelopeServiceImpl`` stops satisfying the
Protocol, whether or not anyone runs the test.
"""

from __future__ import annotations

import inspect

from esign.audit.events import EVENT_DATA_MODELS
from esign.clock import FixedClock, SystemClock
from esign.config import Settings
from esign.contracts import EnvelopeService, EventType
from esign.envelopes import build_envelope_service
from esign.envelopes.service import EnvelopeServiceImpl
from tests.envelopes.fakes import (
    FakeAuditLog,
    FakeBlobService,
    FakeDocumentService,
    FakeIdentityService,
    FakeSealer,
)


def build(tmp_path_factory: object = None) -> EnvelopeServiceImpl:
    import tempfile
    from pathlib import Path

    settings = Settings(app_env="test")
    clock = FixedClock(SystemClock().now())
    root = Path(tempfile.mkdtemp())
    return build_envelope_service(
        settings,
        clock,
        audit_log=FakeAuditLog(clock),
        blob_service=FakeBlobService(root),
        document_service=FakeDocumentService(),
        identity_service=FakeIdentityService(settings, clock),
        sealer=FakeSealer(clock),
    )


def test_the_factory_returns_something_that_satisfies_the_protocol() -> None:
    service: EnvelopeService = build()
    assert isinstance(service, EnvelopeServiceImpl)


def test_the_factory_is_exported_from_the_package() -> None:
    """SPEC section 2: each module exposes one factory from its ``__init__``."""
    import esign.envelopes as package

    assert package.build_envelope_service is build_envelope_service
    assert "build_envelope_service" in package.__all__


def test_every_protocol_method_is_implemented_with_the_same_signature() -> None:
    for name, expected in inspect.getmembers(EnvelopeService, inspect.isfunction):
        if name.startswith("_"):
            continue
        actual = getattr(EnvelopeServiceImpl, name, None)
        assert actual is not None, f"EnvelopeService.{name} is not implemented"
        assert inspect.signature(actual) == inspect.signature(expected), name


def test_the_fakes_satisfy_the_protocols_they_stand_in_for() -> None:
    """A fake that has drifted from its contract makes every test using it worthless."""
    from esign.contracts import AuditLog, BlobService, DocumentService, IdentityService, Sealer

    settings = Settings(app_env="test")
    clock = FixedClock(SystemClock().now())
    import tempfile
    from pathlib import Path

    audit: AuditLog = FakeAuditLog(clock)
    blobs: BlobService = FakeBlobService(Path(tempfile.mkdtemp()))
    documents: DocumentService = FakeDocumentService()
    identity: IdentityService = FakeIdentityService(settings, clock)
    sealer: Sealer = FakeSealer(clock)
    assert all(x is not None for x in (audit, blobs, documents, identity, sealer))


def test_the_audit_allowlist_has_one_definition_and_it_is_not_here() -> None:
    """The envelope module used to keep its own copy of the allowed ``data`` keys, and the copy
    disagreed with the audit module's. There is now one definition, in ``esign.audit.events``."""
    import esign.envelopes.service as service_module

    assert not hasattr(service_module, "AUDIT_DATA_KEYS")
    assert set(EVENT_DATA_MODELS) == set(EventType)


def test_the_download_gates_are_part_of_the_protocol() -> None:
    for name in ("may_download_copy", "signer_copy", "sealed_document", "signing_view"):
        assert callable(getattr(EnvelopeServiceImpl, name))
        assert hasattr(EnvelopeService, name)
