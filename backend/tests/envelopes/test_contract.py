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
from esign.contracts import EnvelopeService, EventType, FieldDef, SignerRoleDef
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


def test_the_fake_resolver_answers_what_the_real_one_answers() -> None:
    """Addendum 2: the envelope tests reason about host documents through ``FakeDocumentService``.

    Satisfying the Protocol is not enough for that to be worth anything -- the fake also has to
    produce the *shape of answer* the real resolver produces, or the envelope service is being
    tested against a document module nobody ships. So the same report, in both worlds: the real
    one as an actual PDF with real AcroForm widgets, the fake one as its pseudo-PDF header.

    Geometry is deliberately not compared: the fake invents rects, and where a widget really sits
    is ``tests/documents/test_supplied.py``'s subject. What must agree is everything the envelope
    service and the signer-facing payload are built from -- the ids, the types, which role owns
    each field, whether it is required, and the label a signer reads.
    """
    from esign.documents.supplied import resolve_named_fields
    from tests.documents.helpers import NamedWidget, generated_report
    from tests.envelopes.fakes import supplied_pdf

    roles = [
        SignerRoleDef(
            key="clinician",
            label="Attending physician",
            allowed_capacities=("clinician",),
            requires_reauth=True,
            order_index=0,
        ),
        SignerRoleDef(
            key="cosigner",
            label="Co-signing physician",
            allowed_capacities=("clinician",),
            requires_reauth=True,
            order_index=1,
        ),
    ]
    names = ("clinician_signature", "clinician_date", "cosigner_signature", "filed_by")

    real = resolve_named_fields(
        generated_report(
            pages=4,
            widgets=[
                NamedWidget(name=name, rect=(54, 96 + 60 * i, 294, 146 + 60 * i), page=4)
                for i, name in enumerate(names)
            ],
        ),
        roles,
    )
    fake = FakeDocumentService().resolve_named_fields(supplied_pdf(pages=4, widgets=names), roles)

    def shape(fields: list[FieldDef]) -> list[tuple[str, str, str, bool, str]]:
        return sorted((f.id, f.type, f.signer_role, f.required, f.label) for f in fields)

    assert shape(real) == shape(fake)
    # And the agreed answer is the right one: the unmatched widget is gone, and the label a signer
    # reads comes from the role the host declared, not from the name inside the file.
    assert [f.id for f in real] == ["clinician_signature", "clinician_date", "cosigner_signature"]
    assert [f.label for f in real] == [
        "Attending physician signature",
        "Attending physician date signed",
        "Co-signing physician signature",
    ]
