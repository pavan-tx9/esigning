"""The ``esign`` command.

    esign migrate [--status | --dry-run]        apply backend/migrations as the owner role
    esign dev-pki [--force]                     generate the development PKI (never for production)
    esign hosts create --name N --origin O ...  register an EHR; prints its API key ONCE
    esign hosts rotate-key HOST_ID              replace a host's API key; prints the new one ONCE
    esign consent add --default                 seed the bundled ESIGN disclosure
    esign consent add --version V --locale L --file F [--effective-at T]
    esign templates import --host HOST_ID [--dir templates/] [--no-publish]
    esign worker [--once]                       seal jobs, expiries, webhooks
    esign verify ENVELOPE_ID [--json]           re-check an envelope; exit 1 if anything failed
    esign serve [--host H] [--port P]           run the API (and the signing UI when it is built)

Secrets are printed to stdout exactly once and are never logged. Everything else this command says
is ids, counts and statuses.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from esign.api.template_service import TemplateService
from esign.config import Settings, get_settings
from esign.contracts import Actor, Clock, EsignError, Host, NotFound, RequestContext
from esign.logging import configure_logging
from esign.runtime import Runtime, build_runtime

__all__ = ["main"]

RuntimeFactory = Callable[[], Runtime]


def _say(text: str = "") -> None:
    sys.stdout.write(text + "\n")


def _fail(text: str) -> int:
    sys.stderr.write(text + "\n")
    return 2


# --------------------------------------------------------------------------- commands


def _migrate(args: argparse.Namespace, _rt: RuntimeFactory) -> int:
    from esign import migrate

    argv: list[str] = []
    if args.status:
        argv.append("--status")
    if args.dry_run:
        argv.append("--dry-run")
    return migrate.main(argv)


def _dev_pki(args: argparse.Namespace, _rt: RuntimeFactory, *, settings: Settings, clock: Clock) -> int:
    from esign.sealing import generate_dev_pki

    if settings.app_env == "prod":
        return _fail("refusing: the development PKI is not for production. Use SEAL_KEY_BACKEND=aws_kms.")
    try:
        generate_dev_pki(settings.dev_pki_dir, clock, force=args.force)
    except FileExistsError:
        return _fail(
            f"{settings.dev_pki_dir} already holds a dev PKI. --force replaces it, and every document "
            "sealed with the old key stops validating."
        )
    _say(f"development PKI written to {settings.dev_pki_dir}")
    _say(f"trust roots: {settings.dev_pki_dir / 'trust-roots.pem'}")
    return 0


def _hosts_create(args: argparse.Namespace, rt_factory: RuntimeFactory) -> int:
    from esign.identity import create_host, rotate_webhook_secret

    rt = rt_factory()
    with rt.transaction() as db:
        key, host = create_host(db, args.name, tuple(args.origin or ()), args.webhook_url, clock=rt.clock)
        secret = rotate_webhook_secret(db, host.id) if args.webhook_url else None
    _say(f"host id:        {host.id}")
    _say(f"api key:        {key}")
    if secret is not None:
        _say(f"webhook secret: {secret.hex()}")
    _say("These secrets are shown once and are not stored. Keep them now.")
    return 0


def _hosts_rotate_key(args: argparse.Namespace, rt_factory: RuntimeFactory) -> int:
    from esign.identity import rotate_host_key

    rt = rt_factory()
    with rt.transaction() as db:
        key, host = rotate_host_key(db, args.host_id)
    _say(f"host id: {host.id}")
    _say(f"api key: {key}")
    _say("The previous key no longer works. This one is shown once and is not stored.")
    return 0


def _consent_add(args: argparse.Namespace, rt_factory: RuntimeFactory) -> int:
    from esign.identity import add_consent_text, seed_default_consent

    rt = rt_factory()
    with rt.transaction() as db:
        if args.default:
            added = seed_default_consent(db)
        else:
            if not (args.version and args.locale and args.file):
                return _fail("consent add needs --default, or --version, --locale and --file")
            effective = datetime.fromisoformat(args.effective_at) if args.effective_at else rt.clock.now()
            if effective.tzinfo is None:
                return _fail("--effective-at must carry a timezone, e.g. 2026-01-01T00:00:00+00:00")
            body = Path(args.file).read_text(encoding="utf-8")
            added = (add_consent_text(db, version=args.version, locale=args.locale, body=body, effective_at=effective),)
    for consent in added:
        _say(f"consent {consent.version} ({consent.locale}) sha256 {consent.body_sha256.hex()}")
    return 0


def _templates_import(args: argparse.Namespace, rt_factory: RuntimeFactory) -> int:
    rt = rt_factory()
    directory = Path(args.dir) if args.dir else rt.settings.templates_dir
    definitions = sorted(directory.glob("*.json"))
    if not definitions:
        return _fail(f"no template definitions (*.json) in {directory}")
    service = TemplateService(rt.settings, rt.clock, audit=rt.audit, blobs=rt.blobs, documents=rt.documents)
    ctx = RequestContext(auth_method="cli")
    for path in definitions:
        pdf_path = path.with_suffix(".pdf")
        if not pdf_path.is_file():
            return _fail(f"{path.name} has no matching PDF")
        document = json.loads(path.read_text(encoding="utf-8"))
        with rt.transaction() as db:
            host = _host(db, args.host)
            try:
                existing = service.get(db, host, str(document.get("key", "")))
            except EsignError:
                existing = None
            if existing is None:
                view = service.create(
                    db,
                    host,
                    key=str(document.get("key", "")),
                    name=str(document.get("name", "")),
                    document_type=str(document.get("document_type", "")),
                    pdf=pdf_path.read_bytes(),
                    definitions=document,
                )
            else:
                view = service.add_version(db, host, existing.key, pdf=pdf_path.read_bytes(), definitions=document)
            version = view.versions[-1].version
            if not args.no_publish:
                service.publish(db, host, view.key, version, ctx)
        _say(f"{view.key} v{version} {'draft' if args.no_publish else 'published'}")
    return 0


def _host(db: Session, host_id: UUID) -> Host:
    row = db.execute(
        text("SELECT id, name, allowed_origins FROM hosts WHERE id = :id AND disabled_at IS NULL"), {"id": host_id}
    ).first()
    if row is None:
        raise NotFound("no such host", code="host_not_found")
    return Host(id=row.id, name=str(row.name), allowed_origins=tuple(row.allowed_origins or ()))


def _worker(args: argparse.Namespace, rt_factory: RuntimeFactory) -> int:
    from esign.worker import run_forever, run_once

    rt = rt_factory()
    if args.once:
        result = run_once(rt)
        _say(
            f"sealed {result.sealed}, seal failures {result.seal_failures}, expired {result.expired}, "
            f"webhooks delivered {result.webhooks_delivered}, failed {result.webhooks_failed}"
        )
        return 0
    run_forever(rt)
    return 0


def _verify(args: argparse.Namespace, rt_factory: RuntimeFactory) -> int:
    from esign.verification import Verifier

    rt = rt_factory()
    verifier = Verifier(audit=rt.audit, blobs=rt.blobs, sealer=rt.sealer)
    with rt.transaction() as db:
        report = verifier.verify_envelope(
            db, args.envelope_id, actor=Actor(role="system"), ctx=RequestContext(auth_method="cli")
        )
    if args.json:
        _say(json.dumps(report.to_json(), indent=2))
    else:
        _say(f"envelope {report.envelope_id}: {report.envelope_status}")
        for check in report.checks:
            _say(f"  {check.status.upper():<8}{check.name}{'  ' + check.detail if check.detail else ''}")
        _say(f"audit trail: {report.audit_event_count} events")
        if report.complete:
            _say("RESULT: verified. The seal, every stored hash and the audit chain all check out.")
        elif report.ok:
            _say("RESULT: consistent so far, but NOT complete: the envelope is not sealed.")
        else:
            _say(f"RESULT: FAILED. {len(report.problems)} problem(s) found.")
    return 0 if report.ok else 1


def _serve(args: argparse.Namespace, _rt: RuntimeFactory) -> int:
    import uvicorn

    # Proxy headers are handled by the app itself, against TRUSTED_PROXY_CIDRS; uvicorn must not
    # rewrite the peer address first or that check would be looking at the wrong thing.
    uvicorn.run("esign.api:app", host=args.host, port=args.port, proxy_headers=False, server_header=False)
    return 0


# --------------------------------------------------------------------------- parser


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="esign", description="E-signing service administration.")
    commands = parser.add_subparsers(dest="command", required=True)

    migrate = commands.add_parser("migrate", help="apply migrations as the owner role")
    migrate.add_argument("--status", action="store_true")
    migrate.add_argument("--dry-run", action="store_true")
    migrate.set_defaults(run=_migrate)

    dev_pki = commands.add_parser("dev-pki", help="generate the development PKI")
    dev_pki.add_argument("--force", action="store_true", help="replace an existing dev PKI")
    dev_pki.set_defaults(run=_dev_pki)

    hosts = commands.add_parser("hosts", help="manage EHR hosts").add_subparsers(dest="action", required=True)
    create = hosts.add_parser("create", help="register a host and print its API key once")
    create.add_argument("--name", required=True)
    create.add_argument("--origin", action="append", help="origin allowed to embed the signing UI (repeatable)")
    create.add_argument("--webhook-url")
    create.set_defaults(run=_hosts_create)
    rotate = hosts.add_parser("rotate-key", help="replace a host's API key")
    rotate.add_argument("host_id", type=UUID)
    rotate.set_defaults(run=_hosts_rotate_key)

    consent = commands.add_parser("consent", help="manage disclosure texts").add_subparsers(
        dest="action", required=True
    )
    add = consent.add_parser("add", help="add a disclosure version (immutable once added)")
    add.add_argument("--default", action="store_true", help="seed the bundled US English ESIGN disclosure")
    add.add_argument("--version")
    add.add_argument("--locale")
    add.add_argument("--file")
    add.add_argument("--effective-at")
    add.set_defaults(run=_consent_add)

    templates = commands.add_parser("templates", help="manage templates").add_subparsers(dest="action", required=True)
    importer = templates.add_parser("import", help="import templates/*.json + *.pdf for a host")
    importer.add_argument("--host", required=True, type=UUID)
    importer.add_argument("--dir")
    importer.add_argument("--no-publish", action="store_true", help="leave the imported versions as drafts")
    importer.set_defaults(run=_templates_import)

    worker = commands.add_parser("worker", help="seal jobs, expiries and webhooks")
    worker.add_argument("--once", action="store_true", help="one tick, then exit")
    worker.set_defaults(run=_worker)

    verify = commands.add_parser("verify", help="re-check an envelope's seal, hashes and audit chain")
    verify.add_argument("envelope_id", type=UUID)
    verify.add_argument("--json", action="store_true")
    verify.set_defaults(run=_verify)

    serve = commands.add_parser("serve", help="run the API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.set_defaults(run=_serve)
    return parser


def main(argv: list[str] | None = None, *, runtime: Runtime | None = None) -> int:
    """Entry point for the ``esign`` console script. ``runtime`` is for tests."""
    args = _parser().parse_args(argv)
    settings = runtime.settings if runtime else get_settings()
    # Logs go to stderr: stdout is this command's own output (`esign verify --json | jq`).
    configure_logging(
        level=settings.log_level, json_output=settings.app_env != "dev", app_env=settings.app_env, stderr=True
    )

    def rt_factory() -> Runtime:
        return runtime or build_runtime(settings)

    try:
        if args.command == "dev-pki":
            from esign.clock import SystemClock

            return _dev_pki(args, rt_factory, settings=settings, clock=runtime.clock if runtime else SystemClock())
        return int(args.run(args, rt_factory))
    except EsignError as exc:
        # The code only: a module's message may quote what it was given.
        return _fail(f"error: {exc.code}")


if __name__ == "__main__":
    raise SystemExit(main())
