# Brief: envelopes module

Read `CLAUDE.md`, `docs/SPEC.md` and `backend/src/esign/contracts.py` in full before writing code.

Rules for this task:
- Edit only the paths listed under "You own". Do not edit `contracts.py`, `0001_schema.sql`, `pyproject.toml`, `conftest.py` or any other module. If a contract is wrong or a dependency is missing, finish what you can and say so clearly in your final message.
- Dependencies are already installed in `backend/.venv` (run things with `uv run --offline ...` from `backend/`). You have no network access and the database may be unreachable from your sandbox: write the database tests anyway, using the fixtures in `backend/tests/conftest.py`, and run whatever does not need the database. A later step runs the full suite.
- Implement the Protocols from `contracts.py` exactly. Expose the factory named in SPEC section 2 from the package `__init__.py`.
- Tests go in `backend/tests/<module>/`. Cover every item in SPEC section 12 that touches your module, plus the edge cases you find. Prefer real objects over mocks.
- Code must pass `uv run --offline ruff check` and `uv run --offline mypy src`.
- Do not run git commands that change state (no add, commit, checkout, stash).
- Final message: what you built, anything in the spec you could not satisfy and why, and any contract problems.

## You own
- `backend/src/esign/envelopes/`, `backend/tests/envelopes/`, migrations `05xx` if truly needed

## Build
SPEC section 3, `EnvelopeService` in contracts. Other modules are being written at the same time, so depend only on the Protocols and take `AuditLog`, `BlobService`, `DocumentService`, `IdentityService`, `Sealer`, `Clock` and settings by constructor injection. Write simple in-memory or thin fakes for them in `tests/envelopes/fakes.py`; database state for envelopes, signers, revisions, captures and seal jobs is real (use the conftest fixtures).

- Keep the transition rules in a pure module (`state.py`): given envelope status, signer statuses, order and a command, return the new statuses or a `Conflict` code. Exhaustively unit-test it with a table. The service layer does locking (`SELECT ... FOR UPDATE` on the envelope row), persistence and audit events, all in the caller's transaction.
- Template lookup: published versions only, host-scoped, approved `document_type` list from settings. Validate signers against `SignerRoleDef` (role exists, capacity allowed, guardian/proxy carry `on_behalf_of`, required roles present, no duplicate roles). `requires_reauth` is copied from the role.
- `create`: prepare the PDF via `DocumentService`, store as revision 1, record `envelope.created` and `document.prepared`. Prefill values must not be persisted or logged. Supersede: the old envelope must be sealed and same host; record `envelope.superseded` on the old stream.
- `present` sets `signing_sessions.presented_sha256` and moves `created -> in_progress`. `record_viewed`, `accept_consent` (version must equal the current one), `sign`, `decline`, `void`, `expire_due`.
- `sign`: checks viewed, consented, fresh re-auth when required, captures belong to this signer, all required fields covered; stores drawn images as blobs and rows in `signature_captures`; applies marks to `current_revision_sha256`; writes a new `document_revisions` row; records `signer.signed` with `document_sha256` = new revision and `data` containing the presented hash and the base revision hash; on the last signer sets `completed_pending_seal`, records `envelope.completed`, inserts the `seal_jobs` row; revokes the signer's sessions except for copy download (leave the session usable for `GET copy` only: expose `may_download_copy(session)`).
- `seal_pending`: builds `CertificateSummary` from the audit trail and rows, builds certificate, finalizes, stores the unsealed final, seals, validates the sealer's output and refuses to proceed if validation fails, stores the sealed blob with `retain_until` from the retention setting, marks `sealed`, records `document.finalized`, `document.sealed`, `document.stored`. On `SealUnavailable` record `seal.failed` with the error code in a separate committed step if the caller provides a way, and re-raise. Provide `next_backoff(attempts)` implementing the schedule in SPEC 3.
- Tests: SPEC 12 items for ordering, preconditions, re-auth, decline, void, expiry, supersede, foreign-field capture, two threads signing the same parallel envelope, and seal failure then success.
