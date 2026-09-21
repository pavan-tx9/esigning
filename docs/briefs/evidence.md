# Brief: evidence module (audit trail + blob storage)

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
- `backend/src/esign/audit/`, `backend/src/esign/storage/`, `backend/tests/audit/`, `backend/tests/storage/`, migrations `01xx` if truly needed

## Build
SPEC sections 4 and 7, `AuditLog` and `BlobService` in contracts.

Audit: canonical JSON and hashing in one small pure module with a documented field list and a worked test vector in `audit/README.md` (someone must be able to re-verify a chain by hand). Per-stream advisory lock, gapless sequence, per-event-type `data` validation with Pydantic models that forbid unknown keys and free text (define the allowed `data` shape for every `EventType`; keep them to ids, enums, hashes, versions, counts and error codes). `verify` must report every problem it finds, not stop at the first: sequence gaps, wrong `prev_event_hash`, hash mismatch, non-monotonic `occurred_at`.

Storage: `fs` and `s3` backends behind `BlobService`, selected by settings. FS: exclusive create, read-only file mode, fan-out directories, fsync, refuses overwrite, atomic (temp file + link, never rename-over). S3: Object Lock retain-until in COMPLIANCE mode by default (GOVERNANCE by config), conditional put (`IfNoneMatch="*"`), SSE enabled; tests with `moto`. `put` is idempotent for identical content and records the row in `blobs`. `get` re-hashes. There is no delete method anywhere.

Tests: everything in SPEC 12 about audit and blobs, including the concurrency test (threads, separate connections) and both role-permission tests.
