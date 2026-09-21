# Brief: identity module

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
- `backend/src/esign/identity/`, `backend/tests/identity/`, migrations `04xx` if truly needed

## Build
SPEC section 8, `IdentityService` and `RateLimiter` in contracts.

- Host keys `esk_` + 32 random bytes base64url; session tokens `est_` + 32 random bytes. Store SHA-256 only. Constant-time comparison. Host lookup ignores disabled hosts.
- `create_session`: validates `auth_time` window using `Clock`, validates kiosk context, revokes earlier live sessions for the signer, stores server-captured IP and user agent from `RequestContext`. It does not check envelope state (the envelopes module does, via `assert_signer_may_start`, and the API calls both).
- `authenticate_session`: unknown, expired and revoked are one indistinguishable `Unauthorized`. Join through signer to return `envelope_id`.
- Re-auth attestations append-only; `fresh_reauth` uses `REAUTH_MAX_AGE_SECONDS` and rejects attestations whose `auth_time` predates the session or is in the future.
- Consent: immutable versions, `current_consent` picks the latest effective version for the locale with fallback to `en-US`; ship a careful default US ESIGN disclosure (right to paper, how to withdraw consent, hardware/software needs, how to get a copy) as a versioned text file, plus an `add_consent_text` function for the CLI to call.
- Helpers for the CLI: `create_host(db, name, allowed_origins, webhook_url) -> (key_plain, Host)`, `rotate_host_key`.
- In-memory sliding-window `RateLimiter`, thread-safe, using `Clock`, bounded memory.
- A small pure helper that derives client IP from a peer address plus `X-Forwarded-For` given `TRUSTED_PROXY_CIDRS`, with tests for spoofing attempts.
- Tests: everything above, token entropy/format, that plaintext tokens never reach the database, revocation on new session, clock edge cases.
