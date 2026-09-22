# esign backend

Python 3.13, FastAPI, SQLAlchemy 2 + psycopg 3, pyHanko. Managed with `uv`.

```
uv sync                       # install (already done by the foundation step)
uv run python -m esign.migrate   # apply backend/migrations/*.sql as the owner role
uv run pytest                 # tests; database tests skip when Postgres is unreachable
uv run ruff check && uv run mypy src
```

Configuration is read from the environment (see `.env.example`) by `esign.config.Settings`.
Nothing in here ever logs PHI: use `esign.logging.get_logger` and the key allowlist.

## Running it

```
make up                                  # Postgres on :54329
uv run esign migrate                     # schema, roles, guards
uv run esign dev-pki                     # development PKI into .dev-pki/ (git-ignored; never production)
uv run esign consent add --default       # the bundled US English ESIGN disclosure
uv run esign hosts create --name "Demo EHR" --origin http://localhost:5280 \
    --webhook-url http://localhost:5280/hooks/esign      # prints the API key and webhook secret ONCE
uv run esign templates import --host <host id>           # templates/*.json + *.pdf, published
uv run esign serve                       # API on :8000, signing UI at /sign?host=<host id> once built
uv run esign worker                      # seal retries, expiries, webhooks (run as many as you like)
uv run esign verify <envelope id>        # re-check seal, stored hashes and audit chain; exit 1 on failure
```

`SEAL_PROFILE` defaults to `PAdES-B-LT`; `PAdES-B-T` is a deliberate dev/test choice and is set by
name in `.env.example` and `tests/conftest.py`, never fallen back to. `APP_ENV=prod` refuses to
start without `aws_kms` (with its key id and certificate), `s3`, a long-term profile, a TSA URL, an
existing trust-roots file, real database credentials and `DB_ECHO` off. The check lives in
`esign/runtime.py` and runs in `build_runtime`, so the API, `esign worker`, `esign verify` and every
other command are gated identically -- the worker is the process that seals.

## Layout of the integration layer

| Path | What it is |
|---|---|
| `esign/runtime.py` | the one place every module factory is called; the unit-of-work helper |
| `esign/api/` | FastAPI app: host routes, signer routes, templates, idempotency, middleware, `/sign` |
| `esign/worker/` | `run_once` / `run_forever`: seal jobs, expiries, webhook delivery |
| `esign/verification/` | `Verifier.verify_envelope` and its report |
| `esign/webhooks/` | the queue (an `EnvelopeNotifier`), signing, delivery |
| `esign/cli.py` | the `esign` command |
| `tests/e2e/` | the real HTTP app over real modules: local keys, in-process TSA, fs blobs |
