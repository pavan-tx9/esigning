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
