# E-signing service

Legally binding e-signatures for an EHR. Read `docs/SPEC.md` before changing anything; the rules in
`docs/ehr-esignature-developer-guide.pdf` are requirements. The product is evidence: prefer the
design that better proves who signed, what they saw, that they meant it, and that nothing changed.

## Layout
- `backend/` Python 3.13, FastAPI, SQLAlchemy 2 + psycopg 3, pyHanko. Managed with `uv`.
- `frontend/` Bun, Vite, React 19, TypeScript strict, TanStack Query, Tailwind v4, Base UI, Zod, Biome.
- `demo-host/` stand-in EHR used for end-to-end runs.
- `backend/src/esign/contracts.py` and `backend/migrations/0001_schema.sql` are the cross-module
  contract. Changing them is an architecture change: update `docs/SPEC.md` in the same commit.

## Commands
- `make up` start Postgres (port 54329) · `make migrate` · `make check` (everything; must pass)
- `cd backend && uv run pytest tests/<module>` · `uv run ruff check` · `uv run mypy src`
- `cd frontend && bun run dev | typecheck | check | test`

## Hard rules
- No PHI in logs, URLs, error messages, webhook payloads or audit `data`. Use the structured logger.
- The client never supplies PDF bytes, hashes, timestamps or identity. Time comes from `Clock`.
- Audit events, blobs, revisions and consent texts are append-only. There is no delete path. Do not add one.
- Never fail open: a document is not complete until it is sealed, validated and stored.
- No private keys in the repo, env vars or images. No hand-rolled cryptography; use pyHanko.
- Modules import `esign.contracts` and foundation files only, never a sibling module's internals.
- Frontend: `fetch` only in `src/lib/api.ts`; every response parsed with Zod; server state in TanStack Query.
- Do not copy code from DocuSeal, Documenso or OpenSign (AGPL).
