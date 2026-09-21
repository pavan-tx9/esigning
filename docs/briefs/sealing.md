# Brief: sealing module

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
- `backend/src/esign/sealing/`, `backend/tests/sealing/`

## Build
SPEC section 5, `Sealer` in contracts. This is the highest technical risk in the project, so be rigorous and verify against pyHanko's actual installed API (read the installed package source under `backend/.venv` rather than guessing).

- `build_sealer(settings, clock)` returning a `Sealer`. Key backends `local` and `aws_kms` behind an internal interface (pyHanko `Signer` subclass whose raw signing calls `kms:Sign`; support RSA PKCS#1 v1.5 SHA-256 and ECDSA P-256 keys). Tests with `moto` for KMS.
- `dev_pki.py`: generate root CA, intermediate, seal certificate and a timestamp-authority certificate into a directory (default `.dev-pki/`, git-ignored), with file modes 0600 for keys. Include CRLs so that offline B-LT is possible if pyHanko allows it; if it is not, make B-T in dev an explicit `SEAL_PROFILE` choice and explain in `sealing/README.md`. Never silently downgrade: the achieved profile is returned in `SealResult`.
- Certification signature, DocMDP no-changes, visible seal not required. RFC 3161 timestamp from a configurable URL; an in-process dummy TSA for tests.
- Map failures carefully: network, KMS and TSA problems -> `SealUnavailable`; malformed input -> `ValidationFailed`. No other exception types escape `seal`.
- `validate()` never raises on bad documents and never trusts embedded certificates: trust roots come from settings only. Distinct problem strings for: not signed, byte-range digest mismatch, content appended after the seal, untrusted chain, bad or missing timestamp, more than one signature, signature that is not a certification signature.
- Tests: seal then validate ok; flip one byte at several offsets (inside content, inside the signature container, in the trailer); append an incremental update with pypdf; strip the signature; seal with a second unrelated PKI and validate against the first (untrusted); TSA down and KMS down raise `SealUnavailable`; sealing a PDF that is already signed is refused.
