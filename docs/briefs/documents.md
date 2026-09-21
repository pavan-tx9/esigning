# Brief: documents module

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
- `backend/src/esign/documents/`, `backend/tests/documents/`, `templates/`, migrations `03xx` if truly needed

## Build
SPEC section 6, `DocumentService` in contracts. pypdf for structure, reportlab for drawing overlays and the certificate, Pillow for images. Embed an OFL-licensed script font for typed signatures and a plain font for everything else; vendor the font files under `documents/fonts/` with their licence files. If you cannot fetch fonts (no network), use the fonts already present in the reportlab package and report it.

- `inspect_template_pdf`: reject encrypted, signed, JavaScript, XFA, embedded files, launch/URI-less risky actions; enforce `MAX_TEMPLATE_BYTES` and `MAX_TEMPLATE_PAGES` from settings. Return displayed page sizes (account for `/Rotate`, `CropBox`).
- `validate_definitions`: collect and report every problem in one `ValidationFailed`.
- `prepare`, `apply_signer_marks`, `finalize`: correct placement on rotated pages and pages whose box origin is not (0,0); text clipped or shrunk to fit its rect, never overflowing; output has no AcroForm, no JavaScript, no editable annotations. `date_signed` comes from the `SignerStamp`, never from a capture.
- `sanitize_signature_png`: bounded decode (max dimensions, max pixels, guard against decompression bombs), PNG only, strip metadata, reject blank or near-blank canvases, re-encode.
- `build_certificate`: clean, legible, paginates for many signers, contains exactly the fields in SPEC 6 and nothing from the chart.
- `templates/`: a reproducible generator script plus the three sample templates and their JSON definitions described in SPEC 6. Validate them in a test.
- Tests: geometry tests that extract text/image positions from the output to prove marks landed inside their rects on normal, rotated and offset-origin pages; rejection tests for each forbidden PDF feature (build fixtures in code); oversize and bomb PNGs; capture for a field not in the given subset is rejected; missing required capture is rejected.
