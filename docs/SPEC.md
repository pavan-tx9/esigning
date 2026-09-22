# E-signing service: specification

A standalone signing service that an EHR embeds. It produces legally defensible electronic
signatures under ESIGN/UETA for signers the EHR has **already authenticated**. The rules in
`docs/ehr-esignature-developer-guide.pdf` are requirements, not advice. This spec turns them into
an architecture.

**The job is evidence.** If a signature is disputed years from now, the stored record alone must
show who signed, what they saw, that they meant to sign, and that nothing changed afterwards. When
two designs are otherwise equal, pick the one that produces better evidence.

The contract lives in two files that module authors must not edit. They were revised once, at
integration, from the module hand-off reports; every such revision is listed in section 13:

- `backend/src/esign/contracts.py`: every cross-module type and interface
- `backend/migrations/0001_schema.sql`: the full schema

## 1. Scope

In: authenticated signers (portal patients, in-clinic tablet, clinicians), PDF templates the host
controls, single and multi-signer envelopes, consent, re-authentication, cryptographic sealing,
hash-chained audit trail, write-once storage, signer copy, verification tool, webhooks to the host,
an embeddable signing UI, and a demo host that exercises everything end to end.

Out, and must stay out: email-link signing for people without an account, a drag-and-drop template
builder, bulk send, arbitrary uploaded PDFs at signing time, controlled-substance prescriptions,
notarisation, non-US signature regimes. If a request needs one of these, the API refuses with a
clear error code rather than approximating it.

## 2. Architecture

```
EHR backend (host) --API key--> esign API --+-- Postgres (state, audit trail)
EHR page --iframe + postMessage--> signing UI |-- blob store (FS in dev, S3 Object Lock in prod)
                                              |-- KMS/HSM signing key (local dev PKI in dev)
                                              +-- RFC 3161 timestamp authority
```

- **Backend**: Python 3.13, FastAPI (sync endpoints), SQLAlchemy 2.0 + psycopg 3, Pydantic v2,
  pyHanko for PAdES, pypdf + reportlab + Pillow for document work, boto3 for KMS and S3. Managed
  with `uv`. Lint `ruff`, types `mypy`, tests `pytest`.
- **Frontend**: Bun, Vite, React 19, TypeScript strict, TanStack Query, Tailwind v4, Base UI,
  Zod at the fetch seam, pdf.js for rendering, Biome.
- **Demo host**: a tiny FastAPI app standing in for the EHR.

Directory ownership (an agent edits only its own paths):

| Path | Owner |
|---|---|
| `backend/src/esign/contracts.py`, `backend/migrations/0001_schema.sql`, `docs/SPEC.md` | architecture, read-only for everyone else |
| `backend/pyproject.toml`, `backend/src/esign/{config,db,clock,ids,logging}.py`, `backend/tests/conftest.py`, `docker-compose.yml`, `Makefile`, `frontend/` scaffold | foundation |
| `backend/src/esign/audit/`, `backend/src/esign/storage/`, their tests | evidence module |
| `backend/src/esign/sealing/`, tests | sealing module |
| `backend/src/esign/documents/`, tests, `templates/` | documents module |
| `backend/src/esign/identity/`, tests | identity module |
| `backend/src/esign/envelopes/`, tests | envelopes module |
| `frontend/src/` | frontend module |
| `backend/src/esign/{api,worker,verification,webhooks}/`, `backend/src/esign/cli.py`, `backend/tests/e2e/`, `demo-host/` | integration |

Modules depend on `contracts.py` and foundation files only, never on a sibling module's
internals. Each module exposes one factory in its `__init__.py` (`build_audit_log(settings, clock)`,
`build_blob_service(...)`, `build_sealer(...)`, `build_document_service(...)`,
`build_identity_service(...)`, `build_rate_limiter(...)`, `build_envelope_service(...)`), and
`EnvelopeService` receives its collaborators by constructor injection so it can be tested with fakes.

### Migrations
Plain SQL files in `backend/migrations/`, applied in filename order by `esign migrate`, tracked in
a `schema_migrations` table. `0001` is the schema; `0002_roles.sql` (foundation) creates the roles
and grants. A module that truly needs a change adds a file in its range (evidence 0100s, sealing
0200s, documents 0300s, identity 0400s, envelopes 0500s, integration 0600s) and reports it.

### Database roles
- `esign_owner` runs migrations.
- `esign_app` is the runtime role. It gets `SELECT, INSERT` only on `audit_events`, `blobs`,
  `document_revisions`, `consent_texts`, `reauth_attestations`; `SELECT, INSERT, UPDATE` on the
  rest; `DELETE` on `idempotency_keys` alone; no DDL, no `TRUNCATE`. The append-only triggers are
  the second line of defence: `BEFORE UPDATE OR DELETE` in `0001`, and `BEFORE TRUNCATE` on all
  five tables (`audit_events` in `0001`, `blobs` in `0100`, the other three in `0600`). Tests must
  prove both: the app role is denied, and the owner role hits the trigger.
  `DELETE` is granted nowhere else because the application issues it nowhere else, and `signers`,
  `signing_sessions` and `signature_captures` are the rows the certificate of completion is built
  from: `0602` revokes it and stops `ALTER DEFAULT PRIVILEGES` handing it to new tables.

## 3. The pipeline

Every envelope goes through these steps. Each writes an audit event in the same transaction as
the state change.

1. **Prepare**: host calls `POST /v1/envelopes` with template, signers and prefill data. The
   service renders the PDF server-side, flattens it, stores it as revision 1 (`presented`), records
   its hash. Prefill data is used once and never stored outside the PDF.
2. **Session**: host calls `POST /v1/envelopes/{id}/signers/{sid}/sessions`, attesting how and when
   the user authenticated (and the kiosk context for in-clinic tablets). It gets back an opaque
   token, which it hands to the embedded UI via `postMessage`. The token never appears in a URL.
   The identity module writes no audit events; the **API layer** appends `session.created` in the
   same transaction, `auth.reauthenticated` likewise in step 5, and `session.rejected` in a
   transaction of its own (the refused request's transaction is rolled back, and the refusal is
   evidence that has to survive that).
3. **Present and view**: the UI fetches the current revision. The server records
   `document.presented` with the hash of the bytes it served. The UI reports `viewed` once every
   page has been displayed. The server refuses consent and signing before that.
4. **Consent**: the signer accepts the current ESIGN disclosure. The version and body hash are
   stored. There is always a visible decline/paper path.
5. **Re-authenticate** (roles with `requires_reauth`): the UI asks the host page to re-authenticate
   the user; the host backend then calls `POST /v1/sessions/{id}/reauth`. Signing requires an
   attestation younger than `REAUTH_MAX_AGE_SECONDS` (default 120).
6. **Capture and sign**: the UI sends signature inputs only (PNG, typed text, or click), with an
   `Idempotency-Key`. The server sanitises images, stamps the marks and a caption onto the current
   revision under the envelope row lock, stores the new revision, records `signer.signed` with both
   the presented hash and the new revision hash.
7. **Finalize and seal**: when the last signer signs, the envelope becomes
   `completed_pending_seal` and a seal job is enqueued (and attempted once inline). The job builds
   the certificate of completion from the audit trail, appends it, applies one PAdES certification
   seal with an RFC 3161 timestamp using the KMS-held key, validates its own output, stores it
   write-once, then marks the envelope `sealed`.
8. **Deliver**: the signer can download the sealed copy from the same session; the host is
   notified by webhook and fetches the sealed PDF to file in the chart.
9. **Verify**: `esign verify <envelope_id>` and `GET /v1/envelopes/{id}/verification` re-check the
   seal, every stored hash, and the audit chain, and record that the check happened.

**Why one seal at the end rather than a signature per signer:** the certificate of completion has
to be inside the sealed bytes, and appending pages after a PDF signature invalidates it. So each
signer step produces a hashed, stored, audit-chained revision, and the single final seal covers the
document plus certificate with DocMDP "no changes permitted". The per-signer evidence is the audit
chain and the stored revisions, which verification re-hashes.

**Failure rule:** never fail open. If KMS, the timestamp authority or storage is unavailable
(`SealUnavailable`, `StorageUnavailable`) the envelope stays `completed_pending_seal`,
`seal.failed` is recorded with an error code, the job backs off (1m, 5m, 15m, 1h, then hourly),
and nothing anywhere reports the document as complete. The same holds for a failure that is not
retryable (an integrity failure, a seal that does not validate, a bug): pending, recorded, loud.
`seal.failed` and the job's backoff are written in a separate committed transaction, because the
failed attempt's own transaction is rolled back.

An envelope waiting for its seal cannot be voided (`created|in_progress -> voided` only). This is
deliberate: every signer has signed, and the honest states are "sealed" or "still trying". There
is no operator escape hatch that would turn a fully signed document into a cancelled one.

### Envelope states
```
created -> in_progress -> completed_pending_seal -> sealed
created|in_progress -> declined | voided | expired
```
`created` becomes `in_progress` on first presentation. Sealed envelopes are never voided: a
correction is a new envelope with `supersedes_envelope_id`, which records `envelope.superseded` on
the old stream. Signer states: `pending -> viewed -> consented -> signed`, or `declined`. Any
decline ends the envelope. Sequential order gates session creation on all earlier signers having
signed; parallel order allows any order, serialised by the envelope row lock.

## 4. Audit trail

- One chain per stream (`envelope`, `template`, `system`). `sequence` starts at 1 and has no gaps.
  `prev_event_hash` of the first event is 32 zero bytes.
- Writers serialise per stream with `pg_advisory_xact_lock` on a hash of the stream id, then read
  the head, then insert.
- `event_hash = SHA-256(canonical_json(event without event_hash))`. Canonical JSON: keys sorted,
  no insignificant whitespace, UTF-8, bytes as lowercase hex, UUIDs as lowercase strings, timestamps
  as RFC 3339 UTC with exactly six fractional digits and `Z`, absent values as `null`. The exact
  field set and a worked test vector live in `esign/audit/` and must be documented there, because
  someone will need to re-verify a chain by hand one day.
- `occurred_at` comes from `Clock` on the server. Nothing in an audit row comes from client JSON
  except through validated, typed fields.
- `data` is validated per event type against an allowlist of keys and value shapes (ids, enums,
  hashes, versions, counts, error codes). Names, dates of birth, free text and prefill values can
  never appear. Reject unknown keys. The allowlist has exactly one definition,
  `esign/audit/events.py` (`EVENT_DATA_MODELS`); no other module keeps a copy, and the envelope
  module's tests validate through it so the two cannot drift.
- Host-chosen identifiers that reach the trail (`host_user_id`, `patient_ref`, kiosk
  `staff_user_id`) must be opaque: `contracts.is_opaque_id` (no whitespace, not a date, not an SSN).
  They are checked where they enter (envelope and session creation) and again on append.
- If `Clock` is behind the head of a stream, `append` refuses with `IntegrityFailure`
  (`audit_clock_regression`) rather than writing an out-of-order event or clamping the time.
- IP and user agent are taken from the request server-side, honouring `TRUSTED_PROXY_CIDRS`.

## 5. Sealing

- PAdES via pyHanko. Production profile `PAdES-B-LT` (embedded validation info); `B-LTA` available
  by config. If the dev PKI cannot supply revocation data offline, dev and test may use `B-T`, but
  this must be an explicit `SEAL_PROFILE` setting, never a silent downgrade. The profile actually
  achieved is recorded in the `document.sealed` event. The certificate of completion is inside the
  sealed bytes, so it is written before the seal exists: it prints the *configured* profile
  (`CertificateSummary.seal_profile`), labelled as such.
- The envelope id is written into the signature dictionary (`/Location = envelope:<id>`), binding
  the seal to the envelope it completes.
- `SealValidation.ok` is false whenever `problems` is non-empty, whatever the four flags say.
- The seal is a certification signature with DocMDP level 1 (no changes).
- Key backends behind one interface: `local` (dev PKI generated by `esign dev-pki` into a
  git-ignored directory: root CA, intermediate, seal certificate, timestamp authority certificate)
  and `aws_kms` (boto3 `kms:Sign`; certificate chain from PEM files). No private key material in
  the repo, in environment variables, or in the image. Tests for KMS use `moto`.
- Timestamp authority: URL from config. Tests use an in-process dummy authority from the dev PKI.
- Network or KMS failure raises `SealUnavailable`. A malformed input PDF raises `ValidationFailed`.
- `validate()` must detect: a flipped byte, an incremental update appended after the seal, a
  removed signature, and an untrusted chain, each with a distinct problem string. It must never
  trust a certificate merely because it is embedded in the document.

## 6. Documents

- Templates are PDFs the host uploads ahead of time. `inspect_template_pdf` rejects encrypted,
  signed, scripted, XFA or attachment-bearing files and enforces size and page limits.
- Field geometry uses displayed-page coordinates (`Rect`). Handle `/Rotate` and non-zero
  `MediaBox`/`CropBox` origins correctly and test them.
- Stamping: drawn signatures as images scaled to fit the rect preserving aspect ratio; typed
  signatures in an embedded script-style font with a plain fallback; click-to-sign renders the
  signer's name in the plain font. Every signature gets a small caption: name, capacity (and "on
  behalf of" where relevant), UTC time, signer id. `date_signed` fields are filled by the server
  from `Clock`, never by the client. Signature and initials fields are at least 80x28pt, so the
  caption never has to abbreviate the signer id (the link between the mark and the audit trail).
- A signer role may be declared `required: false` (an optional witness or interpreter); an
  envelope may omit such a role. Every role that is present must sign.
- Embed fonts. Output must contain no JavaScript, no form fields, no annotations that can be edited.
- Certificate of completion: envelope id, document type, template key and version, hashes, and per
  signer: name, role, capacity, authentication method, re-authentication method, consent version,
  viewed/consented/signed times, IP, user agent, kiosk details. Plus the audit event count and head
  hash, the seal profile, and a line on how to verify. No chart data.
- Ship three sample templates in `templates/` with definitions: a patient consent form (patient,
  optional guardian capacity), a HIPAA acknowledgement (patient), and a procedure consent needing
  patient, witness and clinician in sequence. Generate the PDFs with a script so they are reproducible.

## 7. Storage

- `BlobService` is content-addressed and write-once. Backends: `fs` (files created read-only,
  exclusive create, refuses overwrite) and `s3` (Object Lock with retain-until, conditional put so
  an existing key is never replaced). S3 tests use `moto`; an optional MinIO integration test may
  be included but skipped when MinIO is not running.
- `get` re-hashes and raises `IntegrityFailure` on mismatch.
- `retain_until` comes from `RETENTION_YEARS_BY_DOCUMENT_TYPE` (default 10 years): the caller
  computes it with `Settings.retain_until(document_type, now)` and passes it to `put`; an omitted
  value gets the default retention. Nothing in the codebase deletes a blob. There is no delete
  method.
- An unreachable backend raises `StorageUnavailable` (retryable, 503).

## 8. Identity

- Host API keys look like `esk_<random>`, are shown once by `esign hosts create`, and are stored as
  SHA-256 hashes.
- Session tokens look like `est_<random>` (256 bits), stored hashed, bound to one signer, expire
  after `SESSION_TTL_SECONDS` (default 1800), and creating a new one revokes the previous one.
  Unknown, expired and revoked tokens are indistinguishable to the caller.
- `auth_time` older than `AUTH_MAX_AGE_SECONDS` (default 12 hours) or in the future is rejected.
- Kiosk sessions record the staff member and the identity check method. The signature is
  attributed to the patient (or guardian), never to the staff member.
- Consent texts are versioned, immutable, and seeded by migration-independent `esign consent add`.
  A default US English ESIGN disclosure ships in `backend/src/esign/identity/consent/`.
- Rate limits (in-memory sliding window behind the `RateLimiter` protocol): per session and per IP
  on sign, consent and token failures; per host on session creation and reauth.

## 9. API

Errors are `{"error": {"code": "...", "message": "..."}}` with the `EsignError` status. Messages
never echo input. All ids are UUIDv4. Hashes are lowercase hex.

### Host API (`Authorization: Bearer esk_...`)
| Method and path | Purpose |
|---|---|
| `POST /v1/templates` | create template as draft v1. Multipart: `pdf` (file) + `definitions` (JSON text: `{key, name, document_type, fields, prefill_fields, signer_roles}`) |
| `POST /v1/templates/{key}/versions` | new draft version |
| `POST /v1/templates/{key}/versions/{n}/publish` | publish (immutable from here) |
| `POST /v1/templates/{key}/versions/{n}/retire` | retire |
| `GET /v1/templates`, `GET /v1/templates/{key}` | list, detail |
| `POST /v1/envelopes` | create from a published version; body is `NewEnvelope`; supports `Idempotency-Key` (a replay returns the *same envelope*, as it is now: what is stored is its id, not a second copy of the signers' names) |
| `GET /v1/envelopes/{id}` | `EnvelopeView` |
| `POST /v1/envelopes/{id}/void` | `{reason_code}` from the fixed list `contracts.VOID_REASON_CODES` (a host-invented code would be free text with underscores, and it reaches the audit trail) |
| `POST /v1/envelopes/{id}/signers/{sid}/sessions` | `{auth: {method, auth_time}, kiosk?: {staff_user_id, identity_check}}` -> `{token, session_id, expires_at}` |
| `POST /v1/sessions/{session_id}/reauth` | `{method, auth_time}` -> `{session_id, reauth_valid_until}`; another host's session is `not_found` |
| `GET /v1/envelopes/{id}/document` | sealed PDF, or 409 `not_sealed` |
| `GET /v1/envelopes/{id}/audit` | audit events |
| `GET /v1/envelopes/{id}/verification` | run and return a verification report. Always 200 for an envelope that exists: a failed verification is a finding (`ok: false`, `problems`), not a transport error |

Requests outside the scope of section 1 (`POST /v1/envelopes/bulk`, `.../email-links`,
`.../documents`) are refused with `422 out_of_scope`. There is no `DELETE`, `PUT` or `PATCH` route.

### Signer API (`Authorization: Bearer est_...`)
| Method and path | Purpose |
|---|---|
| `GET /v1/signing/session` | everything the UI needs, shape below. `?locale=` picks the disclosure language |
| `GET /v1/signing/document` | current revision PDF; records `document.presented` |
| `POST /v1/signing/viewed` | `{pages_viewed: int}` must equal the page count |
| `POST /v1/signing/consent` | `{consent_version, accepted: true, locale?}` (`locale` as shown in the session payload; default locale when omitted) |
| `POST /v1/signing/sign` | `{intent_confirmed: true, captures: [...]}` + `Idempotency-Key` |
| `POST /v1/signing/decline` | `{reason_code}` from a fixed list including `prefers_paper` |
| `GET /v1/signing/copy` | sealed PDF (records `document.downloaded`), or 202 `{status: "sealing"}` while the seal is pending, or 409 `envelope_not_complete` while other signers are outstanding |

Every signer `POST` answers `{"envelope": {"id", "status"}, "signer": {"id", "status"}}`: ids and
statuses only. `sign` reports the state as of the signature (`completed_pending_seal` for the last
signer) even when the inline seal attempt then succeeds; the UI learns of sealing from `copy` or
the session. `sign` requires `Idempotency-Key` (422 `idempotency_key_required`). Request bodies
forbid unknown keys, so a client that sends a hash, a timestamp, a PDF or a `date_signed` value is
refused (422) rather than ignored.

`GET /v1/signing/session` response:
```json
{
  "envelope": {"id": "...", "status": "in_progress", "document_type": "procedure_consent",
               "title": "Procedure consent", "page_count": 3, "expires_at": "..."},
  "signer": {"id": "...", "display_name": "...", "role_label": "Patient", "capacity": "self",
             "on_behalf_of_label": null, "status": "pending", "requires_reauth": false,
             "reauth_valid_until": null},
  "other_signers": [{"role_label": "Witness", "status": "pending"}],
  "fields": [{"id": "patient_sig", "type": "signature", "page": 3,
              "rect": {"x": 72, "y": 120, "w": 220, "h": 48}, "required": true,
              "label": "Patient signature"}],
  "consent": {"version": "2026-09", "locale": "en-US", "body": "..."},
  "session": {"id": "...", "expires_at": "...", "kiosk": false},
  "decline_reasons": [{"code": "prefers_paper", "label": "I would rather sign on paper"}]
}
```
Capture shapes: `{"field_id", "kind": "drawn", "image_png_base64"}`, `{"field_id", "kind":
"typed", "typed_text"}`, `{"field_id", "kind": "click"}`, and for non-signature fields
`{"field_id", "checked"}` or `{"field_id", "text_value"}`. The two families never mix: a capture
with a `kind` (or a signature payload) *and* a `checked`/`text_value` is refused with 422 at the
edge and is not representable as a `contracts.Capture` at all, because the trail records a
signature's `kind` and a value field's type, and a client must not choose that wording. Signature
and initials fields accept any of the three kinds (the UI sends initials typed); `typed_text` and
`text_value` are bounded by `MAX_TYPED_SIGNATURE_CHARS` (200) and `MAX_TEXT_FIELD_CHARS` (2000).

### Embedding protocol
The UI is served at `/sign?host=<host id>` and loaded in an iframe. The host id is not a secret and
says nothing about a patient; it lets that response carry `Content-Security-Policy: frame-ancestors
<the host's allowed_origins>` and `<meta name="esign-allowed-origins" content="...">` (the list
the UI checks `init` against) before any token exists. Without a known host both are empty: the UI
cannot be framed and trusts nobody. Built assets are served from `/assets`. On load it posts
`{type: "esign:ready"}` to the parent. The parent replies `{type: "esign:init", token, locale?}`. The UI accepts `init` only from
an origin in the host's `allowed_origins` (checked again server-side via a `frame-ancestors` CSP).
UI to parent: `esign:reauth_required {session_id}`, `esign:signed`, `esign:sealed`,
`esign:declined`, `esign:expired`, `esign:resize {height}`. Parent to UI: `esign:reauth_done`.
The token lives in memory only: not in the URL, not in storage.

### Webhooks
`envelope.completed`, `envelope.sealed`, `envelope.declined`, `envelope.voided`,
`envelope.expired`. Payload: ids, status, hashes only (`id` of the delivery, `event`,
`occurred_at`, `envelope_id`, `status`, template key and version (not the document type), the three hashes, and each
signer's `id`, `role_key` and `status`; never a name, `patient_ref` or `host_document_ref`). Signed
with `X-Esign-Signature: t=<unix>,v1=<hex hmac-sha256 of "t.body">` using the secret printed once
by `esign hosts create`; a receiver should reject a `t` more than five minutes old
(`esign.webhooks.verify_signature` is the reference). A delivery row is written in the transaction
that changed the envelope and sent by the worker: at least once, in queue order while nothing
fails, retried with backoff (30s, 2m, 10m, 30m, then hourly) up to `WEBHOOK_MAX_ATTEMPTS`.

### Worker
`esign worker` claims due `seal_jobs` with `FOR UPDATE SKIP LOCKED` in a short transaction that
commits before sealing starts (the claim is `locked_at`; one older than
`SEAL_JOB_LOCK_TIMEOUT_SECONDS` is taken over), runs `seal_pending` in a transaction of its own,
sweeps expiries, and delivers webhooks. Any number of workers may run. The envelope row lock means
two workers holding the same job still seal once.

## 10. Security and PHI rules

- The database and blob store hold PHI. Logs, metrics, error messages, URLs, webhook payloads and
  audit `data` do not. Logging goes through one structured logger with an allowlist of fields;
  request and response bodies are never logged.
- Every document fetch is authorised against the host or the session. A host can never see another
  host's envelope: return `not_found`, not `forbidden`.
- The client is untrusted: it never supplies PDF bytes, hashes, timestamps, signer identity, or
  `date_signed` values.
- Responses carrying PDFs set `Cache-Control: no-store`. The app sets a strict CSP;
  `frame-ancestors` is the host's allowed origins.
- Size limits on every body. PNG decoding is bounded (dimensions, pixel count, decompression).
- Signing is idempotent: a retried request with the same key returns the first response; the same
  key with a different body is a `conflict`.
- Do not copy code from DocuSeal, Documenso or OpenSign (AGPL).

## 11. Frontend

One flow, six states, all reachable by keyboard and screen reader, all usable at 360px wide and on
a tablet held by a patient in a clinic:

1. **Connecting**: waiting for the token. Clear failure if it never arrives.
2. **Review**: the PDF rendered with pdf.js, page by page, with progress ("Page 2 of 3"). The
   continue action unlocks when every page has been displayed. A text alternative explains that
   staff can provide a paper copy.
3. **Consent**: the disclosure text, an unchecked checkbox, agree, and an equally visible "I'd
   rather sign on paper" that leads to decline.
4. **Sign**: guided through this signer's fields in order. Adopt a signature once per session by
   drawing, typing, or choosing click-to-sign, then apply it to each field with an explicit action
   per field. Show how many remain. Review screen before submitting.
5. **Confirm**: for re-auth roles, hand off to the host and wait. Then a final, plainly worded
   intent confirmation and submit. Disable double submission; send an `Idempotency-Key`; survive a
   retry after a network failure.
6. **Done**: confirmation and the signed copy. While sealing is pending, say so honestly and poll.
   If other signers remain, say the copy will be available when everyone has signed. Decline,
   expired and error states each have their own screen with a next step.

Conventions: `fetch` only in `src/lib/api.ts`, every response parsed with Zod, all server state in
TanStack Query, no hand-rolled fetch state. Token in memory only. Kiosk mode (from the session
payload) ends on a screen that tells the patient to hand the tablet back and clears all state.
Copy is calm, plain, second person, no legalese outside the disclosure itself, no exclamation marks.

## 12. Testing

Each module ships its own tests under `backend/tests/<module>/`. Database tests run against the
Postgres in `docker-compose.yml` (port 54329) through the fixtures in `conftest.py`, which give
each test a migrated schema and connections as both roles. Required evidence tests:

- flip one byte of a sealed PDF -> validation fails; append an incremental update -> fails
- app role cannot `UPDATE`/`DELETE`/`TRUNCATE` audit events; owner role hits the trigger
- tampering with any audit column breaks `verify`; removing a row is reported as a gap
- concurrent appends to one stream produce a gapless chain
- blob overwrite refused; corrupted blob raises `IntegrityFailure`
- sign before viewed/consented -> `conflict`; clinician sign without fresh re-auth -> `forbidden`
- sequential order enforced; parallel signers serialise correctly
- double-submitted sign returns the same response and creates one revision
- KMS down and TSA down -> envelope stays pending, `seal.failed` recorded, retry succeeds later
- decline, void, expiry, supersede paths
- a capture for someone else's field is rejected
- no log line in a full end-to-end run contains a signer name or prefill value

`make check` runs ruff, mypy, pytest, and the frontend's typecheck, lint and tests. It must pass.

## 13. Contract revisions made at integration

The modules were built in parallel against `contracts.py` and reported where it was wrong. These
changes were made once, by the integration owner, with this document updated alongside:

- **Audit allowlist**: the envelope module kept its own copy of the allowed `data` keys and it
  disagreed with the audit module's on almost every event (a real envelope could not be created).
  One definition now (`esign/audit/events.py`); the envelope service emits exactly those shapes.
  `signer.signed` gained `base_revision_sha256` and `reauth_method`; capture kinds in the trail
  are `drawn | typed | click | checkbox | text`. New event `envelope.declined`.
- **Errors**: `StorageUnavailable` (retryable, like `SealUnavailable`); `RateLimited` carries
  `retry_after_seconds`.
- **Types**: `Actor.role`/`capacity`, `AuthContext.method` and `KioskContext.identity_check` are
  `Literal`s. `Capture.kind` is optional (checkbox and text captures have none, matching the wire
  shapes). `SignerRoleDef.required`. `CertificateSummary.seal_profile` (the configured profile).
  `EnvelopeView` gained `current_revision_sha256`, `created_at`, `host_id`.
  `DECLINE_REASON_CODES`, `VOID_REASON_CODES`, `OPAQUE_ID_PATTERN` and `is_opaque_id` live in `contracts.py`.
- **Sealing**: `SealValidation.ok` also requires `problems` to be empty; the envelope id is bound
  into the signature; `Sealer.seal` documents which exceptions escape.
- **Identity**: `attest_reauth` takes the `Host` (another host's session is `not_found`) and
  returns the `SessionInfo`; `revoke_sessions(..., except_session_id=)`; `create_session`
  documents its error codes; the API layer owns the three session audit events.
- **Documents**: `DocumentService.page_count`.
- **Envelopes**: `record_viewed` takes `pages_viewed` and checks it against the bytes the session
  was served; `accept_consent` takes the signer's `locale`; `signing_view`, `may_download_copy`,
  `signer_copy` and `sealed_document` are part of the Protocol (the last two record
  `document.downloaded`); `seal_pending` documents the separately committed failure record;
  `EnvelopeNotifier` lets the service queue a webhook in the transaction that made the change.
- **Schema**: `0600` adds the missing `BEFORE TRUNCATE` triggers; `0601` gives
  `webhook_deliveries` an insertion sequence to order by.
- **Foundation**: `configure_logging` no longer caches loggers or binds `sys.stdout` at configure
  time (it broke full-suite runs); signature PNG per-axis limits moved into `Settings`.

Second round, from the envelopes module's review of the integrated system:

- **`Capture` is one shape or the other**: `Capture.__post_init__` refuses a signature `kind` (or
  `image_png`/`typed_text`) together with `checked`/`text_value`, a payload without a `kind`, and
  `checked` with `text_value`. `esign.api.schemas.CaptureBody` refuses the same shapes on the wire
  (422 `validation_failed`), and the envelope service's own check remains as the last line. Before
  this, `Capture(field_id=..., kind="click", checked=True)` was a legal value that reached the
  `signer.signed` payload with the client's word for how the field was filled.
- **Bounds live in `Settings`**: `max_typed_signature_chars` (200) and `max_text_field_chars`
  (2000), read by both the API body and the envelope service, replacing a private copy in each.
- **`EnvelopeService.seal_pending` docstring** now lists `IntegrityFailure` among the exceptions
  that escape and says what a worker must do with it: the envelope stays pending, `seal.failed`
  is recorded, and no retry can fix it.

Third round, from the review of the integrated system:

- **The certificate of completion is built from the audit trail** (section 3 step 7), not from the
  mutable rows. Each signer's `viewed_at`, `consented_at`, `signed_at` and `consent_version` come
  from `document.viewed` / `consent.accepted` / `signer.signed`; the signer's `ip` and `user_agent`
  come from the `signer.signed` event's context, because `signing_sessions.ip`/`user_agent` are the
  *host backend's* (it opens the session server to server) and printing them attributed the EHR's
  address and HTTP client to the patient. `auth_method` and the kiosk details come from
  `session.created`. The rows are kept as a cross-check: a disagreement raises `IntegrityFailure`
  (`certificate_evidence_mismatch`), which leaves the envelope pending with `seal.failed` recorded.
  `reauth_method` is the method `signer.signed` says was used, and `None` for a role that does not
  require re-authentication.
- **`EnvelopeService.assert_reauth_allowed(db, envelope_id, signer_id)`**: the API calls it after
  `attest_reauth`, so an attestation cannot be recorded for a signer who has already signed
  (`signer_finished`), for a role with `requires_reauth: false` (`reauth_not_required`), or on an
  envelope that is no longer being signed (`envelope_not_live`). Declared on
  `runtime.GatedEnvelopeService` until it can move into `contracts.EnvelopeService`.
- **`sign` requires the bytes to have been viewed, not just presented**: `signers.viewed_sha256`
  (`0501`) records the revision `record_viewed` confirmed, and signing refuses with
  `not_viewed` unless the session's presented hash equals it. The signing UI owns the way out of
  that refusal, because nothing else can offer it: the signer's status is still `consented`, so
  the step the flow derives from the server never goes back to Review. On 409 `not_viewed` the UI
  drops the document it holds, returns to Review saying another signer signed while they were
  reading, and the fresh `POST /signing/viewed` that step already sends is what lets the signature
  through. The draft is kept, so nothing they filled in is lost.
- **Audit allowlist**: `CaptureRef` gained `image_sha256` and `typed_text_sha256`, so the raw drawn
  PNG and the typed text are tied to the hash chain rather than only to a mutable row.
  `signature_captures` is append-only from `0502` (grant plus trigger, like every other piece of
  evidence). `audit/README.md`'s worked vector was regenerated.
- **`Sealer`**: `seal` now reads `/Location` back out of its own output and refuses with
  `location_mismatch` if it is not `envelope:<id>`; `Verifier` checks the same thing
  (`seal_bound_to_envelope`), so the binding section 5 requires is evidence rather than intent.
- **`check_production_settings` moved into `esign.runtime`** and is called from `build_runtime`, so
  the API, `esign worker`, `esign verify` and every other command are gated identically -- the
  worker is the process that seals, and it was gated by nothing. It raises
  `runtime.ConfigurationError` (a `RuntimeError`) and additionally refuses dev database passwords,
  `DB_ECHO`, and `aws_kms` with no key id or certificate. `Settings.seal_profile` now defaults to
  `PAdES-B-LT`: `PAdES-B-T` is set explicitly by `.env.example` and `tests/conftest.py`.
- **Bounds**: the documents module's private 80/500 copies are gone; `stamping.apply_signer_marks`
  takes `Settings` and uses `max_typed_signature_chars` / `max_text_field_chars`.
- **Verification** gained `signer_rows_match_trail`, `captures_match_trail`,
  `capture_images_intact`, `sealed_pages_match_final_revision` and `seal_bound_to_envelope`, and
  looks for the certificate's head hash on every page rather than the last four.
- **Rate limits**: `RateLimits.PRESENT`, `COPY` and `VERIFY` cover the GETs that append an audit
  event or re-hash a revision (`/signing/session`, `/signing/document`, `/signing/copy`,
  `/envelopes/{id}/verification`).
- **Consent**: `en-US.2026-10` replaces `2026-09` from 1 October. `2026-09` promised a download
  "from this screen", which is false on a kiosk (section 11 hands the tablet back and wipes state).

Fourth round, from the review of the integrated system. No change to `contracts.py` or
`0001_schema.sql`; these are behaviours the two files already allowed and the code did not enforce:

- **Consent is recorded once, in full**: `accept_consent` is legal for a signer who is already
  `consented` (another locale, or the disclosure rolled over and the client re-posted after a
  `consent_version_stale` refusal), and it kept the first `consented_at` while overwriting
  `consent_text_id`. The row then described one disclosure and the certificate builder's first
  `consent.accepted` another, so a fully signed envelope raised
  `IntegrityFailure(certificate_evidence_mismatch)` on every seal attempt -- for ever, because such
  an envelope cannot be voided and the first event cannot be removed. `only_if_unset` now covers
  `consent_text_id` too: the row keeps the *first* accepted disclosure, matching `consented_at`,
  `_first_event` in the certificate and `signer.signed.consent_version`.
- **`sign` requires the bytes to have been viewed *and* to still be the current revision**: the
  round-3 guard compared the session's presented hash with `signers.viewed_sha256`, which in a
  parallel envelope both still named revision 1 after a co-signer committed revision 2 -- so the
  marks landed on a revision the signer had never been shown, co-signer's field values included.
  `sign` now also refuses (409 `not_viewed`) when the presented hash is not
  `envelopes.current_revision_sha256`, under the envelope row lock, which is the case section 13's
  third round described ("another signer signed while they were reading"). The UI's way out is
  unchanged. `Verifier._viewed_what_was_signed` compares `document.viewed` against
  `signer.signed.base_revision_sha256` rather than `presented_sha256`, so a trail written before
  this is a finding under `signer_rows_match_trail`.
- **Clinician re-authentication is enforced at both ends**: `validate_definitions` refuses a
  template whose role allows the `clinician` capacity without `requires_reauth`
  (`template_definitions_invalid`), and `EnvelopeService.create` sets `requires_reauth` for a
  clinician signer whatever an already-published version says. The developer guide makes this a
  requirement; it was convention in `templates/procedure_consent.json`.
- **The certificate's document-level facts are cross-checked too**: `created_at`, `document_type`,
  `template_version_id` and the template key and version are compared with the first
  `envelope.created` (whose `occurred_at` is the creation time), exactly as the per-signer facts are.
  Verification mirrors the five comparisons as `envelope_row_matches_trail`, and
  `signer_rows_match_trail` gained `role_key`, `capacity`, `on_behalf_of` and `consent_text_id` --
  the columns the seal-time check already required to agree.
- **Sealing validates revocation**: `validate` builds its validation context from the document's own
  `/DSS` under `revocation_mode="hard-fail"`, so the data a `PAdES-B-LT` seal embeds is actually
  consulted (`validate_pdf_signature` does not read the DSS by itself, so it never was). New problem
  strings `certificate_revoked` and `revocation_unknown`; a long-term configuration handed a document
  with no store reports the latter rather than passing, and `PAdES-B-T` -- the explicit dev and test
  profile -- keeps soft-fail. Section 5's list of what `validate` must detect gains these two.
- **`sealed_pages_match_final_revision` compares page resources**: a drawn signature is an image
  XObject invoked by name and a typed one an embedded font, so a swapped signature image left the
  content stream byte-identical. Each named image, font and form XObject is digested with every
  indirect reference resolved, so `finalize`'s renumbering is not a difference and different ink is.
- **The in-process timestamp authority is unreachable from a real key**: `build_timestamper` refused
  only when `APP_ENV=prod`, and `APP_ENV` defaults to `dev`, so a KMS deployment that forgot it
  sealed with a throwaway dev certificate's RFC 3161 time. It now also refuses any non-`local` key
  backend outside `APP_ENV=test` (`tsa_not_configured`), and `check_production_settings` refuses
  `APP_ENV=dev` together with `aws_kms` or `s3` at startup.
- **`check_production_settings` requires `BLOB_S3_BUCKET`** whenever `BLOB_BACKEND=s3`, in any
  environment: it was a bare `ValueError` from `S3ObjectStore.__init__` at the first blob write, and
  `esign worker` / `esign verify` catch `ConfigurationError` and `EsignError` only.
- **Rate limits**: `POST /signing/viewed` is metered under the `present` rule on a key of its own.
  It is legal repeatedly, and every call re-hashes the revision, re-parses it for its page count and
  appends `document.viewed`, which has no delete path.
- **Logging**: `esign serve` passes `log_config=None, access_log=False`. uvicorn's default config
  gives `uvicorn` and `uvicorn.access` their own handlers with `propagate: False`, so their records
  never reached the allowlisted root handler, and the access line carries the raw path and query
  string inside the reserved `event` key.

Fifth round, closing what the fourth left open:

- **Every way the server starts goes through `esign serve`**: `make dev-api` (now
  `esign serve --port 8000 --reload`, the new flag) and `demo-host/demo.sh` called uvicorn
  themselves with `--no-access-log`, which drops the raw-URL access line but leaves uvicorn's own
  error logger on its non-propagating handler, outside `drop_unlisted_keys`. Dropping the log
  config is the part that matters and it has one home.
- **The mocked signer API refuses what the real one refuses**: `frontend/src/mocks/db.ts` simulated
  only the round-3 condition (presented hash != `viewed_sha256`), so the mocked flow and the
  Playwright specs never saw the refusal that a parallel envelope actually produces -- both hashes
  name the revision the signer read, and it is the *current* revision that has moved on. The mock
  now refuses that too, and the case is covered in `App.test.tsx` and in the mocked Playwright run
  (a co-signer signs while the signer sits on the confirm screen). No UI change was needed:
  `mustReadAgain` and the return to Review already handle the 409.
