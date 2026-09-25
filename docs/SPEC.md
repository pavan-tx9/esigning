# E-signing service: specification

A standalone signing service that an EHR embeds. It produces legally defensible electronic
signatures under ESIGN/UETA for signers the EHR has **already authenticated**. The rules in
`docs/ehr-esignature-developer-guide.pdf` are requirements, not advice. This spec turns them into
an architecture.

**The job is evidence.** If a signature is disputed years from now, the stored record alone must
show who signed, what they saw, that they meant to sign, and that nothing changed afterwards. When
two designs are otherwise equal, pick the one that produces better evidence.

The contract lives in four files that module authors must not edit. They were revised once, at
integration, from the module hand-off reports, and again for Addendum 1 (section 14), Addendum 2
(section 15) and Addendum 3 (section 16, which adds no migration); every such revision is listed
in section 13:

- `backend/src/esign/contracts.py`: every cross-module type and interface
- `backend/migrations/0001_schema.sql`: the full schema
- `backend/migrations/0700_addendum_1.sql`: the schema for Addendum 1 (section 14)
- `backend/migrations/0800_addendum_2.sql`: the schema for Addendum 2 (section 15)

## 1. Scope

In: authenticated signers (portal patients, in-clinic tablet, clinicians), PDF templates the host
controls, documents the host's backend supplies over its API key (section 15), single and
multi-signer envelopes, consent, re-authentication, cryptographic sealing, hash-chained audit
trail, write-once storage, signer copy, verification tool, webhooks to the host, an embeddable
signing UI, and a demo host that exercises everything end to end.

Out, and must stay out: email-link signing for people without an account, a drag-and-drop template
builder, bulk send, PDFs uploaded by signers or end users, controlled-substance prescriptions,
notarisation, non-US signature regimes. If a request needs one of these, the API refuses with a
clear error code rather than approximating it.

The exclusion is about *who* supplies the document, not about uploading as such. A file the
signer's browser hands in at signing time is refused: it is untrusted, it is not what the audit
trail says was presented, and nothing about it is evidence. A document the host's backend supplies
server to server, authenticated by the API key that already creates envelopes and attests
identity, is the same trust boundary as a template the host published -- and it is the common
clinical case, a report generated per patient with a signature block at the end. Section 15 adds
that path and nothing else.

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
| `backend/src/esign/contracts.py`, `backend/migrations/0001_schema.sql`, `backend/migrations/0700_addendum_1.sql`, `backend/migrations/0800_addendum_2.sql`, `docs/SPEC.md` | architecture, read-only for everyone else |
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
`0700_addendum_1.sql` (architecture) is the schema for section 14 and `0800_addendum_2.sql` the
schema for section 15; both were written before their features were, and the features add nothing
to them -- they build against them as they stand.

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
  `adopted_signatures` (`0700`, section 14 B) is the one table with a narrower rule than either
  list: `SELECT, INSERT, UPDATE`, where the trigger `adopted_signatures_guard` permits exactly one
  UPDATE per row -- setting `revoked_at` and `revoke_reason` together, once, changing nothing
  else -- and refuses DELETE and TRUNCATE like the append-only tables. Rows are revoked, never
  removed, because a `signature_captures` row may point at one.

## 3. The pipeline

Every envelope goes through these steps. Each writes an audit event in the same transaction as
the state change.

1. **Prepare**: host calls `POST /v1/envelopes` with template, signers and prefill data. The
   service renders the PDF server-side, flattens it, stores it as revision 1 (`presented`), records
   its hash (`document.prepared`). Prefill data is used once and never stored outside the PDF.
   An envelope has a `source` (section 15): `template`, which is this, or `host_document`, where
   the same route takes a multipart request carrying the PDF the host's backend generated, its
   signer roles and where the fields go. The service then checks the upload's hygiene under
   `MAX_SUPPLIED_DOCUMENT_BYTES` / `MAX_SUPPLIED_DOCUMENT_PAGES`, resolves the fields (from the
   PDF's own widget names, or from rects the host sent, whose `page` may count from the end),
   flattens every widget and annotation away, stores the upload as a `supplied_pdf` blob *and* the
   flattened bytes as revision 1 (kind `supplied`), and records `document.supplied` with both
   hashes in place of `document.prepared`. There is no prefill on that path, and there is no
   template version: the resolved field and role definitions live on the envelope. Steps 2 to 9
   are identical for both sources.
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
   stored. There is always a visible decline/paper path. With `CONSENT_SPAN_SECONDS` above zero
   (section 16 C; default 0, at most 3600) an acceptance the same `(host_id, host_user_id)` gave
   for the same consent text within the span is **standing**: the UI shows when it was given
   instead of the checkbox and posts `relies_on_envelope_id`, and this envelope records its own
   `consent.accepted` naming that earlier acceptance and its time. The row is set exactly as it is
   without the span, so every envelope still carries its own consent; what the span changes is
   whether the disclosure was displayed again, and the trail, the certificate and verification all
   say which. The span is measured from the acceptance where the disclosure was last *displayed*
   (`relied_on_root_accepted_at`, carried forward unchanged through a chain of documents), never
   from the acceptance being relied on: a queue may not renew the window a document at a time.
   Never for a kiosk session, in either direction.
5. **Re-authenticate** (roles with `requires_reauth`): the UI asks the host page to re-authenticate
   the user; the host backend then calls `POST /v1/sessions/{id}/reauth`. Signing requires an
   attestation younger than `REAUTH_MAX_AGE_SECONDS` (default 120). By default the attestation
   covers the one session it was made for. With `REAUTH_SPAN_SECONDS` above zero (section 14 C;
   default 0, at most 900) an attestation for a user also covers that user's other sessions on the
   same host for that long after its `auth_time`, and `signer.signed` records which attestation was
   used, whether it was made in this session or borrowed (`reauth_scope: session | span`), and its
   age at the moment of signing. `fresh_reauth` resolves this session's own attestation first and
   a span one only when there is none.
6. **Capture and sign**: the UI sends signature inputs only (PNG, typed text, click, or -- section
   14 B -- the id of a signature the signer saved in an earlier session), with an
   `Idempotency-Key`. The server sanitises images, stamps the marks and a caption onto the current
   revision under the envelope row lock, stores the new revision, records `signer.signed` with both
   the presented hash and the new revision hash. An `adopted` capture is resolved server-side to the
   saved image or text, which must be the signer's own live saved signature, never from a kiosk
   session; the capture row records `kind = adopted` and the saved signature's id. With
   `save_adopted_signature`, the drawn or typed signature just applied is saved for the signer's
   `(host_id, host_user_id)` in the same transaction (`signature.adopted`), replacing and revoking
   any earlier one (`signature.adoption_revoked`); never from a kiosk session.
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

### Paper archives (section 14 A)
An envelope has a `kind`: `electronic` (everything above) or `paper_archive`, a scan of a document
signed in ink that the host files with an attestation so it gets the same write-once storage,
seal, timestamp, audit trail and verification. A paper archive has no template, no signers and no
sessions (`template_version_id` and `signing_order` are null, and a CHECK ties every paper column
to the kind). Its pipeline is steps 1, 7, 8 and 9 with the scan in place of the rendered document:

1. **File**: `POST /v1/archives` with the scan and the attestation. The scan passes the template
   hygiene rules under `MAX_SCAN_BYTES` / `MAX_SCAN_PAGES` and is stored write-once as revision 1
   of kind `scan` (blob kind `scan_pdf`); `archive.created` (actor: the host) and
   `archive.attested` (actor: the attesting staff member) are appended, and the envelope goes
   `created -> completed_pending_seal` with a seal job, all in one transaction.
2. **Seal**: the job builds a one-page cover (`build_archive_cover`: "Scanned copy of a document
   signed on paper", document type, paper signing date, who attested and when, disposition of the
   original, the scan's SHA-256, the envelope id, and what the seal does and does not prove),
   places it *before* the scan, appends the archive variant of the certificate (the attestation in
   place of the signer table) and seals the whole thing exactly as for an electronic envelope.
   The cover is one page and never overflows it: a filing with more paper signers than the page
   holds prints as many as fit and then "and N more, listed on the certificate of completion",
   which paginates and names every one of them. Nothing else on the cover gives way -- who
   attested, the scan's digest and the sentence about what the seal proves are reserved first.

```
created -> completed_pending_seal -> sealed
created|completed_pending_seal -> voided
```
Unlike an electronic envelope, an archive may be voided while `completed_pending_seal`: nobody
signed anything electronically, the scan is still the host's, and the seal has not happened. Once
sealed it is corrected like any other envelope, by a new envelope (of either kind) that supersedes
it. It never enters `in_progress`, `declined` or `expired`.

**What the seal proves, and what it does not.** That the scan has not changed since the moment it
was filed, and who filed and attested to it. Not that the ink signature is genuine: that rests on
the paper original and the attesting staff member, and the cover page and the certificate say so.

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
- Section 14 adds four event types. `archive.created` (document type, page count, size, scan hash,
  what it supersedes; the row's `document_sha256` is the scan hash too) and `archive.attested`
  (the attesting `staff_user_id`, the statement, the disposition of the original, the *count*
  of paper signers, and `attested_detail_sha256` -- their names are PHI and go on the cover page
  and the certificate, never here, and the paper signing date is a date-shaped value about a
  patient, so all of them reach the trail as one joint SHA-256 over the canonical JSON of
  `{staff_display_name, paper_signers: [{display_name, capacity}], paper_signed_on}`
  (`audit/events.py::attested_detail_digest`). Joint rather than per field: the digest of a bare
  date is brute-forceable in seconds. An archive has no signer row, no session and no stamped
  revision, so the attestation is its entire attribution, and a mutable column nothing can
  contradict is not evidence -- the seal recomputes this before printing those names
  (`certificate_evidence_mismatch`) and verification recomputes it again afterwards) are on the
  archive's envelope stream. `signature.adopted` is on the envelope stream
  of the session the signature was saved in (the saved signature's id and kind, and the digest of
  its image or text, tying the saved ink to the chain like a `CaptureRef`).
  `signature.adoption_revoked` is on the `system` stream, with the *host id* as the stream id, so
  one host's revocations form one chain (host, opaque user id, the id, and the reason). Any other
  `system`-stream event a host causes should use the same stream id.
- Section 15 adds one event type. `document.supplied` takes the place of `document.prepared` on a
  `host_document` envelope and carries the upload's hash, the presented (flattened) hash, the page
  count, `field_source` (`named_fields | explicit`) and `host_document_ref`. Two hashes rather
  than one because "we flattened what you sent" is a claim, and two stored blobs are evidence of
  it. `host_document_ref` is the only place that reference reaches the trail, so on that path it
  must be opaque like every other host-chosen identifier. It also carries `signer_roles_sha256`,
  the digest of the `SignerRoleDef` list the envelope was created with: a template envelope's
  roles live in an immutable `template_versions` row, but a host document's live in
  `envelopes.field_definitions`, which the runtime role may UPDATE, and the certificate's
  re-authentication block and verification's `requires_reauth` check would otherwise be two
  mutable copies of each other. The digest is checked by `envelope_row_matches_trail` and again
  before the seal, the same way `archive.attested`'s `attested_detail_sha256` is. The *fields*
  have no digest: where every mark landed is already in the presented revision's hash, in each
  stamped revision's hash and in the captures `signer.signed` records. `envelope.created`'s `template_key`,
  `template_version` and `template_version_id` became optional, and are all null together on a
  `host_document` envelope: there is no published version to name, and the `document.supplied`
  that follows says where the document did come from.
- Section 16 adds no event type and three fields. `consent.accepted` gained
  `relied_on_envelope_id`, `relied_on_accepted_at` and `relied_on_root_accepted_at`, set together
  when the acceptance was recorded against a standing one (section 16 C) and `null` together
  otherwise -- which is every acceptance while `CONSENT_SPAN_SECONDS` is zero. The envelope id and
  the two times, and nothing else: the earlier envelope's own `consent.accepted` is the record of
  *what* was agreed, and pointing at it is what makes the shortcut checkable by the certificate and
  by verification (`consent_relied_on_matches_trail`, which reads that other stream).
  `relied_on_root_accepted_at` is when the disclosure was last actually *displayed* -- the head of
  the chain, carried forward unchanged by each document that stands on the one before -- and it is
  what the span is measured from, at record time and at verification. Two times rather than one
  because bounding a single hop bounds nothing: without the root, document N stands on N-1 inside
  the span, N-1 stood on N-2 inside the span, and how long the notice has gone unshown is
  unbounded while every individual link looks lawful. The model refuses an event carrying some of
  the three but not all, and one whose root is later than the acceptance it heads. A
  `consent.accepted` written before this is reported by `verify` as `data keys do not match` --
  the same consequence Addendum 1's `signer.signed` change had.
- `signer.signed` gained `reauth_attestation_id`, `reauth_scope` and `reauth_age_seconds`, set
  together whenever `reauth_used`, and `adopted_signature_id` when an `adopted` capture was
  applied. Capture kinds in the trail are `drawn | typed | click | adopted | checkbox | text`.
  Every declared field is always written (absent ones as `null`), so `audit/README.md`'s worked
  vector was regenerated, and a `signer.signed` written before `0700` is reported by `verify` as
  `data keys do not match` -- the same consequence round three's `CaptureRef` change had.

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
  viewed/consented/signed times, IP, user agent, kiosk details. Section 16 C: where the acceptance
  was recorded against a standing one, the Consented line says so in words -- "09:12 (given for an
  earlier document in the same sitting; disclosure displayed 08:58)" -- so a reader is never left
  to infer from two nearby timestamps that the disclosure was displayed twice, and never left to
  guess how much earlier "earlier" was. The displayed time is
  `relied_on_root_accepted_at` from the trail, not a time read off a row. Plus the audit event
  count and head hash, the seal profile, and a line on how to verify. No chart data.
- Ship three sample templates in `templates/` with definitions: a patient consent form (patient,
  optional guardian capacity), a HIPAA acknowledgement (patient), and a procedure consent needing
  patient, witness and clinician in sequence. Generate the PDFs with a script so they are reproducible.
  Addendum 1 adds a fourth, `clinical_order`: one clinician signer, one page, re-authentication
  required -- the document a signing queue (section 14 C) is made of.

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
- `SessionInfo` carries whose session it is -- `host_id` and `host_user_id`, read from the signer
  and envelope rows, never from the request. The saved-signature rules and the re-authentication
  span are keyed on that pair.
- Re-authentication (section 14 C): `reauth_attestations` rows carry `host_id` and
  `host_user_id`, copied from the session's signer at insert (`0700`; rows from before it have
  neither and are never borrowed). `fresh_reauth` returns `ReauthEvidence(attestation_id, method,
  auth_time, scope)`: the most recent usable attestation made for this session (`scope =
  session`), else -- only when `REAUTH_SPAN_SECONDS > 0` -- the most recent one for the same
  `(host_id, host_user_id)` on any of that user's sessions with `auth_time` within the span
  (`scope = span`). In either scope the attestation must be within `REAUTH_MAX_AGE_SECONDS`, not
  in the future, and the session it was made for and the session asking must both be live. A
  different user or host never matches. The span is off by default and capped at
  `config.REAUTH_SPAN_MAX_SECONDS` (900) by `Settings` validation -- the same constant
  verification re-checks, so a `scope = span` signature naming an attestation older than the cap
  is a finding however consistent the rest of the event is.
- Adopted signatures (section 14 B): `adopted_signatures` holds at most one live row per
  `(host_id, host_user_id)` (partial unique index); `kind` is `drawn` (a `signature_image` blob)
  or `typed`. Only the signer creates one, from inside their own live, non-kiosk session, after
  their signature in that session succeeded (`adopt_signature`); replacing one revokes the old row
  with reason `replaced` in the same transaction. There is no host path to create one: staff
  cannot create a doctor's signature. Either side can revoke (`revoke_adopted_signature`, reason
  `user` or `host`), which is the only UPDATE the row ever takes. A kiosk session never offers or
  saves one. The identity module writes no audit events; the API layer appends
  `signature.adopted` / `signature.adoption_revoked` in the same transaction, as it does for the
  session events.
- Kiosk sessions record the staff member and the identity check method. The signature is
  attributed to the patient (or guardian), never to the staff member.
- Consent texts are versioned, immutable, and seeded by migration-independent `esign consent add`.
  A default US English ESIGN disclosure ships in `backend/src/esign/identity/consent/`.
- Standing consent (section 16 C): with `CONSENT_SPAN_SECONDS` above zero (default 0, at most
  `config.CONSENT_SPAN_MAX_SECONDS` = 3600), an acceptance stands for that user's other documents
  on the same host for that long. It is *found*, never stored a second time: the lookup is over
  the `signers` and `signing_sessions` rows that are already there -- same `(host_id,
  host_user_id)`, same `consent_text_id` (`consent_texts` is unique on version and locale, so one
  id is both), `consented_at` inside the span and not in the future, a different envelope from the
  one being signed, and no kiosk session on the signer whose acceptance it is. The session asking
  must not be a kiosk session either. A candidate that itself stood on an earlier acceptance is
  then held to *that* acceptance's root: the service reads the candidate envelope's own
  `consent.accepted`, takes its `relied_on_root_accepted_at`, and the span is measured from there,
  so a chain of documents is bounded as a whole rather than one hop at a time. An acceptance the
  trail does not account for -- a `signers` row with no matching event -- never stands.
  `EnvelopeService` owns the lookup because it owns the
  `signers` rows, and one definition answers both "is there one to offer?" and "is the one this
  request names still good?", so offering and recording cannot drift.
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
| `POST /v1/envelopes` | create from a published version; body is `NewEnvelope`; supports `Idempotency-Key` (a replay returns the *same envelope*, as it is now: what is stored is its id, not a second copy of the signers' names). Section 15: the same route also accepts a **multipart** request -- `document` (the PDF the host generated) plus `body` (JSON: `NewEnvelope` minus `template_key`/`template_version`/`prefill`, plus `document_type`, `signer_roles` (a `SignerRoleDef` list) and `fields`: `{"mode": "named"}`, the default, or `{"mode": "explicit", "fields": [FieldDef...]}` where `page` may count from the end (`-1` is the last page)), i.e. `NewHostDocumentEnvelope`. The request-size limit for a multipart request on this route is `MAX_SUPPLIED_DOCUMENT_BYTES` plus multipart overhead, not `MAX_REQUEST_BYTES`; the `Idempotency-Key` request hash covers the document bytes. Returns an `EnvelopeView` with `source: "host_document"`. On both shapes a `guardian` or `proxy` signer may carry `on_behalf_of_display` beside `on_behalf_of`: the host's own words for the person it names, shown to the signer and printed in the document, never in the trail, a webhook or a log (section 16 A). Any other capacity is refused `on_behalf_of_display_not_allowed` |
| `POST /v1/archives` | section 14 A: file a scan of a paper-signed document. Multipart: `scan` (a PDF; converting images is the host's job) + `body` (JSON text: `{patient_ref, document_type, host_document_ref?, paper_signed_on, attestation: {staff_user_id, staff_display_name, statement: "true_copy", original_disposition, paper_signers: [{display_name, capacity}]}, supersedes_envelope_id?}`, i.e. `NewArchive`). Supports `Idempotency-Key`. Returns an `EnvelopeView` with `kind: "paper_archive"`. The request-size limit for this route is `MAX_SCAN_BYTES` plus multipart overhead, not `MAX_REQUEST_BYTES` |
| `GET /v1/envelopes/{id}` | `EnvelopeView`. Gained `kind`; for a paper archive `template_key`, `template_version` and `signing_order` are `null`, `signers` is empty, and `paper_signed_on` and `attested_at` are set. Gained `source` (section 15): for a host document `template_key` and `template_version` are `null` and everything else is as for a template envelope. `/document`, `/audit`, `/verification` and `/void` apply to every kind and source |
| `POST /v1/envelopes/{id}/void` | `{reason_code}` from the fixed list `contracts.VOID_REASON_CODES` (a host-invented code would be free text with underscores, and it reaches the audit trail) |
| `POST /v1/envelopes/{id}/signers/{sid}/sessions` | `{auth: {method, auth_time}, kiosk?: {staff_user_id, identity_check}}` -> `{token, session_id, expires_at}` |
| `POST /v1/sessions/{session_id}/reauth` | `{method, auth_time}` -> `{session_id, reauth_valid_until}`; another host's session is `not_found`. With the span on (section 14 C) the host still calls this once, on the first document |
| `POST /v1/users/{host_user_id}/adopted-signature/revoke` | section 14 B: `{reason?}` (free text is not stored; the trail records `reason: host`). Revokes the user's live saved signature; 200 `{"revoked": bool}` whether or not there was one, so another host's user is indistinguishable from a user with none (both answer `false`) |
| `GET /v1/envelopes/{id}/document` | sealed PDF, or 409 `not_sealed` |
| `GET /v1/envelopes/{id}/audit` | audit events |
| `GET /v1/envelopes/{id}/verification` | run and return a verification report. Always 200 for an envelope that exists: a failed verification is a finding (`ok: false`, `problems`), not a transport error |

Requests outside the scope of section 1 (`POST /v1/envelopes/bulk`, `.../email-links`,
`.../documents`) are refused with `422 out_of_scope`. `.../documents` stays refused after
section 15: a host document is supplied as a multipart `POST /v1/envelopes`, and a route that
sounds like "upload a PDF" is exactly what a signer-side upload would reach for. There is no
`DELETE`, `PUT` or `PATCH` route.

### Signer API (`Authorization: Bearer est_...`)
| Method and path | Purpose |
|---|---|
| `GET /v1/signing/session` | everything the UI needs, shape below. `?locale=` picks the disclosure language |
| `GET /v1/signing/document` | current revision PDF; records `document.presented` |
| `POST /v1/signing/viewed` | `{pages_viewed: int}` must equal the page count |
| `POST /v1/signing/consent` | `{consent_version, accepted: true, locale?, relies_on_envelope_id?}` (`locale` as shown in the session payload; default locale when omitted). Section 16 C: `relies_on_envelope_id` is the envelope named by `consent.standing` in the session payload. The server re-finds that acceptance under the same rule that offered it and refuses with 409 `consent_not_standing` otherwise, on which the UI shows the checkbox and posts again without it. Omitted, the route behaves exactly as it did before the addendum |
| `POST /v1/signing/sign` | `{intent_confirmed: true, captures: [...], save_adopted_signature?: bool}` + `Idempotency-Key`. `save_adopted_signature: true` (section 14 B) saves the drawn or typed signature just applied, after the signature succeeds and in the same transaction; what is saved is the first such capture landing on a **signature** field, never an initials one (initials are the signer's own typed text and a template may ask for them first); refused (422 `no_signature_to_save`) when the request has no such capture, and always (403) from a kiosk session |
| `POST /v1/signing/adopted-signature/revoke` | section 14 B: the signer removes their own saved signature (`reason: user`). No body. 200 `{"revoked": bool}` whether or not there was one. Refused (403 `adoption_not_allowed`) from a kiosk session, as saving is: a shared tablet is not shown this signature and may not destroy it either, and the revocation is irreversible and would be recorded as the person's own request |
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
             "reauth_valid_until": null, "reauth_scope": null, "reauth_at": null},
  "other_signers": [{"role_label": "Witness", "status": "pending"}],
  "fields": [{"id": "patient_sig", "type": "signature", "page": 3,
              "rect": {"x": 72, "y": 120, "w": 220, "h": 48}, "required": true,
              "label": "Patient signature"}],
  "consent": {"version": "2026-09", "locale": "en-US", "body": "...",
              "standing": {"accepted_at": "...", "envelope_id": "..."}},
  "session": {"id": "...", "expires_at": "...", "kiosk": false},
  "adopted_signature": null,
  "decline_reasons": [{"code": "prefers_paper", "label": "I would rather sign on paper"}]
}
```
`reauth_valid_until` reflects a span attestation too (section 14 C), so the UI can skip the
hand-off when a valid one exists, `reauth_scope` (`session | span | null`) says which, and
`reauth_at` is that attestation's `auth_time`, so the UI can say "you confirmed your identity at
HH:MM" rather than infer it. The three are `null` together.
`adopted_signature` (section 14 B) is `{id, kind, image_png_base64 | typed_text, created_at}` or
`null`: the signer's own live saved signature, served only to a session with the same
`(host_id, host_user_id)`, and always `null` on a kiosk session.
`consent.standing` (section 16 C) is `{accepted_at, envelope_id}` or `null`: an acceptance of
*this* version in *this* locale that this signer already gave, within `CONSENT_SPAN_SECONDS`.
Inside the consent block rather than beside it, because standing is a fact about one disclosure in
one language and says nothing read apart from them -- `?locale=` therefore decides it too.
`null` whenever the span is off and on every kiosk session. The body is served with it either way:
the UI offers "Read the full notice" on both paths. `accepted_at` is the acceptance the UI names;
how long the disclosure has gone undisplayed is the server's business, not the UI's, so the root
the span is measured from stays out of the payload.
`on_behalf_of_label` is who this signer acts for, in words a person can read: the host's
`on_behalf_of_display` for that signer when it sent one, and the opaque `on_behalf_of` otherwise.
`null` for a signer acting for themselves. Since section 16 A the sign button carries the whole of
the intent confirmation ("Sign as Grace Okafor, on behalf of ..."), so the sentence a guardian
reads before performing that act must not be an internal reference; what the trail records is
unchanged, and is always the opaque value.

Capture shapes: `{"field_id", "kind": "drawn", "image_png_base64"}`, `{"field_id", "kind":
"typed", "typed_text"}`, `{"field_id", "kind": "click"}`, `{"field_id", "kind": "adopted",
"adopted_signature_id"}` (section 14 B: the id from the session payload and nothing else -- an
image or text beside it is refused), and for non-signature fields `{"field_id", "checked"}` or
`{"field_id", "text_value"}`. The two families never mix: a capture with a `kind` (or a signature
payload) *and* a `checked`/`text_value` is refused with 422 at the edge and is not representable
as a `contracts.Capture` at all, because the trail records a signature's `kind` and a value
field's type, and a client must not choose that wording. Signature and initials fields accept any
of the four kinds (the UI sends initials typed); `typed_text` and `text_value` are bounded by
`MAX_TYPED_SIGNATURE_CHARS` (200) and `MAX_TEXT_FIELD_CHARS` (2000).

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
`occurred_at`, `envelope_id`, `kind`, `status`, template key and version (not the document type;
both `null` for a paper archive, and both `null` for a host-supplied document too, which has no
template version), the three hashes, and each
signer's `id`, `role_key` and `status`; never a name, `patient_ref` or `host_document_ref` --
including on a host-document envelope, where the host already knows which report it sent). A
paper archive fires `envelope.sealed` and `envelope.voided` only. Signed
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

One flow, four states, all reachable by keyboard and screen reader, all usable at 360px wide and on
a tablet held by a patient in a clinic. Addendum 3 A (section 16) merged what were five signing
screens onto three; the acts are the same acts, and it is normative for their arrangement:

1. **Connecting**: waiting for the token. Clear failure if it never arrives.
2. **Read**: the PDF rendered with pdf.js, page by page, in the one region of the frame that
   scrolls, with progress in the action bar ("Page 2 of 3", a mark per page seen; the primary
   button is "Next unseen page (n)" until every page has been displayed -- addendum 3 F). Directly
   under the last page, in the same scroll, the consent block: the disclosure collapsed to its
   opening lines and expanding in place, and an unchecked checkbox — or, where an acceptance
   already stands (section 16 C), a line saying when it was given. One button, **Continue to
   sign**, inert until every page has been displayed and the consent condition is met, and saying
   which of the two is missing when pressed. `POST /signing/viewed` goes when the last page has
   been displayed, `POST /signing/consent` when the button is pressed. A text alternative explains
   that staff can provide a paper copy.
3. **Sign**: the signature panel at the top (the one on file, with "Change", or the
   draw / type / click-to-sign chooser inline), then this signer's fields as a list, each applied
   by an explicit action of its own, with how many remain. One primary button, "Sign as <name>",
   inert until every required field is done: **that press is the intent confirmation**, and it is
   what `intent_confirmed: true` means. For a re-auth role with nothing live, the press hands off
   to the host and waits inline, then sends the signature itself when the server vouches — no
   second press. Disable double submission; send an `Idempotency-Key`; survive a retry after a
   network failure.
4. **Done**: confirmation and the signed copy. While sealing is pending, say so honestly and poll.
   If other signers remain, say the copy will be available when everyone has signed. In a run the
   host is driving (section 16 B), say what is next, count down, and ask for it with `esign:next`.
   Decline, expired and error states each have their own screen with a next step.

An equally visible "I'd rather sign on paper", leading to decline, is on every screen before Done.

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
  (`signer_finished`), for a role that does not re-authenticate (`reauth_not_required`), or on an
  envelope that is no longer being signed (`envelope_not_live`). Whether the role re-authenticates
  is re-derived from the immutable template version, as at signing and at sealing, never read off
  `signers.requires_reauth`. Declared on
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
  requirement; it was convention in `templates/procedure_consent.json`. `signers.requires_reauth`
  is a mutable copy on a fully UPDATE-able table and no audit event records it, so it is never
  read as the gate: `sign`, `_certificate_signer` and `assert_reauth_allowed` all re-derive the
  rule from the immutable template version plus the capacity, and verification mirrors the
  comparison under `signer_rows_match_trail`. A flipped column is refused at signing
  (`reauth_required`), stops the seal (`certificate_evidence_mismatch`) and is reported
  afterwards, instead of either waving a clinician signature through with no attestation or
  stripping the attestation off a certificate while the envelope waits for a backing-off seal.
  It also does not make `POST /v1/sessions/{id}/reauth` answer `reauth_not_required` for a
  signature that will then demand one: three places decide the same question, so they decide it
  the same way.
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

Addendum 1 (section 14), made once by the architecture step before the three features were
built, so the builders work against a fixed contract. Everything the addendum lists under
"Contract and schema changes", plus the few things it did not name that the listed ones need:

- **`contracts.py`**: `EnvelopeKind`, `ReauthScope`, `AttestationStatement`,
  `OriginalDisposition`, `PaperSigner` (the element type of `Attestation.paper_signers`),
  `Attestation`, `ArchiveCoverSummary`, `NewArchive`, `ReauthEvidence`, `AdoptedSignatureKind`,
  `AdoptedRevokeReason`, `AdoptedSignature`. `CaptureKind` gains `adopted` and `Capture` gains
  `adopted_signature_id`, paired with that kind by the constructor. `BlobKind` gains `scan_pdf`.
  `EventType` gains `archive.created`, `archive.attested`, `signature.adopted`,
  `signature.adoption_revoked`. `CertificateSummary` gains `kind` and `attestation`, and its
  `template_key` / `template_version` are optional (an archive has none). `CertificateSigner`
  gains `reauth_scope`, `reauth_at`, `adopted_signature_id` and `adopted_at` (the adoption date
  the certificate prints). `EnvelopeView` gains `kind`, `paper_signed_on`, `attested_at`, and its
  `template_key`, `template_version` and `signing_order` are optional. `SigningView` gains
  `reauth_scope`. `SessionInfo` gains `host_id` and `host_user_id`, read from the rows.
  `IdentityService.fresh_reauth` returns `ReauthEvidence | None` (the one existing signature that
  changed; both implementations answer `scope = session` until the span is built);
  `get_adopted_signature`, `adopt_signature`, `revoke_adopted_signature`;
  `DocumentService.build_archive_cover`; `EnvelopeService.create_archive`. The `sign`, `void`,
  `build_certificate` and `finalize` docstrings say what the features change about them.
- **`0700_addendum_1.sql`**: `envelopes.kind`, `paper_signed_on`, `attestation`, `attested_at`,
  with `template_version_id` and `signing_order` nullable and CHECKs tying every one of them to
  the kind (`envelopes_kind_template`, `_signing_order`, `_paper`, `_status`,
  `_attestation_shape`); `blobs.kind` gains `scan_pdf` and `document_revisions.kind` gains `scan`
  (a paper archive's revision 1); `adopted_signatures` with its partial unique index, its guard
  trigger and its grants; `signature_captures.kind` gains `adopted` with `adopted_signature_id`
  and `signature_captures_kind_adopted`; `reauth_attestations.host_id` / `host_user_id` with the
  both-or-neither CHECK and a partial index by user.
- **`config.py`**: `max_scan_bytes` (20 MiB), `max_scan_pages` (100), `reauth_span_seconds`
  (0, validated `0..REAUTH_SPAN_MAX_SECONDS`, the named constant verification also re-checks).
  `check_production_settings` refuses nothing new; `.env.example` says why the span is off by
  default.
- **Audit allowlist**: the four new data models, `SignerSignedData`'s four new optional fields,
  and the widened capture and revision kind vocabularies, in `esign/audit/events.py` -- the one
  definition. `audit/README.md`'s worked vector was regenerated.
- **Stubs**: every new Protocol method raises `NotImplementedError` in `SqlIdentityService`,
  `PdfDocumentService`, `EnvelopeServiceImpl` and the envelope tests' fakes, with a `TODO` naming
  the feature, so the tree stays green until each builder replaces its own.

Reconciliation, after the three features and the signing UI were built in parallel against that
contract. Made once, by the integration owner, with the reasons recorded here:

- **`contracts.ArchiveCreator`**: the Protocol `EnvelopeService.create_archive` delegates to. It
  was declared inside `envelopes/service.py` while `contracts.py` was frozen; it is a cross-module
  seam (`runtime` builds `esign.archives` and injects it), so it lives with the other seams now.
- **`DocumentService.inspect_scan_pdf`**: the template hygiene rules under `MAX_SCAN_BYTES` /
  `MAX_SCAN_PAGES`, answering with `scan_` codes. `inspect_template_pdf` reads its bounds from the
  settings the service was built with, so the archives module had been handed a second document
  service built from a copy of `Settings` with two values swapped. One service, one extra method.
- **`create_archive` refuses a non-opaque `patient_ref` with `patient_ref_invalid`**, the code
  `create` uses for the same field; `host_user_id_invalid` is for the attesting staff member. The
  contract docstring said `host_user_id_invalid` for both and the implementation followed it.
- **`SigningView.reauth_at`** (and `reauth_at` in the session payload, section 9): the attestation's
  `auth_time`. The addendum's confirm-step copy ("you confirmed your identity at HH:MM") could not
  be stated from `reauth_valid_until` alone, because a span attestation's validity ends at
  `min(REAUTH_MAX_AGE_SECONDS, REAUTH_SPAN_SECONDS)` after `auth_time` and the UI has neither.
- **`reauth_age_seconds` is measured immediately before `signer.signed` is appended**, not from
  the `Clock` read the stamp carries: stamping and storing the revision sat between the two, so
  `occurred_at - age` could miss the attestation's `auth_time` by however long that took, and
  verification had to allow the general 60-second row-versus-event tolerance. It now allows five
  seconds for that one comparison (`_REAUTH_AGE_TOLERANCE`); the id, method, session and
  host/user comparisons were exact already.
- **The saved signature's image is named from the trail**: `save_adopted_signature` reads
  `image_sha256` out of the `signer.signed` event's `CaptureRef` for the field it is saving from,
  rather than sanitising the client's PNG a second time and trusting the result to hash to the
  blob `sign` stored. `adopt_signature` still checks that blob exists and is a `signature_image`.
- **Verification follows an `adopted` capture to its saved signature**: `captures_match_trail`
  compared the digest in `signer.signed` with the capture row's own `image_sha256` / `typed_text`,
  and an `adopted` row has neither (it points at `adopted_signatures`), so every envelope signed
  with a saved signature failed verification. The check now resolves the pointer, and
  `capture_images_intact` re-hashes the saved image with the rest.
- **The effective borrow window is `min(REAUTH_MAX_AGE_SECONDS, REAUTH_SPAN_SECONDS)`**, by the
  addendum's own rule that the attestation must be within the maximum age in every scope. A host
  configuring a five-minute queue sets both (the demo does); `.env.example` and the README say so.
- **Recorded as designed, not changed**: the cover page's paper signing date is read from the
  envelope row, not the trail, and is the one fact on the cover not cross-checked against it -- a
  date about a person stays out of audit data (section 4). A paper archive carries the default
  `expires_at` like every envelope (`EnvelopeView.expires_at` is not optional and the column is
  `NOT NULL`), and nothing ever acts on it: `expire_due` sweeps `created | in_progress` only and an
  archive leaves `created` in the transaction that files it. `FakeIdentityService` in the envelope
  tests now writes `host_id` / `host_user_id` on attestations and resolves a span, so the envelope
  service can be tested with a queue against the fake as well as the real identity module.

Addendum 2 (section 15), made once by the architecture step before the feature was built, so the
builders work against a fixed contract. Everything the addendum lists under "Contract and schema
changes", plus the few things it did not name that the listed ones need:

- **`contracts.py`**: `EnvelopeSource`, `FieldSourceKind`, `NamedFields`, `ExplicitFields` (with
  a `field_source` property each, so the mapping from the request's `mode` to the trail's
  `field_source` has one definition), `FieldSpec` and `NewHostDocumentEnvelope`. `NewEnvelope` is
  untouched: the template path is unchanged, and the two creation shapes stay separate rather than
  one shape with half its fields conditionally null. `resolve_page(page, page_count)`, the one
  definition of what `-1` means, because the API edge, the documents module and the envelope
  service must all read it the same way; `FieldDef.page` stays a positive, 1-based, *stored*
  number and its docstring says the negative spelling exists only at the boundary.
  `DocumentService.resolve_named_fields` and `flatten_supplied`; `EnvelopeService.create_from_document`;
  `BlobKind` gains `supplied_pdf`; `EventType` gains `document.supplied`; `EnvelopeView.source`;
  `CertificateSummary.source` and `host_document_ref`.
- **Not named by the addendum, needed by what is**: `DocumentService.inspect_supplied_pdf`. The
  supplied bounds differ from the template ones, `inspect_template_pdf` reads its bounds from the
  settings the service was built with, and the reconciliation after Addendum 1 records what
  happens otherwise -- a second document service built from a copy of `Settings` with two values
  swapped. One service, one more method, `supplied_` codes, exactly as `inspect_scan_pdf` does for
  a scan.
- **`0800_addendum_2.sql`**: `envelopes.source` and `envelopes.field_definitions`, with
  `envelopes_source_check`, `envelopes_source_kind` (`source` is meaningful for `kind =
  electronic` alone), `envelopes_source_field_definitions` and `envelopes_field_definitions_shape`;
  `envelopes_kind_template` from `0700` is replaced by `envelopes_source_template`, so exactly the
  electronic envelopes that say `template` name a template version. `blobs.kind` gains
  `supplied_pdf` and `document_revisions.kind` gains `supplied`.
  `document_revisions.page_count` is recorded when a revision is written: nullable and never
  backfilled, because the table is append-only and its trigger refuses UPDATE, so rows from before
  `0800` keep `null` and are counted the old way. Grants are unchanged -- no new table, and the app
  role's existing rights say what they allow.
- **`config.py`**: `max_supplied_document_bytes` (25 MiB), `max_supplied_document_pages` (200).
  `check_production_settings` refuses nothing new.
- **Audit allowlist**: `DocumentSuppliedData` (`upload_sha256`, `presented_sha256`, `page_count`,
  `field_source`, `host_document_ref`, the last of them an `OpaqueId`), `RevisionKind` gains
  `supplied`, and `EnvelopeCreatedData`'s three template fields became optional so a host-document
  envelope can record its own creation. `signer.signed` is untouched, so `audit/README.md`'s
  worked vector still stands.
- **Stubs**: every new Protocol method raises `NotImplementedError` with a `TODO` naming the
  feature, in `PdfDocumentService`, `EnvelopeServiceImpl` and the envelope tests'
  `FakeDocumentService`, so the tree stays green until each builder replaces its own.

Addendum 3 (section 16), made once by the architecture step for section C of the addendum, the
only one of its three sections that reaches the contract. Sections A and B are the signing UI's
and the demo host's; the server side of them is unchanged, which is the point of them:

- **`contracts.py`**: `StandingConsent` (the found acceptance: `envelope_id`, `accepted_at`);
  `SigningView.consent_standing`, which the session payload serves as `consent.standing`;
  `SigningView` and `signing_view` gained a `locale` keyword, because whether an acceptance stands
  is a question about one consent text and the UI may ask for another language -- the same
  parameter, with the same meaning, `accept_consent` already had; `accept_consent` gained
  `relies_on_envelope_id`; `CertificateSigner.consent_relied_on`. Nothing else: standing consent
  is a way of *arriving at* an acceptance, and everything downstream of one is untouched.
- **No schema change.** The acceptance is found in the `signers` and `signing_sessions` rows that
  are already written (section 8). A second store of it would be a second place for it to disagree
  with the trail, and the trail is what the certificate and verification are built from. The
  envelopes module did add one migration in its own range, as "Migrations" above allows and asks
  to be reported: `0503_standing_consent_lookup.sql`, a partial index on
  `signers (host_user_id, consent_text_id, consented_at DESC)`. It stores nothing and changes no
  grant; it exists because the lookup runs on every load of the signing UI while the span is on,
  and `signers` had no index for it.
- **`config.py`**: `consent_span_seconds` (0, validated `0..CONSENT_SPAN_MAX_SECONDS`, the named
  constant verification also re-checks). `check_production_settings` refuses nothing new;
  `.env.example` and `docs/CONFIGURATION.md` say why the span is off by default.
- **Audit allowlist**: `ConsentAcceptedData` gained `relied_on_envelope_id` and
  `relied_on_accepted_at` (section 4). `audit/README.md`'s worked vector is over `signer.signed`
  and still stands.
- **Verification** gained `consent_relied_on_matches_trail`, which follows the pointer into the
  other envelope's stream. Without it, `relied_on_envelope_id` would be a pair of values this
  envelope's own hash chain cannot contradict -- and the borrowing envelope verifies clean while
  the acceptance it rests on is rewritten out of the other one's trail, which is exactly what its
  tests do.
- **Recorded as designed, not changed**: the standing lookup returns the *most recent* matching
  acceptance, so a queue of five forms stands on the fourth rather than on the first, and each
  one's trail names the document the signer had most recently agreed on. `accept_consent` is
  still legal for a signer who is already `consented` and still keeps the first acceptance in the
  row (section 13, fourth round); an envelope never stands for itself.

Addendum 3, from the review of the built system. Two findings about section 16 and one about
what its shorter flow left on the screen; no change to `0001`, `0700` or `0800`:

- **The span is measured from the display, not from the last agreement.** Standing on the most
  recent acceptance (above) is right for *which* document the trail names, and was wrong for *how
  long* the shortcut lasts: the relying acceptance sets `consented_at` on its own row, which then
  satisfied the same predicate for the next document, so document N stood on N-1, which stood on
  N-2, and the window renewed itself one document at a time. Verification did not contradict it,
  because it bounded the single hop `occurred_at - relied_on_accepted_at` and every hop was
  inside the cap. Twenty documents an hour apart is one display of the disclosure and a working
  day of standing consent -- which is the opposite of what
  `config.CONSENT_SPAN_MAX_SECONDS` is quoted as containing. `consent.accepted` now also carries
  `relied_on_root_accepted_at`, the moment the notice was last actually displayed, carried forward
  unchanged by every link; `_standing_consent_for` reads the candidate's own event to find it and
  measures the span from there; the certificate prints it; and
  `consent_relied_on_matches_trail` bounds `occurred_at - root` by the cap *and* re-derives the
  root from the earlier acceptance's own event, so the number is evidence rather than an
  assertion. `ConsentAcceptedData` refuses an event carrying some of the three fields and not the
  others, or a root later than the acceptance it heads.
- **Verification re-derives the kiosk exclusion too.** "A kiosk session never has standing
  consent" is section 16 C's hardest rule and was enforced at record time only, by a `NOT EXISTS`
  inside `_STANDING_CONSENT_SQL`. `consent_relied_on_matches_trail` now runs the same exclusion
  against the earlier acceptance's signer, for the reason the module gives for borrowed
  attestations: a check that assumes the writer got it right is not a check. Nothing today
  produces such an envelope, which is the point at which it is cheap to catch.
- **A guardian reads a name, not a reference.** `signers.on_behalf_of_display` (`0504`) and
  `NewSigner.on_behalf_of_display`: `on_behalf_of` is the envelope's `patient_ref` and is held to
  `is_opaque_id` because it reaches the trail, so `SigningView.on_behalf_of_label` could only ever
  be an internal identifier -- and section 16 A made the button carrying it the single act that
  signs the document and the whole of the intent confirmation. The label is now the host's own
  words when it sends them and the opaque value otherwise; the attribution in the record, the
  actor on every event and the `signers.on_behalf_of` column are untouched. It is PHI and gets
  `display_name`'s treatment exactly: the row, the signature caption in the PDF, and nowhere else.
  The column is paired with `on_behalf_of` by a CHECK, and by
  `on_behalf_of_display_not_allowed` at the edge, where the host can read the refusal. A host that
  sends no display name still leaves an identifier in that sentence, so the signing UI makes one
  last substitution of its own: a label still shaped like an opaque id is rendered "for the
  patient named in this document", which is true, readable, and points at the thing on the screen
  that does name them (`frontend/src/lib/signing-api.ts::onBehalfOfPhrase`). It is a display
  decision and reaches no request, event or column.

## 14. Addendum 1: paper archives, adopted signatures, re-authentication span

`docs/SPEC-ADDENDUM-1.md` adds three features to this spec and is normative for them:

- **A. Archiving paper-signed documents**: a host files a scan of a document signed in ink, with
  an attestation, and it gets the same write-once storage, seal, timestamp, audit trail and
  verification as an electronic signature (section 3 "Paper archives", sections 4, 9).
- **B. Adopted signatures**: a signer saves the signature they adopted so it is offered again in
  their next session; only the signer can create one, either side can revoke it, and a kiosk
  session never offers or saves one (sections 3 step 6, 4, 8, 9).
- **C. Re-authentication span**: a host may let one attestation cover a user's other sessions on
  the same host for `REAUTH_SPAN_SECONDS` (default 0, at most 900) after `auth_time`, with every
  signature recording which attestation it rests on and whether it was borrowed (sections 3 step 5,
  4, 8, 9).

Everything in sections 1 to 13 still applies; where the addendum is silent, this document decides.
The addendum says what each feature weakens and how that is contained. Its contract and schema
changes were made once, up front (section 13, "Addendum 1"), in `contracts.py`,
`0700_addendum_1.sql`, `config.py` and this document; the sections above that changed say so
inline. The addendum's Documents, Frontend, Demo host and Tests headings apply to sections 6, 11
and 12 without restating them here.

## 15. Addendum 2: host-supplied documents

`docs/SPEC-ADDENDUM-2.md` adds a second way to create an *electronic* envelope and is normative
for it: the host's backend supplies the document itself, over the API key it already uses to
create envelopes and attest identity, instead of naming a published template version. The case it
exists for is the common clinical one -- a report the EHR generates per patient, 20 to 30 pages,
different every time, with a signature block at the end for the clinician (and sometimes a second
for a co-signer). A template cannot express that document, and section 1's exclusion was never
aimed at it.

- **Source**: `envelopes.source` is `template` (everything sections 1 to 14 describe) or
  `host_document`. For `host_document` there is no template version; the resolved `FieldDef` and
  `SignerRoleDef` lists live in `envelopes.field_definitions`, and the signing UI is served them
  in place of a template version's. `source` applies to `kind = electronic` only (a scan arrives
  through `POST /v1/archives` with an attestation), and a CHECK says so.
- **Revision 1**: the upload passes the template hygiene rules -- no encryption, existing
  signatures, JavaScript, XFA, embedded files or launch actions -- under
  `MAX_SUPPLIED_DOCUMENT_BYTES` (25 MiB) and `MAX_SUPPLIED_DOCUMENT_PAGES` (200). Its fields are
  resolved either from the PDF's own AcroForm widget names (`<role_key>_signature`,
  `_initials`, `_date`, or `<role_key>__<field_id>`) or from explicit rects the host sent, whose
  `page` may count from the end (`-1` is the last page, because the page count varies per
  patient) and is resolved to a positive page before anything is stored. Every declared role must
  resolve to at least one signature field. Then every widget and annotation is flattened away,
  the upload is stored as a `supplied_pdf` blob, and the flattened bytes become revision 1 of kind
  `supplied`.
- **Evidence**: `document.supplied` replaces `document.prepared` and records both hashes, the
  page count, how the fields were arrived at, and the host's reference for the document, so the
  step from what the host sent to what the signer was shown is evidence rather than an assertion.
  The certificate of completion prints "Document supplied by the host" in place of the template
  line, with that reference and the upload's hash (`CertificateSummary.source`,
  `host_document_ref`).
- **The roles are a column, so the trail holds their digest.** Section 12's rule that
  `requires_reauth` is re-derived rather than read from the mutable `signers` row assumed the
  definition it is re-derived from is immutable, which is true of a template version and false of
  `envelopes.field_definitions`. `document.supplied` therefore records `signer_roles_sha256` over
  the roles as created, and the comparison is made twice: on every signer-facing load, so a
  rewritten role refuses the *signature* (`certificate_evidence_mismatch`), and again at seal time,
  so it cannot be certified either. Verification reports the same comparison afterwards. A role key
  or field id is held to the audit trail's own `[a-z][a-z0-9_]{0,63}`, so nothing this path accepts
  can be refused by the allowlist after two events are already in the trail.
- **Refusals name the file, not a template.** The hygiene codes are `supplied_`-prefixed, and so is
  `supplied_definitions_invalid`; two refusals exist that the template path does not need, because
  flattening here removes rather than draws: an AcroForm signature field, empty or not
  (`supplied_signature_field` -- a host places a slot by naming a text widget), and a visible
  non-widget annotation carrying ink (`supplied_annotation_not_removable`). Field ids are built
  from the role key and the field type and never from a widget's name, which is host text from
  inside a per-patient file and would otherwise reach the trail as a capture's `field_id`.
- **Unchanged**: everything downstream of revision 1 -- presentation, viewed-every-page, consent,
  re-authentication and the span, signing, revisions, the certificate, the single seal, storage,
  verification, webhooks, the signing UI, and Addendum 1's adopted signatures. Approved document
  types apply exactly as they do to a template: compliance decides what may be signed
  electronically, whoever rendered the PDF.

**What this weakens.** Nothing in the evidence chain: the document is hashed and recorded before
anyone sees it, and every later step is identical. What changes is *provenance* -- the content came
from the host rather than from a version somebody published and retired deliberately -- and the
trail and the certificate say so rather than leaving it to be inferred. What stays excluded is a
PDF from a signer or an end user at signing time (section 1): that is a different trust boundary,
and no amount of hashing makes an untrusted upload into evidence of what a clinic meant to present.

Everything in sections 1 to 14 still applies; where the addendum is silent, this document decides.
Its contract and schema changes were made once, up front (section 13, "Addendum 2"), in
`contracts.py`, `0800_addendum_2.sql`, `config.py` and this document; the sections above that
changed say so inline. The addendum's Documents module, Demo host and Tests headings apply to
sections 6, 11 and 12 without restating them here.

## 16. Addendum 3: a shorter signing flow, and a faster queue

`docs/SPEC-ADDENDUM-3.md` shortens the signing flow and is normative for it. Nothing that produces
evidence is removed; steps are merged onto fewer screens, and the acts that matter stay explicit.
Every page displayed before signing is still possible, consent is still given explicitly, there is
still one explicit act per field and one explicit act that signs the document, re-authentication
still happens for the roles that need it, and the decline-to-paper path is still visible on every
screen. What goes is duplication: a checkbox that restates what the button says, a summary screen
that repeats what the signer just did, a separate adopt screen.

- **A. Read → Sign → Done**: the flow becomes three screens. The consent block sits under the last
  page of the document (screen 1); the signature panel, the fields and the sign button sit on one
  screen (screen 2); re-authentication happens on the press rather than on a screen of its own.
  This is entirely the signing UI's: `POST /signing/viewed`, `POST /signing/consent` and
  `POST /signing/sign` are sent at the same points, carrying the same things, and the server's
  `signers.status` progression (`pending → viewed → consented → signed`) is unchanged, so a reload
  still lands where the record says the signer is. The button press is what `intent_confirmed:
  true` now means, and `docs/COMPLIANCE-CHECKLIST.md` records that for counsel.
- **B. Queue auto-advance**: `esign:init` gains an optional `queue {index, total, next_title}` and
  the UI posts `esign:next {envelope_id}` when a document is done. The host owns the queue and the
  tokens; the UI never fetches the next document itself. Nothing server-side changes.
- **C. Consent once per run**: consent to sign electronically is consent to doing business
  electronically, and with `CONSENT_SPAN_SECONDS` above zero (default 0, at most 3600) one
  acceptance stands for the same person's other documents on the same host for that long
  (sections 3 step 4, 4, 6, 8, 9). Every envelope still records its own `consent.accepted` and
  still sets `signers.consent_text_id` and `consented_at`; what the span changes is whether the
  disclosure was displayed again, and the trail says which by naming the acceptance relied on and
  when it was given. The certificate says it in words and verification re-checks it against the
  earlier envelope's trail. A kiosk session never has standing consent, in either direction: a
  shared tablet is the one place "the same person is still sitting here" cannot be assumed.

**What this weakens.** One thing, and only in section C: a signer on the second document of a
sitting is not shown the disclosure again before agreeing. The containment is the same shape as
Addendum 1 C's: off by default, capped by a constant in the code rather than by configuration
(`config.CONSENT_SPAN_MAX_SECONDS`, one hour) so verification can re-check it years later, never
available to a kiosk session, recorded on every envelope it is used on, printed on the certificate
in words, and re-derived from the other envelope's own hash-chained trail by `esign verify`. The
checklist gains an item for counsel, as the re-authentication span did. Sections A and B weaken
nothing: they remove a checkbox that duplicated the button beneath it and a screen that repeated
what the signer had just done, neither of which was evidence of anything the trail does not hold.

Everything in sections 1 to 15 still applies; where the addendum is silent, this document decides.
Its contract changes were made once, up front (section 13, "Addendum 3"), in `contracts.py`,
`config.py` and this document; the sections above that changed say so inline. There is no
migration: standing consent is found in rows the base schema already writes. The addendum's
Frontend, Demo host and Tests headings apply to sections 11 and 12 without restating them here.
