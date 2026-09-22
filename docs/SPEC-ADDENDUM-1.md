# Addendum 1: paper archives, adopted signatures, re-authentication span

Three additions to `docs/SPEC.md`. Everything in the base spec still applies; where this document
is silent, the base spec decides. Contract and schema changes are made once, up front, by the
architecture step (`contracts.py`, migration `0700_addendum_1.sql`, and the SPEC sections named
here), and module authors do not touch them afterwards.

The same test applies to each feature as to the base system: does the stored record alone still
show who signed, what they saw, that they meant it, and that nothing changed? Each feature below
says what it weakens and how that is contained.

## A. Archiving paper-signed documents

A host can file a scan of a document that was signed in ink, so it enjoys the same write-once
storage, seal, timestamp, audit trail and verification as an electronic signature.

**What the seal proves, and what it does not.** It proves the scan has not changed since the moment
it was filed, and who filed it and attested to it. It does not prove the ink signature is genuine;
that rests on the paper original and the attesting staff member. The cover page says this in plain
words, and so does the certificate.

### Model
- `envelopes.kind`: `electronic` (default, existing behaviour) or `paper_archive`. A paper archive
  has no signers, no sessions and no template; `template_version_id` becomes nullable and a CHECK
  ties it to the kind.
- New columns on `envelopes` for paper archives: `paper_signed_on date`, `attestation jsonb`
  (`staff_user_id`, `staff_display_name`, `statement` = `true_copy`, `original_disposition` in
  `retained | returned_to_signer | destroyed_per_policy`, `paper_signers` = list of
  `{display_name, capacity}`), `attested_at timestamptz`.
- States: `created -> completed_pending_seal -> sealed`, plus `voided` before the seal. The existing
  seal job, worker, webhooks (`envelope.sealed`, `envelope.voided`) and verification apply unchanged
  except where noted.
- Audit events (new `EventType` members): `archive.created` (data: document_type, page_count,
  scan hash), `archive.attested` (data: staff_user_id, statement, original_disposition,
  paper_signer_count, `attested_detail_sha256`; never names), then the existing
  `document.finalized`, `document.sealed`, `document.stored`. `attested_detail_sha256` is one
  SHA-256 over the canonical JSON of `{staff_display_name, paper_signers, paper_signed_on}`: those
  are PHI and belong on the cover page, not in the trail, but the mutable `attestation` column is
  the whole attribution of a paper signature, so the chain has to be able to contradict a rewritten
  name or date. The digest is what lets it (`docs/SPEC.md` section 4).

### API (host, `Authorization: Bearer esk_...`)
- `POST /v1/archives` multipart: `scan` (PDF only; image files are the host's job to convert),
  `body` JSON `{patient_ref, document_type, host_document_ref?, paper_signed_on, attestation,
  supersedes_envelope_id?}`. Supports `Idempotency-Key`. Returns an `EnvelopeView` with
  `kind: "paper_archive"`.
- The scan goes through the same hygiene as a template (`inspect_template_pdf` rules: no
  encryption, JavaScript, XFA, embedded files, existing signatures; page and byte limits from a new
  `MAX_SCAN_BYTES` / `MAX_SCAN_PAGES`). Rasterised, image-only pages are expected and fine.
- Everything else uses the existing envelope routes: `GET /v1/envelopes/{id}`, `/document`,
  `/audit`, `/verification`, `/void`. `EnvelopeView` gains `kind` and, for archives,
  `paper_signed_on` and `attested_at`.

### Documents
- `DocumentService.build_archive_cover(summary: ArchiveCoverSummary) -> bytes`: one page, placed
  **before** the scan, stating: "Scanned copy of a document signed on paper", document type, paper
  signing date, who attested and when, disposition of the original, the scan's SHA-256, the envelope
  id, and the sentence about what the seal does and does not prove. Then the existing certificate of
  completion (with an archive variant: no signer table, the attestation instead) is appended after
  the scan as today, and the whole thing is sealed. `CertificateSummary` gains `kind` and an
  optional `attestation` block.

### Frontend
Nothing. Filing a scan is a host-side action. The demo host gets a "File a paper document" page
for staff.

### Tests
Happy path to sealed and verified; hygiene rejections; void before seal; supersede a sealed
electronic envelope with a paper archive and the reverse; verification catches a swapped scan;
webhook fires; no PHI in logs; `paper_signers` names never reach audit data.

## B. Adopted signatures (a saved signature per user)

A signer can save the signature they adopted so it is offered again in their next session. This
removes the drawing step for clinicians who sign many documents a day. It does not remove any other
step: review, consent, re-authentication and an explicit apply action per field stay exactly as
they are.

**Who can create one.** Only the signer, inside their own authenticated signing session. There is
no host API to upload a signature for a user: staff cannot create a doctor's signature. The host
can revoke one.

### Model
- Table `adopted_signatures`: `id`, `host_id`, `host_user_id`, `kind` (`drawn | typed`),
  `image_sha256` (blob, kind `signature_image`) or `typed_text`, `created_in_envelope_id`,
  `created_by_session_id`, `created_at`, `revoked_at`, `revoke_reason` (`replaced | user |
  host`). At most one unrevoked row per `(host_id, host_user_id)` (partial unique index). Rows are
  never deleted; replacing one revokes the old row.
- `signature_captures.kind` gains `adopted`, with a new nullable `adopted_signature_id` column and a
  CHECK tying them together. `Capture` in contracts gains `adopted_signature_id: UUID | None`.
- Audit: `signature.adopted` (envelope stream of the session it was created in; data:
  adopted_signature_id, kind) and `signature.adoption_revoked` (`system` stream; data:
  adopted_signature_id, host_user_id, reason). `signer.signed` data gains `adopted_signature_id`
  when one was used, so the certificate can say "signed with a saved signature adopted on <date>".

### API
- Signer: `GET /v1/signing/session` gains `adopted_signature: {id, kind, image_png_base64 |
  typed_text, created_at} | null`. `POST /v1/signing/sign` accepts `save_adopted_signature: true`
  with a drawn or typed capture, which creates the row after the signature succeeds (same
  transaction). `POST /v1/signing/adopted-signature/revoke` for the signer themselves.
- Host: `POST /v1/users/{host_user_id}/adopted-signature/revoke` (`{reason?}`).
- The stored image is served only to a session belonging to the same `host_user_id`.

### Frontend
Adopt step: if a saved signature exists, show it first with "Use my saved signature", "Create a
new one" and "Remove saved signature" as equal choices. Applying it to each field remains an
explicit action per field. When adopting a new drawn or typed signature, an unchecked "Save this
signature for next time" checkbox. Kiosk sessions never offer or save an adopted signature (a
patient on a shared tablet must not leave their signature behind).

### Tests
Create in session A, offered in session B for the same user, not offered for a different user or
host; kiosk never offers or saves; revoke by user and by host; replace revokes the old row; the
`adopted` capture applies the stored image and the audit event carries its id; the image blob is
not readable by another user's session.

## C. Re-authentication span (a signing queue)

By default a re-authentication attestation covers one session, which is one document. A host can
opt into a span: an attestation for a user covers that user's other sessions on the same host for
`REAUTH_SPAN_SECONDS` after `auth_time`, so a clinician re-authenticates once and then signs several
documents in a row.

**What this weakens.** Per-document proof that the clinician re-authenticated for that document.
It is contained by: the span is off by default (`REAUTH_SPAN_SECONDS = 0`), capped at 900 seconds
by validation, the attestation still has to be younger than `REAUTH_MAX_AGE_SECONDS` counted from
`auth_time`, each document still needs its own review, consent and explicit sign action in its own
session, and every `signer.signed` event records which attestation was used and whether it was
made in this session or borrowed from another (`reauth_scope: session | span`), with its age at the
moment of signing. The certificate prints the same.

### Model
- `reauth_attestations` gains `host_id` and `host_user_id` (copied from the session's signer at
  insert). `IdentityService.fresh_reauth(db, session_id)` keeps its signature but returns a richer
  `ReauthEvidence(attestation_id, method, auth_time, scope)` (contract change: the return type).
  Resolution order: an attestation on this session first; otherwise, when the span is on, the most
  recent one for the same `(host_id, host_user_id)` within the span.
- `EnvelopeService.sign` records `reauth_attestation_id`, `reauth_scope` and `reauth_age_seconds`
  in `signer.signed` data; `CertificateSigner` gains `reauth_scope` and `reauth_at`.

### API
- `GET /v1/signing/session` already returns `reauth_valid_until`; it now reflects span
  attestations too, so the UI can skip the hand-off when a valid one exists. A new field
  `reauth_scope` says which.
- No new host endpoint: the host keeps calling `POST /v1/sessions/{id}/reauth` once, on the first
  document.

### Frontend
Confirm step: when `reauth_valid_until` is in the future, skip the hand-off and show "You confirmed
your identity at HH:MM; this signature will be recorded under that confirmation" with a "Confirm
again" option. Otherwise unchanged.

### Demo host
A clinician "signing queue" page: list of the clinician's pending documents, re-authenticate once,
then sign each in turn with the embedded UI. Runs with the span set to 300 seconds in the demo
configuration, and the README says why it is off by default.

### Tests
Span off: second document demands its own attestation. Span on: the second document within the
span signs with `reauth_scope = span` and the right age; outside the span it is refused; a
different user or host never borrows; an attestation older than `REAUTH_MAX_AGE_SECONDS` is refused
even inside the span; the certificate and audit data say which attestation was used; verification
still passes and still catches tampering with the attestation row.

## Contract and schema changes (architecture step, done first)

- `contracts.py`: `EnvelopeKind`, `Attestation`, `ArchiveCoverSummary`, `NewArchive`,
  `EnvelopeService.create_archive(db, host, spec, scan, ctx)`; `Capture.adopted_signature_id`;
  `AdoptedSignature`, `IdentityService.get_adopted_signature / adopt_signature /
  revoke_adopted_signature`; `ReauthEvidence` as the return of `fresh_reauth`;
  `DocumentService.build_archive_cover`; new `EventType` members; `CertificateSummary.kind`,
  `attestation`; `CertificateSigner.reauth_scope`, `reauth_at`, `adopted_signature_id`.
- `0700_addendum_1.sql`: everything under "Model" above, with the append-only trigger on
  `adopted_signatures` (update allowed only to set `revoked_at`/`revoke_reason` once) and the
  grants for `esign_app` (`SELECT, INSERT, UPDATE` on `adopted_signatures`; `INSERT` only on
  `reauth_attestations` as before).
- `config.py`: `MAX_SCAN_BYTES`, `MAX_SCAN_PAGES`, `REAUTH_SPAN_SECONDS` (0, max 900).
- `docs/SPEC.md`: add a section 14 pointing at this addendum, and update sections 3, 4, 8, 9 where
  they now differ.
