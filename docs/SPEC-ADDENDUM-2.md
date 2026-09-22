# Addendum 2: host-supplied documents

The base spec starts every electronic envelope from a template published ahead of time, and
excludes "arbitrary uploaded PDFs at signing time". That exclusion was aimed at untrusted uploads.
It also rules out the most common clinical case: a report the EHR generates per patient (20 to 30
pages, different every time) with a signature block at the end for the clinician. This addendum
adds a second way to create an electronic envelope: the host backend supplies the document itself,
over its API key, as a trusted server-to-server upload.

Everything downstream of revision 1 is unchanged: presentation, viewed-every-page, consent,
re-authentication, signing, revisions, certificate, seal, storage, verification, webhooks, the
signing UI, and Addendum 1's adopted signatures and re-authentication span.

**What this weakens.** Nothing in the evidence chain: the document Dr X sees is still hashed and
recorded before they see it, and every later step is identical. What changes is provenance: the
content came from the host rather than from a published template. The audit trail and certificate
say so (`document.supplied` instead of `document.prepared`, "Document supplied by the host" on the
certificate, with the upload's hash and the host's document reference).

## Model
- `envelopes.source`: `template` (default, existing behaviour) or `host_document`. For
  `host_document`, `template_version_id` is NULL and a new `field_definitions jsonb` column on the
  envelope holds the resolved `FieldDef` list and `SignerRoleDef` list for this envelope (the same
  shapes a template version carries). Addendum 1's `kind` stays as it is; `source` applies only to
  `kind = electronic`, enforced by CHECK.
- `document_revisions.kind` gains `supplied` for revision 1 of a host document (the hygiene-checked,
  flattened bytes actually presented). The raw upload is stored too, as a blob of a new kind
  `supplied_pdf`, and its hash recorded in `document.supplied` data, so the transformation from
  upload to presented bytes is itself evidenced.
- New audit event `document.supplied` (data: upload hash, presented hash, page_count,
  field_source `named_fields | explicit`, host_document_ref). No prefill exists for this source.
- Approved document types apply unchanged.

## API (host)
`POST /v1/envelopes` accepts, in addition to the existing JSON body, a multipart form with:
- `document`: the PDF (limits `MAX_SUPPLIED_DOCUMENT_BYTES`, default 25 MB, and
  `MAX_SUPPLIED_DOCUMENT_PAGES`, default 200).
- `body`: JSON as today minus `template_key`/`template_version`/`prefill`, plus `document_type`,
  `signers` (as today, each with `role_key`), `signer_roles` (a `SignerRoleDef` list: key, label,
  allowed capacities, `requires_reauth`, order), and `fields`, resolved one of two ways:
  - **Named fields.** `fields: {"mode": "named"}` (or omitted): the server reads the PDF's AcroForm
    widgets and maps each one whose name is `<role_key>_signature`, `<role_key>_initials`,
    `<role_key>_date` (or more generally `<role_key>__<field_id>` with an optional type suffix) to a
    `FieldDef` using the widget's page and rectangle (converted to displayed-page coordinates,
    honouring `/Rotate`). Every declared role must resolve to at least one signature field or the
    request fails with `fields_unresolved` listing the roles. Unmatched widgets are removed.
  - **Explicit rects.** `fields: {"mode": "explicit", "fields": [FieldDef...]}`, where `page` may
    be a positive integer or a negative one counted from the end (`-1` = last page), so a variable
    page count does not matter. Validated with `validate_definitions` against the actual page sizes.
- The same hygiene as templates (`inspect_template_pdf`: no encryption, JavaScript, XFA, embedded
  files, existing signatures, launch actions), then flattening of any remaining form fields and
  annotations, then storage as revision 1 (`supplied`). The upload is also stored as `supplied_pdf`.
- `Idempotency-Key` applies (the request hash covers the document bytes).
- `EnvelopeView` gains `source`, and the existing signer-facing payload needs no change (fields
  are served from the envelope's own definitions).

Multiple signers work exactly as with templates: a co-signing physician is a second role with its
own field and `requires_reauth`, sequential or parallel.

## Documents module
- `resolve_named_fields(pdf, signer_roles) -> list[FieldDef]` with the naming rules above and
  correct geometry on rotated and offset-origin pages.
- `flatten_supplied(pdf) -> bytes`: remove all widgets and annotations, keep page content, embed
  nothing new. Refuse (ValidationFailed) if the result would differ in page count.
- Performance: a 30-page report must prepare in well under two seconds and present without
  re-parsing on every request (Addendum 0's page_count concern applies: persist `page_count` on
  `document_revisions` in this addendum's migration and use it everywhere the page count is needed).

## Demo host
A "Reports" page for each clinician: the demo host generates a sample multi-page report (25 pages
of generated clinical text, a signature block on the last page with named fields
`clinician_signature` and `clinician_date`, and for one sample a second block for a co-signer),
creates a host-document envelope, and signs it through the embedded UI and the signing queue.

## Tests
- Named-field resolution: role mapping, type suffixes, rotated last page, unmatched widgets
  removed, missing role refused, page-count check.
- Explicit rects with negative pages; out-of-page rects refused.
- Hygiene rejections on supplied documents (same fixtures as templates, plus an AcroForm with
  JavaScript actions).
- End to end: a 30-page generated report signed by a clinician with re-authentication; a two-role
  report signed sequentially; the raw upload and the presented revision both stored and both hashes
  in `document.supplied`; verification catches a swapped upload blob and a swapped revision; the
  certificate says "Document supplied by the host"; a host cannot supply a document type outside the
  approved list; idempotent replay with the same document bytes returns the first response and with
  different bytes is a conflict.
- Signing UI: no change expected; one Playwright run through a long document to confirm the
  viewed-every-page gate and progress copy behave on 30 pages at phone width.

## Contract and schema changes (architecture step, done first)
- `contracts.py`: `EnvelopeSource`; `NewEnvelope` becomes either template-based (as today) or
  document-based (`NewHostDocumentEnvelope` with `document: bytes`, `document_type`,
  `signer_roles`, `fields: NamedFields | ExplicitFields`, signers, order, refs, expiry, supersede);
  `EnvelopeService.create_from_document(db, host, spec, ctx)`; `DocumentService.resolve_named_fields`
  and `flatten_supplied`; `BlobKind` gains `supplied_pdf`; `EventType.DOCUMENT_SUPPLIED`;
  `EnvelopeView.source`; `CertificateSummary.source` and `host_document_ref`.
- `0800_addendum_2.sql`: `envelopes.source`, `envelopes.field_definitions`, the CHECKs,
  `document_revisions.kind` accepting `supplied`, `document_revisions.page_count`, `blobs.kind`
  accepting `supplied_pdf`.
- `config.py`: `MAX_SUPPLIED_DOCUMENT_BYTES`, `MAX_SUPPLIED_DOCUMENT_PAGES`.
- `docs/SPEC.md`: section 1's exclusion reworded to "PDFs uploaded by signers or end users", a
  section 15 pointing here, and section 3 step 1 and section 9 updated.
