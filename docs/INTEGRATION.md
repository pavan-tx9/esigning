# Integrating an EHR

The full host-side walk-through, moved here from the README. Every command was run against `make demo`.

Three things happen on the host side: the backend talks to the Host API with an API key, the page
embeds the signing UI in an iframe and hands it a token by `postMessage`, and the backend receives
webhooks. `demo-host/` is a working implementation of all three, in about 1,300 lines of Python plus
its templates, and it speaks HTTP rather than importing anything from `esign` — so it proves the
integration rather than assuming it.

## 0. Get registered

Done once, by an operator of the service, not by the EHR:

```sh
uv --directory backend run esign hosts create \
  --name "Riverside Clinic" \
  --origin https://ehr.riverside.example \
  --webhook-url https://ehr.riverside.example/webhooks/esign
```

It prints a host id, an API key (`esk_…`) and a webhook secret, **once**. Only SHA-256 hashes are
stored, so a lost key is rotated (`esign hosts rotate-key <host id>`), never recovered. The
`--origin` list becomes the `frame-ancestors` CSP on the signing UI: a page at any other origin
cannot frame it, and the UI will not accept a token from it.

The examples below use the credentials `make demo` wrote to `.demo/env`:

```sh
set -a; source .demo/env; set +a
AUTH="Authorization: Bearer $DEMO_ESIGN_API_KEY"
API=http://localhost:8000
```

## 1. Create the envelope

The host chooses a published template version, supplies the prefill (chart data) and the signers.
Prefill is used once to render the PDF and is never stored outside it.

```sh
curl -s -X POST $API/v1/envelopes -H "$AUTH" \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: chart-note-5521' \
  -d '{
    "template_key": "hipaa_acknowledgement",
    "template_version": 1,
    "patient_ref": "pat-90412",
    "host_document_ref": "chart-note-5521",
    "signing_order": "parallel",
    "signers": [{
      "role_key": "patient",
      "host_user_id": "user-90412",
      "display_name": "Maria Alvarez",
      "capacity": "self"
    }],
    "prefill": {"patient_name": "Maria Alvarez", "notice_version": "2026-01"}
  }'
```

```json
{
  "id": "280ee839-293b-4a3b-b7c1-162b72bf4742",
  "status": "created",
  "document_type": "hipaa_acknowledgement",
  "template_key": "hipaa_acknowledgement",
  "template_version": 1,
  "signing_order": "parallel",
  "signers": [{"id": "85d51657-24b4-4764-959a-cc31e7492715", "role_key": "patient",
               "role_label": "Patient", "display_name": "Maria Alvarez", "capacity": "self",
               "order_index": 0, "requires_reauth": false, "status": "pending"}],
  "presented_sha256": "9edfa997…feb32",
  "current_revision_sha256": "9edfa997…feb32",
  "sealed_sha256": null,
  "created_at": "2026-09-22T05:08:16.419618Z",
  "expires_at": "2026-10-06T05:08:16.419618Z",
  "supersedes_envelope_id": null,
  "superseded_by_envelope_id": null
}
```

Things worth knowing here:

- `template_version: null` means "the latest published version". Naming the version explicitly is
  better: it is what the certificate of completion will print.
- `patient_ref`, `host_user_id` and a kiosk `staff_user_id` must be **opaque** — no whitespace, and
  not shaped like a date of birth or a social security number. They reach the audit trail, and the
  trail refuses to hold a fact about a person. A display name is rejected here (`host_user_id_invalid`)
  rather than at the moment somebody signs.
- `Idempotency-Key` makes a retry return the *same envelope, as it is now*. What is stored is the
  envelope's id, not a second copy of the request; the same key with a different body is a
  `conflict`.
- `capacity` must be one the template's role allows. A `guardian` or `proxy` must also send
  `on_behalf_of`, and it must equal this envelope's `patient_ref`.
- `on_behalf_of_display` (optional, `guardian` and `proxy` only, otherwise
  `on_behalf_of_display_not_allowed`) is how that person should be *named* to the signer acting for
  them. `on_behalf_of` has to be opaque because it reaches the audit trail, and since the sign
  button became the whole of the intent confirmation the signer reads it: without this, a parent's
  button says "Sign as Grace Okafor, on behalf of mrn-100907". Send the patient's name and it says
  so instead. It is PHI, and is treated exactly like `display_name` — stored on the signer row and
  printed in the document, never in the audit trail, a webhook payload, a log line or an error
  message. The attribution in the record does not move: `on_behalf_of` is still what every event
  carries. Omit it and the UI falls back to `on_behalf_of`, as it did before.
- `signing_order` is `sequential` (session creation is gated on every earlier signer having signed)
  or `parallel` (any order, serialised by the envelope row lock).
- A signer whose capacity is `clinician` always gets `requires_reauth: true`, whatever the
  published template says.

## 1b. Create the envelope from a document you generated

Section 15 of the spec. Some documents cannot come from a template: a report the EHR renders for
one patient, twenty or thirty pages of their own record, different every time, with a signature
block at the end. The same route takes those as **multipart** instead of JSON — the PDF in
`document`, and in `body` the JSON a template envelope would carry minus `template_key`,
`template_version` and `prefill`, plus the roles the document is signed by and how to find the
fields.

```sh
curl -s -X POST $API/v1/envelopes -H "$AUTH" \
  -H 'Idempotency-Key: report-88120' \
  -F 'document=@annual-summary.pdf;type=application/pdf' \
  -F 'body={
    "document_type": "clinical_report",
    "patient_ref": "pat-90412",
    "host_document_ref": "report-88120",
    "signing_order": "sequential",
    "signers": [{
      "role_key": "clinician",
      "host_user_id": "dr-0431",
      "display_name": "Dr Priya Raghunathan",
      "capacity": "clinician"
    }],
    "signer_roles": [{
      "key": "clinician",
      "label": "Attending physician",
      "allowed_capacities": ["clinician"],
      "requires_reauth": true,
      "order_index": 0
    }],
    "fields": {"mode": "named"}
  }'
```

The reply is an `EnvelopeView` like the one above, with `source: "host_document"`,
`template_key` and `template_version` both `null`. Everything after this point — sessions, the
iframe, viewed-every-page, consent, re-authentication, signing, the seal, webhooks, verification —
is identical to a template envelope, so sections 2 onwards apply unchanged.

What the service does with the upload, in order: the same hygiene rules a template must pass (no
encryption, no existing signatures, no JavaScript, XFA, embedded files or launch actions) under
`MAX_SUPPLIED_DOCUMENT_BYTES` (25 MiB) and `MAX_SUPPLIED_DOCUMENT_PAGES` (200); then the fields;
then every widget and annotation is flattened away and those bytes become revision 1. The upload
is stored too, and `document.supplied` records both hashes — so "we showed the signer what you
sent us" is checkable rather than asserted, and the certificate of completion prints both.

Two ways to say where the signatures go:

- **`{"mode": "named"}`** (the default). The service reads the PDF's own AcroForm widgets and
  claims the ones named `<role_key>_signature`, `<role_key>_initials`, `<role_key>_date`, or
  `<role_key>__<field_id>` with an optional type suffix. A report generator that already places a
  signature block only has to name the widget. Positions come from the widget, `/Rotate` and a
  non-zero `MediaBox` origin included. **Every role must resolve to at least one `_signature`
  field**; otherwise the request is refused with `fields_unresolved`. Widgets no role claims are
  dropped, and none of them survives into revision 1.
  **Draw the signature slot as an ordinary text widget** (`/FT /Tx`) named `<role_key>_signature`,
  not as an AcroForm signature field (`/FT /Sig`). A `/Sig` field is refused with
  `supplied_signature_field` even when it is an empty placeholder: this service applies its own
  signature and seals the result, and a document that already carries signature machinery is not
  something it will sign over.
- **`{"mode": "explicit", "fields": [...]}`** — `FieldDef`s with their own rects, for a generator
  that does not emit an AcroForm. `page` may count from the end (`-1` is the last page), which is
  what makes a variable page count harmless; it is resolved to a positive page before anything is
  stored, and a rect outside the page is refused.

Things worth knowing here:

- **Approved document types apply unchanged.** Compliance decides what may be signed
  electronically, whoever rendered the PDF: a type outside `APPROVED_DOCUMENT_TYPES` is
  `document_type_not_approved`, the same as for a template.
- **`Idempotency-Key` covers the document bytes.** A retry has to send the same PDF — keep the
  rendered bytes rather than re-rendering, unless your renderer is deterministic. The same key
  with different bytes is a 409 `idempotency_key_reused`, exactly as a changed body is.
- **`host_document_ref` reaches the audit trail on this path** (it is in `document.supplied`), so
  it must be opaque like every other host-chosen identifier: `report-88120`, not
  `annual-summary-alvarez-1962`.
- **Nothing is stored until every refusal has had its chance.** A document refused for hygiene,
  for an unresolved role or for its type leaves no blob and no envelope row behind.
- **Every role carries its own `order_index`, and it is required.** There is no default: two roles
  that both left it out would share position 0 and be refused as an ambiguous sequential order the
  host never chose. Role keys are `[a-z][a-z0-9_]*`, at most 64 characters — the same shape the
  audit trail accepts, so a key this route takes is one that can be recorded.
- **Nothing from inside the file becomes an identifier.** Field ids are built from the role key
  you declared and the type of the field — `clinician_signature`, `clinician_date_signed`, and
  `clinician_signature_2` for a second signature widget of the same role — never from the widget's
  own name. Those ids come back in the signer-facing payload and are written into the audit trail,
  which may not hold anything about a patient; a generator that uniquifies its widget names per
  document (an MRN, a surname, a date of service) is doing the normal thing and costs you nothing
  here. The labels a signer reads are built from the role labels in this request, for the same
  reason.
- **Bake every mark into the page content.** Annotations are removed from the upload without being
  drawn, so ink that lives in one would silently not be in the bytes the signer reads. A visible
  non-widget annotation with an appearance — a `/FreeText` "AMENDED" note, a `/Stamp`, a `/Square`
  redaction box, an `/Ink` mark — is refused with `supplied_annotation_not_removable` rather than
  quietly dropped. `/Link` and `/Popup`, and anything flagged Hidden or NoView, draw nothing and
  are fine.

Every refusal on this path is a stable `code` with a fixed sentence beside it; the message never
quotes your roles, your ids or anything out of the file (SPEC section 9), so the `code` is what to
branch on:

| code | what to fix |
|---|---|
| `fields_unresolved` | a declared role has no `<role_key>_signature` widget in the document (a role key that is not `[a-z][a-z0-9_]*` answers `supplied_definitions_invalid` instead, in both field modes: a key no widget name could match is a malformed key, not a missing signature block) |
| `supplied_definitions_invalid` | the resolved fields or the `signer_roles` you sent were refused: a key that is not `[a-z][a-z0-9_]*`, two roles sharing an `order_index`, a signature rect under 80×28pt, a role allowing the clinician capacity without `requires_reauth` |
| `field_page_out_of_range` | an explicit field names a page the document does not have |
| `supplied_signature_field` | a slot was drawn as `/FT /Sig`; use a text widget |
| `supplied_annotation_not_removable` | a visible annotation carries ink; draw it into the page |
| `supplied_already_signed` | the PDF already carries a signature |
| `supplied_too_large`, `supplied_too_many_pages` | over `MAX_SUPPLIED_DOCUMENT_BYTES` / `_PAGES` |
| `supplied_encrypted`, `supplied_javascript`, `supplied_xfa`, `supplied_embedded_file`, `supplied_forbidden_action` | the hygiene rules, same as for a template |
| `document_type_not_approved` | the type is not in `APPROVED_DOCUMENT_TYPES` |

## 2. Open a signing session

Immediately before showing the UI, and once per signer. The body is the host's **attestation** of
how that person authenticated — the host backend is trusted because it holds the API key, and the
browser is never the source of these values.

```sh
curl -s -X POST "$API/v1/envelopes/$ENVELOPE_ID/signers/$SIGNER_ID/sessions" -H "$AUTH" \
  -H 'Content-Type: application/json' \
  -d '{"auth": {"method": "portal_otp", "auth_time": "2026-09-22T05:08:24Z"}}'
```

```json
{"token": "est_<256-bit token, shown once>",
 "session_id": "2f81c362-59e7-4d0f-9582-c016ac7d1d4f",
 "expires_at": "2026-09-22T05:38:24.060817Z"}
```

`method` is one of `password`, `password+mfa`, `sso`, `portal_otp`, `pin`, `staff_verified`.
`auth_time` older than `AUTH_MAX_AGE_SECONDS` (12 hours) or in the future is refused. For an
in-clinic tablet, add the kiosk context:

```json
{"auth": {"method": "staff_verified", "auth_time": "…"},
 "kiosk": {"staff_user_id": "staff-3310", "identity_check": "photo_id"}}
```

`identity_check` is one of `photo_id`, `dob_and_name`, `known_to_staff`, `wristband`. The staff
member and the check are recorded on the certificate; the **signature is still attributed to the
patient**, never to the staff member.

The token is 256 bits, stored only as a hash, bound to one signer, and valid for
`SESSION_TTL_SECONDS` (30 minutes). Creating a new session revokes the previous one. Return it to
the browser over your own authenticated channel and hand it to the iframe by `postMessage` — never
in a URL, never in storage.

## 3. Embed the signing UI

Serve the iframe from `/sign?host=<host id>`. The host id is not a secret and says nothing about a
patient; it is what lets that response carry `Content-Security-Policy: frame-ancestors <your
allowed origins>` and `<meta name="esign-allowed-origins" content="…">` *before* any token exists.
With an unknown host both are empty: the UI cannot be framed and trusts nobody.

```html
<iframe id="esign-frame"
        src="https://esign.example/sign?host=1f0c…"
        title="Sign this document"
        allow="clipboard-write"></iframe>
```

```js
const frame = document.getElementById("esign-frame");
const serviceOrigin = new URL(frame.src).origin;
let sessionId = null;

window.addEventListener("message", async (event) => {
  // Believe a message only from our own iframe, only from the service's origin.
  if (event.source !== frame.contentWindow || event.origin !== serviceOrigin) return;
  const message = event.data;
  if (message === null || typeof message !== "object") return;

  switch (message.type) {
    case "esign:ready": {
      // Our backend mints the token; the browser never sees the API key.
      const response = await fetch("/internal/esign/token", { method: "POST" });
      const { token, session_id } = await response.json();
      sessionId = session_id;
      // Never "*": post only to the origin we were told to trust.
      frame.contentWindow.postMessage({ type: "esign:init", token, locale: "en-US" }, serviceOrigin);
      break;
    }
    case "esign:reauth_required":
      // Re-authenticate the user in *your* page, then have your backend attest it (step 4).
      await reauthenticate(sessionId);
      frame.contentWindow.postMessage({ type: "esign:reauth_done" }, serviceOrigin);
      break;
    case "esign:resize":
      // A maximum, not an instruction. See the note below.
      frame.style.height = `${Math.min(message.height + 24, window.innerHeight * 0.92)}px`;
      break;
    case "esign:signed":
    case "esign:sealed":
    case "esign:declined":
    case "esign:expired":
      showOutcome(message.type);
      break;
  }
});
```

The full contract:

| Direction | Message | Meaning |
|---|---|---|
| UI → host | `esign:ready` | the iframe has loaded and wants a token |
| host → UI | `esign:init {token, locale?, queue?}` | the token, by `postMessage` only; `queue {index, total, next_title?}` when this document is one of a run (§9) |
| UI → host | `esign:reauth_required {session_id}` | this role must re-authenticate before signing |
| host → UI | `esign:reauth_done` | your backend has attested it |
| UI → host | `esign:signed`, `esign:sealed`, `esign:declined`, `esign:expired` | the outcome |
| UI → host | `esign:next {envelope_id}` | "I am finished with this one; open the next" (§9) |
| UI → host | `esign:resize {height}` | how tall the content is |

**Treat `esign:resize` as a maximum, not an instruction.** If the frame is made as tall as its
content, the signing UI never scrolls: its own viewport becomes the whole document, every page of
the PDF is on screen as far as the browser is concerned, and "I have looked at every page" is
satisfied the moment it loads. The signature would then be evidence that somebody had a document
open, not that they read it. Cap the height at the viewport and let the person scroll inside it.

## 4. Re-authentication

Roles with `requires_reauth` — every clinician, and any role the template marks — cannot sign
without an attestation younger than `REAUTH_MAX_AGE_SECONDS` (120 seconds). The UI asks the host
page; the host page re-authenticates the user however it normally does; then the **host backend**,
not the browser, tells the service:

```sh
curl -s -X POST "$API/v1/sessions/$SESSION_ID/reauth" -H "$AUTH" \
  -H 'Content-Type: application/json' \
  -d '{"method": "password", "auth_time": "2026-09-22T05:20:11Z"}'
```

```json
{"session_id": "2f81c362-…", "reauth_valid_until": "2026-09-22T05:22:11Z"}
```

Another host's session is `not_found`, never `forbidden`. The attestation is refused
(`signer_finished`, `reauth_not_required`, `envelope_not_live`) if it could not belong to a
signature — a host cannot manufacture a re-authentication record after the fact. Then post
`esign:reauth_done` and the UI proceeds.

## 5. What the signer's browser does

For completeness, this is the Signer API the UI drives. A host never calls it.

```sh
SAUTH="Authorization: Bearer $TOKEN"
curl -s $API/v1/signing/session -H "$SAUTH"                     # everything the UI needs
curl -s $API/v1/signing/document -H "$SAUTH" -o document.pdf    # records document.presented
curl -s -X POST $API/v1/signing/viewed  -H "$SAUTH" -d '{"pages_viewed": 1}'
curl -s -X POST $API/v1/signing/consent -H "$SAUTH" -d '{"consent_version": "2026-09", "accepted": true}'
curl -s -X POST $API/v1/signing/sign    -H "$SAUTH" -H 'Idempotency-Key: sign-1' \
  -d '{"intent_confirmed": true,
       "captures": [{"field_id": "patient_signature", "kind": "typed", "typed_text": "Maria Alvarez"}]}'
curl -s $API/v1/signing/copy -H "$SAUTH" -o signed.pdf          # 202 {"status":"sealing"} while pending
```

Every signer `POST` answers ids and statuses only:

```json
{"envelope": {"id": "280ee839-…", "status": "completed_pending_seal"},
 "signer":   {"id": "85d51657-…", "status": "signed"}}
```

The client sends signature *inputs* and nothing else. Request bodies forbid unknown keys, so a
client that sends a PDF, a hash, a timestamp or a `date_signed` value is refused with 422 rather
than quietly ignored. `sign` requires an `Idempotency-Key` (422 `idempotency_key_required`); a
retry with the same key returns the first response and creates one revision.

## 6. Webhooks

Five events: `envelope.completed`, `envelope.sealed`, `envelope.declined`, `envelope.voided`,
`envelope.expired`. A delivery row is written in the transaction that changed the envelope, so a
notification exists if and only if the change committed; the worker sends it. Delivery is
**at least once**, in queue order, retried with backoff (30s, 2m, 10m, 30m, then hourly) up to
`WEBHOOK_MAX_ATTEMPTS`. Deduplicate on `id`.

```http
POST /webhooks/esign
Content-Type: application/json
X-Esign-Event: envelope.sealed
X-Esign-Delivery: 7c1d…
X-Esign-Signature: t=1790053742,v1=9f2c…
```

```json
{
  "id": "7c1d…", "event": "envelope.sealed",
  "occurred_at": "2026-09-22T05:08:41.220914Z",
  "envelope_id": "280ee839-…", "kind": "electronic", "status": "sealed",
  "template_key": "hipaa_acknowledgement", "template_version": 1,
  "presented_sha256": "9edfa997…", "current_revision_sha256": "cf3629c7…",
  "sealed_sha256": "3e5acf26…", "supersedes_envelope_id": null,
  "signers": [{"id": "85d51657-…", "role_key": "patient", "status": "signed"}]
}
```

Ids, statuses, hashes and `kind`. There is no name, no `patient_ref`, no `host_document_ref` and no
document type in a payload: a webhook leaves the network, and the host already knows which envelope
an id refers to. Fetch the sealed PDF yourself with `GET /v1/envelopes/{id}/document`.

`kind` is on **every** delivery. A paper archive (§7) sends `"kind": "paper_archive"` with
`template_key` and `template_version` null and `signers` empty, and fires only `envelope.sealed`
and `envelope.voided` — it has no signers to progress through. Accept unknown fields: this service
adds them, and the "unknown keys are rejected" rule applies to what you send it, not to what it
sends you.

**Verify the signature before you read the body.** `v1` is HMAC-SHA256 over the literal bytes
`"{t}.{body}"` with the secret printed by `esign hosts create`; reject a `t` more than five minutes
old. `esign.webhooks.verify_signature` is the reference implementation:

```python
def verify_signature(secret: bytes, body: bytes, header: str, *, now, tolerance_seconds=300) -> bool:
    parts = dict(part.split("=", 1) for part in header.split(",") if "=" in part)
    timestamp = int(parts["t"])
    if abs(int(now.timestamp()) - timestamp) > tolerance_seconds:
        return False
    expected = hmac.new(secret, f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, parts.get("v1", ""))
```

## 7. Filing a document that was signed on paper

A host can file a scan of a document signed in ink, so it gets the same write-once storage, seal,
timestamp, audit trail and verification (`docs/SPEC-ADDENDUM-1.md`, section A). Multipart: the
`scan` (a PDF; converting a photograph is the host's job) beside a `body` that says what it is and
who attests to it.

```sh
curl -s -X POST $API/v1/archives -H "$AUTH" -H 'Idempotency-Key: paper-5531' \
  -F 'scan=@consent-scan.pdf;type=application/pdf' \
  -F 'body={"patient_ref": "pat-90412", "document_type": "patient_consent",
            "host_document_ref": "paper-5531", "paper_signed_on": "2026-09-01",
            "attestation": {"staff_user_id": "staff-3310", "staff_display_name": "Alice Wu",
                            "statement": "true_copy", "original_disposition": "retained",
                            "paper_signers": [{"display_name": "Maria Alvarez", "capacity": "self"}]}}'
```

`201`, and an `EnvelopeView` with no template and no signers:

```json
{
  "id": "d46a3548-f58d-485e-b9e4-a0fef192ef5e",
  "status": "completed_pending_seal",
  "kind": "paper_archive",
  "document_type": "patient_consent",
  "template_key": null, "template_version": null, "signing_order": null, "signers": [],
  "presented_sha256": "a3a74b64…8240",
  "current_revision_sha256": "a3a74b64…8240",
  "sealed_sha256": null,
  "created_at": "2026-09-22T08:06:07.700592Z",
  "expires_at": "2026-10-06T08:06:07.700592Z",
  "paper_signed_on": "2026-09-01",
  "attested_at": "2026-09-22T08:06:07.700592Z",
  "supersedes_envelope_id": null, "superseded_by_envelope_id": null
}
```

Nobody has to sign, so filing *is* completion: the scan is stored write-once as revision 1 (kind
`scan`), `archive.created` and `archive.attested` are the first two events, and the envelope goes
straight to `completed_pending_seal`. The seal is attempted once inline and retried by the worker
exactly as for the last signature, `envelope.sealed` fires when it lands, and `/document`,
`/audit`, `/verification` and `/void` work as for any envelope. (`expires_at` is filled in for
every envelope; an archive never expires — it is complete the moment it is filed.)

The sealed PDF is **cover page, scan, certificate of completion**, in that order, under one seal.
The cover states what it is, the document type, the paper signing date, the number of pages
scanned, the envelope id, who signed on paper, who attested and when, what became of the original,
the scan's SHA-256, and, in these words:

> The seal on this document proves that this scan has not changed since it was filed, and who filed
> and attested to it. It does not prove that the signature on the paper is genuine: that rests on
> the paper original and on the person who attested to this copy.

The certificate prints the same sentence, the attestation in place of the signer table, and the
audit head hash. `HOW-SIGNATURES-WORK.md` §5 explains what that is and is not evidence of, and
§2(g) shows how to check an attestation by hand.

Things worth knowing here:

- The scan goes through the template hygiene rules — no encryption, JavaScript, XFA, embedded
  files or existing signatures — under `MAX_SCAN_BYTES` / `MAX_SCAN_PAGES` (20 MiB, 100 pages)
  rather than the template limits, because image-only pages are large. The codes say `scan_`
  (`scan_too_large`, `scan_too_many_pages`, `scan_encrypted`, …) so you know which file they are
  about. Rasterised pages are expected and fine.
- `document_type` must be on `APPROVED_DOCUMENT_TYPES`: compliance decides what may be filed this
  way, exactly as it decides what may be signed electronically.
- `patient_ref` and `attestation.staff_user_id` must be opaque (`patient_ref_invalid`,
  `host_user_id_invalid`). The paper signers' and staff member's **names reach the cover page and
  the certificate only** — `archive.attested` records the opaque staff id, the statement, the
  disposition, a *count* of paper signers, and `attested_detail_sha256`: one SHA-256 over the
  canonical JSON of `{staff_display_name, paper_signers, paper_signed_on}`, so those names and
  that date can be contradicted by the append-only trail without ever appearing in it. Verify it
  by hand as `HOW-SIGNATURES-WORK.md` §2(g) shows.
- `paper_signed_on` is a date, and one in the future is refused (`paper_signed_on_in_future`).
- `statement` is a closed vocabulary of one: `true_copy`. `original_disposition` is `retained`,
  `returned_to_signer` or `destroyed_per_policy`, and it is printed on the cover. What actually
  happens to the paper is your records policy — this service records the claim and never judges it
  (`COMPLIANCE-CHECKLIST.md` C11).
- `Idempotency-Key` hashes the scan bytes as well as the body, so a retry files one archive and
  the same key with a different document is refused (`409 idempotency_key_reused`) rather than
  replaying the first answer.
- A paper archive may be voided while it is still unsealed, and may supersede — or be superseded
  by — a sealed envelope of either kind. Once sealed it is corrected the same way everything else
  is: a new envelope with `supersedes_envelope_id`.

Then verify it like anything else — a real run, cover page and all:

```
$ uv --directory backend run esign verify d46a3548-f58d-485e-b9e4-a0fef192ef5e
envelope d46a3548-f58d-485e-b9e4-a0fef192ef5e: sealed
  PASSED  revision_numbers_gapless
  PASSED  revision_1_scan_hash  a3a74b6443ae260bf5663136d66d3782d6fec39520d3e00a6304dd1f0aee8240
  PASSED  revision_2_final_unsealed_hash  028df7a5…
  PASSED  revision_3_sealed_hash  fa92d74f…
  …
  PASSED  sealed_pages_match_final_revision
  PASSED  certificate_head_hash_in_document
audit trail: 5 events
RESULT: verified. The seal, every stored hash and the audit chain all check out.
```

## 8. Saved signatures

A signer can keep the signature they adopted so their next session offers it back. The host does
nothing for this — it happens inside the signing UI — but it is worth knowing what the host can
see and do.

**Only the signer creates one**, from inside their own live session, after their signature has
succeeded, and never from a kiosk: a patient on a shared tablet must not leave a signature behind
for the next person handed the tablet. There is no host API that uploads a signature for a user,
because staff must not be able to manufacture a doctor's signature.

- The UI sends `"save_adopted_signature": true` on `POST /v1/signing/sign` beside a drawn or typed
  capture. The row is written in the same transaction as the signature, and names the *stored*
  image the trail recorded — never bytes from the request.
- The next session's `GET /v1/signing/session` carries
  `"adopted_signature": {"id", "kind", "image_png_base64" | "typed_text", "created_at"}` (`null`
  on a kiosk session, and for anyone else). The image is served only to a session belonging to
  the same `(host, host_user_id)`.
- Using it is `{"field_id": "…", "kind": "adopted", "adopted_signature_id": "…"}` as a capture —
  one explicit action per field, as before. The trail records `kind = adopted`, the row's id, and
  the digest of what was stamped; the certificate says
  "signed with a saved signature adopted on 2026-09-22".
- There is at most one live saved signature per user per host. Saving another revokes the old one
  (`reason: replaced`). Rows are never deleted — a signature already applied points at one.

Either side can remove it. The signer does it from their own session
(`POST /v1/signing/adopted-signature/revoke` — also refused from a kiosk, with
`adoption_not_allowed`: a shared tablet is shown none of this and may not destroy it either, and
the trail would otherwise record "the signer asked for this" for a request nobody's own session
made); a host does it for a user:

```sh
curl -s -X POST "$API/v1/users/user-0311/adopted-signature/revoke" \
  -H "$AUTH" -H 'Content-Type: application/json' -d '{"reason": "left the practice"}'
```

```json
{"revoked": true}
```

200 either way: another host's user, an id that is not opaque, and a user with nothing saved all
answer `false`, so the call says nothing about who exists. `reason` is accepted for your own logs
and deliberately not stored — the trail records `reason: host` and free text is how a name gets in.
Send JSON or no body at all; `-d '{}'` without a `Content-Type` is form-encoded and is refused.

Revoking stops the signature being offered and applied from now on. It does not — and must not —
touch documents already signed with it: those are sealed, and the row survives so the capture that
points at it can still be verified.

## 9. The signing queue (`REAUTH_SPAN_SECONDS`)

With `REAUTH_SPAN_SECONDS` above zero (default `0`, at most `900`), a re-authentication attested on
one of a user's sessions also covers that user's **other sessions on the same host** for that long
after its `auth_time`, so a clinician confirms their identity once and signs a queue of orders.
The host still calls `POST /v1/sessions/{id}/reauth` once, on the first document, and nothing else
changes: each document is its own envelope, its own session, its own review, consent and signature.

```sh
# attested on the first document's session only
curl -s -X POST "$API/v1/sessions/$FIRST_SESSION_ID/reauth" -H "$AUTH" \
  -H 'Content-Type: application/json' \
  -d '{"method": "password", "auth_time": "2026-09-22T08:08:05Z"}'
# {"session_id":"36fbc470-…","reauth_valid_until":"2026-09-22T08:10:05Z"}

# the *second* document's session, which was never attested for
curl -s $API/v1/signing/session -H "Authorization: Bearer $SECOND_TOKEN"
```

```json
{"signer": {"…": "…",
            "requires_reauth": true,
            "reauth_valid_until": "2026-09-22T08:10:05Z",
            "reauth_scope": "span",
            "reauth_at": "2026-09-22T08:08:05Z"}}
```

`reauth_scope` is `session` for an attestation made for this session and `span` for a borrowed one,
and `reauth_at` is when the person actually confirmed their identity, so the UI can say "you
confirmed your identity at 08:08" instead of asking again. Every `signer.signed` event then records
`reauth_attestation_id`, `reauth_scope` and `reauth_age_seconds`, and the certificate prints
"password, at 2026-09-22 08:00:10 UTC in an earlier session, 5 seconds before signing" rather than
"for this document". Verification re-checks all of it against the attestation row, including the
`900`-second ceiling itself: a `span` signature naming an attestation older than the cap describes
something this service could not have produced, whatever the host's configuration was at the time.

**Set both windows together.** An attestation older than `REAUTH_MAX_AGE_SECONDS` (default 120 s)
covers nothing, span or no span — so `REAUTH_SPAN_SECONDS=300` on its own still gives a two-minute
queue, as the `reauth_valid_until` above shows. `make demo` exports `REAUTH_SPAN_SECONDS=300` **and**
`REAUTH_MAX_AGE_SECONDS=300` for this reason. The default is off, and turning it on is a compliance
decision, not an engineering one: it weakens per-document proof that the clinician re-authenticated
for *that* document (`COMPLIANCE-CHECKLIST.md` C10, `RUNBOOK.md` §7).

### Opening them one after another

A queue is the host's: the service has no idea there is one, and the signing UI never fetches the
next document or holds a second token. What it can do is say when it is finished with this one.

Send the position on `esign:init`:

```js
frame.contentWindow.postMessage(
  { type: "esign:init", token, locale: "en-US",
    queue: { index: 3, total: 8, next_title: "Order for R. P." } },
  serviceOrigin,
);
```

The UI then shows "3 of 8" in its header, and on the Done screen names what is coming, counts down
for a few seconds (cancellable with "Stay here") and posts `esign:next {envelope_id}`. That message
means one thing: *this* document is done with. What comes next is yours to decide — check the
envelope id against the document you opened for that person, create the next envelope and session,
and post a fresh `esign:init` into the same iframe. Send no `queue` at all and nothing changes.

**When a second `esign:init` is taken.** Into a live frame, only once the current document has
reached its Done screen — which is the only moment `esign:next` is sent from, so answering that
message is always in time. Posted any earlier it is ignored without a reply: a token arriving
while a signature is being made would swap identities under the person signing, and no host has a
good reason to do it. On the one it does take, the UI drops everything belonging to the finished
document first (its token, its cached session, the document bytes, any signature in progress), so
nothing of one signer's sitting can be read by the next. Reloading the iframe instead — a new
`src`, then `esign:init` into the fresh frame on its `esign:ready` — is equally valid and is what
`demo-host/src/demo_host/static/embed.js` does; it costs a page load and gains nothing beyond it.

`next_title` is shown to the signer, so it is a title, never a name or a record number; the UI
renders it as text and nothing else. A position that cannot be one ("9 of 3") is dropped rather
than displayed. `demo-host/` implements the whole of this in about forty lines of `static/embed.js`
and one route (`POST /queue/next`).

### Agreeing to sign electronically, once per sitting (`CONSENT_SPAN_SECONDS`)

There is a second thing a queue asks for twice. With `CONSENT_SPAN_SECONDS` above zero (default
`0`, at most `3600`) an acceptance of the ESIGN disclosure by the same `(host_id, host_user_id)`,
for the same disclosure version and language, stands for that person's other documents for that
long: `GET /v1/signing/session` reports it as `consent.standing {accepted_at, envelope_id}` and the
UI shows "You agreed to sign electronically at 09:12" instead of the checkbox. Nothing in the
record changes — every envelope still writes its own `consent.accepted`, still sets the signer's
`consent_text_id` and `consented_at`, and the event names the acceptance it stood on so the
certificate and `esign verify` can re-read it from that envelope's own trail. A kiosk session never
has it, in either direction. There is nothing for a host to call: it is configuration, and turning
it on is a compliance decision (`COMPLIANCE-CHECKLIST.md` C12).

The span bounds how long the **disclosure may go undisplayed**, not how far apart two documents
may be. Document three stands on document two, which stood on document one, and each event carries
`relied_on_root_accepted_at` — the moment the notice was actually shown — forward unchanged. The
span is measured from there, so a queue cannot renew the window a document at a time: whatever
`CONSENT_SPAN_SECONDS` says, that many seconds after the person read the notice the checkbox comes
back, however many forms they signed in between.

## 10. Reading the record back

```sh
curl -s "$API/v1/envelopes/$ENVELOPE_ID"               -H "$AUTH"   # EnvelopeView
curl -s "$API/v1/envelopes/$ENVELOPE_ID/document"      -H "$AUTH" -o sealed.pdf   # 409 not_sealed until it is
curl -s "$API/v1/envelopes/$ENVELOPE_ID/audit"         -H "$AUTH"   # the whole chain
curl -s "$API/v1/envelopes/$ENVELOPE_ID/verification"  -H "$AUTH"   # run the checks now
```

`verification` is always 200 for an envelope that exists: a failed verification is a finding
(`"ok": false`, `"problems": [...]`), not a transport error. Running it appends
`verification.performed` to the trail, so "somebody checked, and this is what they found" is itself
evidence. `HOW-SIGNATURES-WORK.md` explains every check.

## Errors

```json
{"error": {"code": "not_viewed", "message": "The document has changed. Please look through every page again before you sign."}}
```

The `code` is stable and machine-readable; the `message` is a fixed sentence and never echoes the
input. A host asking about another host's envelope, template or session gets `404 not_found`, not
`403` — the difference would confirm the thing exists. `429` carries `Retry-After`. `503`
(`seal_unavailable`, `storage_unavailable`) means nothing was completed and a retry is appropriate.
