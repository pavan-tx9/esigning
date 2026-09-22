# E-signing service

A standalone signing service that an EHR embeds. It produces legally defensible electronic
signatures under ESIGN/UETA for signers the EHR has **already authenticated**: patients in a
portal, patients on an in-clinic tablet, and clinicians signing off on forms.

The product is evidence. If a signature is disputed years from now, the stored record alone has to
show who signed, what they saw, that they meant to sign, and that nothing changed afterwards.
Everything below follows from that.

- `docs/SPEC.md` — the architecture, and the rules it is built from.
- `docs/HOW-SIGNATURES-WORK.md` — what evidence exists, and how to verify a document by hand.
- `docs/RUNBOOK.md` — production setup, key rotation, outages, retention, incidents.
- `docs/COMPLIANCE-CHECKLIST.md` — every requirement mapped to code and to the test that proves it.

## What it is

One HTTP service with two APIs and a background worker.

- The **Host API** (`Authorization: Bearer esk_…`) is server to server. The EHR's backend creates
  envelopes, opens signing sessions, attests re-authentication, fetches the sealed PDF, reads the
  audit trail and runs verifications.
- The **Signer API** (`Authorization: Bearer est_…`) is used only by the embedded signing UI, on
  behalf of one signer of one envelope. The token is the only thing that says which.
- The **worker** (`esign worker`) seals, retries, sweeps expiries and delivers webhooks.

An *envelope* is one document, one template version, and one or more signers. It ends `sealed`,
`declined`, `voided` or `expired`, and nothing else.

What is deliberately out of scope, and refused with `422 out_of_scope` rather than approximated:
email-link signing for people without an account, a template builder, bulk send, uploaded PDFs at
signing time, controlled-substance prescriptions, notarisation, non-US signature regimes.

## The pipeline

Every envelope goes through these steps in this order. Each one writes an audit event in the same
database transaction as the state change, so a state change without its event — or an event
describing a change that did not happen — is not representable.

```
  EHR backend                    esign                          evidence written
  ───────────                    ─────                          ────────────────
1 POST /v1/envelopes ─────────▶  render template + prefill,     envelope.created
                                 flatten, hash, store as        document.prepared
                                 revision 1 "presented"         → blob (write-once)

2 POST …/signers/{id}/sessions▶  mint est_ token, bound to      session.created
    {auth: how they logged in}   one signer, 30 min             (or session.rejected)
         │
         │ token by postMessage only, never in a URL
         ▼
  ┌──────────────────┐
  │ signing UI       │  3 GET  /v1/signing/document ────────▶   document.presented (hash of
  │ in an iframe     │         every page rendered              the exact bytes served)
  │ on the EHR page  │     POST /v1/signing/viewed ────────▶    document.viewed
  │                  │  4 POST /v1/signing/consent ───────▶     consent.accepted (version + body hash)
  │                  │  5 esign:reauth_required ──▶ host ──▶
  │                  │       POST /v1/sessions/{id}/reauth ▶    auth.reauthenticated
  │                  │  6 POST /v1/signing/sign ──────────▶     signer.signed (presented, base and
  │                  │       {captures}, Idempotency-Key        new revision hashes, capture digests)
  └──────────────────┘                                     └─▶  revision N stored write-once
                                     last signer?  ──────────▶  envelope.completed + seal job
                                          │
7                                         ▼
  worker / inline attempt        build certificate of           document.finalized
                                 completion from the trail,     document.sealed
                                 append it, apply ONE PAdES     document.stored
                                 seal (DocMDP no-changes) with
                                 an RFC 3161 timestamp, using
                                 a key held in KMS, validate
                                 the output, store it
                                          │
8 webhook envelope.sealed  ◀──────────────┘                     (delivery row, HMAC signed)
  GET …/document  ─────────────▶ the sealed PDF                 document.downloaded
  GET /v1/signing/copy ────────▶ the same bytes for the signer  document.downloaded

9 esign verify <id>  /  GET …/verification ─────────────────▶   verification.performed
```

**One seal, at the end, rather than one signature per signer.** The certificate of completion has
to be *inside* the sealed bytes, and appending pages after a PDF signature invalidates it. So each
signer step produces a hashed, stored, audit-chained revision, and a single final certification
seal covers the document plus its certificate. The per-signer evidence is the audit chain and the
stored revisions, which verification re-hashes. `docs/HOW-SIGNATURES-WORK.md` explains what that
does and does not prove.

**Never fail open.** If KMS, the timestamp authority or storage is unavailable, the envelope stays
`completed_pending_seal`, `seal.failed` is recorded with an error code, the job backs off
(1m, 5m, 15m, 1h, then hourly), and nothing anywhere reports the document as complete. The same
holds for a failure no retry can fix: pending, recorded, loud. An envelope waiting for its seal
cannot be voided — every signer has signed, and the honest states are "sealed" or "still trying".

## Quick start

You need Docker (for Postgres), [`uv`](https://docs.astral.sh/uv/) and
[`bun`](https://bun.sh/). Then:

```sh
make install      # backend, demo host and frontend dependencies
make demo         # everything, in the foreground; Ctrl-C stops it
```

`make demo` starts Postgres on 54329, applies the migrations, generates a development PKI into
`.dev-pki/`, seeds the ESIGN disclosure, builds the signing UI, starts the API on :8000, registers
a demo EHR (keeping its credentials in `.demo/env`, because `esign hosts create` prints the API key
exactly once), imports the four sample templates, starts the worker, and starts a stand-in EHR on
:8100. It then prints where to click. Everything it does is safe to repeat. The demo runs the
service with a five-minute re-authentication span (`REAUTH_SPAN_SECONDS=300` together with
`REAUTH_MAX_AGE_SECONDS=300`, because the span never reaches further back than the maximum age —
both are off or default in production; `demo-host/README.md` says why) so the clinician's signing
queue can be shown.

Open <http://localhost:8100> and sign in as any of `maria`, `sam`, `grace`, `ben`, `priya`,
`tomas` or `alice` with the password `demo1234`. Worth doing in this order:

1. **maria** — a patient with a privacy acknowledgement to sign. The whole flow in one signer.
2. **grace** — a parent signing a consent to treatment on behalf of her child. The signature is
   attributed to the guardian, acting for the patient, and the certificate says so.
3. **maria**, then **ben**, then **priya** — the procedure consent, signed in sequence by patient,
   witness and clinician. Priya is asked for her password again immediately before her signature.
4. **alice** — "Clinic tablet" starts a kiosk session. Staff record how they checked the patient's
   identity; the signature is still the patient's.
5. The **Webhooks** page shows each delivery and whether its HMAC checked out. Any document in a
   chart has a button that re-verifies the seal, every stored hash and the whole audit chain.
6. **alice** — "File a paper document" uploads a scan of an ink-signed document with her
   attestation; it is sealed and lands in the chart with the same verification button.
7. **priya** — "Signing queue": three order sign-offs, one confirmation of her identity, then each
   signed in turn without being asked again. Every signature's record says which confirmation it
   rests on and whether it was borrowed.
8. **tomas** — the same queue; tick "Save this signature for next time" on the first order and the
   second offers it back.
9. **sam** — the saved signature from the other side, in three documents: sign the annual
   acknowledgement and keep the signature, then have **alice** start the hydrotherapy consent on
   the "Clinic tablet" (a kiosk is offered nothing, whatever Sam kept on the portal), then have
   alice remove it from "People" — the review consent is offered nothing either, and Sam adopts a
   fresh one. "People" is the only thing a host may do about a saved signature: remove it.

Logs from everything `make demo` started are in `.demo/logs/`.

### Other commands

| Command | What it does |
|---|---|
| `make up` / `make down` | Postgres on 54329 (keeps the data volume) |
| `make migrate` / `make migrate-status` | apply / list `backend/migrations/*.sql` |
| `make check` | ruff, mypy, pytest, and the frontend's typecheck, lint and tests. The gate |
| `make test` | tests only |
| `make e2e` | Playwright against the mocked API |
| `make e2e-demo` | Playwright against the real stack through the demo host |
| `make dev` | API on :8000 and the signing UI on :5273, together |
| `make clean-db` | destroy the database volume and start again |

## How an EHR integrates

Three things happen on the host side: the backend talks to the Host API with an API key, the page
embeds the signing UI in an iframe and hands it a token by `postMessage`, and the backend receives
webhooks. `demo-host/` is a working implementation of all three, in about 1,300 lines of Python plus
its templates, and it speaks HTTP rather than importing anything from `esign` — so it proves the
integration rather than assuming it.

### 0. Get registered

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

### 1. Create the envelope

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
- `signing_order` is `sequential` (session creation is gated on every earlier signer having signed)
  or `parallel` (any order, serialised by the envelope row lock).
- A signer whose capacity is `clinician` always gets `requires_reauth: true`, whatever the
  published template says.

### 2. Open a signing session

Immediately before showing the UI, and once per signer. The body is the host's **attestation** of
how that person authenticated — the host backend is trusted because it holds the API key, and the
browser is never the source of these values.

```sh
curl -s -X POST "$API/v1/envelopes/$ENVELOPE_ID/signers/$SIGNER_ID/sessions" -H "$AUTH" \
  -H 'Content-Type: application/json' \
  -d '{"auth": {"method": "portal_otp", "auth_time": "2026-09-22T05:08:24Z"}}'
```

```json
{"token": "est_qONcQnccfC4py3qQGrWiClDtd1iZayYBxIwm1CasvHk",
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

### 3. Embed the signing UI

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
| host → UI | `esign:init {token, locale?}` | the token, by `postMessage` only |
| UI → host | `esign:reauth_required {session_id}` | this role must re-authenticate before signing |
| host → UI | `esign:reauth_done` | your backend has attested it |
| UI → host | `esign:signed`, `esign:sealed`, `esign:declined`, `esign:expired` | the outcome |
| UI → host | `esign:resize {height}` | how tall the content is |

**Treat `esign:resize` as a maximum, not an instruction.** If the frame is made as tall as its
content, the signing UI never scrolls: its own viewport becomes the whole document, every page of
the PDF is on screen as far as the browser is concerned, and "I have looked at every page" is
satisfied the moment it loads. The signature would then be evidence that somebody had a document
open, not that they read it. Cap the height at the viewport and let the person scroll inside it.

### 4. Re-authentication

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

### 5. What the signer's browser does

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

### 6. Webhooks

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

### 7. Filing a document that was signed on paper

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
audit head hash. `docs/HOW-SIGNATURES-WORK.md` §5 explains what that is and is not evidence of, and
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
  by hand as `docs/HOW-SIGNATURES-WORK.md` §2(g) shows.
- `paper_signed_on` is a date, and one in the future is refused (`paper_signed_on_in_future`).
- `statement` is a closed vocabulary of one: `true_copy`. `original_disposition` is `retained`,
  `returned_to_signer` or `destroyed_per_policy`, and it is printed on the cover. What actually
  happens to the paper is your records policy — this service records the claim and never judges it
  (`docs/COMPLIANCE-CHECKLIST.md` C11).
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

### 8. Saved signatures

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

### 9. The signing queue (`REAUTH_SPAN_SECONDS`)

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
for *that* document (`docs/COMPLIANCE-CHECKLIST.md` C10, `docs/RUNBOOK.md` §7).

### 10. Reading the record back

```sh
curl -s "$API/v1/envelopes/$ENVELOPE_ID"               -H "$AUTH"   # EnvelopeView
curl -s "$API/v1/envelopes/$ENVELOPE_ID/document"      -H "$AUTH" -o sealed.pdf   # 409 not_sealed until it is
curl -s "$API/v1/envelopes/$ENVELOPE_ID/audit"         -H "$AUTH"   # the whole chain
curl -s "$API/v1/envelopes/$ENVELOPE_ID/verification"  -H "$AUTH"   # run the checks now
```

`verification` is always 200 for an envelope that exists: a failed verification is a finding
(`"ok": false`, `"problems": [...]`), not a transport error. Running it appends
`verification.performed` to the trail, so "somebody checked, and this is what they found" is itself
evidence. `docs/HOW-SIGNATURES-WORK.md` explains every check.

### Errors

```json
{"error": {"code": "not_viewed", "message": "The document has changed. Please look through every page again before you sign."}}
```

The `code` is stable and machine-readable; the `message` is a fixed sentence and never echoes the
input. A host asking about another host's envelope, template or session gets `404 not_found`, not
`403` — the difference would confirm the thing exists. `429` carries `Retry-After`. `503`
(`seal_unavailable`, `storage_unavailable`) means nothing was completed and a retry is appropriate.

## Configuration

Everything is read from the environment into one `Settings` object
(`backend/src/esign/config.py`). `backend/.env.example` is a copyable template of the development
values. No secret value lives in the repo, in an image, or in these variables — the signing key is
in KMS and only its *identifier* is configuration.

### Environment

| Variable | Default | Notes |
|---|---|---|
| `APP_ENV` | `dev` | `dev`, `test`, `prod`. `prod` turns on the production checks and HSTS; `dev` together with `aws_kms` or `s3` is refused at startup |
| `LOG_LEVEL` | `INFO` | JSON output whenever `APP_ENV` is not `dev` |

### Database

| Variable | Default | Notes |
|---|---|---|
| `DATABASE_URL` | dev DSN on :54329 | the **runtime** role `esign_app`: no DDL, no `TRUNCATE`, and no `UPDATE`/`DELETE` on the append-only tables |
| `DATABASE_OWNER_URL` | dev DSN | the **migration** role `esign_owner`. Used by `esign migrate` and the test harness only |
| `MIGRATIONS_DIR` | `backend/migrations` | numbered SQL, applied in filename order |
| `DB_ECHO` | `false` | refused in production: SQLAlchemy's echo logs bound parameters, which carry PHI |
| `DB_POOL_SIZE` | `5` | |

### Blob store

| Variable | Default | Notes |
|---|---|---|
| `BLOB_BACKEND` | `fs` | `fs` or `s3`. Production must be `s3`: the fs backend cannot enforce retention |
| `BLOB_FS_ROOT` | `.blobstore` | content-addressed, files created read-only, exclusive create |
| `BLOB_S3_BUCKET` | — | required whenever the backend is `s3`, in any environment |
| `BLOB_S3_REGION` | `us-east-1` | |
| `BLOB_S3_ENDPOINT_URL` | — | for MinIO or a VPC endpoint |
| `BLOB_S3_PREFIX` | `esign/` | |
| `BLOB_S3_OBJECT_LOCK_MODE` | `COMPLIANCE` | `GOVERNANCE` is an explicit choice, never a default |
| `BLOB_S3_SSE` | `AES256` | or `aws:kms` |
| `BLOB_S3_SSE_KMS_KEY_ID` | — | with `aws:kms` |

### Sealing

| Variable | Default | Notes |
|---|---|---|
| `SEAL_KEY_BACKEND` | `local` | `local` is the dev PKI; production must be `aws_kms` |
| `SEAL_PROFILE` | `PAdES-B-LT` | `PAdES-B-T` is an explicit dev/test choice, never a silent fallback. `PAdES-B-LTA` adds an archive timestamp |
| `DEV_PKI_DIR` | `.dev-pki` | generated by `esign dev-pki`, git-ignored, never production |
| `SEAL_KMS_KEY_ID` | — | required with `aws_kms` |
| `SEAL_KMS_REGION` | `us-east-1` | |
| `SEAL_KMS_ENDPOINT_URL` | — | |
| `SEAL_CERT_PATH` | — | the seal certificate, PEM, exactly one certificate |
| `SEAL_CHAIN_PATH` | — | the intermediates, PEM |
| `TSA_URL` | — | RFC 3161 authority. Required in production; empty outside production uses an in-process dummy, which a non-`local` key backend refuses |
| `TSA_TIMEOUT_SECONDS` | `10` | |
| `TRUST_ROOTS_PATH` | `.dev-pki/trust-roots.pem` | the **only** roots `validate` may trust. A certificate embedded in a PDF never counts |

### Identity

| Variable | Default | Notes |
|---|---|---|
| `SESSION_TTL_SECONDS` | `1800` | |
| `AUTH_MAX_AGE_SECONDS` | `43200` | how stale the host's `auth_time` may be |
| `REAUTH_MAX_AGE_SECONDS` | `120` | how fresh a re-authentication must be to cover a signature |
| `REAUTH_SPAN_SECONDS` | `0` | for how long after its `auth_time` an attestation also covers the same user's other sessions on the same host (a signing queue). `0`: one attestation, one document. At most `900`, and never further than `REAUTH_MAX_AGE_SECONDS`, so a queue's window is the smaller of the two. Off unless compliance has agreed; every signature records whether it borrowed one |
| `TRUSTED_PROXY_CIDRS` | *(empty)* | only these peers' `X-Forwarded-For` is believed; everything else uses the peer address. A typo silently changes every recorded IP, so it is parsed at startup |
| `DEFAULT_LOCALE` | `en-US` | which disclosure is served when none is asked for |

### Envelopes and retention

| Variable | Default | Notes |
|---|---|---|
| `APPROVED_DOCUMENT_TYPES` | the four samples | compliance owns this list. A template of any other type cannot produce an envelope, and a scan of any other type cannot be filed |
| `RETENTION_YEARS_BY_DOCUMENT_TYPE` | `{}` | JSON. Anything absent gets the default |
| `DEFAULT_RETENTION_YEARS` | `10` | a floor, not a schedule; 365-day years |
| `ENVELOPE_DEFAULT_TTL_DAYS` | `14` | when the host does not send `expires_at` |

### Limits

| Variable | Default | Notes |
|---|---|---|
| `MAX_TEMPLATE_BYTES` | 20 MiB | |
| `MAX_TEMPLATE_PAGES` | `50` | |
| `MAX_SCAN_BYTES` / `MAX_SCAN_PAGES` | 20 MiB / `100` | a scan filed with `POST /v1/archives` (image-only pages are large) |
| `MAX_SUPPLIED_DOCUMENT_BYTES` / `MAX_SUPPLIED_DOCUMENT_PAGES` | 25 MiB / `200` | a document the host supplies with a multipart `POST /v1/envelopes` (a generated report is 20 to 30 pages where a template is one to five) |
| `MAX_SIGNATURE_PNG_BYTES` | 1 MiB | |
| `MAX_SIGNATURE_PNG_PIXELS` | 4,000,000 | |
| `MAX_SIGNATURE_PNG_DIMENSION` / `MIN_SIGNATURE_PNG_DIMENSION` | `4000` / `8` | a 4000×1 image passes a pixel budget and is not a signature |
| `MAX_TYPED_SIGNATURE_CHARS` | `200` | stamped into the document and kept for years |
| `MAX_TEXT_FIELD_CHARS` | `2000` | likewise |
| `MAX_REQUEST_BYTES` | 8 MiB | enforced while the body is arriving, not after. Three routes carry files and are bounded by their own limit plus 1 MiB of multipart framing instead: `POST /v1/templates` by `MAX_TEMPLATE_BYTES`, `POST /v1/archives` by `MAX_SCAN_BYTES`, and a multipart `POST /v1/envelopes` by `MAX_SUPPLIED_DOCUMENT_BYTES`. Over the bound is `413 payload_too_large`; an oversized file part inside a legal request is `scan_too_large` / `supplied_too_large` |

### API and worker

| Variable | Default | Notes |
|---|---|---|
| `FRONTEND_DIST_DIR` | `frontend/dist` | the built signing UI; `/sign` appears when it exists |
| `TEMPLATES_DIR` | `templates` | where `esign templates import` looks |
| `WORKER_POLL_SECONDS` | `5` | |
| `SEAL_JOB_LOCK_TIMEOUT_SECONDS` | `600` | a claim older than this belonged to a worker that died |
| `WEBHOOK_TIMEOUT_SECONDS` | `10` | |
| `WEBHOOK_MAX_ATTEMPTS` | `12` | |
| `IDEMPOTENCY_TTL_HOURS` | `48` | a replay after this is a new request, which the envelope service still refuses to turn into a second signature |

Rate limits are not configurable: they are policy, defined once in
`esign.identity.ratelimit.RateLimits`, and metered per host, per session and per IP.

## The `esign` command

```
esign migrate [--status | --dry-run]          apply backend/migrations as the owner role
esign dev-pki [--force]                       generate the development PKI (never for production)
esign hosts create --name N --origin O …      register an EHR; prints its API key ONCE
esign hosts rotate-key HOST_ID                replace a host's API key; prints the new one ONCE
esign consent add --default                   seed the bundled ESIGN disclosure
esign consent add --version V --locale L --file F [--effective-at T]
esign templates import --host HOST_ID [--dir templates/] [--no-publish]
esign worker [--once]                         seal jobs, expiries, webhooks
esign verify ENVELOPE_ID [--json]             re-check an envelope; exit 1 if anything failed
esign serve [--host H] [--port P] [--reload]  run the API (and the signing UI when it is built)
```

Secrets are printed to stdout exactly once and are never logged; everything else the command says
is ids, counts and statuses. Logs go to stderr, so `esign verify --json | jq` works.

## Project layout

```
backend/              Python 3.13, FastAPI, SQLAlchemy 2 + psycopg 3, pyHanko. Managed with uv.
  migrations/         numbered plain SQL. 0001 is the schema; 0002 the roles and grants.
  src/esign/
    contracts.py      every cross-module type and interface. Architecture-owned; modules never edit it.
    config.py         Settings. One object, read from the environment, passed to every factory.
    runtime.py        the one place every module factory is called, and the production settings gate.
    clock.py  ids.py  db.py  logging.py     foundation: time, ids, engines, the allowlisted logger.
    audit/            the hash chain. README.md here is the normative hashing definition.
    storage/          content-addressed write-once blobs: fs and S3 Object Lock. No delete path.
    sealing/          PAdES via pyHanko, KMS and dev-PKI key backends, RFC 3161, validation.
    documents/        template inspection, prefill, stamping, the certificate of completion.
    identity/         host keys, session tokens, re-authentication, consent texts, rate limits.
    envelopes/        every envelope and signer state transition, under the envelope row lock.
    api/              the HTTP layer: host routes, signer routes, middleware, /sign.
    worker/           seal jobs, expiry sweeps, webhook delivery.
    verification/     Verifier.verify_envelope and its report.
    webhooks/         the queue, the HMAC signature, the delivery loop.
    cli.py            the esign command.
  tests/              one directory per module, plus tests/e2e/ over the real HTTP app.
frontend/             Bun, Vite, React 19, TypeScript strict, TanStack Query, Tailwind v4, Base UI.
  src/lib/api.ts      the only place fetch is called; every response parsed with Zod.
  src/flow/           the six-state signing flow and its steps.
  e2e/                Playwright, against the mocks and against the real stack.
demo-host/            a stand-in EHR. Not product code; it speaks HTTP like a customer would.
templates/            four sample templates, with a script that regenerates the PDFs byte for byte.
docs/                 SPEC.md, this documentation, and the developer guide the rules come from.
```

Modules import `esign.contracts` and the foundation files only, never a sibling module's internals.
Each exposes exactly one factory, and `runtime.build_runtime` is the only caller.
