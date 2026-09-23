# demo-host

A stand-in for an EHR. It exists so the signing service can be exercised the way a customer would
exercise it: over HTTP, with an API key, from a browser, with webhooks coming back.

It is **not** part of the product. Nothing here is production code, the login is a single shared
password, and all of its state is in memory and forgotten on restart.

## Running it

`make demo` from the repository root brings up everything — database, migrations, the development
PKI, the host registration, the sample templates, the API, the worker, the built signing UI and
this app — and prints where to click. That is the intended way in.

By hand:

```
DEMO_ESIGN_API_URL=http://localhost:8000 \
DEMO_ESIGN_API_KEY=esk_... \
DEMO_ESIGN_HOST_ID=<host uuid> \
DEMO_ESIGN_WEBHOOK_SECRET=<hex> \
uv run python -m demo_host
```

| Variable | Default | What it is |
|---|---|---|
| `DEMO_ESIGN_API_URL` | `http://localhost:8000` | The signing service's API |
| `DEMO_ESIGN_UI_URL` | same as the API | Where the browser loads `/sign` from |
| `DEMO_ESIGN_API_KEY` | — | `esk_…`, printed once by `esign hosts create` |
| `DEMO_ESIGN_HOST_ID` | — | Host id, so `/sign?host=…` can send the right `frame-ancestors` |
| `DEMO_ESIGN_WEBHOOK_SECRET` | — | Hex secret for `X-Esign-Signature`. Empty means every webhook is refused |
| `DEMO_PUBLIC_URL` | `http://localhost:8100` | This app's origin; must be a registered allowed origin |
| `DEMO_HOST_PORT` | `8100` | Port |
| `DEMO_PASSWORD` | `demo1234` | The one password everybody here has |

`demo.sh` also exports `REAUTH_SPAN_SECONDS=300`, `REAUTH_MAX_AGE_SECONDS=300` and
`CONSENT_SPAN_SECONDS=900` to the service it starts (unless they are already set), for the signing
queue below, and adds `clinical_report` to `APPROVED_DOCUMENT_TYPES` for the reports. Approved
document types are a compliance decision and the service enforces them whoever rendered the PDF,
so a generated report is refused (`document_type_not_approved`) until somebody has said that kind
of document may be signed electronically.

## What it covers

- **People.** Two patients, a guardian, a witness, two clinicians and a member of the front desk.
- **A worklist.** One item per sample template: a HIPAA acknowledgement (one signer), a consent to
  treatment signed by a guardian on behalf of a child, and a procedure consent needing the patient,
  a witness and a clinician in that order.
- **Envelopes over the Host API,** with the task id as the idempotency key.
- **The embedding protocol,** in `static/embed.js`: `esign:ready` → `esign:init` with a token that
  never touches a URL, `esign:reauth_required` → password prompt → *server-to-server*
  `POST /v1/sessions/{id}/reauth` → `esign:reauth_done`, plus the resize and ending messages.
- **Kiosk mode,** started by staff, who must say how they checked the patient's identity. The
  signature is attributed to the patient; the member of staff is recorded as the one who handed the
  tablet over.
- **Webhooks,** verified with HMAC and a five-minute timestamp tolerance before anything is
  believed, and deduplicated by delivery id because delivery is at-least-once.
- **A chart,** where the sealed PDF is filed and can be downloaded and re-verified on demand.
- **Filing a paper document** (`/archive`, staff). Upload a scan of an ink-signed document, say who
  signed it and what happened to the original, and attest that the scan is a true copy. It goes to
  `POST /v1/archives` with the member of staff's opaque id as the attesting party, comes back sealed
  by webhook, and appears in the chart as a paper archive with the same "Verify it now" button. A
  sample scan is at `/static/sample-scan.pdf`.
- **A signing queue** (`/queue`, clinicians). Every order sign-off needs the clinician to confirm
  their identity immediately before signing. The queue confirms once -- the password is checked
  here, then attested server to server against the *first* document's signing session -- and the
  clinician signs each document in turn without being asked again, because the service is running
  with a re-authentication span.

  Addendum 3 B made it a **run**. Opening the first order fixes the order of the rest; the signing
  UI is told where it is (`esign:init` carries `queue {index, total, next_title}`), counts down on
  its Done screen and says `esign:next {envelope_id}` when it is finished. This host decides what
  that means: `POST /queue/next` checks that the envelope named is the one it opened for the
  document it has open for that person, creates the next envelope and session, and reloads the
  same iframe, which asks for its token exactly as the first one did. The list is not returned to
  in between, and the run ends on an "All 5 signed" panel. Reports stay out of it (below), and so
  does anything waiting on another signer. With the consent span on as well, each order after the
  first shows "You agreed to sign electronically at 09:12" instead of the checkbox -- three taps
  per document: continue, place the signature, sign. Which document displays the notice is decided
  by when this person last read it, not by where they are in the run: the service's database
  outlives a demo run, so a clinician who agreed a few minutes ago in an earlier run is still in
  that sitting and the first order stands too, and a sitting that began fifteen minutes ago runs
  out part-way through, which puts the checkbox back on that document and starts the window again.
- **Reports** (`/reports`, clinicians). Addendum 2: a document this system generates rather than
  one the service renders. "Generate and sign" renders a report for that patient with
  `reportlab` -- thirty pages of their own record for the annual summary, twenty-five for the case
  review -- and uploads it to `POST /v1/envelopes` as multipart, with the roles it is signed by and
  `fields: {"mode": "named"}`. The signature block on the last page carries AcroForm widgets called
  `clinician_signature` and `clinician_date` (and `cosigner_signature` / `cosigner_date` on the
  co-signed one); the service reads the positions off those names, removes every widget, and
  presents the flattened bytes. The page shows the SHA-256 of what was uploaded and links to those
  exact bytes, so they can be held against the upload hash in `document.supplied` and against the
  sealed copy in the chart. The renderer is deterministic -- `invariant=1` and no random number
  generator -- because the `Idempotency-Key` on that route hashes the document too.

  Reports are signed from this page, each with its own re-authentication, and deliberately do not
  join the signing queue above, which the addendum's demo paragraph mentions. The queue exists to
  show one identity confirmation covering a run of short, near-identical order sign-offs
  (Addendum 1 C); a twenty-five page report is the document that has to be *read*, and putting it
  behind a confirmation made for something else would be demonstrating the weakening rather than
  the containment. Nothing in the service stops it: a host that wants reports in a queue gets the
  same behaviour by listing them there.
- **People** (`/people`, staff). The one thing a host may do about a saved signature: remove it
  (`POST /v1/users/{id}/adopted-signature/revoke`). There is no host call to create or read one, so
  staff cannot make a doctor's signature and this page cannot say whether anybody has one.

### Why both spans are off by default

The developer guide asks for per-document proof that a clinician re-authenticated for *that*
document, and the service's default (`REAUTH_SPAN_SECONDS=0`) gives exactly that: one attestation
covers one session, which is one document. A span trades that proof for convenience. It is
contained -- at most 900 seconds, never further back than `REAUTH_MAX_AGE_SECONDS`, each document
still reviewed, consented to and signed on its own, and every `signer.signed` event and certificate
saying which attestation was used, whether it was borrowed (`reauth_scope: span`) and how old it
was -- but it is still weaker, and whether the trade is acceptable is a compliance decision, not
an engineering one. The demo turns it on so the queue can be seen working; a deployment should
leave it at zero until compliance has agreed in writing, and set both settings together when it
does (the queue's window is the smaller of the two).

`CONSENT_SPAN_SECONDS` (Addendum 3 C) is the same shape of trade and is off by default for the
same reason. The service's default displays the ESIGN disclosure before every agreement, which is
the plainest reading of the requirement. With the span on, an agreement made by the same person on
the same host, for the same disclosure version and language, stands for their other documents for
that long: the later ones show when it was given instead of asking again. What does **not** change
is what is recorded -- every envelope still writes its own `consent.accepted`, still sets
`signers.consent_text_id` and `consented_at`, and the event, the certificate and `esign verify`
all name the earlier acceptance and re-read it from that envelope's own trail. The window is
measured from the moment the notice was displayed, carried forward through the queue, so five
orders in a row do not add up to five spans. What changes is
whether the notice was put in front of the signer a second time. ESIGN consent is consent to doing
business electronically rather than to one form, so standing consent is defensible -- but whether
it is acceptable here, and for how long, is compliance's decision (C12 in the checklist), not a
default anybody should inherit. A shared tablet never has it in either direction: the person in
front of a kiosk may not be the person who agreed. The demo sets it to 900 seconds, longer than
the re-authentication span, because "I agree to do this on a screen" is a weaker claim to carry
forward than "this is me, right now".

## What it deliberately does not do

- It does not import the `esign` package. A stand-in that used the service's own code would prove
  nothing; it speaks HTTP, like a customer.
- It never puts a name, a record number, a date of birth or a session token in a URL.
- It does not persist anything. Restart it and the demo starts again from the seed.
