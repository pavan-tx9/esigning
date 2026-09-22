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

## What it deliberately does not do

- It does not import the `esign` package. A stand-in that used the service's own code would prove
  nothing; it speaks HTTP, like a customer.
- It never puts a name, a record number, a date of birth or a session token in a URL.
- It does not persist anything. Restart it and the demo starts again from the seed.
