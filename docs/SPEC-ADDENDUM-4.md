# Addendum 4: review evidence, the signing date, a faster sign press, and SDK mode

Four changes to `docs/SPEC.md`. Everything in the base spec still applies; where this document is
silent, the base spec decides. Contract and schema changes are made once, up front
(`contracts.py`, migration `0900_addendum_4.sql`, and the SPEC sections named here).

The same test applies as to the base system: does the stored record alone still show who signed,
what they saw, that they meant it, and that nothing changed? Each feature below says what it
weakens and how that is contained.

**Backward compatibility.** No existing field is renamed, removed or retyped. New request fields
are optional and new response fields are additive. The iframe and the `esign:*` postMessage
protocol are unchanged.

## A. Every page reviewed, plus reaching the end

The Read screen already counted a page as displayed when it was drawn, on screen, and had stayed
there. Continue to sign now also requires that the consent block under the last page has been on
screen (`reached_end`). The primary button is "Next unseen page (n)" until every page has been
displayed, then "Go to end" until that block has been, then Continue to sign.

`POST /signing/viewed` gains optional `pages_seen: int[]` and `reached_end: bool`. When
`pages_seen` is present it must be exactly pages 1 to N of the bytes this session was served.
`review_seconds` is computed on the server from `document.presented` to now using `Clock`; the
client still sends no timestamps. A client that sends only `pages_viewed` is recorded as before.

When the data is present the certificate prints "Reviewed all N pages, reached end, M min".

**Legal basis for counsel (not legal advice).** ESIGN (15 U.S.C. 7001) and UETA require intent and
an attributable record. Neither requires proof that each page was read. Courts enforce assent
where the signer had a reasonable opportunity to review and took an unambiguous act (for example
Meyer v. Uber, 2d Cir. 2017; Berkson v. Gogo, E.D.N.Y. 2015, on scrollwrap). Gating on every page
being displayed, plus reaching the end, is the strongest version of that opportunity. Counsel
should confirm it for this product.

**What this weakens.** Nothing in the evidence chain. The old `pages_viewed` count remains the
gate the server enforces. The new fields are extra evidence when the current UI is driving.

## B. Signature size and date

The mark inside a signature field takes at least 60% of the field height. The caption shrinks
(down to a 3.5 pt floor) to fit the rest, and is at most two lines:

1. `Name (capacity)`, with `on behalf of …` when relevant.
2. `Date: 09/28/2026 11:10 AM EDT  ·  Signer <uuid>`.

The signer id is never shortened (SPEC section 6). If one line does not fit, the date and signer
id wrap. The certificate keeps the full UTC time.

Drawn images are cropped to the ink on the client and on the server, then scaled to the mark
band's height, left-aligned, capped by its width. Typed and click-to-sign text scale to fill the
mark band.

`hosts.display_timezone` is an IANA name (nullable). `DEFAULT_DISPLAY_TIMEZONE` (default `UTC`) is
used when the host has none. Both are validated with `zoneinfo`. `SignerStamp.signed_at` stays UTC
from `Clock`; the timezone is applied only when formatting. `date_signed` fields use the same
format. `esign hosts create --timezone` and `esign hosts set-timezone` set it.

## C. The sign press no longer waits for the seal

When the last signer signs, the envelope becomes `completed_pending_seal` and a seal job is
enqueued in the same transaction. A `NOTIFY esign_seal` wakes the worker. The HTTP response is
the stamp, with the same shape as today; `status` is `completed_pending_seal`. The worker LISTENs
and falls back to `worker_poll_seconds`. It seals before it delivers webhooks, so a slow receiver
cannot delay a seal. Revocation fetches and KMS calls have explicit timeouts.

Nothing about "never fail open" changes. Done already says whether the document is sealed or still
sealing. `esign:sealed` still fires only when the copy arrives.

## D. SDK mode (no iframe), opt-in and additive

`POST /v1/envelopes/{id}/signers/{sid}/sessions` gains optional `client: "iframe" | "sdk"`,
default `iframe`, stored on `signing_sessions.client_mode` and recorded in `session.created`.

CORS middleware applies only to `/v1/signing/*`. Preflight is answered for origins in any host's
`allowed_origins`. Actual requests from another origin are allowed only when the token's session
is in `sdk` mode and `Origin` is one of that session's host's allowed origins; anything else is
`403 origin_not_allowed`. Iframe sessions behave exactly as today.

The SDK sends `X-Esign-Client: esign-sdk/<version>` on every call. For SDK sessions the server
requires the header (`403 client_required`) and records `client` and `origin` in the audit data
for `document.presented`, `document.viewed`, `consent.accepted` and `signer.signed`. The
certificate prints "Signing client: esign-sdk 1.x in \<origin\>".

The header is self-declared. What binds it is the host's server declaring `sdk` mode at session
creation, plus the origin check. The signer's IP and user agent are still captured from the
signer's own browser, because the SDK calls the API directly from their device, not through the
host backend.

The package is `@esign/sdk`: `createSigningClient({ baseUrl, token })` is the headless API client
(every `fetch` still lives in `frontend/src/lib/api.ts`, every response still parsed with Zod);
`<EsignSigner />` is a React component that reuses `SigningFlow`, `DocumentViewer` and the page
tracker. The `esign:*` events are callbacks, not postMessage. Re-authentication uses
`onReauthRequired`; the host backend still calls `POST /v1/sessions/{id}/reauth`.

**What this weakens.** The framed UI's origin check (`frame-ancestors` plus the `init` origin
list) does not apply, because there is no frame. The containment is the host declaring `sdk` at
session creation, CORS allowing only that host's origins, and the library header being required
and recorded. A host that opens an SDK session and then lets an unlisted origin call with the
token is refused; a host that lists an origin it does not control has listed it for embedding
already.

## Tests

- tracker reset; `reached_end` gating
- `pages_seen` server validation plus the old-client path
- mark share and timezone caption, including a DST boundary
- sign returns before the seal; the worker seals on the next tick
- CORS allow and deny by mode and origin
- one SDK Playwright run asserting `client=sdk` in the trail
