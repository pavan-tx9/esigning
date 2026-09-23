# Addendum 3: a shorter signing flow, and a faster queue

Today a single-field document takes five screens (review, consent, sign, confirm, done) and
roughly nine taps. This addendum cuts it to two screens before "done" and, for a clinician with a
saved signature working a queue, three taps per document. Nothing that produces evidence is
removed; steps are merged onto fewer screens, and the acts that matter stay explicit.

**What stays non-negotiable.** Every page displayed before signing is possible; consent to sign
electronically given explicitly (once per run, see C); one explicit act per field; one explicit act
that signs the document; re-authentication for roles that need it; a decline-to-paper path that is
visible on every screen. What is removed is duplication: a checkbox that restates what the button
says, a summary screen that repeats what the signer just did, a separate adopt screen.

## A. The flow: Read → Sign → Done

### Screen 1: Read
The document, page by page, with "Page 2 of 3" progress, as today. Directly under the last page,
in the same scroll, the **consent block**:
- the ESIGN disclosure (collapsed to its first lines with "Read the full notice", expanding in
  place), and one checkbox: "I agree to sign this document electronically";
- when a standing acceptance exists (section C), the checkbox is replaced by one line: "You agreed
  to sign electronically at 09:12. [Read the notice]";
- one primary button, **Continue to sign**, enabled when every page has been displayed and the
  consent condition is met. Before that it is inert and, when pressed, says which of the two is
  missing (the existing inert-button pattern);
- "I'd rather sign on paper" as a quiet link in the footer of this screen and the next.

The server side is unchanged: `POST /signing/viewed` when the last page has been displayed,
`POST /signing/consent` when the button is pressed. The UI simply stops making them separate
screens.

### Screen 2: Sign
One screen holds everything else:
1. **Your signature** panel at the top. If a saved signature exists, it is shown with "Change".
   If not, the draw / type / click-to-sign chooser is inline here (tabs, not a separate screen),
   with the "Save this signature for next time" checkbox (never in kiosk mode).
2. **Fields**, as a list under it, each with its page thumbnail close-up and one button: "Sign
   here" / "Add initials" / the checkbox / the text input. One explicit act per field, as today.
   Tapping a field's button applies the signature shown in the panel. The list shows "2 of 3
   done". For a single-field document the list is one row.
3. **Sign the document**, a single primary button at the bottom, labelled with the signer's name:
   "Sign as Maria Alvarez" (or "… on behalf of …"). Inert until every required field is done; when
   pressed inert it says what is missing. Above it, one sentence: "By pressing this you are signing
   this document. You will get a copy." The button press is the intent confirmation; the separate
   intent checkbox goes. The request still sends `intent_confirmed: true` (that is what the press
   means), and `docs/COMPLIANCE-CHECKLIST.md` records the change for counsel.
4. **Re-authentication** happens on the press, not on a screen of its own. If the role needs it and
   the server does not vouch for a live attestation, the press posts `esign:reauth_required` and
   the button shows "Confirming it's you…" with the host's prompt over the page; on
   `esign:reauth_done` the sign request is sent without another tap. If the attestation is already
   live (span or fresh), nothing is asked. The existing timeout, "not confirmed" and "lapsed"
   states remain, rendered inline on this screen.

The summary/confirm screen is gone. The removed "review your signatures" step is covered by the
fields list itself, which shows every applied mark in place.

### Screen 3: Done
As today, plus queue behaviour (section B). The copy states plainly whether the document is sealed
or sealing.

### Removed or merged
`ConsentStep`, `ConfirmStep` as screens; the intent checkbox; the standalone `AdoptSignature`
screen (its content becomes the panel); the fields summary. `machine.ts` steps become
`read | sign | done`. The server's `signers.status` progression (`pending → viewed → consented →
signed`) is unchanged, so `placeFor` maps `viewed`/`consented` to `read`/`sign` and a reload still
lands in the right place.

## B. Queue: auto-advance and progress

The embedding protocol gains an optional `queue` on `esign:init`:
```json
{"type": "esign:init", "token": "…", "queue": {"index": 3, "total": 8, "next_title": "Order for R. P."}}
```
- The UI shows "3 of 8" in its header and uses `next_title` on the Done screen: "Signed. Next:
  Order for R. P." with a short countdown (4 s, cancellable with "Stay here"), then posts
  `esign:next {envelope_id}` to the host. The host opens the next document (new session, new
  `esign:init` into the same iframe). The UI never fetches the next one itself: the host owns the
  queue and the tokens.
- Without `queue`, nothing changes.
- The demo host's queue page implements it: one re-authentication, then documents open in turn
  with no return to the list, and a final "All 8 signed" page. Long documents (host-supplied
  reports) are excluded from the queue by the demo host, as before.

## C. Consent once per run

Consent to sign electronically is consent to doing business electronically; it does not have to
be re-collected for every document in the same sitting. New setting `CONSENT_SPAN_SECONDS`
(default `0` = per envelope, as today; capped at `3600`). When above zero:
- An acceptance recorded by the same `(host_id, host_user_id)` for the same consent version and
  locale within the span is **standing**. `GET /signing/session` reports it:
  `"consent": {"version", "locale", "body", "standing": {"accepted_at", "envelope_id"} | null}`.
- The UI shows the standing line instead of the checkbox (screen 1). Pressing Continue posts
  `POST /signing/consent {consent_version, relies_on_envelope_id}`. The server re-checks that the
  earlier acceptance exists, is the signer's own, matches version and locale, and is inside the
  span; it then records `consent.accepted` on this envelope with `data.relied_on_envelope_id` and
  `data.relied_on_accepted_at`, and sets `signers.consent_text_id` and `consented_at` as today.
  Anything not matching is `409 consent_not_standing`, and the UI falls back to the checkbox.
- Kiosk sessions never have standing consent (a shared tablet, a different person).
- The certificate prints "Consented 09:12 (given for an earlier document in the same sitting)".
- Verification checks a relied-on acceptance against the earlier envelope's trail.
- Like the re-authentication span, this is a compliance decision: off by default, and the
  checklist gains an item for counsel.

## D. Tests
- Flow: single-field document with a saved signature and standing consent is three taps (Continue,
  Sign here, Sign as …); first-time signer path; multi-field; re-auth on press with the hand-off
  and each failure state; decline reachable from both screens; reload lands on the right screen
  from each server status; kiosk shows no save box and no standing consent; queue header, done
  countdown, `esign:next`, "Stay here".
- Backend: consent span on/off, wrong version, other user, other host, outside span, kiosk; the
  event data and certificate line; verification catches a `relied_on_envelope_id` whose trail has
  no matching acceptance.
- Playwright through the demo host: the clinician queue of five orders with one re-authentication
  and standing consent, asserting per-document `document.viewed`, `consent.accepted` (with
  `relied_on`) and `signer.signed` events exist in each envelope's trail.

## E. Contract and schema
- `config.py`: `CONSENT_SPAN_SECONDS`.
- `audit/events.py`: `ConsentAcceptedData` gains optional `relied_on_envelope_id`,
  `relied_on_accepted_at`.
- `contracts.py`: `EnvelopeService.accept_consent(db, session, consent_version, ctx,
  relies_on_envelope_id: UUID | None = None)`; `SigningView.consent.standing`;
  `CertificateSigner.consent_relied_on: bool`.
- No schema change: standing consent is found from `signers` + `signing_sessions` rows of the
  earlier envelope (same host, same host_user_id, `consent_text_id`, `consented_at`), which are
  already there.
