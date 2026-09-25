/**
 * In-memory stand-in for the esign backend's signer-facing state. One record per mock token;
 * the token names the scenario (`est_mock_<scenario>`), so a test or the dev harness picks a
 * story by choosing a token. It enforces the same ordering rules as the real service (viewed
 * before consent before sign, fresh re-auth, idempotent sign) so the UI is exercised honestly.
 */

import {
  hipaaFields,
  hipaaPdf,
  type MockField,
  orderFields,
  orderPdf,
  procedureFields,
  procedurePdf,
  REPORT_PAGES,
  reportFields,
  reportPdf,
} from "@/mocks/documents";
import { SAVED_SIGNATURE_PNG_BASE64 } from "@/mocks/signature";

export const SCENARIOS = {
  single: "One patient, two pages. Sealing takes a couple of polls, then the copy is ready.",
  multi: "Patient signs first of three. Done screen explains the copy comes later.",
  clinician: "Last signer, needs re-authentication before signing. Then seals.",
  kiosk:
    "Clinic tablet. Ends on the hand-back screen and clears everything. The patient has a saved signature on file; a kiosk is never offered it.",
  "saved-signature":
    "A patient who saved their signature last time. It is offered first, and can be used, replaced or removed.",
  "initials-only":
    "A signer the document asks only to initial. There is no signature to keep, so nothing offers to keep one.",
  "span-valid":
    "Clinician in a signing queue: re-authenticated for an earlier document a moment ago, and the host's span still covers this one.",
  "span-expired":
    "Clinician in a signing queue whose earlier re-authentication has run out: the hand-off is needed again.",
  "span-saved":
    "Clinician in a signing queue signing with their saved signature. The host can revoke it mid-flow (__esignMock.hostRevokedSignature) to see the signature go out from under them.",
  report:
    "A clinician signing a long generated report in a full-screen host: twenty-two pages, the signature on the last one, a saved signature on file, consent and identity already confirmed for an earlier document. What a queue of packets looks like from the frame.",
  queue:
    "A clinician's signing queue (addendum 3 B): three one-page orders, one confirmation of identity covering all of them, consent already given for the first. Three taps a document.",
  "standing-consent":
    "A patient who agreed to sign electronically a few minutes ago, for an earlier document in the same sitting. The Read screen states that instead of asking again.",
  guardian:
    "A parent signing for her child. The one act that signs the document names the child, in the words the host sent for him and not the chart reference the record keeps.",
  "guardian-ref":
    "The same parent, on a host that sent no name for the child: all the session has is the opaque reference, so the sentence she confirms points at the document instead of reciting it.",
  "first-time":
    "A signer with nothing on file: no saved signature and no standing consent. The signature panel opens on the chooser and the box is unticked.",
  "reauth-press":
    "A clinician with no live confirmation. Pressing Sign is what asks for one, and the signature goes by itself when the host answers.",
  "reauth-timeout":
    "The same, but the host never answers (press 'Do nothing'). The press times out and says nothing has been signed.",
  "reauth-lapsed":
    "The confirmation is live when the screen opens and has run out by the time the signature lands: 403 reauth_required on the sign request.",
  "consent-lapsed":
    "The session reports a standing agreement, but the span has run out by the time Continue is pressed: 409 consent_not_standing, and the checkbox comes back.",
  "flaky-sign":
    "The first sign request is processed but the reply is lost. Retry must reuse the key.",
  "sealing-stuck": "Sealing never finishes. The UI must stay honest.",
  "ending-soon": "The session has under two minutes left.",
  expired: "The token is already expired: 401 on first call.",
  voided: "The clinic withdrew the document.",
  error: "The session endpoint returns 500.",
  "document-error": "The PDF endpoint returns 500.",
  "no-token": "The host never sends a token (handled by the harness, not the API).",
} as const;

export type Scenario = keyof typeof SCENARIOS;

/** How many documents the `queue` scenario's host has waiting. */
export const QUEUE_TOTAL = 3;
/** What the host calls each of them; the host owns the queue, so these live on its side. */
export const QUEUE_TITLES = ["Order for R. P.", "Order for T. N.", "Order for K. A."];

/**
 * The token names the scenario. `queue` takes a position as well (`est_mock_queue-2`), because
 * each document in a run is its own envelope, its own session and its own token: the host opens
 * the next one into the same iframe, and nothing about the previous one comes with it.
 */
export const tokenFor = (scenario: Scenario, position?: number) =>
  scenario === "queue" && position !== undefined
    ? `est_mock_queue-${position}`
    : `est_mock_${scenario}`;

/**
 * The disclosure the real service ships (`backend/src/esign/identity/consent/en-US.2026-09.txt`),
 * headings, bullets, line wrapping and all. A mock with four tidy paragraphs was hiding the fact
 * that the stored text is structured and had to be laid out rather than printed.
 */
export const CONSENT = {
  version: "2026-09",
  locale: "en-US",
  body: `# Agreement to sign electronically

Before you sign, please read this. It explains what you are agreeing to, and how to sign on paper
instead if you would rather.

## What you are agreeing to

You are agreeing to receive this document electronically and to sign it with an electronic
signature. Your electronic signature has the same legal effect as a signature in ink.

This agreement covers only the document in front of you now. If you are asked to sign something
else later, you will be asked again.

## You can sign on paper instead

You do not have to sign electronically. At any point before you sign, you can choose to sign on
paper instead. Select "I would rather sign on paper", or tell a member of staff, and this signing
session will end. No one will treat you differently for asking, and your care is not affected.

## Withdrawing your agreement

You can withdraw this agreement at any time before you sign, by choosing to sign on paper or by
closing this window without signing. Withdrawing costs nothing.

Once you have signed, the signed document is part of your record and cannot be withdrawn. If you
believe you signed something in error, tell your care team: they can correct the record by issuing
a replacement document.

## Getting a copy

When everyone has signed, you can download a copy of the signed document from this screen. The
copy includes a certificate showing who signed, when, and how their identity was established.

You can also ask for a paper copy at any time, at no charge, by contacting the clinic or health
system that asked you to sign. Your copy stays available through your patient record.

## What you need to sign electronically

To read and sign this document, you need:

- a device with an up-to-date web browser and internet access,
- the ability to display and read a PDF document,
- a screen and either a touchscreen, a mouse or a keyboard, so you can draw or type your
  signature, and
- somewhere to save or print a copy, if you would like to keep one yourself.

If your device cannot do one of these things, ask staff for a paper copy instead.

## Keeping your details current

If your contact details change, update them with the clinic or health system in the usual way.
This service does not hold your contact details separately, and does not send you email.

## Questions

If anything here is unclear, ask a member of staff before you sign. You can stop at any point.
`,
};

/**
 * Exactly the list the service sends (`contracts.DECLINE_REASON_CODES` with the labels from
 * `api/schemas.py`). The mock used to invent codes of its own, which meant the UI was never tried
 * against the real ones.
 */
export const DECLINE_REASONS = [
  { code: "prefers_paper", label: "I would rather sign on paper" },
  { code: "needs_more_time", label: "I need more time to read this" },
  { code: "disagrees_with_terms", label: "I do not agree with what it says" },
  { code: "needs_interpreter", label: "I need an interpreter" },
  { code: "incorrect_information", label: "Some of the information is wrong" },
  { code: "not_the_right_signer", label: "I am not the right person to sign this" },
  { code: "wants_to_ask_a_question", label: "I want to ask a question first" },
  { code: "other", label: "Another reason" },
];

const REAUTH_MAX_AGE_MS = 120_000;
const POLLS_UNTIL_SEALED = 2;
/** How long ago the earlier document's re-authentication happened in each queue scenario. */
const SPAN_AUTH_AGE_MS = {
  "span-valid": 20_000,
  "span-saved": 20_000,
  "span-expired": 10 * 60_000,
} as const;

type SignerStatus = "pending" | "viewed" | "consented" | "signed" | "declined";
type EnvelopeStatus =
  | "created"
  | "in_progress"
  | "completed_pending_seal"
  | "sealed"
  | "declined"
  | "voided"
  | "expired";
type ReauthScope = "session" | "span";

/**
 * A row of `adopted_signatures`: never deleted, revoked with a reason instead. The live one is
 * the row with no `revokedAt`, and there is at most one.
 */
export interface MockSavedSignature {
  id: string;
  kind: "drawn" | "typed";
  imagePngBase64: string | null;
  typedText: string | null;
  createdAt: number;
  revokedAt: number | null;
  revokeReason: "replaced" | "user" | "host" | null;
}

/**
 * An acceptance of the disclosure given for an *earlier* envelope by this person on this host,
 * still inside `CONSENT_SPAN_SECONDS` (addendum 3 C). The mock keeps it on the record because
 * that is all the UI can see of it: `GET /signing/session` reports it, and `POST /signing/consent`
 * re-checks it.
 */
export interface MockStandingConsent {
  acceptedAt: number;
  envelopeId: string;
}

export interface MockRecord {
  scenario: Scenario;
  /** The envelope this session is for. One per document, so a queue has one per position. */
  envelopeId: string;
  signerStatus: SignerStatus;
  envelopeStatus: EnvelopeStatus;
  reauthValidUntil: number | null;
  /** Which attestation `reauthValidUntil` rests on: this session's, or a borrowed span one. */
  reauthScope: ReauthScope | null;
  /** When that attestation was made (`auth_time`): what the UI says the signer confirmed at. */
  reauthAt: number | null;
  /** This person's saved signatures on this host, oldest first. */
  savedSignatures: MockSavedSignature[];
  copyPolls: number;
  signRequests: { key: string | null; body: string }[];
  revisions: number;
  presented: number;
  /**
   * The revision this session was last served (`document.presented`), and the revision the signer
   * said they had read (`signers.viewed_sha256`). Signing needs them to be the same one *and* to
   * still be the current revision (`revisions`): a signer whose co-signer signed while they were
   * reading either holds bytes they never confirmed, or bytes that are no longer the ones the
   * marks would land on. Both are refused with `not_viewed` until they read the document again.
   */
  presentedRevision: number | null;
  viewedRevision: number | null;
  downloads: number;
  declineReason: string | null;
  /** The last `?locale=` the UI asked the session for; null when it asked for none. */
  requestedLocale: string | null;
  /** The locale the UI said the signer read the disclosure in, as posted with consent. */
  consentLocale: string | null;
  /** The standing acceptance this session reports, or null for the per-envelope default. */
  standingConsent: MockStandingConsent | null;
  /**
   * Whether the server would still honour it *now*. The session payload and the POST are answered
   * at different moments, and the span can run out in between: that is the case the UI has to
   * fall back from, so the mock can be told to stop honouring it without un-reporting it.
   */
  standingHonoured: boolean;
  /** What the accepted consent leaned on, as the audit event's `relied_on_envelope_id` would. */
  reliedOnEnvelopeId: string | null;
  /** Let the session read as covered, then refuse the signature once, as a lapse does. */
  lapseOnSign: boolean;
  sessionExpiresAt: number;
  createdAt: number;
}

export class MockHttpError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

const records = new Map<string, MockRecord>();

/**
 * How far ahead of this fake server the browser's clock runs. Real deadlines (`expires_at`,
 * `reauth_valid_until`) are server time, and a clinic tablet's clock is its own business, so the
 * mock keeps a clock of its own: nothing in the UI may depend on the two agreeing.
 */
let deviceClockSkewMs = 0;

const serverNow = () => Date.now() - deviceClockSkewMs;

function scenarioOf(token: string): Scenario | null {
  if (!token.startsWith("est_mock_")) {
    return null;
  }
  const name = token.slice("est_mock_".length);
  if (/^queue-[1-9]$/.test(name)) {
    return "queue";
  }
  return name in SCENARIOS ? (name as Scenario) : null;
}

export const mockDb = {
  reset(): void {
    records.clear();
    deviceClockSkewMs = 0;
  },

  /** Run the fake server `ms` behind the browser: the device's clock is fast by that much. */
  setDeviceClockSkew(ms: number): void {
    deviceClockSkewMs = ms;
  },

  /** Unknown, expired and revoked tokens are indistinguishable, as in the real service. */
  authenticate(authorization: string | null): MockRecord {
    const token = authorization?.startsWith("Bearer ") ? authorization.slice(7) : "";
    const scenario = scenarioOf(token);
    if (scenario === null || scenario === "expired") {
      throw new MockHttpError(401, "unauthorized", "The session is not valid.");
    }
    let record = records.get(token);
    if (record === undefined) {
      const now = serverNow();
      const spanAge = spanAuthAge(scenario);
      record = {
        scenario,
        envelopeId: envelopeIdFor(token),
        signerStatus: "pending",
        envelopeStatus: scenario === "voided" ? "voided" : "in_progress",
        // A queue scenario starts with an attestation made for an *earlier* document of this
        // clinician's. Whether it still covers this one is decided when the session is read.
        reauthValidUntil: spanAge === null ? null : now - spanAge + REAUTH_MAX_AGE_MS,
        reauthScope: spanAge === null ? null : "span",
        reauthAt: spanAge === null ? null : now - spanAge,
        savedSignatures: hasSavedSignature(scenario)
          ? [
              {
                id: SAVED_SIGNATURE_ID,
                kind: "drawn",
                imagePngBase64: SAVED_SIGNATURE_PNG_BASE64,
                typedText: null,
                createdAt: now - 6 * 86_400_000,
                revokedAt: null,
                revokeReason: null,
              },
            ]
          : [],
        copyPolls: 0,
        signRequests: [],
        revisions: 1,
        presented: 0,
        presentedRevision: null,
        viewedRevision: null,
        downloads: 0,
        declineReason: null,
        requestedLocale: null,
        consentLocale: null,
        // A kiosk is never among these: a shared tablet is a different person until proved
        // otherwise, so `hasStandingConsent` never names one and `sessionBody` nulls it as well.
        standingConsent: hasStandingConsent(scenario)
          ? { acceptedAt: now - 8 * 60_000, envelopeId: EARLIER_ENVELOPE_ID }
          : null,
        standingHonoured: scenario !== "consent-lapsed",
        reliedOnEnvelopeId: null,
        lapseOnSign: scenario === "reauth-lapsed",
        sessionExpiresAt: now + (scenario === "ending-soon" ? 100_000 : 1_800_000),
        createdAt: now,
      };
      records.set(token, record);
    }
    if (serverNow() >= record.sessionExpiresAt) {
      throw new MockHttpError(401, "unauthorized", "The session is not valid.");
    }
    return record;
  },

  /**
   * The span ran out between the session being read and Continue being pressed (addendum 3 C).
   * The session payload still reports the standing acceptance -- it did when it was answered --
   * and the POST refuses it, which is the fallback the Read screen has to make good.
   */
  consentNoLongerStanding(scenario: Scenario, position?: number): void {
    const record = records.get(tokenFor(scenario, position));
    if (record !== undefined) {
      record.standingHonoured = false;
    }
  },

  /** What the host backend does after re-authenticating the user: POST /v1/sessions/{id}/reauth. */
  attestReauth(scenario: Scenario = "clinician", position?: number): void {
    const record = records.get(tokenFor(scenario, position));
    if (record !== undefined) {
      record.reauthAt = serverNow();
      record.reauthValidUntil = record.reauthAt + REAUTH_MAX_AGE_MS;
      record.reauthScope = "session";
    }
  },

  /**
   * The attestation runs out where the real one does: on the server, between a session being read
   * and a signature being sent. The UI's cached session still says the signer is covered.
   */
  lapseReauth(scenario: Scenario, position?: number): void {
    const record = records.get(tokenFor(scenario, position));
    if (record !== undefined) {
      record.reauthValidUntil = serverNow() - 1;
    }
  },

  /** What the host does with `POST /v1/users/{id}/adopted-signature/revoke`. */
  hostRevokedSignature(scenario: Scenario, position?: number): void {
    const record = records.get(tokenFor(scenario, position));
    if (record !== undefined) {
      revokeSavedSignature(record, "host");
    }
  },

  /**
   * Another signer on the same envelope signs, so the current revision moves on. Nothing about
   * this signer changes -- which is the point: what they read is no longer what they would sign.
   */
  otherSignerSigned(scenario: Scenario, position?: number): void {
    const record = records.get(tokenFor(scenario, position));
    if (record !== undefined) {
      record.revisions += 1;
    }
  },

  expireSession(scenario: Scenario, position?: number): void {
    const record = records.get(tokenFor(scenario, position));
    if (record !== undefined) {
      record.sessionExpiresAt = 0;
    }
  },

  peek(scenario: Scenario, position?: number): MockRecord | undefined {
    return records.get(tokenFor(scenario, position));
  },
};

// --------------------------------------------------------------------------- shape of each story

/** The one-page orders a signing queue is made of, and the screens that stand in for one. */
const isOrder = (scenario: Scenario) =>
  scenario === "queue" ||
  scenario === "reauth-press" ||
  scenario === "reauth-timeout" ||
  scenario === "reauth-lapsed";
/** The long generated report a full-screen host asks a clinician to sign at the end. */
const isReport = (scenario: Scenario) => scenario === "report";
const isClinician = (scenario: Scenario) =>
  scenario === "clinician" ||
  isReport(scenario) ||
  scenario === "span-valid" ||
  scenario === "span-saved" ||
  scenario === "span-expired" ||
  isOrder(scenario);
const isProcedure = (scenario: Scenario) =>
  scenario === "multi" ||
  scenario === "initials-only" ||
  (isClinician(scenario) && !isOrder(scenario) && !isReport(scenario));
const roleOf = (scenario: Scenario) => (isClinician(scenario) ? "clinician" : "patient");
/** Who has a signature on file from an earlier session. The kiosk patient does too: a shared
 * tablet must never be offered it, and the only way to prove that is for one to exist. */
const hasSavedSignature = (scenario: Scenario) =>
  scenario === "saved-signature" ||
  isReport(scenario) ||
  scenario === "kiosk" ||
  scenario === "span-saved" ||
  scenario === "standing-consent" ||
  scenario === "consent-lapsed" ||
  isOrder(scenario);
/** Who already agreed to sign electronically, for an earlier document in the same sitting. */
const hasStandingConsent = (scenario: Scenario) =>
  scenario === "standing-consent" ||
  isReport(scenario) ||
  scenario === "consent-lapsed" ||
  scenario === "queue" ||
  scenario === "reauth-press" ||
  scenario === "reauth-timeout" ||
  scenario === "reauth-lapsed";

/**
 * How long ago the earlier document's confirmation of identity happened. The three queue-shaped
 * order scenarios arrive covered (or not) exactly as a real span would leave them.
 */
function spanAuthAge(scenario: Scenario): number | null {
  if (scenario === "span-valid" || scenario === "span-saved" || scenario === "span-expired") {
    return SPAN_AUTH_AGE_MS[scenario];
  }
  if (scenario === "queue" || scenario === "reauth-lapsed" || isReport(scenario)) {
    return 20_000;
  }
  // `reauth-press` and `reauth-timeout` have nothing to lean on: the press has to ask for it.
  return null;
}

export const SAVED_SIGNATURE_ID = "9a1e5d2c-7b3f-4e8a-9c0d-1f2e3a4b5c6d";

export const liveSavedSignature = (record: MockRecord): MockSavedSignature | null =>
  record.savedSignatures.find((row) => row.revokedAt === null) ?? null;

function revokeSavedSignature(
  record: MockRecord,
  reason: NonNullable<MockSavedSignature["revokeReason"]>,
): MockSavedSignature | null {
  const live = liveSavedSignature(record);
  if (live !== null) {
    live.revokedAt = serverNow();
    live.revokeReason = reason;
  }
  return live;
}

/** `reauth_valid_until` is only ever a usable attestation: a lapsed one is `null`, not a past time. */
const usableReauthUntil = (record: MockRecord): number | null =>
  record.reauthValidUntil !== null && record.reauthValidUntil > serverNow()
    ? record.reauthValidUntil
    : null;

export function fieldsFor(record: MockRecord): MockField[] {
  const all = isOrder(record.scenario)
    ? orderFields
    : isReport(record.scenario)
      ? reportFields
      : isProcedure(record.scenario)
        ? procedureFields
        : hipaaFields;
  const mine = all.filter((field) => field.role === roleOf(record.scenario));
  // A template can ask a signer for initials and nothing else. The signature they adopt would
  // land nowhere -- initials go over as their own typed text -- so there is nothing to save, and
  // the service refuses `save_adopted_signature` from such a request (`no_signature_to_save`).
  return record.scenario === "initials-only"
    ? mine.filter((field) => field.type !== "signature")
    : mine;
}

export function pageCountFor(record: MockRecord): number {
  if (isOrder(record.scenario)) {
    return 1;
  }
  if (isReport(record.scenario)) {
    return REPORT_PAGES;
  }
  return isProcedure(record.scenario) ? 3 : 2;
}

export function documentFor(record: MockRecord, sealed = false): Uint8Array {
  if (isOrder(record.scenario)) {
    return orderPdf(sealed);
  }
  if (isReport(record.scenario)) {
    return reportPdf(sealed);
  }
  if (isProcedure(record.scenario)) {
    return procedurePdf({ earlierSigned: record.scenario === "clinician", sealed });
  }
  return hipaaPdf(sealed);
}

const iso = (ms: number) => new Date(ms).toISOString();

/**
 * The child a guardian scenario's signer acts for, in the host's own words
 * (`NewSigner.on_behalf_of_display`, SPEC section 16 A). The record's own attribution is the
 * opaque `on_behalf_of` and never this, which is exactly why the UI has to be handed it: the
 * reference is unreadable, and the press of "Sign as ..." is the whole intent confirmation.
 */
export const GUARDIAN_CHILD_NAME = "Sam Okafor";
/** The same child as the record has him: the envelope's `patient_ref`, held to `is_opaque_id`. */
export const GUARDIAN_CHILD_REF = "mrn-100907";

/**
 * Who this signer acts for, as the host left it: its own words when it sent them, and otherwise
 * the opaque reference, which is all `GET /signing/session` can report (SPEC section 9).
 */
const onBehalfOfLabelFor = (scenario: Scenario): string | null =>
  scenario === "guardian"
    ? GUARDIAN_CHILD_NAME
    : scenario === "guardian-ref"
      ? GUARDIAN_CHILD_REF
      : null;

export const ENVELOPE_ID = "6f1c1a52-4a0e-4c59-9d7e-0a4d5f6b7c81";
export const SIGNER_ID = "0b9d7f3e-2c41-4f7a-8a55-3e1f2d4c5b6a";
/** The envelope a standing acceptance was given for: an earlier document, already signed. */
export const EARLIER_ENVELOPE_ID = "1d2c3b4a-5e6f-4a7b-8c9d-0e1f2a3b4c5d";

/**
 * Each queue position is its own envelope. Every other scenario is a single document and keeps
 * the id the tests have always named.
 */
function envelopeIdFor(token: string): string {
  const position = /^est_mock_queue-([1-9])$/.exec(token)?.[1];
  return position === undefined ? ENVELOPE_ID : `6f1c1a52-4a0e-4c59-9d7e-0a4d5f6b7c8${position}`;
}

/** Which of the host's orders this token is, 1-based, or null outside a queue. */
export function queuePositionOf(record: MockRecord): number | null {
  if (record.scenario !== "queue") {
    return null;
  }
  const last = record.envelopeId.slice(-1);
  return /[1-9]/.test(last) ? Number(last) : 1;
}

export function sessionBody(record: MockRecord) {
  const clinician = isClinician(record.scenario);
  const actingFor = onBehalfOfLabelFor(record.scenario);
  const guardian = actingFor !== null;
  const kiosk = record.scenario === "kiosk";
  const others =
    record.scenario === "multi"
      ? [
          { role_label: "Witness", status: "pending" },
          { role_label: "Clinician", status: "pending" },
        ]
      : clinician
        ? [
            { role_label: "Patient", status: "signed" },
            { role_label: "Witness", status: "signed" },
          ]
        : [];
  const reauthUntil = usableReauthUntil(record);
  const saved = kiosk ? null : liveSavedSignature(record);
  const position = queuePositionOf(record);
  return {
    envelope: {
      id: record.envelopeId,
      status: record.envelopeStatus,
      document_type: isOrder(record.scenario)
        ? "imaging_order"
        : isReport(record.scenario)
          ? "clinical_report"
          : isProcedure(record.scenario)
            ? "procedure_consent"
            : "hipaa_acknowledgement",
      title: isOrder(record.scenario)
        ? (QUEUE_TITLES[(position ?? 1) - 1] ?? "Order for imaging")
        : isReport(record.scenario)
          ? "Discharge summary for R. P."
          : isProcedure(record.scenario)
            ? "Consent to procedure"
            : "Privacy notice acknowledgement",
      page_count: pageCountFor(record),
      expires_at: iso(record.createdAt + 7 * 86_400_000),
    },
    signer: {
      id: SIGNER_ID,
      display_name: clinician ? "Dr. Priya Raman" : guardian ? "Grace Okafor" : "Maria Alvarez",
      role_label: clinician ? "Clinician" : guardian ? "Patient or guardian" : "Patient",
      capacity: clinician ? "clinician" : guardian ? "guardian" : "self",
      on_behalf_of_label: actingFor,
      status: record.signerStatus,
      requires_reauth: clinician,
      reauth_valid_until: reauthUntil === null ? null : iso(reauthUntil),
      reauth_scope: reauthUntil === null ? null : record.reauthScope,
      reauth_at: reauthUntil === null || record.reauthAt === null ? null : iso(record.reauthAt),
    },
    other_signers: others,
    fields: fieldsFor(record).map(({ role: _role, ...field }) => ({
      ...field,
      rect: { ...field.rect },
    })),
    // Copies: a caller that pokes at the body it was handed (a schema test corrupting a field to
    // prove it is rejected) must not leave the mock's own disclosure broken for everyone after it.
    //
    // `standing` is addendum 3 C. It is reported whether or not the span is still good at this
    // instant: that is the whole point of the 409 the UI has to fall back from.
    consent: {
      ...CONSENT,
      standing:
        record.standingConsent === null || kiosk
          ? null
          : {
              accepted_at: iso(record.standingConsent.acceptedAt),
              envelope_id: record.standingConsent.envelopeId,
            },
    },
    session: {
      id: "5c4b3a29-1d8e-4f70-9b61-2a3c4d5e6f70",
      expires_at: iso(record.sessionExpiresAt),
      kiosk,
    },
    // SPEC section 14 B: the signer's own live saved signature, and always null on a kiosk. As
    // the service serialises it (`api/schemas.py::adopted_signature_json`): both payload keys are
    // always present, and the one that does not apply to the kind is null.
    adopted_signature:
      saved === null
        ? null
        : {
            id: saved.id,
            kind: saved.kind,
            image_png_base64: saved.kind === "drawn" ? (saved.imagePngBase64 ?? "") : null,
            typed_text: saved.kind === "typed" ? (saved.typedText ?? "") : null,
            created_at: iso(saved.createdAt),
          },
    decline_reasons: DECLINE_REASONS.map((reason) => ({ ...reason })),
  };
}

// --------------------------------------------------------------------------- transitions

/** What `GET /v1/signing/session?locale=` and `ConsentBody.locale` accept on the real service. */
export const LOCALE_PATTERN = /^[A-Za-z0-9-]{1,35}$/;

const conflict = (message: string) => new MockHttpError(409, "conflict", message);
const invalid = (message: string) => new MockHttpError(422, "validation_failed", message);

function assertLive(record: MockRecord): void {
  if (record.envelopeStatus !== "in_progress" && record.envelopeStatus !== "created") {
    throw conflict("The envelope is not open for signing.");
  }
}

/** `GET /v1/signing/document`: the current revision, recorded against this session. */
export function recordPresented(record: MockRecord): void {
  record.presented += 1;
  record.presentedRevision = record.revisions;
}

export function recordViewed(record: MockRecord, pagesViewed: unknown): void {
  assertLive(record);
  if (record.presentedRevision === null) {
    throw new MockHttpError(409, "not_presented", "The document has not been opened.");
  }
  if (pagesViewed !== pageCountFor(record)) {
    throw invalid("Every page must be viewed.");
  }
  // The bytes this session was served are the ones now confirmed as read. A repeat view moves it
  // on, which is how a signer recovers from `not_viewed`.
  record.viewedRevision = record.presentedRevision;
  if (record.signerStatus === "pending") {
    record.signerStatus = "viewed";
  }
}

export function recordConsent(
  record: MockRecord,
  version: unknown,
  accepted: unknown,
  locale: unknown,
  reliesOn?: unknown,
): void {
  assertLive(record);
  if (record.signerStatus === "pending") {
    throw conflict("The document has not been viewed.");
  }
  if (version !== CONSENT.version || accepted !== true) {
    throw invalid("The consent version is not current.");
  }
  /**
   * Addendum 3 C. Leaning on an earlier acceptance is re-checked here and not taken on trust:
   * the client names the envelope, the server decides whether that acceptance is the signer's
   * own, matches this version and locale, and is still inside the span. Anything else is 409
   * `consent_not_standing`, and the UI asks for the tick instead.
   */
  if (reliesOn !== undefined && reliesOn !== null) {
    const standing = record.standingConsent;
    const usable =
      record.scenario !== "kiosk" &&
      record.standingHonoured &&
      standing !== null &&
      reliesOn === standing.envelopeId;
    if (!usable) {
      throw new MockHttpError(
        409,
        "consent_not_standing",
        "That agreement does not cover this document.",
      );
    }
    record.reliedOnEnvelopeId = standing.envelopeId;
  } else {
    record.reliedOnEnvelopeId = null;
  }
  // SPEC 9: `locale` is optional, and is the locale as shown in the session payload -- what the
  // server served. A client that echoes back a language it was never given is refused.
  if (locale !== undefined && locale !== null) {
    if (typeof locale !== "string" || !LOCALE_PATTERN.test(locale)) {
      throw invalid("The locale is not a language tag.");
    }
    if (locale !== CONSENT.locale) {
      throw invalid("That is not the locale this disclosure was served in.");
    }
  }
  record.consentLocale = typeof locale === "string" ? locale : null;
  if (record.signerStatus === "viewed") {
    record.signerStatus = "consented";
  }
}

export function recordDecline(record: MockRecord, reason: unknown): void {
  assertLive(record);
  if (!DECLINE_REASONS.some((option) => option.code === reason)) {
    throw invalid("Unknown reason.");
  }
  record.signerStatus = "declined";
  record.envelopeStatus = "declined";
  record.declineReason = String(reason);
}

const PNG_MAGIC = "iVBORw0KGgo";

/** The drawn or typed signature-field capture that `save_adopted_signature` would keep. */
type Saveable = { kind: "drawn"; png: string } | { kind: "typed"; text: string };

function validateCaptures(record: MockRecord, captures: unknown): Saveable | null {
  if (!Array.isArray(captures)) {
    throw invalid("Captures are required.");
  }
  const fields = fieldsFor(record);
  const seen = new Set<string>();
  let saveable: Saveable | null = null;
  for (const capture of captures as Record<string, unknown>[]) {
    const field = fields.find((candidate) => candidate.id === capture.field_id);
    if (field === undefined || field.type === "date_signed") {
      throw invalid("A capture targets a field that is not this signer's.");
    }
    seen.add(field.id);
    if (field.type === "checkbox" && typeof capture.checked !== "boolean") {
      throw invalid("A checkbox needs a checked value.");
    }
    if (field.type === "text" && typeof capture.text_value !== "string") {
      throw invalid("A text field needs a text value.");
    }
    if (field.type === "signature" || field.type === "initials") {
      if (capture.kind === "drawn") {
        const png = capture.image_png_base64;
        if (typeof png !== "string" || !png.startsWith(PNG_MAGIC) || png.length < 200) {
          throw invalid("The signature image is not usable.");
        }
        if (field.type === "signature") {
          saveable = { kind: "drawn", png };
        }
      } else if (capture.kind === "typed") {
        if (typeof capture.typed_text !== "string" || capture.typed_text.trim() === "") {
          throw invalid("Typed text is required.");
        }
        if (field.type === "signature") {
          saveable = { kind: "typed", text: capture.typed_text };
        }
      } else if (capture.kind === "adopted") {
        // SPEC section 14 B: the id and nothing else, and it must be this signer's own live saved
        // signature, never from a kiosk. Anything else is `forbidden`, not a validation error.
        if ("image_png_base64" in capture || "typed_text" in capture) {
          throw invalid("An adopted capture carries the saved signature's id and nothing else.");
        }
        const live = record.scenario === "kiosk" ? null : liveSavedSignature(record);
        if (live === null || capture.adopted_signature_id !== live.id) {
          throw new MockHttpError(
            403,
            "adopted_signature_unavailable",
            "That saved signature is not available to this session.",
          );
        }
      } else if (capture.kind !== "click") {
        throw invalid("Unknown capture kind.");
      }
    }
    if (field.type === "checkbox" && field.required && capture.checked !== true) {
      throw invalid("A required box is not ticked.");
    }
  }
  for (const field of fields) {
    if (field.required && field.type !== "date_signed" && !seen.has(field.id)) {
      throw invalid("A required field has no capture.");
    }
  }
  return saveable;
}

/**
 * `POST /v1/signing/adopted-signature/revoke`: the signer removes their own saved signature.
 * Answers whether there was one to revoke, as the service does (`{"revoked": bool}`).
 *
 * Never from a kiosk, exactly as saving is never from a kiosk (`api/signer_routes.py`): a shared
 * tablet is shown no saved signature and may not destroy one either. The UI never offers it there,
 * so this refusal should be unreachable -- which is the reason to mock it, rather than let the
 * mocked API be more permissive than the real one and hide a regression that reaches it.
 */
export function recordRevokeSaved(record: MockRecord): boolean {
  if (record.scenario === "kiosk") {
    throw new MockHttpError(
      403,
      "adoption_not_allowed",
      "A saved signature cannot be removed from a shared tablet.",
    );
  }
  return revokeSavedSignature(record, "user") !== null;
}

/** Returns "replayed" when the key was seen before with the same body: the first answer stands. */
export function recordSign(
  record: MockRecord,
  key: string | null,
  body: { intent_confirmed?: unknown; captures?: unknown; save_adopted_signature?: unknown },
): "signed" | "replayed" {
  const serialised = JSON.stringify(body);
  record.signRequests.push({ key, body: serialised });
  if (key === null || key === "") {
    throw invalid("An Idempotency-Key is required.");
  }
  const earlier = record.signRequests.slice(0, -1).find((request) => request.key === key);
  if (earlier !== undefined && record.signerStatus === "signed") {
    if (earlier.body !== serialised) {
      throw conflict("The key was used with a different request.");
    }
    return "replayed";
  }
  assertLive(record);
  if (record.signerStatus !== "consented") {
    throw conflict("Consent has not been given.");
  }
  if (record.presentedRevision === null) {
    throw new MockHttpError(409, "not_presented", "The document has not been opened.");
  }
  if (record.viewedRevision !== record.presentedRevision) {
    throw new MockHttpError(
      409,
      "not_viewed",
      "The document has changed. Please look through every page again before you sign.",
    );
  }
  // ...and what they read must still be the current revision. A co-signer who commits while this
  // signer sits on the confirm screen leaves both hashes naming the old bytes, so the check above
  // is happy and the marks would land on a revision nobody showed them, co-signer's field values
  // included. The real service refuses this under the envelope row lock (SPEC section 13, fourth
  // round); the mocked flow has to refuse it too, or the specs never see the case that happens.
  if (record.presentedRevision !== record.revisions) {
    throw new MockHttpError(
      409,
      "not_viewed",
      "The document has changed. Please look through every page again before you sign.",
    );
  }
  if (body.intent_confirmed !== true) {
    throw invalid("Intent must be confirmed.");
  }
  // The attestation that was live when the screen was read and is not live any more. The real
  // service finds this under the envelope row lock, between the two requests.
  if (record.lapseOnSign) {
    record.lapseOnSign = false;
    record.reauthValidUntil = serverNow() - 1;
  }
  if (isClinician(record.scenario) && usableReauthUntil(record) === null) {
    // The service's own code for it (`api/errors.py`): the UI tells a lapsed re-authentication
    // apart from the other 403s on this route by the code, never by the status alone.
    throw new MockHttpError(403, "reauth_required", "Please confirm it is you before signing.");
  }
  const saveable = validateCaptures(record, body.captures);
  // SPEC section 14 B: everything about saving is checked before anything is signed, because the
  // real service does both in one transaction and a refused save is a refused signature.
  const save = body.save_adopted_signature;
  if (save !== undefined && save !== true && save !== false) {
    throw invalid("save_adopted_signature must be a boolean.");
  }
  if (save === true) {
    if (record.scenario === "kiosk") {
      throw new MockHttpError(
        403,
        "adoption_not_allowed",
        "A signature cannot be saved from a shared tablet.",
      );
    }
    if (saveable === null) {
      throw invalid("There is no drawn or typed signature to save.");
    }
  }
  record.signerStatus = "signed";
  record.revisions += 1;
  if (record.scenario !== "multi") {
    record.envelopeStatus = "completed_pending_seal";
  }
  if (save === true && saveable !== null) {
    revokeSavedSignature(record, "replaced");
    record.savedSignatures.push({
      id: crypto.randomUUID(),
      kind: saveable.kind,
      imagePngBase64: saveable.kind === "drawn" ? saveable.png : null,
      typedText: saveable.kind === "typed" ? saveable.text : null,
      createdAt: serverNow(),
      revokedAt: null,
      revokeReason: null,
    });
  }
  return "signed";
}

/** null while sealing; the sealed bytes once ready. */
export function pollCopy(record: MockRecord): Uint8Array | null {
  if (record.signerStatus !== "signed") {
    throw conflict("Nothing has been signed.");
  }
  if (record.envelopeStatus === "completed_pending_seal") {
    record.copyPolls += 1;
    if (record.scenario !== "sealing-stuck" && record.copyPolls > POLLS_UNTIL_SEALED) {
      record.envelopeStatus = "sealed";
    }
  }
  if (record.envelopeStatus !== "sealed") {
    return null;
  }
  record.downloads += 1;
  return documentFor(record, true);
}
