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
  procedureFields,
  procedurePdf,
} from "@/mocks/documents";

export const SCENARIOS = {
  single: "One patient, two pages. Sealing takes a couple of polls, then the copy is ready.",
  multi: "Patient signs first of three. Done screen explains the copy comes later.",
  clinician: "Last signer, needs re-authentication before signing. Then seals.",
  kiosk: "Clinic tablet. Ends on the hand-back screen and clears everything.",
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

export const tokenFor = (scenario: Scenario) => `est_mock_${scenario}`;

export const CONSENT = {
  version: "2026-09",
  locale: "en-US",
  body: [
    "You are being asked to sign this document electronically instead of on paper. Your electronic signature has the same legal effect as a handwritten one.",
    "You do not have to agree. You can ask for a paper copy to read and sign instead, at no cost, by telling a member of staff. You can also withdraw this agreement at any time before you sign by choosing to sign on paper.",
    "To read and keep your signed copy you need a device that can open PDF files. After signing, you can save a copy from this page, and the clinic can give you a printed copy on request.",
    "This agreement applies only to this document.",
  ].join("\n\n"),
};

export const DECLINE_REASONS = [
  { code: "prefers_paper", label: "I would rather sign on paper" },
  { code: "has_questions", label: "I have questions I want answered first" },
  { code: "not_my_document", label: "This document isn't meant for me" },
  { code: "other", label: "Another reason" },
];

const REAUTH_MAX_AGE_MS = 120_000;
const POLLS_UNTIL_SEALED = 2;

type SignerStatus = "pending" | "viewed" | "consented" | "signed" | "declined";
type EnvelopeStatus =
  | "created"
  | "in_progress"
  | "completed_pending_seal"
  | "sealed"
  | "declined"
  | "voided"
  | "expired";

export interface MockRecord {
  scenario: Scenario;
  signerStatus: SignerStatus;
  envelopeStatus: EnvelopeStatus;
  reauthValidUntil: number | null;
  copyPolls: number;
  signRequests: { key: string | null; body: string }[];
  revisions: number;
  presented: number;
  downloads: number;
  declineReason: string | null;
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

function scenarioOf(token: string): Scenario | null {
  const name = token.replace(/^est_mock_/, "");
  return token.startsWith("est_mock_") && name in SCENARIOS ? (name as Scenario) : null;
}

export const mockDb = {
  reset(): void {
    records.clear();
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
      const now = Date.now();
      record = {
        scenario,
        signerStatus: "pending",
        envelopeStatus: scenario === "voided" ? "voided" : "in_progress",
        reauthValidUntil: null,
        copyPolls: 0,
        signRequests: [],
        revisions: 1,
        presented: 0,
        downloads: 0,
        declineReason: null,
        sessionExpiresAt: now + (scenario === "ending-soon" ? 100_000 : 1_800_000),
        createdAt: now,
      };
      records.set(token, record);
    }
    if (Date.now() >= record.sessionExpiresAt) {
      throw new MockHttpError(401, "unauthorized", "The session is not valid.");
    }
    return record;
  },

  /** What the host backend does after re-authenticating the user: POST /v1/sessions/{id}/reauth. */
  attestReauth(scenario: Scenario = "clinician"): void {
    const record = records.get(tokenFor(scenario));
    if (record !== undefined) {
      record.reauthValidUntil = Date.now() + REAUTH_MAX_AGE_MS;
    }
  },

  expireSession(scenario: Scenario): void {
    const record = records.get(tokenFor(scenario));
    if (record !== undefined) {
      record.sessionExpiresAt = 0;
    }
  },

  peek(scenario: Scenario): MockRecord | undefined {
    return records.get(tokenFor(scenario));
  },
};

// --------------------------------------------------------------------------- shape of each story

const isProcedure = (scenario: Scenario) => scenario === "multi" || scenario === "clinician";
const roleOf = (scenario: Scenario) => (scenario === "clinician" ? "clinician" : "patient");

export function fieldsFor(record: MockRecord): MockField[] {
  const all = isProcedure(record.scenario) ? procedureFields : hipaaFields;
  return all.filter((field) => field.role === roleOf(record.scenario));
}

export function pageCountFor(record: MockRecord): number {
  return isProcedure(record.scenario) ? 3 : 2;
}

export function documentFor(record: MockRecord, sealed = false): Uint8Array {
  if (isProcedure(record.scenario)) {
    return procedurePdf({ earlierSigned: record.scenario === "clinician", sealed });
  }
  return hipaaPdf(sealed);
}

const iso = (ms: number) => new Date(ms).toISOString();

export function sessionBody(record: MockRecord) {
  const clinician = record.scenario === "clinician";
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
  return {
    envelope: {
      id: "6f1c1a52-4a0e-4c59-9d7e-0a4d5f6b7c81",
      status: record.envelopeStatus,
      document_type: isProcedure(record.scenario) ? "procedure_consent" : "hipaa_acknowledgement",
      title: isProcedure(record.scenario)
        ? "Consent to procedure"
        : "Privacy notice acknowledgement",
      page_count: pageCountFor(record),
      expires_at: iso(record.createdAt + 7 * 86_400_000),
    },
    signer: {
      id: "0b9d7f3e-2c41-4f7a-8a55-3e1f2d4c5b6a",
      display_name: clinician ? "Dr. Priya Raman" : "Maria Alvarez",
      role_label: clinician ? "Clinician" : "Patient",
      capacity: clinician ? "clinician" : "self",
      on_behalf_of_label: null,
      status: record.signerStatus,
      requires_reauth: clinician,
      reauth_valid_until: record.reauthValidUntil === null ? null : iso(record.reauthValidUntil),
    },
    other_signers: others,
    fields: fieldsFor(record).map(({ role: _role, ...field }) => field),
    consent: CONSENT,
    session: { expires_at: iso(record.sessionExpiresAt), kiosk: record.scenario === "kiosk" },
    decline_reasons: DECLINE_REASONS,
  };
}

// --------------------------------------------------------------------------- transitions

const conflict = (message: string) => new MockHttpError(409, "conflict", message);
const invalid = (message: string) => new MockHttpError(422, "validation_failed", message);

function assertLive(record: MockRecord): void {
  if (record.envelopeStatus !== "in_progress" && record.envelopeStatus !== "created") {
    throw conflict("The envelope is not open for signing.");
  }
}

export function recordViewed(record: MockRecord, pagesViewed: unknown): void {
  assertLive(record);
  if (pagesViewed !== pageCountFor(record)) {
    throw invalid("Every page must be viewed.");
  }
  if (record.signerStatus === "pending") {
    record.signerStatus = "viewed";
  }
}

export function recordConsent(record: MockRecord, version: unknown, accepted: unknown): void {
  assertLive(record);
  if (record.signerStatus === "pending") {
    throw conflict("The document has not been viewed.");
  }
  if (version !== CONSENT.version || accepted !== true) {
    throw invalid("The consent version is not current.");
  }
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

function validateCaptures(record: MockRecord, captures: unknown): void {
  if (!Array.isArray(captures)) {
    throw invalid("Captures are required.");
  }
  const fields = fieldsFor(record);
  const seen = new Set<string>();
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
      } else if (capture.kind === "typed") {
        if (typeof capture.typed_text !== "string" || capture.typed_text.trim() === "") {
          throw invalid("Typed text is required.");
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
}

/** Returns "replayed" when the key was seen before with the same body: the first answer stands. */
export function recordSign(
  record: MockRecord,
  key: string | null,
  body: { intent_confirmed?: unknown; captures?: unknown },
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
  if (body.intent_confirmed !== true) {
    throw invalid("Intent must be confirmed.");
  }
  if (
    record.scenario === "clinician" &&
    (record.reauthValidUntil === null || record.reauthValidUntil < Date.now())
  ) {
    throw new MockHttpError(403, "forbidden", "Re-authentication is required.");
  }
  validateCaptures(record, body.captures);
  record.signerStatus = "signed";
  record.revisions += 1;
  if (record.scenario !== "multi") {
    record.envelopeStatus = "completed_pending_seal";
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
