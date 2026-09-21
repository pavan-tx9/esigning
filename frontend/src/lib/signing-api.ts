/**
 * The Signer API (SPEC section 9): one Zod schema per response, with the query options and
 * mutation functions that use it right beside it. Components import from here and never build a
 * request themselves.
 */

import { queryOptions } from "@tanstack/react-query";
import { z } from "zod";
import { ApiError, ApiNetworkError, api, apiBytes, apiPdfOrPending } from "@/lib/api";

// --------------------------------------------------------------------------- session

const timestamp = z.iso.datetime({ offset: true });

export const envelopeStatusSchema = z.enum([
  "created",
  "in_progress",
  "completed_pending_seal",
  "sealed",
  "declined",
  "voided",
  "expired",
]);
export const signerStatusSchema = z.enum(["pending", "viewed", "consented", "signed", "declined"]);
export const fieldTypeSchema = z.enum(["signature", "initials", "date_signed", "text", "checkbox"]);
export const capacitySchema = z.enum([
  "self",
  "guardian",
  "proxy",
  "witness",
  "interpreter",
  "clinician",
]);

/** PDF points, origin bottom-left of the page as displayed. */
export const rectSchema = z.object({
  x: z.number(),
  y: z.number(),
  w: z.number().positive(),
  h: z.number().positive(),
});

export const fieldSchema = z.object({
  id: z.string().min(1),
  type: fieldTypeSchema,
  page: z.number().int().min(1),
  rect: rectSchema,
  required: z.boolean(),
  label: z.string(),
});

export const sessionSchema = z.object({
  envelope: z.object({
    id: z.uuid(),
    status: envelopeStatusSchema,
    document_type: z.string(),
    title: z.string(),
    page_count: z.number().int().min(1),
    expires_at: timestamp,
  }),
  signer: z.object({
    id: z.uuid(),
    display_name: z.string().min(1),
    role_label: z.string(),
    capacity: capacitySchema,
    on_behalf_of_label: z.string().nullable(),
    status: signerStatusSchema,
    requires_reauth: z.boolean(),
    reauth_valid_until: timestamp.nullable(),
  }),
  other_signers: z.array(z.object({ role_label: z.string(), status: signerStatusSchema })),
  fields: z.array(fieldSchema),
  consent: z.object({ version: z.string().min(1), locale: z.string(), body: z.string().min(1) }),
  session: z.object({
    expires_at: timestamp,
    kiosk: z.boolean(),
    // Not in the SPEC 9 example, but `esign:reauth_required {session_id}` needs it from
    // somewhere. Accepted when the server sends it; the flow works without it.
    id: z.uuid().optional(),
  }),
  decline_reasons: z.array(z.object({ code: z.string().min(1), label: z.string().min(1) })),
});

export type SigningSession = z.infer<typeof sessionSchema>;
export type SigningField = z.infer<typeof fieldSchema>;
export type Rect = z.infer<typeof rectSchema>;
export type EnvelopeStatus = z.infer<typeof envelopeStatusSchema>;
export type SignerStatus = z.infer<typeof signerStatusSchema>;

export const signingKeys = {
  all: ["signing"] as const,
  session: ["signing", "session"] as const,
  document: ["signing", "document"] as const,
  copy: ["signing", "copy"] as const,
};

export const sessionQueryOptions = () =>
  queryOptions({
    queryKey: signingKeys.session,
    queryFn: ({ signal }) => api("/signing/session", sessionSchema, { signal }),
  });

// --------------------------------------------------------------------------- document

/**
 * The PDF being signed. Each fetch is recorded server-side as `document.presented`, so it is
 * fetched once per session and held: never refetched on focus, never considered stale.
 */
export const documentQueryOptions = () =>
  queryOptions({
    queryKey: signingKeys.document,
    queryFn: ({ signal }) => apiBytes("/signing/document", { signal }),
    staleTime: Number.POSITIVE_INFINITY,
    gcTime: Number.POSITIVE_INFINITY,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  });

// --------------------------------------------------------------------------- signed copy

export const copyPendingSchema = z.object({ status: z.literal("sealing") });

export type SignedCopy = { status: "sealing" } | { status: "ready"; bytes: Uint8Array };

/** How long to wait before asking again: quick at first, then easing off to every 10 seconds. */
export function copyPollDelay(attempt: number): number {
  return Math.min(10_000, 1_500 * 1.5 ** Math.max(0, attempt - 1));
}

/**
 * The sealed copy. While the server says 202 "sealing" this polls; the moment the PDF arrives it
 * stops and holds the bytes (each 200 is recorded as a download, so it is fetched exactly once).
 */
export const signedCopyQueryOptions = () =>
  queryOptions({
    queryKey: signingKeys.copy,
    queryFn: async ({ signal }): Promise<SignedCopy> => {
      const result = await apiPdfOrPending("/signing/copy", copyPendingSchema, { signal });
      return result.kind === "pdf"
        ? { status: "ready", bytes: result.bytes }
        : { status: result.body.status };
    },
    staleTime: Number.POSITIVE_INFINITY,
    gcTime: Number.POSITIVE_INFINITY,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    refetchInterval: (query) => {
      if (query.state.data?.status === "ready" || query.state.status === "error") {
        return false;
      }
      return copyPollDelay(query.state.dataUpdateCount);
    },
  });

// --------------------------------------------------------------------------- mutations

/**
 * SPEC 9 does not define the bodies of the POST responses, so nothing is read from them: after
 * every mutation the session is refetched and that (specified) shape is the source of truth.
 * The schema still runs, so a non-object body is rejected like any other bad response.
 */
export const ackSchema = z.looseObject({});

export type SignatureCapture =
  | { field_id: string; kind: "drawn"; image_png_base64: string }
  | { field_id: string; kind: "typed"; typed_text: string }
  | { field_id: string; kind: "click" };
export type Capture =
  | SignatureCapture
  | { field_id: string; checked: boolean }
  | { field_id: string; text_value: string };

export interface SignRequest {
  intent_confirmed: true;
  captures: Capture[];
}

export function postViewed(pagesViewed: number) {
  return api("/signing/viewed", ackSchema, { body: { pages_viewed: pagesViewed } });
}

export function postConsent(consentVersion: string) {
  return api("/signing/consent", ackSchema, {
    body: { consent_version: consentVersion, accepted: true },
  });
}

export function postDecline(reasonCode: string) {
  return api("/signing/decline", ackSchema, { body: { reason_code: reasonCode } });
}

export function postSign(request: SignRequest, idempotencyKey: string) {
  return api("/signing/sign", ackSchema, { body: request, idempotencyKey });
}

// --------------------------------------------------------------------------- idempotency

/**
 * One key per distinct submission. Retrying the same captures (after a dropped connection, a
 * double tap, a timeout) reuses the key, so the server returns its first answer instead of signing
 * twice. Changing anything about the submission produces a new key, because the server treats the
 * same key with a different body as a conflict.
 */
export class SubmissionKeys {
  private fingerprint: string | null = null;
  private key: string | null = null;

  keyFor(request: SignRequest): string {
    const fingerprint = JSON.stringify(request);
    if (this.key === null || this.fingerprint !== fingerprint) {
      this.fingerprint = fingerprint;
      this.key = crypto.randomUUID();
    }
    return this.key;
  }

  reset(): void {
    this.fingerprint = null;
    this.key = null;
  }
}

// --------------------------------------------------------------------------- errors and retries

/** The token is unknown, expired or revoked; the server does not say which. */
export function isSessionGone(error: unknown): boolean {
  return error instanceof ApiError && error.status === 401;
}

export function isNetworkError(error: unknown): boolean {
  return error instanceof ApiNetworkError;
}

/** Retry what might work next time (network, 5xx, 429); never a 4xx the server meant. */
export function shouldRetryQuery(failureCount: number, error: unknown): boolean {
  if (failureCount >= 2) {
    return false;
  }
  if (error instanceof ApiNetworkError) {
    return true;
  }
  return error instanceof ApiError && (error.status >= 500 || error.status === 429);
}
