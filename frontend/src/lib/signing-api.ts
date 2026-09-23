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

/**
 * Which attestation `reauth_valid_until` rests on (SPEC section 14 C). `session`: made for this
 * session. `span`: borrowed from an earlier session of the same person on the same host, within
 * the host's signing-queue window. `null`: none the server is willing to vouch for right now.
 */
export const reauthScopeSchema = z.enum(["session", "span"]);

/**
 * The signature this person saved in an earlier session (SPEC section 14 B), served only to a
 * session of the same person on the same host, and always `null` on a kiosk. The image comes as
 * PNG bytes in base64; the UI shows it and sends back the id, never the bytes.
 */
export const adoptedSignatureSchema = z.discriminatedUnion("kind", [
  z.object({
    id: z.uuid(),
    kind: z.literal("drawn"),
    image_png_base64: z.string().min(1),
    created_at: timestamp,
  }),
  z.object({
    id: z.uuid(),
    kind: z.literal("typed"),
    typed_text: z.string().min(1),
    created_at: timestamp,
  }),
]);

/**
 * A standing acceptance of the electronic-signature disclosure (addendum 3 C): the same person,
 * on the same host, for the same consent version and locale, inside `CONSENT_SPAN_SECONDS`. The
 * envelope it was given for is named because the UI sends it back and the server re-checks it.
 */
export const standingConsentSchema = z.object({
  accepted_at: timestamp,
  envelope_id: z.uuid(),
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
    reauth_scope: reauthScopeSchema.nullable(),
    /** When that attestation was made: the moment the signer confirmed their identity. */
    reauth_at: timestamp.nullable(),
  }),
  other_signers: z.array(z.object({ role_label: z.string(), status: signerStatusSchema })),
  fields: z.array(fieldSchema),
  consent: z.object({
    version: z.string().min(1),
    locale: z.string(),
    body: z.string().min(1),
    /**
     * An acceptance this person already gave, for this same disclosure, inside the host's consent
     * span (addendum 3 C). It is what lets the Read screen show one line instead of a checkbox.
     * `.default(null)` rather than required: a service with `CONSENT_SPAN_SECONDS=0` -- the
     * default, and every service built before this addendum -- sends no such key, and that is the
     * ordinary per-envelope case, not a broken response.
     */
    standing: standingConsentSchema.nullable().default(null),
  }),
  session: z.object({
    // The host page is told which session to re-authenticate (`esign:reauth_required`), so this
    // is required, as SPEC section 9 has it. A response without it is a broken response.
    id: z.uuid(),
    expires_at: timestamp,
    kiosk: z.boolean(),
  }),
  adopted_signature: adoptedSignatureSchema.nullable(),
  decline_reasons: z.array(z.object({ code: z.string().min(1), label: z.string().min(1) })),
});

export type SigningSession = z.infer<typeof sessionSchema>;
export type SigningField = z.infer<typeof fieldSchema>;
export type Rect = z.infer<typeof rectSchema>;
export type EnvelopeStatus = z.infer<typeof envelopeStatusSchema>;
export type SignerStatus = z.infer<typeof signerStatusSchema>;
export type ReauthScope = z.infer<typeof reauthScopeSchema>;
export type SavedSignature = z.infer<typeof adoptedSignatureSchema>;
export type StandingConsent = z.infer<typeof standingConsentSchema>;

export const signingKeys = {
  all: ["signing"] as const,
  session: ["signing", "session"] as const,
  document: ["signing", "document"] as const,
  copy: ["signing", "copy"] as const,
};

/**
 * The session, in the language the host page asked for (SPEC section 9: `?locale=` picks the
 * disclosure language, falling back to the default locale). The locale is part of the key, so the
 * disclosure the signer read and the one the cache holds can never be two different texts.
 */
export const sessionQueryOptions = (locale?: string | null) =>
  queryOptions({
    queryKey: locale ? [...signingKeys.session, locale] : signingKeys.session,
    queryFn: ({ signal }) =>
      api(
        locale ? `/signing/session?locale=${encodeURIComponent(locale)}` : "/signing/session",
        sessionSchema,
        { signal },
      ),
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
  | { field_id: string; kind: "click" }
  /** The saved signature's id and nothing else: the server holds the image or text. */
  | { field_id: string; kind: "adopted"; adopted_signature_id: string };
export type Capture =
  | SignatureCapture
  | { field_id: string; checked: boolean }
  | { field_id: string; text_value: string };

export interface SignRequest {
  intent_confirmed: true;
  captures: Capture[];
  /**
   * Save the drawn or typed signature in this submission for next time (SPEC section 14 B).
   * Present only when true: the server refuses it from a kiosk and without such a capture, and
   * an unchanged submission must keep its idempotency fingerprint.
   */
  save_adopted_signature?: true;
}

export function postViewed(pagesViewed: number) {
  return api("/signing/viewed", ackSchema, { body: { pages_viewed: pagesViewed } });
}

/**
 * `locale` is the language of the disclosure as the *server served it* (`consent.locale` in the
 * session payload), never the host's raw request: the trail has to say which text was accepted.
 *
 * `reliesOnEnvelopeId` is the earlier envelope whose acceptance this one leans on (addendum 3 C).
 * It is sent only when the session reported a standing acceptance; the server re-checks that it
 * is the signer's own, matches version and locale, and is inside the span, and refuses with 409
 * `consent_not_standing` otherwise -- at which point the screen asks for the tick instead.
 */
export function postConsent(
  consentVersion: string,
  locale: string,
  reliesOnEnvelopeId?: string | null,
) {
  const body: Record<string, unknown> = {
    consent_version: consentVersion,
    accepted: true,
    locale,
  };
  if (reliesOnEnvelopeId !== undefined && reliesOnEnvelopeId !== null) {
    body.relies_on_envelope_id = reliesOnEnvelopeId;
  }
  return api("/signing/consent", ackSchema, { body });
}

export function postDecline(reasonCode: string) {
  return api("/signing/decline", ackSchema, { body: { reason_code: reasonCode } });
}

export function postSign(request: SignRequest, idempotencyKey: string) {
  return api("/signing/sign", ackSchema, { body: request, idempotencyKey });
}

/**
 * The signer removes their own saved signature (SPEC section 14 B). The server answers 200
 * whether or not there was one, so this is safe to send twice; the session is refetched
 * afterwards and its `adopted_signature: null` is what the UI believes.
 */
export function postRevokeAdoptedSignature() {
  // No body: the route takes none, and the session token says whose signature it is.
  return api("/signing/adopted-signature/revoke", ackSchema, { method: "POST" });
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

/**
 * The server will not let this consent lean on the earlier one after all (addendum 3 C): the
 * span ran out between the session being read and the button being pressed, the disclosure
 * version moved on, or the earlier acceptance is not this signer's. Nothing is wrong and nothing
 * is lost -- the screen falls back to the checkbox and asks for it in as many words.
 */
export function isConsentNotStanding(error: unknown): boolean {
  return error instanceof ApiError && error.status === 409 && error.code === "consent_not_standing";
}

/**
 * The server will not take this signature because the bytes this session was served are not the
 * bytes the signer confirmed reading: another signer signed in between, so the document moved on
 * (SPEC section 3, `signers.viewed_sha256`). It is not a failure and nothing is wrong with the
 * submission -- the way out is to read the document as it stands now and say so, which is a fresh
 * `POST /signing/viewed`. The flow has to send the signer back to the review step for that: their
 * signer status is still `consented`, so nothing else would.
 */
export function mustReadAgain(error: unknown): boolean {
  return error instanceof ApiError && error.status === 409 && error.code === "not_viewed";
}

/**
 * The server refused the signature because it will not vouch for this signer's re-authentication
 * any more: it lapsed between the session being read and the signature being sent (SPEC section
 * 14 C). The way out is another hand-off to the host.
 */
export function isReauthLapsed(error: unknown): boolean {
  return error instanceof ApiError && error.status === 403 && error.code === "reauth_required";
}

/**
 * The server refused the signature because the saved signature it applied is not this session's
 * to use (SPEC section 14 B): the host revoked it, another session of this person's replaced it,
 * or the id is not theirs. It shares its status with a lapsed re-authentication and has nothing
 * to do with one -- confirming their identity again would only produce the same refusal -- so the
 * signer has to choose a signature again.
 */
export function isSignatureUnavailable(error: unknown): boolean {
  return (
    error instanceof ApiError &&
    error.status === 403 &&
    error.code === "adopted_signature_unavailable"
  );
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
