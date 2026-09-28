import { api, apiBytes, apiPdfOrPending, configureApi, setSessionToken } from "@/lib/api";
import {
  copyPendingSchema,
  postConsent,
  postDecline,
  postSign,
  postViewed,
  type SignedCopy,
  type SignRequest,
  sessionSchema,
} from "@/lib/signing-api";
import { SDK_CLIENT } from "@/sdk/version";

export interface SigningClientOptions {
  baseUrl: string;
  token: string;
}

/**
 * Headless Signer API client. `fetch` stays in `api.ts`; every response is still parsed with Zod.
 */
export function createSigningClient(options: SigningClientOptions) {
  configureApi({ baseUrl: options.baseUrl, client: SDK_CLIENT });
  setSessionToken(options.token);
  return {
    session: (locale?: string | null) =>
      api(
        locale ? `/signing/session?locale=${encodeURIComponent(locale)}` : "/signing/session",
        sessionSchema,
      ),
    document: () => apiBytes("/signing/document"),
    viewed: (pagesViewed: number, extras?: { pagesSeen?: number[]; reachedEnd?: boolean }) =>
      postViewed(pagesViewed, extras),
    consent: (consentVersion: string, locale: string, reliesOnEnvelopeId?: string | null) =>
      postConsent(consentVersion, locale, reliesOnEnvelopeId),
    sign: (request: SignRequest, idempotencyKey: string) => postSign(request, idempotencyKey),
    decline: (reasonCode: string) => postDecline(reasonCode),
    copy: async (): Promise<SignedCopy> => {
      const result = await apiPdfOrPending("/signing/copy", copyPendingSchema);
      return result.kind === "pdf"
        ? { status: "ready", bytes: result.bytes }
        : { status: result.body.status };
    },
  };
}
