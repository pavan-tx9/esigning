import { delay, HttpResponse, http } from "msw";
import {
  documentFor,
  LOCALE_PATTERN,
  MockHttpError,
  type MockRecord,
  mockDb,
  pollCopy,
  recordConsent,
  recordDecline,
  recordPresented,
  recordRevokeSaved,
  recordSign,
  recordViewed,
  SIGNER_ID,
  sessionBody,
} from "@/mocks/db";

function errorResponse(error: unknown) {
  if (error instanceof MockHttpError) {
    return HttpResponse.json(
      { error: { code: error.code, message: error.message } },
      { status: error.status },
    );
  }
  throw error;
}

const pdfResponse = (bytes: Uint8Array) =>
  new HttpResponse(bytes.slice().buffer as ArrayBuffer, {
    headers: { "Content-Type": "application/pdf", "Cache-Control": "no-store" },
  });

const serverError = () =>
  HttpResponse.json({ error: { code: "error", message: "Internal error." } }, { status: 500 });

type Handle = (record: MockRecord, request: Request) => Promise<Response> | Response;

/** Every handler authenticates first, like the real API. `latency` makes dev feel like a network. */
function signerRoute(latency: number, handle: Handle) {
  return async ({ request }: { request: Request }) => {
    if (latency > 0) {
      await delay(latency);
    }
    try {
      const record = mockDb.authenticate(request.headers.get("Authorization"));
      return await handle(record, request);
    } catch (error) {
      return errorResponse(error);
    }
  };
}

/** Every signer POST answers ids and statuses only (SPEC section 9), the real shape exactly. */
const ack = (record: MockRecord) =>
  HttpResponse.json({
    envelope: { id: record.envelopeId, status: record.envelopeStatus },
    signer: { id: SIGNER_ID, status: record.signerStatus },
  });

export function signerApiHandlers({ latency = 0 }: { latency?: number } = {}) {
  return [
    http.get(
      "/v1/signing/session",
      signerRoute(latency, (record, request) => {
        if (record.scenario === "error") {
          return serverError();
        }
        // `?locale=` picks the disclosure language, and only en-US is seeded, so anything else
        // falls back to it -- exactly as the real service does.
        const requested = new URL(request.url).searchParams.get("locale");
        if (requested !== null && !LOCALE_PATTERN.test(requested)) {
          return errorResponse(
            new MockHttpError(422, "validation_failed", "The locale is not a language tag."),
          );
        }
        record.requestedLocale = requested;
        return HttpResponse.json(sessionBody(record));
      }),
    ),

    http.get(
      "/v1/signing/document",
      signerRoute(latency, (record) => {
        if (record.scenario === "document-error") {
          return serverError();
        }
        recordPresented(record);
        return pdfResponse(documentFor(record));
      }),
    ),

    http.post(
      "/v1/signing/viewed",
      signerRoute(latency, async (record, request) => {
        const body = (await request.json()) as { pages_viewed?: unknown };
        recordViewed(record, body.pages_viewed);
        return ack(record);
      }),
    ),

    http.post(
      "/v1/signing/consent",
      signerRoute(latency, async (record, request) => {
        const body = (await request.json()) as {
          consent_version?: unknown;
          accepted?: unknown;
          locale?: unknown;
          relies_on_envelope_id?: unknown;
        };
        recordConsent(
          record,
          body.consent_version,
          body.accepted,
          body.locale,
          body.relies_on_envelope_id,
        );
        return ack(record);
      }),
    ),

    http.post(
      "/v1/signing/decline",
      signerRoute(latency, async (record, request) => {
        const body = (await request.json()) as { reason_code?: unknown };
        recordDecline(record, body.reason_code);
        return ack(record);
      }),
    ),

    http.post(
      "/v1/signing/adopted-signature/revoke",
      signerRoute(latency, (record) =>
        // 200 either way; the body says whether there was one (`api/signer_routes.py`).
        HttpResponse.json({ revoked: recordRevokeSaved(record) }),
      ),
    ),

    http.post(
      "/v1/signing/sign",
      signerRoute(latency, async (record, request) => {
        const body = (await request.json()) as {
          intent_confirmed?: unknown;
          captures?: unknown;
          save_adopted_signature?: unknown;
        };
        const outcome = recordSign(record, request.headers.get("Idempotency-Key"), body);
        // The nasty case: the server signed, but the reply never made it back.
        if (record.scenario === "flaky-sign" && outcome === "signed") {
          return HttpResponse.error();
        }
        return ack(record);
      }),
    ),

    http.get(
      "/v1/signing/copy",
      signerRoute(latency, (record) => {
        const sealed = pollCopy(record);
        return sealed === null
          ? HttpResponse.json({ status: "sealing" }, { status: 202 })
          : pdfResponse(sealed);
      }),
    ),
  ];
}
