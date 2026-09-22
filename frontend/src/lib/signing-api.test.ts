import { HttpResponse, http } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
import { ApiError, ApiNetworkError, ApiValidationError, setSessionToken } from "@/lib/api";
import {
  copyPollDelay,
  isReauthLapsed,
  isSignatureUnavailable,
  postConsent,
  postSign,
  type SignRequest,
  SubmissionKeys,
  sessionQueryOptions,
  sessionSchema,
  shouldRetryQuery,
  signedCopyQueryOptions,
  signingKeys,
} from "@/lib/signing-api";
import { mockDb, sessionBody, tokenFor } from "@/mocks/db";
import { signerApiHandlers } from "@/mocks/handlers";
import { server } from "@/test/server";

const context = { signal: new AbortController().signal } as never;
const fetchSession = () => sessionQueryOptions().queryFn?.(context);
const fetchCopy = () => signedCopyQueryOptions().queryFn?.(context);

function validSession() {
  setSessionToken(tokenFor("single"));
  return sessionBody(mockDb.authenticate(`Bearer ${tokenFor("single")}`));
}

describe("the session schema is SPEC 9, exactly", () => {
  beforeEach(() => {
    mockDb.reset();
    setSessionToken(null);
  });

  it("accepts the documented shape, and the SPEC's own example", () => {
    expect(sessionSchema.safeParse(validSession()).success).toBe(true);
    const specExample = {
      envelope: {
        id: "6f1c1a52-4a0e-4c59-9d7e-0a4d5f6b7c81",
        status: "in_progress",
        document_type: "procedure_consent",
        title: "Procedure consent",
        page_count: 3,
        expires_at: "2026-10-01T00:00:00.000000+00:00",
      },
      signer: {
        id: "0b9d7f3e-2c41-4f7a-8a55-3e1f2d4c5b6a",
        display_name: "A Signer",
        role_label: "Patient",
        capacity: "self",
        on_behalf_of_label: null,
        status: "pending",
        requires_reauth: false,
        reauth_valid_until: null,
        reauth_scope: null,
        reauth_at: null,
      },
      other_signers: [{ role_label: "Witness", status: "pending" }],
      fields: [
        {
          id: "patient_sig",
          type: "signature",
          page: 3,
          rect: { x: 72, y: 120, w: 220, h: 48 },
          required: true,
          label: "Patient signature",
        },
      ],
      consent: { version: "2026-09", locale: "en-US", body: "..." },
      session: {
        id: "5c4b3a29-1d8e-4f70-9b61-2a3c4d5e6f70",
        expires_at: "2026-09-21T10:30:00Z",
        kiosk: false,
      },
      adopted_signature: null,
      decline_reasons: [{ code: "prefers_paper", label: "I would rather sign on paper" }],
    };
    expect(sessionSchema.safeParse(specExample).success).toBe(true);
  });

  /** SPEC section 14: the saved signature and the re-authentication span, as the payload has them. */
  it("accepts the addendum's fields in every shape the SPEC allows", () => {
    const drawn = validSession();
    Object.assign(drawn, {
      adopted_signature: {
        id: "9a1e5d2c-7b3f-4e8a-9c0d-1f2e3a4b5c6d",
        kind: "drawn",
        image_png_base64: "iVBORw0KGgo=",
        created_at: "2026-09-16T09:00:00Z",
      },
    });
    Object.assign(drawn.signer, {
      reauth_valid_until: "2026-09-22T10:02:00Z",
      reauth_scope: "span",
      reauth_at: "2026-09-22T10:00:00Z",
    });
    const parsed = sessionSchema.parse(drawn);
    expect(parsed.adopted_signature?.kind).toBe("drawn");
    expect(parsed.signer.reauth_scope).toBe("span");

    const typed = validSession();
    Object.assign(typed, {
      adopted_signature: {
        id: "9a1e5d2c-7b3f-4e8a-9c0d-1f2e3a4b5c6d",
        kind: "typed",
        typed_text: "Priya Raman",
        created_at: "2026-09-16T09:00:00Z",
      },
    });
    Object.assign(typed.signer, {
      reauth_valid_until: "2026-09-22T10:02:00Z",
      reauth_scope: "session",
      reauth_at: "2026-09-22T10:00:00Z",
    });
    expect(sessionSchema.safeParse(typed).success).toBe(true);

    // As the service actually serialises it (`api/schemas.py`): both payload keys are always
    // present and the one that does not apply is null. The unused key is dropped, not refused.
    const asServed = validSession();
    Object.assign(asServed, {
      adopted_signature: {
        id: "9a1e5d2c-7b3f-4e8a-9c0d-1f2e3a4b5c6d",
        kind: "typed",
        image_png_base64: null,
        typed_text: "Priya Raman",
        created_at: "2026-09-16T09:00:00.000000Z",
      },
    });
    const served = sessionSchema.parse(asServed);
    expect(served.adopted_signature).toEqual({
      id: "9a1e5d2c-7b3f-4e8a-9c0d-1f2e3a4b5c6d",
      kind: "typed",
      typed_text: "Priya Raman",
      created_at: "2026-09-16T09:00:00.000000Z",
    });
    Object.assign(asServed, {
      adopted_signature: {
        id: "9a1e5d2c-7b3f-4e8a-9c0d-1f2e3a4b5c6d",
        kind: "drawn",
        image_png_base64: "iVBORw0KGgo=",
        typed_text: null,
        created_at: "2026-09-16T09:00:00.000000Z",
      },
    });
    expect(sessionSchema.parse(asServed).adopted_signature).not.toHaveProperty("typed_text");

    // The mock's own kiosk session: a saved signature exists for the patient and is not offered.
    setSessionToken(tokenFor("kiosk"));
    const kiosk = sessionBody(mockDb.authenticate(`Bearer ${tokenFor("kiosk")}`));
    expect(kiosk.adopted_signature).toBeNull();
    expect(sessionSchema.safeParse(kiosk).success).toBe(true);
  });

  it.each([
    [
      "a saved signature with no id",
      (s: ReturnType<typeof validSession>) =>
        Object.assign(s, {
          adopted_signature: {
            kind: "typed",
            typed_text: "Priya",
            created_at: "2026-09-16T09:00:00Z",
          },
        }),
    ],
    [
      "a drawn saved signature without its image",
      (s: ReturnType<typeof validSession>) =>
        Object.assign(s, {
          adopted_signature: {
            id: "9a1e5d2c-7b3f-4e8a-9c0d-1f2e3a4b5c6d",
            kind: "drawn",
            created_at: "2026-09-16T09:00:00Z",
          },
        }),
    ],
    [
      "a saved signature of an unknown kind",
      (s: ReturnType<typeof validSession>) =>
        Object.assign(s, {
          adopted_signature: {
            id: "9a1e5d2c-7b3f-4e8a-9c0d-1f2e3a4b5c6d",
            kind: "click",
            created_at: "2026-09-16T09:00:00Z",
          },
        }),
    ],
    [
      "a missing adopted_signature",
      (s: ReturnType<typeof validSession>) => Object.assign(s, { adopted_signature: undefined }),
    ],
    [
      "a re-authentication scope that is not session or span",
      (s: ReturnType<typeof validSession>) => Object.assign(s.signer, { reauth_scope: "host" }),
    ],
    [
      "a missing re-authentication scope",
      (s: ReturnType<typeof validSession>) => Object.assign(s.signer, { reauth_scope: undefined }),
    ],
  ])("rejects %s", (_, corrupt) => {
    const body = validSession();
    corrupt(body);
    expect(sessionSchema.safeParse(body).success).toBe(false);
  });

  it.each([
    [
      "an unknown envelope status",
      (s: ReturnType<typeof validSession>) => Object.assign(s.envelope, { status: "done" }),
    ],
    [
      "an unknown field type",
      (s: ReturnType<typeof validSession>) => Object.assign(s.fields[0] ?? {}, { type: "stamp" }),
    ],
    [
      "a rect with a string in it",
      (s: ReturnType<typeof validSession>) => Object.assign(s.fields[0]?.rect ?? {}, { x: "72" }),
    ],
    [
      "a zero-size rect",
      (s: ReturnType<typeof validSession>) => Object.assign(s.fields[0]?.rect ?? {}, { w: 0 }),
    ],
    [
      "a page count of zero",
      (s: ReturnType<typeof validSession>) => Object.assign(s.envelope, { page_count: 0 }),
    ],
    [
      "a missing consent body",
      (s: ReturnType<typeof validSession>) => Object.assign(s.consent, { body: undefined }),
    ],
    [
      "kiosk as a string",
      (s: ReturnType<typeof validSession>) => Object.assign(s.session, { kiosk: "false" }),
    ],
    [
      "a date that is not a timestamp",
      (s: ReturnType<typeof validSession>) => Object.assign(s.session, { expires_at: "soon" }),
    ],
    [
      "a non-uuid id",
      (s: ReturnType<typeof validSession>) => Object.assign(s.signer, { id: "42" }),
    ],
  ])("rejects %s", (_, corrupt) => {
    const body = validSession();
    corrupt(body);
    expect(sessionSchema.safeParse(body).success).toBe(false);
  });

  it("surfaces a bad session from the server as ApiValidationError, not as data", async () => {
    const body = validSession();
    Object.assign(body.signer, { requires_reauth: "no" });
    server.use(http.get("/v1/signing/session", () => HttpResponse.json(body)));
    await expect(fetchSession()).rejects.toBeInstanceOf(ApiValidationError);
  });
});

/**
 * The host page may embed the UI with a locale, and SPEC section 9 gives that locale two jobs:
 * `?locale=` picks the disclosure language, and consent records the locale as shown in the session
 * payload. Neither had a client, so a host asking for one language got the default text and the
 * trail recorded the default locale.
 */
describe("the disclosure language the host asked for", () => {
  beforeEach(() => {
    mockDb.reset();
    setSessionToken(null);
  });

  it("asks the session for that locale, and keeps it in the query key", async () => {
    server.use(...signerApiHandlers());
    setSessionToken(tokenFor("single"));

    const options = sessionQueryOptions("es-MX");
    expect(options.queryKey).toEqual(["signing", "session", "es-MX"]);
    expect(sessionQueryOptions().queryKey).toEqual(["signing", "session"]);
    // Still under the key the flow invalidates after every mutation.
    expect(options.queryKey.slice(0, 2)).toEqual([...signingKeys.session]);

    await options.queryFn?.(context);

    expect(mockDb.peek("single")?.requestedLocale).toBe("es-MX");
  });

  it("asks for no locale when the host named none, rather than guessing one", async () => {
    server.use(...signerApiHandlers());
    setSessionToken(tokenFor("single"));

    await sessionQueryOptions().queryFn?.(context);

    expect(mockDb.peek("single")?.requestedLocale).toBeNull();
  });

  it("records consent in the locale the server served, not the one the host asked for", async () => {
    server.use(...signerApiHandlers());
    const token = tokenFor("single");
    setSessionToken(token);
    const record = mockDb.authenticate(`Bearer ${token}`);
    record.signerStatus = "viewed";
    const served = sessionBody(record).consent;

    await postConsent(served.version, served.locale);

    expect(record.consentLocale).toBe("en-US");
    expect(record.signerStatus).toBe("consented");
  });
});

describe("the signed copy", () => {
  beforeEach(() => {
    mockDb.reset();
    setSessionToken(null);
  });

  it("reads 202 as sealing and 200 as the PDF bytes", async () => {
    let ready = false;
    server.use(
      http.get("/v1/signing/copy", () =>
        ready
          ? new HttpResponse(new Uint8Array([37, 80, 68, 70]).buffer, {
              headers: { "Content-Type": "application/pdf" },
            })
          : HttpResponse.json({ status: "sealing" }, { status: 202 }),
      ),
    );
    expect(await fetchCopy()).toEqual({ status: "sealing" });
    ready = true;
    const copy = await fetchCopy();
    expect(copy?.status).toBe("ready");
    expect(copy?.status === "ready" && Array.from(copy.bytes)).toEqual([37, 80, 68, 70]);
  });

  it("rejects a 202 that does not say what the SPEC says", async () => {
    server.use(
      http.get("/v1/signing/copy", () => HttpResponse.json({ status: "done" }, { status: 202 })),
    );
    await expect(fetchCopy()).rejects.toBeInstanceOf(ApiValidationError);
  });

  it("polls quickly at first and never slower than every ten seconds", () => {
    expect(copyPollDelay(1)).toBe(1_500);
    expect(copyPollDelay(3)).toBeGreaterThan(copyPollDelay(2));
    expect(copyPollDelay(50)).toBe(10_000);
  });
});

describe("idempotent signing", () => {
  const request: SignRequest = {
    intent_confirmed: true,
    captures: [
      { field_id: "ack_received", checked: true },
      { field_id: "patient_sig", kind: "click" },
    ],
  };

  beforeEach(() => {
    mockDb.reset();
    setSessionToken(null);
  });

  it("keeps one key for one submission and mints a new one when the submission changes", () => {
    const keys = new SubmissionKeys();
    const first = keys.keyFor(request);
    expect(keys.keyFor(request)).toBe(first);
    expect(keys.keyFor(structuredClone(request))).toBe(first);
    const changed: SignRequest = {
      ...request,
      captures: [{ field_id: "patient_sig", kind: "click" }],
    };
    expect(keys.keyFor(changed)).not.toBe(first);
    keys.reset();
    expect(keys.keyFor(request)).not.toBe(first);
  });

  it("survives a lost reply: the retry carries the same key and nothing is signed twice", async () => {
    server.use(...signerApiHandlers());
    const token = tokenFor("flaky-sign");
    setSessionToken(token);
    const record = mockDb.authenticate(`Bearer ${token}`);
    // Mid-flow, as the service sees it: served the current revision, and told it was read.
    Object.assign(record, { signerStatus: "consented", presentedRevision: 1, viewedRevision: 1 });

    const keys = new SubmissionKeys();
    await expect(postSign(request, keys.keyFor(request))).rejects.toBeInstanceOf(ApiNetworkError);
    await expect(postSign(request, keys.keyFor(request))).resolves.toBeDefined();

    expect(record.signRequests).toHaveLength(2);
    expect(record.signRequests[0]?.key).toBe(record.signRequests[1]?.key);
    expect(record.revisions).toBe(2); // the presented revision plus exactly one signed revision
  });

  it("is told about a conflict when a key is reused with a different body", async () => {
    server.use(...signerApiHandlers());
    const token = tokenFor("single");
    setSessionToken(token);
    Object.assign(mockDb.authenticate(`Bearer ${token}`), {
      signerStatus: "consented",
      presentedRevision: 1,
      viewedRevision: 1,
    });
    await postSign(request, "fixed-key");
    const different: SignRequest = { ...request, captures: [...request.captures].reverse() };
    const failure = await postSign(different, "fixed-key").catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(ApiError);
    expect((failure as ApiError).code).toBe("conflict");
  });
});

/**
 * `POST /v1/signing/sign` refuses a lapsed re-authentication and an unusable saved signature with
 * the same 403 (`api/errors.py`), and they want opposite things from the signer: one more
 * hand-off to the host, or a different signature. Reading the status alone left a clinician whose
 * saved signature had been revoked pressing "Confirm again" for ever, so each is told by its code.
 */
describe("telling the two 403s on the sign route apart", () => {
  it("is the code that decides, never the status", () => {
    expect(isReauthLapsed(new ApiError(403, "reauth_required", ""))).toBe(true);
    expect(isReauthLapsed(new ApiError(403, "adopted_signature_unavailable", ""))).toBe(false);
    expect(isReauthLapsed(new ApiError(403, "adoption_not_allowed", ""))).toBe(false);
    expect(isSignatureUnavailable(new ApiError(403, "adopted_signature_unavailable", ""))).toBe(
      true,
    );
    expect(isSignatureUnavailable(new ApiError(403, "reauth_required", ""))).toBe(false);
    // And neither is anything but a 403 from the server.
    expect(isReauthLapsed(new ApiError(401, "reauth_required", ""))).toBe(false);
    expect(isSignatureUnavailable(new ApiError(409, "adopted_signature_unavailable", ""))).toBe(
      false,
    );
    expect(isReauthLapsed(new ApiNetworkError())).toBe(false);
    expect(isSignatureUnavailable(new ApiNetworkError())).toBe(false);
  });
});

describe("retry policy", () => {
  it("retries what might work next time, and never an answer the server meant", () => {
    expect(shouldRetryQuery(0, new ApiNetworkError())).toBe(true);
    expect(shouldRetryQuery(0, new ApiError(503, "seal_unavailable", ""))).toBe(true);
    expect(shouldRetryQuery(0, new ApiError(401, "unauthorized", ""))).toBe(false);
    expect(shouldRetryQuery(0, new ApiError(409, "conflict", ""))).toBe(false);
    expect(shouldRetryQuery(0, new ApiValidationError("/x", []))).toBe(false);
    expect(shouldRetryQuery(2, new ApiNetworkError())).toBe(false);
  });
});
