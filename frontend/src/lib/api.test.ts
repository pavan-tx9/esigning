import { HttpResponse, http } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
import { z } from "zod";
import {
  ApiError,
  ApiNetworkError,
  ApiValidationError,
  api,
  hasSessionToken,
  setSessionToken,
} from "@/lib/api";
import { server } from "@/test/server";

const sessionSchema = z.object({ envelope: z.object({ id: z.string(), page_count: z.number() }) });

describe("the fetch seam", () => {
  beforeEach(() => {
    setSessionToken(null);
  });

  it("parses a well-shaped response", async () => {
    server.use(
      http.get("/v1/signing/session", () =>
        HttpResponse.json({ envelope: { id: "abc", page_count: 3 } }),
      ),
    );

    const result = await api("/signing/session", sessionSchema);

    expect(result.envelope.page_count).toBe(3);
  });

  it("rejects a response that does not match its schema", async () => {
    server.use(
      http.get("/v1/signing/session", () =>
        HttpResponse.json({ envelope: { id: "abc", page_count: "three" } }),
      ),
    );

    await expect(api("/signing/session", sessionSchema)).rejects.toBeInstanceOf(ApiValidationError);
  });

  it("turns the error envelope into a typed ApiError", async () => {
    server.use(
      http.get("/v1/signing/session", () =>
        HttpResponse.json({ error: { code: "conflict", message: "Not yet." } }, { status: 409 }),
      ),
    );

    const failure = await api("/signing/session", sessionSchema).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(ApiError);
    expect((failure as ApiError).code).toBe("conflict");
    expect((failure as ApiError).status).toBe(409);
  });

  it("says something safe when the server sends no usable error body", async () => {
    server.use(http.get("/v1/signing/session", () => new HttpResponse("nope", { status: 500 })));

    const failure = (await api("/signing/session", sessionSchema).catch(
      (error: unknown) => error,
    )) as ApiError;

    expect(failure.code).toBe("error");
    expect(failure.message).not.toContain("nope");
  });

  it("sends the session token as a bearer credential once it has one", async () => {
    let seen: string | null = null;
    server.use(
      http.get("/v1/signing/session", ({ request }) => {
        seen = request.headers.get("Authorization");
        return HttpResponse.json({ envelope: { id: "abc", page_count: 1 } });
      }),
    );

    expect(hasSessionToken()).toBe(false);
    setSessionToken("est_testtoken");
    expect(hasSessionToken()).toBe(true);
    await api("/signing/session", sessionSchema);

    expect(seen).toBe("Bearer est_testtoken");
  });

  it("never puts the token in the URL", async () => {
    let url = "";
    server.use(
      http.get("/v1/signing/session", ({ request }) => {
        url = request.url;
        return HttpResponse.json({ envelope: { id: "abc", page_count: 1 } });
      }),
    );

    setSessionToken("est_testtoken");
    await api("/signing/session", sessionSchema);

    expect(url).not.toContain("est_testtoken");
  });

  it("passes an idempotency key through on a submission", async () => {
    let key: string | null = null;
    server.use(
      http.post("/v1/signing/sign", ({ request }) => {
        key = request.headers.get("Idempotency-Key");
        return HttpResponse.json({ envelope: { id: "abc", page_count: 1 } });
      }),
    );

    await api("/signing/sign", sessionSchema, {
      body: { intent_confirmed: true },
      idempotencyKey: "key-1",
    });

    expect(key).toBe("key-1");
  });

  it("reports a request that never completed as a network error, distinct from an API error", async () => {
    server.use(http.get("/v1/signing/session", () => HttpResponse.error()));

    await expect(api("/signing/session", sessionSchema)).rejects.toBeInstanceOf(ApiNetworkError);
  });

  it("still validates an empty 204 against the schema", async () => {
    server.use(http.post("/v1/signing/viewed", () => new HttpResponse(null, { status: 204 })));

    await expect(api("/signing/viewed", z.looseObject({}), { body: {} })).resolves.toEqual({});
    await expect(api("/signing/viewed", sessionSchema, { body: {} })).rejects.toBeInstanceOf(
      ApiValidationError,
    );
  });

  it("rejects a 2xx whose body is not JSON at all", async () => {
    server.use(http.get("/v1/signing/session", () => new HttpResponse("<html>")));

    await expect(api("/signing/session", sessionSchema)).rejects.toBeInstanceOf(ApiValidationError);
  });
});
