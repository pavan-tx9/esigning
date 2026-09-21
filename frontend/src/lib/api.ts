/**
 * The fetch seam. The only file in the app allowed to call `fetch` -- Biome fails the lint
 * anywhere else.
 *
 * Everything passes through here so that four rules hold without anyone having to remember them:
 *
 *  - every response is parsed with Zod before a component sees it;
 *  - the session token is attached from memory and never read from a URL or from storage;
 *  - an error body (`{"error": {"code", "message"}}`) becomes a typed `ApiError`;
 *  - PDF responses are fetched as bytes, never cached.
 *
 * This is the scaffold. The frontend module owns `src/` and will grow it: query options next to
 * each schema, `Idempotency-Key` on sign, retry policy. The shape below is the part that other
 * code depends on.
 */

import { z } from "zod";

const errorEnvelope = z.object({
  error: z.object({ code: z.string(), message: z.string() }),
});

/** A non-2xx response from the API. `code` is the stable machine string from the server. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

/** The server answered, but not with the shape we expect. Never shown to a signer verbatim. */
export class ApiValidationError extends Error {
  readonly issues: z.ZodIssue[];

  constructor(path: string, issues: z.ZodIssue[]) {
    super(`unexpected response shape from ${path}`);
    this.name = "ApiValidationError";
    this.issues = issues;
  }
}

/**
 * The signing token, held in memory for the life of the page and nowhere else.
 *
 * It arrives by `postMessage` from the host page. It is deliberately not in the URL, not in
 * `localStorage` and not in a cookie: a shared clinic tablet must forget it when the tab closes.
 */
let sessionToken: string | null = null;

export function setSessionToken(token: string | null): void {
  sessionToken = token;
}

export function hasSessionToken(): boolean {
  return sessionToken !== null;
}

export interface ApiOptions {
  method?: "GET" | "POST";
  /** Serialised as JSON. The client never sends PDF bytes, hashes, timestamps or identity. */
  body?: unknown;
  /** Required on `POST /v1/signing/sign` so a retried submission cannot sign twice. */
  idempotencyKey?: string;
  signal?: AbortSignal;
}

const BASE_URL = "/v1";

function buildHeaders(options: ApiOptions, accept: string): Headers {
  const headers = new Headers({ Accept: accept });
  if (sessionToken !== null) {
    headers.set("Authorization", `Bearer ${sessionToken}`);
  }
  if (options.body !== undefined) {
    headers.set("Content-Type", "application/json");
  }
  if (options.idempotencyKey !== undefined) {
    headers.set("Idempotency-Key", options.idempotencyKey);
  }
  return headers;
}

function buildInit(options: ApiOptions, headers: Headers): RequestInit {
  const init: RequestInit = {
    method: options.method ?? (options.body === undefined ? "GET" : "POST"),
    headers,
    // No cookies: the token is the only credential, and it is explicit.
    credentials: "omit",
    cache: "no-store",
  };
  if (options.body !== undefined) {
    init.body = JSON.stringify(options.body);
  }
  if (options.signal !== undefined) {
    init.signal = options.signal;
  }
  return init;
}

async function toApiError(response: Response): Promise<ApiError> {
  let code = "error";
  let message = "Something went wrong. Please ask a member of staff for help.";
  try {
    const parsed = errorEnvelope.safeParse(await response.json());
    if (parsed.success) {
      code = parsed.data.error.code;
      message = parsed.data.error.message;
    }
  } catch {
    // A body that is not JSON tells us nothing useful; the status still does.
  }
  return new ApiError(response.status, code, message);
}

/** Call the API and parse the response with `schema`. */
export async function api<T>(
  path: string,
  schema: z.ZodType<T>,
  options: ApiOptions = {},
): Promise<T> {
  const response = await fetch(
    `${BASE_URL}${path}`,
    buildInit(options, buildHeaders(options, "application/json")),
  );

  if (!response.ok) {
    throw await toApiError(response);
  }

  const parsed = schema.safeParse(await response.json());
  if (!parsed.success) {
    throw new ApiValidationError(path, parsed.error.issues);
  }
  return parsed.data;
}

/** Fetch a PDF. Returns the raw bytes; nothing about them is cached or persisted. */
export async function apiBytes(path: string, options: ApiOptions = {}): Promise<Uint8Array> {
  const response = await fetch(
    `${BASE_URL}${path}`,
    buildInit(options, buildHeaders(options, "application/pdf")),
  );

  if (!response.ok) {
    throw await toApiError(response);
  }
  return new Uint8Array(await response.arrayBuffer());
}
