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
 * The Signer API's schemas, query options and mutations live next door in `signing-api.ts` and
 * call through the three functions exported here.
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

/** The request never reached the server, or the answer never reached us. Safe to retry. */
export class ApiNetworkError extends Error {
  constructor() {
    super("The network request did not complete.");
    this.name = "ApiNetworkError";
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

async function send(path: string, options: ApiOptions, accept: string): Promise<Response> {
  try {
    return await fetch(`${BASE_URL}${path}`, buildInit(options, buildHeaders(options, accept)));
  } catch (error) {
    // An abort is the caller's own doing and must stay recognisable as one.
    if (error instanceof DOMException && error.name === "AbortError") {
      throw error;
    }
    throw new ApiNetworkError();
  }
}

async function parseJson<T>(path: string, response: Response, schema: z.ZodType<T>): Promise<T> {
  let body: unknown = {};
  if (response.status !== 204) {
    try {
      body = await response.json();
    } catch {
      throw new ApiValidationError(path, []);
    }
  }
  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    throw new ApiValidationError(path, parsed.error.issues);
  }
  return parsed.data;
}

/** Call the API and parse the response with `schema`. */
export async function api<T>(
  path: string,
  schema: z.ZodType<T>,
  options: ApiOptions = {},
): Promise<T> {
  const response = await send(path, options, "application/json");
  if (!response.ok) {
    throw await toApiError(response);
  }
  return parseJson(path, response, schema);
}

export type PdfOrPending<T> = { kind: "pdf"; bytes: Uint8Array } | { kind: "pending"; body: T };

/**
 * For an endpoint that answers 200 with a PDF when it is ready and 202 with a JSON body while it
 * is not (`GET /v1/signing/copy`). The 202 body is parsed with `pendingSchema` like any other.
 */
export async function apiPdfOrPending<T>(
  path: string,
  pendingSchema: z.ZodType<T>,
  options: ApiOptions = {},
): Promise<PdfOrPending<T>> {
  const response = await send(path, options, "application/pdf, application/json");
  if (!response.ok) {
    throw await toApiError(response);
  }
  if (response.status === 202) {
    return { kind: "pending", body: await parseJson(path, response, pendingSchema) };
  }
  return { kind: "pdf", bytes: new Uint8Array(await response.arrayBuffer()) };
}

/** Fetch a PDF. Returns the raw bytes; nothing about them is cached or persisted. */
export async function apiBytes(path: string, options: ApiOptions = {}): Promise<Uint8Array> {
  const response = await send(path, options, "application/pdf");
  if (!response.ok) {
    throw await toApiError(response);
  }
  return new Uint8Array(await response.arrayBuffer());
}
