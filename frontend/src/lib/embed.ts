/**
 * The embedding protocol (SPEC section 9). The UI runs in an iframe; the host page hands it the
 * session token by `postMessage`. This module decides which messages to believe.
 *
 * A message is trusted only when all three hold:
 *  - it came from `window.parent` (not a sibling frame, not a popup, not an extension);
 *  - its origin is one of the host's allowed origins;
 *  - it parses against the schema for its type.
 *
 * The allowed origins are configuration the server puts into the page it serves at `/sign`:
 *   <meta name="esign-allowed-origins" content="https://ehr.example https://portal.example">
 * (the same list it sends as the `frame-ancestors` CSP). With no list, nothing is trusted and the
 * UI shows its "could not connect" screen: it fails closed. In a dev build only, an absent list
 * falls back to the page's own origin so the local harness works.
 */

import { z } from "zod";

const tokenSchema = z
  .string()
  .min(8)
  .max(512)
  .regex(/^est_[A-Za-z0-9._~-]+$/);

/**
 * A BCP 47 language tag, which is all `?locale=` on the Signer API will take (the server refuses
 * anything else). A host that sends junk here loses its choice of disclosure language, not its
 * session: the tag is dropped and the default locale is served.
 */
const localeSchema = z
  .string()
  .max(35)
  .regex(/^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$/);

const initSchema = z.object({
  type: z.literal("esign:init"),
  token: tokenSchema,
  locale: localeSchema.optional().catch(undefined),
});

const reauthDoneSchema = z.object({ type: z.literal("esign:reauth_done") });

export type InboundMessage = z.infer<typeof initSchema> | z.infer<typeof reauthDoneSchema>;

export type OutboundMessage =
  | { type: "esign:ready" }
  | { type: "esign:reauth_required"; session_id: string }
  | { type: "esign:signed" }
  | { type: "esign:sealed" }
  | { type: "esign:declined" }
  | { type: "esign:expired" }
  | { type: "esign:resize"; height: number };

function normaliseOrigin(value: string): string | null {
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" && url.protocol !== "http:") {
      return null;
    }
    return url.origin;
  } catch {
    return null;
  }
}

/** Parse a space- or comma-separated origin list. Wildcards and junk are dropped, not guessed at. */
export function parseOriginList(raw: string | null | undefined): string[] {
  if (raw === null || raw === undefined) {
    return [];
  }
  const origins = raw
    .split(/[\s,]+/)
    .filter((entry) => entry !== "" && !entry.includes("*"))
    .map(normaliseOrigin)
    .filter((origin): origin is string => origin !== null);
  return [...new Set(origins)];
}

export function resolveAllowedOrigins(doc: Document = document): string[] {
  const meta = doc.querySelector('meta[name="esign-allowed-origins"]');
  const configured = parseOriginList(meta?.getAttribute("content"));
  if (configured.length > 0) {
    return configured;
  }
  const fromEnv = parseOriginList(
    import.meta.env.VITE_ALLOWED_PARENT_ORIGINS as string | undefined,
  );
  if (fromEnv.length > 0) {
    return fromEnv;
  }
  return import.meta.env.DEV ? [window.location.origin] : [];
}

interface MessageLike {
  origin: string;
  source: MessageEventSource | null;
  data: unknown;
}

/**
 * Returns the message if it should be believed, otherwise null. Pure: everything it needs is
 * passed in, so the rules are tested directly.
 */
export function acceptMessage(
  event: MessageLike,
  allowedOrigins: readonly string[],
  parentWindow: unknown,
): InboundMessage | null {
  if (parentWindow === null || parentWindow === undefined || event.source !== parentWindow) {
    return null;
  }
  if (event.origin === "null" || !allowedOrigins.includes(event.origin)) {
    return null;
  }
  const init = initSchema.safeParse(event.data);
  if (init.success) {
    return init.data;
  }
  const done = reauthDoneSchema.safeParse(event.data);
  return done.success ? done.data : null;
}

/**
 * The live connection to the host page. After `init` is accepted, the origin that sent it is the
 * only one spoken to or listened to for the rest of the session.
 */
export class ParentChannel {
  private readonly allowed: readonly string[];
  private lockedOrigin: string | null = null;

  private readonly parent: Window | null;

  constructor(
    allowedOrigins: readonly string[],
    parent: Window | null = window.parent === window ? null : window.parent,
  ) {
    this.allowed = allowedOrigins;
    this.parent = parent;
  }

  get embedded(): boolean {
    return this.parent !== null;
  }

  accept(event: MessageEvent): InboundMessage | null {
    const origins = this.lockedOrigin === null ? this.allowed : [this.lockedOrigin];
    const message = acceptMessage(event, origins, this.parent);
    if (message?.type === "esign:init") {
      this.lockedOrigin = event.origin;
    }
    return message;
  }

  /** Never posts with a `*` target: a message only goes to an origin we were told to trust. */
  post(message: OutboundMessage): void {
    const parent = this.parent;
    if (parent === null) {
      return;
    }
    const targets = this.lockedOrigin === null ? this.allowed : [this.lockedOrigin];
    for (const origin of targets) {
      parent.postMessage(message, origin);
    }
  }
}
