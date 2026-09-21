/**
 * Placeholder. The frontend module owns `src/` and replaces this with the six-state signing flow
 * in SPEC section 11 (connecting, review, consent, sign, confirm, done).
 *
 * It exists so the scaffold is provably alive: `bun run dev`, `bun run build` and `bun run test`
 * all have something real to do.
 */

import { hasSessionToken } from "@/lib/api";

export function App() {
  return (
    <main className="mx-auto flex min-h-dvh max-w-2xl flex-col justify-center gap-4 px-6 py-12">
      <h1 className="font-semibold text-2xl text-ink-900">Signing service</h1>
      <p className="text-ink-700 leading-relaxed">
        This is the scaffold. The signing flow is not built yet.
      </p>
      <p className="text-ink-500 text-sm" data-testid="token-state">
        {hasSessionToken() ? "Session token received." : "Waiting for a session token."}
      </p>
    </main>
  );
}
