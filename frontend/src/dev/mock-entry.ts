/**
 * Dev-only entry: start the MSW worker, expose the things that happen *outside* this browser (a
 * host backend attesting re-authentication, a session lapsing, a co-signer signing the same
 * envelope), then boot the real app unchanged.
 */

import { setupWorker } from "msw/browser";
import { mockDb, type Scenario } from "@/mocks/db";
import { signerApiHandlers } from "@/mocks/handlers";

declare global {
  interface Window {
    __esignMock?: {
      attestReauth: (scenario: Scenario, position?: number) => void;
      expireSession: (scenario: Scenario, position?: number) => void;
      /** Another signer on the same envelope signs: the current revision moves on. */
      otherSignerSigned: (scenario: Scenario, position?: number) => void;
      /** The host takes this person's saved signature off the file mid-flow. */
      hostRevokedSignature: (scenario: Scenario, position?: number) => void;
      /** The consent span runs out between the session being read and Continue being pressed. */
      consentNoLongerStanding: (scenario: Scenario, position?: number) => void;
      peek: (scenario: Scenario, position?: number) => unknown;
    };
  }
}

const latency = Number(new URLSearchParams(window.location.search).get("latency") ?? "300");

const worker = setupWorker(
  ...signerApiHandlers({ latency: Number.isFinite(latency) ? latency : 0 }),
);
await worker.start({
  serviceWorker: { url: "/src/dev/mockServiceWorker.js" },
  onUnhandledRequest: "bypass",
  quiet: true,
});

window.__esignMock = {
  attestReauth: (scenario, position) => mockDb.attestReauth(scenario, position),
  expireSession: (scenario, position) => mockDb.expireSession(scenario, position),
  otherSignerSigned: (scenario, position) => mockDb.otherSignerSigned(scenario, position),
  hostRevokedSignature: (scenario, position) => mockDb.hostRevokedSignature(scenario, position),
  consentNoLongerStanding: (scenario, position) =>
    mockDb.consentNoLongerStanding(scenario, position),
  peek: (scenario, position) => mockDb.peek(scenario, position),
};

await import("@/main");
