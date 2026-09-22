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
      attestReauth: (scenario: Scenario) => void;
      expireSession: (scenario: Scenario) => void;
      /** Another signer on the same envelope signs: the current revision moves on. */
      otherSignerSigned: (scenario: Scenario) => void;
      peek: (scenario: Scenario) => unknown;
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
  attestReauth: (scenario) => mockDb.attestReauth(scenario),
  expireSession: (scenario) => mockDb.expireSession(scenario),
  otherSignerSigned: (scenario) => mockDb.otherSignerSigned(scenario),
  peek: (scenario) => mockDb.peek(scenario),
};

await import("@/main");
