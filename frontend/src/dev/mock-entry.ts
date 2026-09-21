/**
 * Dev-only entry: start the MSW worker, expose the two things a host *backend* would do
 * (attest re-authentication, let a session lapse), then boot the real app unchanged.
 */

import { setupWorker } from "msw/browser";
import { mockDb, type Scenario } from "@/mocks/db";
import { signerApiHandlers } from "@/mocks/handlers";

declare global {
  interface Window {
    __esignMock?: {
      attestReauth: (scenario: Scenario) => void;
      expireSession: (scenario: Scenario) => void;
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
  peek: (scenario) => mockDb.peek(scenario),
};

await import("@/main");
