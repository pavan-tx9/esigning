import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterAll, afterEach, beforeAll } from "vitest";
import { server } from "@/test/server";

// Every request a test makes must be one the test declared. An unhandled request is a bug in the
// test or a call the app should not be making, so it fails rather than hitting the network.
beforeAll(() => {
  server.listen({ onUnhandledRequest: "error" });
  bridgeAbortSignals();
});

afterEach(() => {
  cleanup();
  server.resetHandlers();
});

afterAll(() => {
  server.close();
});

/**
 * jsdom replaces the global AbortController with its own, and Node's fetch refuses a signal that
 * is not *its* AbortSignal ("Expected signal to be an instance of AbortSignal"). TanStack Query
 * passes a signal on every query, so without this no query could run under jsdom. The signal is
 * kept out of the real fetch and its meaning is preserved: an abort still rejects with AbortError.
 * Test environment only; the browser has one AbortSignal and needs none of this.
 */
function bridgeAbortSignals(): void {
  const intercepted = globalThis.fetch;
  globalThis.fetch = (input, init) => {
    const signal = init?.signal;
    if (signal === undefined || signal === null) {
      return intercepted(input, init);
    }
    const { signal: _dropped, ...rest } = init ?? {};
    const aborted = () => new DOMException("The operation was aborted.", "AbortError");
    if (signal.aborted) {
      return Promise.reject(aborted());
    }
    return new Promise((resolve, reject) => {
      signal.addEventListener("abort", () => reject(aborted()), { once: true });
      intercepted(input, rest).then(resolve, reject);
    });
  };
}
