import { defineConfig, devices } from "@playwright/test";

/**
 * End-to-end runs against the *real* stack: Postgres, the API, the worker, the built signing UI
 * and the stand-in EHR in `demo-host/`. Nothing is mocked. `demo-host/demo.sh` brings all of it up
 * and these specs drive a browser through it exactly as a person would.
 *
 * The other config (`playwright.config.ts`) covers the same UI against the MSW mocks, which is
 * fast and runs anywhere. This one is the proof that the mocks were telling the truth.
 *
 * Run it with `make e2e-demo`. It needs Docker.
 *
 * Serial on purpose: the whole point is one shared database and one shared worklist, so two specs
 * signing at once would be testing the harness rather than the product.
 */
export default defineConfig({
  testDir: "./e2e/demo",
  fullyParallel: false,
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  retries: 0,
  reporter: process.env.CI ? "github" : "list",
  timeout: 180_000,
  expect: { timeout: 20_000 },
  use: {
    baseURL: process.env.DEMO_HOST_URL ?? "http://localhost:8100",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    // A clinician at a desk. The phone and tablet sizes are set per spec.
    viewport: { width: 1180, height: 900 },
    reducedMotion: "reduce",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: "DEMO_QUIET=1 bash ../demo-host/demo.sh",
    url: "http://localhost:8100/healthz",
    // A fresh worklist per run, because the demo host keeps its state in memory and these specs
    // take documents off it. `DEMO_REUSE=1` attaches to a stack that is already up instead, which
    // is quick while writing a spec and wrong for a full run.
    reuseExistingServer: Boolean(process.env.DEMO_REUSE),
    timeout: 300_000,
    stdout: "pipe",
    stderr: "pipe",
  },
});
