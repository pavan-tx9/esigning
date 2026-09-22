import { defineConfig, devices } from "@playwright/test";

/**
 * The signing UI in a real browser, against the MSW mocks, through the dev harness that plays the
 * host page. Fast, and needs nothing but this project.
 *
 * `e2e/demo/` is the other half -- the same UI against the real API through the stand-in EHR --
 * and is run by `playwright.demo.config.ts` (`make e2e-demo`), which brings that stack up itself.
 */
export default defineConfig({
  testDir: "./e2e",
  testIgnore: ["demo/**"],
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: process.env.ESIGN_UI_URL ?? "http://localhost:5273",
    trace: "on-first-retry",
    // A patient on a clinic tablet, not a desktop browser at 1920px.
    viewport: { width: 834, height: 1112 },
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: "bun run dev",
    url: "http://localhost:5273",
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
});
