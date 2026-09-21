import { defineConfig, devices } from "@playwright/test";

/**
 * End-to-end runs drive the real signing UI against the real API. The integration step adds the
 * specs and the demo host; this config is the scaffold they land in.
 */
export default defineConfig({
  testDir: "./e2e",
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
