import { expect, test } from "@playwright/test";

// A single check that the scaffold serves. The real end-to-end flow belongs to the integration
// step, which drives the demo host through prepare, sign, seal and download.
test("the signing UI loads", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Signing service" })).toBeVisible();
});
