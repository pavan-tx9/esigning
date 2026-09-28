import { expect, test } from "@playwright/test";
import {
  auditTrail,
  placeEveryField,
  readAndContinue,
  shot,
  signDocument,
  signIn,
  task,
  typeSignature,
} from "./flow";

/**
 * Addendum 4: the host page imports the signing library and calls the Signer API from the
 * signer's browser. There is no iframe and no postMessage. The trail still has to say that this
 * library drove the session.
 */

test.describe.configure({ mode: "serial" });

test("signs in the page itself, and the trail records the SDK", async ({ page }) => {
  test.setTimeout(180_000);
  await signIn(page, "maria");
  await task(page, "Acknowledgement of privacy practices (this page)")
    .getByTestId("open-task-sdk")
    .click();
  await expect(page).toHaveURL(/\/sign\/.+\/sdk/);
  await expect(page.getByTestId("sdk-root")).toBeVisible();
  await expect(page.getByTestId("step-read")).toBeVisible({ timeout: 45_000 });
  expect(page.frames().filter((frame) => frame.url().includes("/sign?host="))).toHaveLength(0);
  await shot(page, "sdk-01-in-the-page");

  await readAndContinue(page);
  await typeSignature(page, "Maria Alvarez");
  await placeEveryField(page);
  await signDocument(page);
  await expect(page.getByTestId("step-done")).toBeVisible();
  await shot(page, "sdk-02-signed");

  const envelopeId = await page.locator("#esign-sdk").getAttribute("data-envelope-id");
  expect(envelopeId).toMatch(/^[0-9a-f-]{36}$/);
  const events = await auditTrail(page, envelopeId as string);
  const created = events.find((event) => event.event_type === "session.created");
  expect(created?.data.client_mode).toBe("sdk");
  const signed = events.find((event) => event.event_type === "signer.signed");
  expect(String(signed?.data.client ?? "")).toMatch(/^esign-sdk\//);
});
