import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";
import {
  adoptDrawn,
  adoptTypedAndSave,
  agree,
  confirmAndSign,
  fillEveryField,
  looksSealed,
  openFromQueue,
  openTask,
  readEveryPage,
  reauthenticate,
  reloadUntilVisible,
  shot,
  signIn,
  ui,
  useSavedSignature,
} from "./flow";

/**
 * Addendum 1 against the real stack: a paper document filed by the front desk, a clinician's
 * signing queue on one confirmation, a signature saved on one order and offered on the next, a
 * shared tablet that is never offered it, and the front desk taking it away.
 *
 * Serial with the rest of the demo suite, on documents of its own (Sam's, and the clinicians'
 * order queues), so it leaves the worklist `signing.spec.ts` expects untouched.
 */

test.describe.configure({ mode: "serial" });

const SAMPLE_SCAN = fileURLToPath(
  new URL("../../../demo-host/src/demo_host/static/sample-scan.pdf", import.meta.url),
);

// --------------------------------------------------------------------------- A. a paper document

test("the front desk files a scan of an ink-signed consent, and it is sealed and verified", async ({
  page,
}) => {
  await signIn(page, "alice");
  await page.getByRole("link", { name: "File a paper document" }).click();
  await expect(page.getByRole("heading", { name: "File a paper document" })).toBeVisible();

  await page.getByLabel("Patient").selectOption({ index: 0 });
  await expect(page.getByLabel("Patient").locator("option:checked")).toContainText("Maria Alvarez");
  await page.getByLabel("Document type").selectOption("patient_consent");
  await page.getByLabel("Title in the chart").fill("Consent to treatment (signed on paper)");
  await page.getByLabel("Date it was signed on paper").fill("2026-09-01");
  await page.locator("#archive-scan").setInputFiles(SAMPLE_SCAN);
  await page.locator("#signer-name-1").fill("Maria Alvarez");
  await page.locator("#signer-name-2").fill("Ben Doyle");
  await page.getByLabel("The paper original").selectOption("retained");
  await page
    .getByRole("checkbox", { name: /attest that this scan is a complete and accurate copy/ })
    .check();
  await shot(page, "50-archive-form");
  await page.getByTestId("archive-file").click();

  // Filed: the chart says it is on its way, and the sealed copy comes back by webhook.
  await expect(page.getByTestId("archive-filed")).toBeVisible();
  const filed = page.locator('[data-testid="chart-document"][data-kind="paper_archive"]');
  await reloadUntilVisible(page, filed);
  await shot(page, "51-archive-in-chart");
  await filed.getByRole("link").click();
  await expect(page.getByTestId("document-kind")).toContainText("signed on paper on 2026-09-01");
  await expect(page.getByText("not prove the ink signature is genuine")).toBeVisible();

  await page.getByTestId("verify").click();
  await expect(page.getByTestId("verification-result")).toContainText("Verified.");
  await shot(page, "52-archive-verified");

  const href = await page.getByTestId("download-sealed").getAttribute("href");
  const pdf = await page.request.get(href ?? "");
  expect(pdf.ok()).toBe(true);
  looksSealed(Buffer.from(await pdf.body()));
  // No name or record number went into a URL to get here.
  expect(page.url()).not.toMatch(/Alvarez|mrn-/);
});

// --------------------------------------------------------------------------- C. the signing queue

test("a clinician confirms once and signs three orders in a row; each record says which confirmation", async ({
  page,
}) => {
  await signIn(page, "priya");
  await page.getByRole("link", { name: "Signing queue" }).click();
  await expect(page.getByRole("heading", { name: "Signing queue" })).toBeVisible();
  await expect(page.locator('[data-testid="queue-task"]')).toHaveCount(4);
  await shot(page, "60-queue");

  // One confirmation, checked by the EHR and attested server to server on the first document.
  await page.locator("#queue-password").fill("demo1234");
  await page.getByTestId("queue-confirm").click();
  await expect(page.getByTestId("queue-confirmed")).toBeVisible();
  await shot(page, "61-queue-confirmed");

  const orders = ["Order sign-off ORD-4471", "Order sign-off ORD-4472", "Order sign-off ORD-4473"];
  for (const [index, title] of orders.entries()) {
    const frame = await openFromQueue(page, title);
    await readEveryPage(frame);
    await frame.getByRole("button", { name: "Continue" }).click();
    await agree(frame);
    await frame.getByRole("radio", { name: /Use my printed name/ }).check();
    await frame.getByRole("button", { name: "Use this signature" }).click();
    await fillEveryField(frame);
    await frame.getByRole("button", { name: "Continue" }).click();

    // No hand-off: the service already vouches for her, and the screen says on what grounds.
    await expect(frame.getByTestId("step-confirm")).toBeVisible();
    const covered = frame.getByTestId("reauth-verified");
    await expect(covered).toContainText(/You confirmed your identity at \d{1,2}:\d{2}/);
    await expect(covered).toHaveAttribute("data-reauth-scope", index === 0 ? "session" : "span");
    if (index > 0) {
      await expect(covered).toContainText("for an earlier document");
    }
    await expect(frame.getByRole("button", { name: "Confirm it's me" })).toHaveCount(0);
    await expect(page.locator("#reauth")).toBeHidden();
    if (index === 1) {
      await shot(page, "62-queue-second-document-covered");
    }

    await frame.getByRole("checkbox", { name: /I want to sign it as/ }).check();
    await frame.getByRole("button", { name: "Sign document" }).click();
    await expect(frame.getByTestId("step-done")).toBeVisible();
    await expect(page.getByTestId("back-link")).toBeVisible({ timeout: 120_000 });
    // The host page never had to ask for a password on any of the three.
    await expect(page.locator('#log li[data-message="esign:reauth_required"]')).toHaveCount(0);
    await page.getByTestId("back-link").click();
    await expect(page.getByRole("heading", { name: "Signing queue" })).toBeVisible();
  }
  await expect(page.locator('[data-testid="queue-task"][data-status="signed"]')).toHaveCount(3);
  await shot(page, "63-queue-done");

  // The sealed copies are in the charts, and the verifier is happy with a borrowed attestation.
  await page.getByRole("link", { name: "Worklist" }).click();
  await page.getByRole("link", { name: "Sam Okafor" }).click();
  const order = page.locator('[data-testid="chart-document"]', { hasText: "ORD-4472" });
  await reloadUntilVisible(page, order);
  await order.getByRole("link").click();
  await page.getByTestId("verify").click();
  await expect(page.getByTestId("verification-result")).toContainText("Verified.");
  await shot(page, "64-queue-order-verified");
});

// --------------------------------------------------------------------------- B. a saved signature

test("a clinician saves a signature on one order and is offered it on the next", async ({
  page,
}) => {
  await signIn(page, "tomas");
  await page.getByRole("link", { name: "Signing queue" }).click();

  // The first order: the usual hand-off, and the signature kept for next time.
  let frame = await openFromQueue(page, "Order sign-off ORD-4480");
  await readEveryPage(frame);
  await frame.getByRole("button", { name: "Continue" }).click();
  await agree(frame);
  await adoptTypedAndSave(frame, "Tomas Silva");
  await shot(page, "70-save-signature");
  await fillEveryField(frame);
  await frame.getByRole("button", { name: "Continue" }).click();
  await reauthenticate(page, frame);
  await frame.getByRole("checkbox", { name: /I want to sign it as/ }).check();
  await frame.getByRole("button", { name: "Sign document" }).click();
  await expect(frame.getByTestId("step-done")).toBeVisible();
  await expect(page.getByTestId("back-link")).toBeVisible({ timeout: 120_000 });
  await page.getByTestId("back-link").click();

  // The second: offered first, placed per field, and the confirmation from the first still holds.
  frame = await openFromQueue(page, "Order sign-off ORD-4481");
  await readEveryPage(frame);
  await frame.getByRole("button", { name: "Continue" }).click();
  await agree(frame);
  await expect(frame.getByText(/Typed · saved on/)).toBeVisible();
  await shot(page, "71-saved-signature-offered");
  await useSavedSignature(frame);
  await fillEveryField(frame);
  await frame.getByRole("button", { name: "Continue" }).click();
  await expect(frame.getByTestId("reauth-verified")).toHaveAttribute("data-reauth-scope", "span");
  await frame.getByRole("checkbox", { name: /I want to sign it as/ }).check();
  await frame.getByRole("button", { name: "Sign document" }).click();
  await expect(frame.getByTestId("copy-ready")).toBeVisible({ timeout: 120_000 });
  await shot(page, "72-signed-with-saved-signature");
  await expect(page.getByTestId("filed-link")).toBeVisible({ timeout: 120_000 });
  await page.getByTestId("filed-link").click();
  await page.getByTestId("verify").click();
  await expect(page.getByTestId("verification-result")).toContainText("Verified.");
});

// --------------------------------------------------------------------------- B. kiosk, and the host

test.describe("a saved signature, a shared tablet, and the front desk", () => {
  test.use({ viewport: { width: 834, height: 1112 }, hasTouch: true });

  test("the patient saves one on the portal; the tablet never offers it; the host removes it", async ({
    page,
  }) => {
    // Sam, on the portal, keeps his signature.
    await signIn(page, "sam");
    let frame = await openTask(page, "Acknowledgement of privacy practices (annual)");
    await readEveryPage(frame);
    await frame.getByRole("button", { name: "Continue" }).click();
    await agree(frame);
    await adoptTypedAndSave(frame, "Sam Okafor");
    await fillEveryField(frame);
    await confirmAndSign(frame);
    await expect(frame.getByTestId("step-done")).toBeVisible();

    // The front desk hands him the clinic tablet for the next one: nothing saved is offered.
    await signIn(page, "alice");
    await page.getByRole("link", { name: "Clinic tablet" }).click();
    const card = page
      .locator('[data-testid="kiosk-task"]')
      .filter({ has: page.getByRole("heading", { name: "Consent to treatment (hydrotherapy)" }) });
    await card.getByRole("radio", { name: "Photo ID" }).check();
    await card.getByTestId("kiosk-start").click();
    frame = ui(page);
    await expect(frame.getByTestId("step-review")).toBeVisible({ timeout: 45_000 });
    await readEveryPage(frame);
    await frame.getByRole("button", { name: "Continue" }).click();
    await agree(frame);
    await expect(frame.getByTestId("step-sign-adopt")).toBeVisible();
    await expect(frame.getByTestId("saved-signature")).toHaveCount(0);
    await expect(frame.getByTestId("save-signature")).toHaveCount(0);
    await shot(page, "80-kiosk-nothing-saved-offered");
    await adoptDrawn(page, frame);
    await fillEveryField(frame);
    await confirmAndSign(frame);
    await expect(frame.getByTestId("screen-handback")).toBeVisible();
    await page.getByTestId("kiosk-finish").click();

    // The front desk removes what Sam saved, over the host API.
    await page.getByRole("link", { name: "People" }).click();
    await page
      .locator('[data-testid="person"][data-username="sam"]')
      .getByTestId("revoke-signature")
      .click();
    await expect(page.getByTestId("people-result")).toHaveAttribute("data-result", "revoked");
    await shot(page, "81-saved-signature-removed");

    // His next session on the portal is not offered it.
    await signIn(page, "sam");
    frame = await openTask(page, "Consent to treatment (review appointment)");
    await readEveryPage(frame);
    await frame.getByRole("button", { name: "Continue" }).click();
    await agree(frame);
    await expect(frame.getByTestId("step-sign-adopt")).toBeVisible();
    await expect(frame.getByTestId("saved-signature")).toHaveCount(0);
    await expect(frame.getByTestId("save-signature")).toBeVisible();
    await shot(page, "82-after-revoke-nothing-offered");
  });
});
