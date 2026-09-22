import { readFileSync } from "node:fs";
import { expect, type Frame, type Page, test } from "@playwright/test";
import {
  adoptDrawn,
  adoptTyped,
  agree,
  confirmAndSign,
  fillEveryField,
  heard,
  looksSealed,
  openTask,
  readEveryPage,
  reauthenticate,
  shot,
  signIn,
  task,
  ui,
} from "./flow";

/**
 * The whole product with nothing mocked: a browser, the stand-in EHR, the signing UI in its
 * iframe, the API, the worker, Postgres, the blob store and a real PAdES seal over a real
 * timestamp.
 *
 * The specs run in order against one shared stack, because that is the thing being tested: each
 * takes a document off the worklist and leaves the state the next one expects. They are also run
 * at the sizes the document is really signed at -- a phone in a waiting room, a tablet in a clinic
 * -- rather than at a desktop width nobody uses for this.
 */

test.describe.configure({ mode: "serial" });

const embeddedFrame = (page: Page): Frame => {
  const frame = page.frames().find((f) => f.url().includes("/sign?host="));
  if (frame === undefined) {
    throw new Error("the signing UI is not embedded in this page");
  }
  return frame;
};

const sidewaysScroll = (frame: Frame) =>
  frame.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);

// --------------------------------------------------------------------------- a patient, on a phone

test.describe("a patient with a phone in the waiting room", () => {
  test.use({ viewport: { width: 390, height: 844 }, hasTouch: true, deviceScaleFactor: 2 });

  test("signs the privacy acknowledgement, and the sealed copy checks out", async ({ page }) => {
    await signIn(page, "maria");
    await shot(page, "phone-01-worklist");

    const frame = await openTask(page, "Acknowledgement of privacy practices");
    await expect(frame.getByTestId("signing-as")).toContainText("Maria Alvarez");
    await readEveryPage(frame);
    await shot(page, "phone-02-review");

    // The document is rendered to be read, and nothing forces the page sideways.
    const canvas = await frame.locator('[data-page="1"] canvas').boundingBox();
    expect(canvas?.width ?? 0).toBeGreaterThan(300);
    expect(await sidewaysScroll(embeddedFrame(page))).toBe(0);

    await frame.getByRole("button", { name: "Continue" }).click();
    await shot(page, "phone-03-consent");
    await agree(frame);

    await adoptDrawn(page, frame);
    await shot(page, "phone-04-signature-adopted");

    // A finger, not a mouse: the action that moves the flow on is a real touch target.
    const next = await frame
      .getByRole("button", { name: /^(Sign here|Next|Check your answers)$/ })
      .first()
      .boundingBox();
    expect(next?.height ?? 0).toBeGreaterThanOrEqual(44);

    await fillEveryField(frame);
    await confirmAndSign(frame);

    // Sealed inline or by the worker; the UI polls and says honestly which it is meanwhile.
    await expect(frame.getByTestId("step-done")).toBeVisible();
    await expect(frame.getByTestId("copy-ready")).toBeVisible({ timeout: 120_000 });
    expect(await sidewaysScroll(embeddedFrame(page))).toBe(0);
    await shot(page, "phone-05-signed-and-sealed");

    // The signer's own copy, out of the UI, really is a sealed PDF.
    const [download] = await Promise.all([
      page.waitForEvent("download"),
      frame.getByRole("link", { name: "Save your signed copy" }).click(),
    ]);
    const saved = await download.path();
    expect(saved).not.toBeNull();
    looksSealed(readFileSync(saved as string));

    // The host heard every milestone, and no token reached a URL or browser storage.
    expect(await heard(page)).toEqual(
      expect.arrayContaining(["esign:ready", "esign:init", "esign:signed", "esign:sealed"]),
    );
    expect(page.url()).not.toContain("est_");
    const stored = await embeddedFrame(page).evaluate(() =>
      JSON.stringify([{ ...localStorage }, { ...sessionStorage }]),
    );
    expect(stored).not.toContain("est_");

    // The webhook arrives, the EHR verifies it and files the sealed PDF without being asked.
    await expect(page.getByTestId("filed-link")).toBeVisible({ timeout: 120_000 });
    await page.getByTestId("filed-link").click();
    await expect(
      page.getByRole("heading", { name: "Acknowledgement of privacy practices" }),
    ).toBeVisible();
    await shot(page, "phone-06-filed-in-the-chart");

    // And anybody can make the service re-check the seal, the hashes and the chain on the spot.
    await page.getByTestId("verify").click();
    await expect(page.getByTestId("verification-result")).toContainText("Verified.");
    await shot(page, "phone-07-verified");
  });
});

// --------------------------------------------------------------------------- what the host was told

test("the webhook log is verified deliveries and nothing about the patient", async ({ page }) => {
  await signIn(page, "alice");
  await page.getByRole("link", { name: "Webhooks" }).click();

  const rows = page.locator('[data-testid="webhook-row"]');
  await expect(rows.first()).toBeVisible();
  const verified = await rows.evaluateAll((items) =>
    items.map((i) => (i as HTMLElement).dataset.verified),
  );
  expect(verified).not.toContain("false");
  const events = await rows.evaluateAll((items) =>
    items.map((i) => (i as HTMLElement).dataset.event),
  );
  expect(events).toContain("envelope.completed");
  expect(events).toContain("envelope.sealed");

  // SPEC section 10: a webhook leaves the network, so it carries ids, statuses and hashes only.
  const log = page.getByTestId("webhook-log");
  await expect(log).not.toContainText("Maria");
  await expect(log).not.toContainText("mrn-");
  await shot(page, "10-webhook-log");
});

// --------------------------------------------------------------------------- three signers, in order

test.describe("a procedure consent needing three people", () => {
  test.describe("the patient, on a clinic tablet", () => {
    test.use({ viewport: { width: 834, height: 1112 }, hasTouch: true });

    test("signs first and is told the copy comes later", async ({ page }) => {
      await signIn(page, "maria");
      const frame = await openTask(page, "Consent to a procedure");
      const pages = await readEveryPage(frame);
      expect(pages).toBe(3);
      await shot(page, "tablet-01-review");
      expect(await sidewaysScroll(embeddedFrame(page))).toBe(0);

      await frame.getByRole("button", { name: "Continue" }).click();
      await shot(page, "tablet-02-consent");
      await agree(frame);
      await adoptDrawn(page, frame);
      await shot(page, "tablet-03-signature-adopted");
      await fillEveryField(frame);
      await confirmAndSign(frame);

      await expect(frame.getByTestId("waiting-on-others")).toContainText(
        "the witness and the clinician",
      );
      await shot(page, "tablet-04-waiting-on-others");
    });
  });

  test("the clinician cannot jump the queue", async ({ page }) => {
    await signIn(page, "priya");
    await expect(task(page, "Consent to a procedure").getByTestId("task-waiting")).toContainText(
      "witness",
    );
  });

  test("the witness signs next", async ({ page }) => {
    await signIn(page, "ben");
    const frame = await openTask(page, "Consent to a procedure");
    await readEveryPage(frame);
    await frame.getByRole("button", { name: "Continue" }).click();
    await agree(frame);
    await adoptTyped(frame, "Ben Doyle");
    await fillEveryField(frame);
    await confirmAndSign(frame);
    await expect(frame.getByTestId("step-done")).toBeVisible();
  });

  test("the clinician re-authenticates through the EHR, signs, and it seals", async ({ page }) => {
    await signIn(page, "priya");
    const frame = await openTask(page, "Consent to a procedure");
    await readEveryPage(frame);
    await frame.getByRole("button", { name: "Continue" }).click();
    await agree(frame);
    await adoptTyped(frame, "Priya Raman");
    await fillEveryField(frame);
    await expect(frame.getByTestId("step-sign-summary")).toBeVisible();
    await frame.getByRole("button", { name: "Continue" }).click();
    await shot(page, "20-reauth-asked-for");

    await reauthenticate(page, frame);
    await shot(page, "21-reauth-confirmed");
    expect(await heard(page)).toEqual(
      expect.arrayContaining(["esign:reauth_required", "esign:reauth_done"]),
    );

    await frame.getByRole("checkbox", { name: /I want to sign it as/ }).check();
    await frame.getByRole("button", { name: "Sign document" }).click();
    await expect(frame.getByTestId("copy-ready")).toBeVisible({ timeout: 150_000 });
    await shot(page, "22-three-signers-sealed");

    await expect(page.getByTestId("filed-link")).toBeVisible({ timeout: 120_000 });
    await page.getByTestId("filed-link").click();
    await page.getByTestId("verify").click();
    await expect(page.getByTestId("verification-result")).toContainText("Verified.");
    await shot(page, "23-three-signers-verified");

    const pdf = await page.request.get(`${new URL(page.url()).pathname}/pdf`);
    looksSealed(Buffer.from(await pdf.body()));
  });
});

// --------------------------------------------------------------------------- the paper path

test("choosing paper ends the envelope and tells the clinic", async ({ page }) => {
  await signIn(page, "grace");
  const frame = await openTask(page, "Consent to treatment");
  await readEveryPage(frame);
  await frame.getByRole("button", { name: "Continue" }).click();

  await expect(frame.getByTestId("step-consent")).toBeVisible();
  await frame.getByRole("button", { name: "I'd rather sign on paper" }).click();
  await expect(frame.getByTestId("step-decline")).toBeVisible();
  await expect(frame.getByRole("radio", { name: "I would rather sign on paper" })).toBeChecked();
  await shot(page, "30-decline");

  await frame.getByRole("button", { name: "Stop and tell the clinic" }).click();
  await expect(frame.getByTestId("screen-declined")).toBeVisible();
  await expect(page.getByText("Signed on paper instead")).toBeVisible();
  expect(await heard(page)).toContain("esign:declined");
  await shot(page, "31-declined");

  await signIn(page, "grace");
  await expect(task(page, "Consent to treatment")).toContainText("sign this on paper");
  await page.getByRole("link", { name: "Webhooks" }).click();
  await expect(
    page.locator('[data-testid="webhook-row"][data-event="envelope.declined"]').first(),
  ).toBeVisible();
});

// --------------------------------------------------------------------------- the clinic tablet

test.describe("the clinic tablet", () => {
  test.use({ viewport: { width: 834, height: 1112 }, hasTouch: true });

  test("is started by staff, signed by the patient, and handed back", async ({ page }) => {
    await signIn(page, "alice");
    await page.getByRole("link", { name: "Clinic tablet" }).click();

    const card = page
      .locator('[data-testid="kiosk-task"]')
      .filter({ has: page.getByRole("heading", { name: "Consent to treatment (physiotherapy)" }) });
    await card.getByRole("radio", { name: "Photo ID" }).check();
    await shot(page, "40-kiosk-start");
    await card.getByTestId("kiosk-start").click();

    await expect(page).toHaveURL(/\/sign\//);
    await expect(page.getByText(/identity checked by photo id/i)).toBeVisible();
    const frame = ui(page);
    await expect(frame.getByTestId("step-review")).toBeVisible({ timeout: 45_000 });
    await readEveryPage(frame);
    await frame.getByRole("button", { name: "Continue" }).click();
    await agree(frame);
    await adoptDrawn(page, frame);
    await fillEveryField(frame);
    await confirmAndSign(frame);

    // The tablet ends by asking for itself back, and forgets who was holding it.
    await expect(frame.getByTestId("screen-handback")).toBeVisible();
    await expect(frame.getByText("Maria Alvarez")).toHaveCount(0);
    await expect(page.getByText("hand the tablet back")).toBeVisible();
    await shot(page, "41-kiosk-handback");

    await page.getByTestId("kiosk-finish").click();
    await expect(page.getByRole("heading", { name: "Clinic tablet" })).toBeVisible();

    // The other clinician can open the chart and re-verify what was signed on that tablet.
    await signIn(page, "tomas");
    await page.getByRole("link", { name: "Maria Alvarez" }).click();
    const filed = page.locator('[data-testid="chart-document"]', { hasText: "physiotherapy" });
    await expect(filed).toBeVisible({ timeout: 120_000 });
    await filed.getByRole("link").click();
    await page.getByTestId("verify").click();
    await expect(page.getByTestId("verification-result")).toContainText("Verified.");
    await shot(page, "42-kiosk-verified");
  });
});
