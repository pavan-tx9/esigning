import { readFileSync } from "node:fs";
import { expect, type Frame, type Page, test } from "@playwright/test";
import {
  agreeAndContinue,
  drawSignature,
  heard,
  looksSealed,
  openTask,
  placeEveryField,
  readAndContinue,
  readEveryPage,
  reloadUntilVisible,
  shot,
  signAndConfirmIfAsked,
  signDocument,
  signIn,
  task,
  typeSignature,
  ui,
  waitForWebhook,
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
    await expect(frame.getByTestId("step-progress")).toContainText("Step 1 of 3");
    await readEveryPage(frame);
    await shot(page, "phone-02-read");

    // The document is rendered to be read, and nothing forces the page sideways.
    const canvas = await frame.locator('[data-page="1"] canvas').boundingBox();
    expect(canvas?.width ?? 0).toBeGreaterThan(300);
    expect(await sidewaysScroll(embeddedFrame(page))).toBe(0);

    // Addendum 3 A: the agreement is in the same scroll as the document it is about. It opens in
    // place, so the page it is about is still on screen behind it.
    await frame.getByTestId("consent-block").scrollIntoViewIfNeeded();
    await expect(frame.getByTestId("disclosure")).toHaveAttribute("data-expanded", "false");
    await frame.getByRole("button", { name: "Read the full notice" }).click();
    await expect(frame.getByTestId("disclosure")).toHaveAttribute("data-expanded", "true");
    await shot(page, "phone-03-consent-in-the-same-scroll");
    await agreeAndContinue(frame);

    await expect(frame.getByTestId("step-progress")).toContainText("Step 2 of 3");
    await drawSignature(page, frame);
    await shot(page, "phone-04-signature-chosen");

    // A finger, not a mouse: the action that places a mark is a real touch target.
    const place = await frame
      .getByRole("button", { name: /^(Sign here|Add initials)$/ })
      .first()
      .boundingBox();
    expect(place?.height ?? 0).toBeGreaterThanOrEqual(44);

    await placeEveryField(frame);
    await shot(page, "phone-05-fields-placed");
    await signDocument(frame);

    // Sealed inline or by the worker; the UI polls and says honestly which it is meanwhile.
    await expect(frame.getByTestId("step-done")).toBeVisible();
    await expect(frame.getByTestId("copy-ready")).toBeVisible({ timeout: 120_000 });
    expect(await sidewaysScroll(embeddedFrame(page))).toBe(0);
    await shot(page, "phone-06-signed-and-sealed");

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
    await shot(page, "phone-07-filed-in-the-chart");

    // And anybody can make the service re-check the seal, the hashes and the chain on the spot.
    await page.getByTestId("verify").click();
    await expect(page.getByTestId("verification-result")).toContainText("Verified.");
    await shot(page, "phone-08-verified");
  });
});

// --------------------------------------------------------------------------- what the host was told

test("the webhook log is verified deliveries and nothing about the patient", async ({ page }) => {
  await signIn(page, "alice");
  await page.getByRole("link", { name: "Webhooks" }).click();

  const rows = page.locator('[data-testid="webhook-row"]');
  await expect(rows.first()).toBeVisible();
  const deliveries = await rows.evaluateAll((items) =>
    items.map((i) => ({
      verified: (i as HTMLElement).dataset.verified,
      event: (i as HTMLElement).dataset.event,
    })),
  );

  // The service has other hosts, and one of them may have a delivery of its own still queued for
  // this URL. Arriving with a secret this host does not hold, it is refused and nothing is read
  // out of it -- so a refused row says nothing about any envelope, and no envelope was ever
  // believed on an unverified word.
  const refused = deliveries.filter((row) => row.verified === "false");
  expect(refused.map((row) => row.event).filter(Boolean)).toEqual([]);
  const believed = deliveries.filter((row) => row.verified === "true").map((row) => row.event);
  expect(believed).toContain("envelope.completed");
  expect(believed).toContain("envelope.sealed");

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
      const pages = await readAndContinue(frame);
      expect(pages).toBe(3);
      await shot(page, "tablet-01-read-and-agreed");
      expect(await sidewaysScroll(embeddedFrame(page))).toBe(0);

      await drawSignature(page, frame);
      await placeEveryField(frame);
      await shot(page, "tablet-02-ready-to-sign");
      await signDocument(frame);

      await expect(frame.getByTestId("waiting-on-others")).toContainText(
        "the witness and the clinician",
      );
      await shot(page, "tablet-03-waiting-on-others");
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
    await readAndContinue(frame);
    await typeSignature(frame, "Ben Doyle");
    await placeEveryField(frame);
    await signDocument(frame);
    await expect(frame.getByTestId("step-done")).toBeVisible();
  });

  test("the clinician re-authenticates through the EHR on the press, and it seals", async ({
    page,
  }) => {
    await signIn(page, "priya");
    const frame = await openTask(page, "Consent to a procedure");
    await readAndContinue(frame);
    await typeSignature(frame, "Priya Raman");
    await placeEveryField(frame);

    // Addendum 3 A 4: re-authentication is asked for by the press that signs, not by a screen
    // before it, and nothing else is pressed afterwards. Whether it is asked for at all is the
    // service's call: the demo runs with a re-authentication span, so a confirmation she made on
    // her queue a few minutes ago may still cover this signature -- and then the record says so
    // instead, and the host page is never asked for a password.
    await shot(page, "20-ready-to-sign-as-a-clinician");
    const how = await signAndConfirmIfAsked(page, frame);
    await shot(page, "21-signed-as-a-clinician");
    if (how === "handed off") {
      expect(await heard(page)).toEqual(
        expect.arrayContaining(["esign:reauth_required", "esign:reauth_done"]),
      );
    } else {
      expect(await heard(page)).not.toContain("esign:reauth_required");
    }

    await expect(frame.getByTestId("copy-ready")).toBeVisible({ timeout: 150_000 });
    await shot(page, "22-three-signers-sealed");

    await expect(page.getByTestId("filed-link")).toBeVisible({ timeout: 120_000 });
    await page.getByTestId("filed-link").click();
    await page.getByTestId("verify").click();
    await expect(page.getByTestId("verification-result")).toContainText("Verified.");
    await shot(page, "23-three-signers-verified");

    // What the chart actually holds, as bytes: one seal over a document three people signed.
    const href = await page.getByTestId("download-sealed").getAttribute("href");
    const pdf = await page.request.get(href ?? "");
    expect(pdf.ok()).toBe(true);
    looksSealed(Buffer.from(await pdf.body()));
  });
});

// --------------------------------------------------------------------------- the paper path

test("choosing paper ends the envelope and tells the clinic", async ({ page }) => {
  await signIn(page, "grace");
  const frame = await openTask(page, "Consent to treatment");
  await readEveryPage(frame);

  // Visible on the Read screen as much as on the Sign screen: the way out is never more than one
  // quiet link away, wherever the signer has got to.
  await frame.getByRole("button", { name: "I'd rather sign on paper" }).click();
  await expect(frame.getByTestId("step-decline")).toBeVisible();
  await expect(frame.getByRole("radio", { name: "I would rather sign on paper" })).toBeChecked();
  await shot(page, "30-decline");

  await expect(frame.getByTestId("decline-consequence")).toContainText("closes the document");
  await frame.getByRole("button", { name: "Close this document and tell the clinic" }).click();
  await expect(frame.getByTestId("screen-declined")).toBeVisible();
  await expect(page.getByText("Signed on paper instead")).toBeVisible();
  expect(await heard(page)).toContain("esign:declined");
  await shot(page, "31-declined");

  await signIn(page, "grace");
  await expect(task(page, "Consent to treatment")).toContainText("sign this on paper");
  await page.getByRole("link", { name: "Webhooks" }).click();
  await waitForWebhook(page, "envelope.declined");
  await shot(page, "32-declined-webhook");
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
    // Who is signing, and on whose word: the tablet says both, and the session carries them.
    await expect(page.getByTestId("who-is-signing")).toContainText(
      "Maria Alvarez is signing in front of Alice Wu; identity checked by photo id",
    );
    const frame = ui(page);
    await expect(frame.getByTestId("step-read")).toBeVisible({ timeout: 45_000 });
    await readEveryPage(frame);

    // A shared tablet is never handed somebody else's agreement, whatever the consent span is
    // set to: the person in front of it may not be the person who agreed (Addendum 3 C).
    await expect(frame.getByTestId("standing-consent")).toHaveCount(0);
    await agreeAndContinue(frame);
    await drawSignature(page, frame);
    await placeEveryField(frame);
    await signDocument(frame);

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
    await reloadUntilVisible(page, filed);
    await filed.getByRole("link").click();
    await page.getByTestId("verify").click();
    await expect(page.getByTestId("verification-result")).toContainText("Verified.");
    await shot(page, "42-kiosk-verified");
  });
});
