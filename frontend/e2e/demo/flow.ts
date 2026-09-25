/**
 * Driving the real thing: the stand-in EHR in the page, the signing UI in its iframe, and the
 * actual API, worker, database and sealer behind both. These helpers do what a person does, so a
 * spec reads as a story rather than as a list of selectors.
 *
 * Since Addendum 3 the flow they drive is three screens -- read, sign, done -- so the helpers are
 * three too: read the document and agree in the same scroll, place the signature, press the one
 * button that signs. Nothing that produces evidence was dropped, so nothing here asserts less.
 */

import { readFileSync } from "node:fs";
import { expect, type FrameLocator, type Locator, type Page } from "@playwright/test";

export const PASSWORD = "demo1234";

export const shot = (page: Page, name: string) =>
  page.screenshot({ path: `test-results/demo/${name}.png`, fullPage: false });

/** The signing UI, inside the host page's iframe. */
export const ui = (page: Page): FrameLocator => page.frameLocator("#frame");

export async function signIn(page: Page, username: string): Promise<void> {
  await page.goto("/");
  if (await page.getByRole("link", { name: "Worklist" }).isVisible()) {
    await page.getByRole("button", { name: "Sign out" }).click();
  }
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Documents to sign" })).toBeVisible();
}

export function task(page: Page, title: string) {
  return page
    .locator('[data-testid="task"]')
    .filter({ has: page.getByRole("heading", { name: title }) });
}

export async function openTask(page: Page, title: string): Promise<FrameLocator> {
  await task(page, title).getByTestId("open-task").click();
  await expect(page).toHaveURL(/\/sign\//);
  const frame = ui(page);
  await expect(frame.getByTestId("step-read")).toBeVisible({ timeout: 45_000 });
  return frame;
}

// --------------------------------------------------------------------------- screen 1: read

/** Read the document the way somebody actually does: bring each page up and let it be seen. */
export async function readEveryPage(frame: FrameLocator): Promise<number> {
  await expect(frame.locator("canvas[data-rendered]").first()).toBeVisible({ timeout: 45_000 });
  const pages = await frame.locator("[data-page]").count();
  expect(pages).toBeGreaterThan(0);
  for (let n = 1; n <= pages; n += 1) {
    await frame
      .locator(`[data-page="${n}"]`)
      .evaluate((node) => node.scrollIntoView({ block: "start" }));
    await expect
      .poll(
        async () =>
          (await frame.getByTestId("page-progress").getAttribute("data-seen"))?.split(","),
        {
          timeout: 30_000,
        },
      )
      .toContain(String(n));
  }
  await expect(frame.getByTestId("page-progress")).toContainText("All pages seen");
  return pages;
}

/**
 * Agree to sign electronically and go on to the Sign screen (Addendum 3 A). The agreement is in
 * the same scroll as the document it is about, so this is a tick and a button rather than a screen.
 *
 * Where the service is running with a consent span and this person has already agreed in this
 * sitting, the box is a line saying when they agreed instead. Both are the same act for the
 * signer -- press Continue -- and both post `POST /signing/consent`, so the helper takes either
 * and answers which one it got. A spec that cares asserts that answer against the envelope's
 * trail, never against what an earlier run happened to leave in the service's database.
 */
export async function agreeAndContinue(frame: FrameLocator): Promise<boolean> {
  await expect(frame.getByTestId("consent-block")).toBeVisible();
  const standing = frame.getByTestId("standing-consent");
  const stood = (await standing.count()) > 0;
  if (stood) {
    await expect(standing).toContainText(/You agreed to sign electronically at \d{1,2}:\d{2}/);
  } else {
    await frame
      .getByRole("checkbox", { name: /I agree to sign this document electronically/ })
      .check();
  }
  await frame.getByRole("button", { name: "Continue to sign" }).click();
  await expect(frame.getByTestId("step-sign")).toBeVisible();
  return stood;
}

/** Read every page, agree, and arrive on the Sign screen. */
export async function readAndContinue(frame: FrameLocator): Promise<number> {
  const pages = await readEveryPage(frame);
  await agreeAndContinue(frame);
  return pages;
}

// --------------------------------------------------------------------------- screen 2: sign

/**
 * Open the chooser in the signature panel.
 *
 * The signing service's database outlives a demo run -- only the demo host's worklist is fresh --
 * so a clinician who kept their signature in an earlier run is shown it here rather than a set of
 * ways to make one. A helper that means "make one now" has to ask for the chooser rather than
 * assume nothing is on file.
 */
async function chooseANewSignature(frame: FrameLocator): Promise<void> {
  await expect(frame.getByTestId("signature-panel")).toBeVisible();
  const change = frame.getByRole("button", { name: "Change" });
  if (await change.isVisible()) {
    await change.click();
  }
}

/** Type a name as the signature. Steadier than drawing, and exercises the font embedding. */
export async function typeSignature(frame: FrameLocator, name: string): Promise<void> {
  await chooseANewSignature(frame);
  await frame.getByRole("radio", { name: /Type it/ }).check();
  await frame.getByLabel("Type your full name").fill(name);
}

/** Type a name and tick the box that keeps it for next time (SPEC section 14 B). */
export async function typeSignatureAndSave(frame: FrameLocator, name: string): Promise<void> {
  await typeSignature(frame, name);
  const keep = frame.getByRole("checkbox", { name: /Save this signature for next time/ });
  await expect(keep).not.toBeChecked();
  await keep.check();
}

export async function drawSignature(page: Page, frame: FrameLocator): Promise<void> {
  await chooseANewSignature(frame);
  const pad = frame.getByTestId("signature-pad");
  await pad.scrollIntoViewIfNeeded();
  const box = await pad.boundingBox();
  if (box === null) {
    throw new Error("the signature pad is not on screen");
  }
  const at = (fx: number, fy: number) => [box.x + box.width * fx, box.y + box.height * fy] as const;
  for (const stroke of [
    [at(0.12, 0.62), at(0.2, 0.28), at(0.28, 0.66), at(0.36, 0.3), at(0.44, 0.6)],
    [at(0.5, 0.55), at(0.6, 0.35), at(0.7, 0.6), at(0.82, 0.4)],
  ]) {
    const [first, ...rest] = stroke;
    if (first === undefined) {
      continue;
    }
    await page.mouse.move(first[0], first[1]);
    await page.mouse.down();
    for (const [x, y] of rest) {
      await page.mouse.move(x, y, { steps: 8 });
    }
    await page.mouse.up();
  }
}

/** The signature saved last time is what the panel shows: nothing to choose, only to place. */
export async function savedSignatureIsOffered(frame: FrameLocator): Promise<void> {
  await expect(frame.getByTestId("signature-panel")).toBeVisible();
  await expect(frame.getByTestId("signature-showing")).toBeVisible();
  await expect(frame.getByTestId("saved-signature")).toBeVisible();
}

/**
 * One explicit act per field, which is what the fields list is: a row per field, each with the
 * part of the page its mark lands on. Every template puts different fields in front of a signer,
 * so the loop answers whatever each row is asking for.
 */
export async function placeEveryField(frame: FrameLocator): Promise<void> {
  const rows = frame.locator('[data-testid="field-row"]');
  const count = await rows.count();
  expect(count).toBeGreaterThan(0);
  for (let index = 0; index < count; index += 1) {
    const row = rows.nth(index);
    await row.scrollIntoViewIfNeeded();
    if ((await row.getAttribute("data-done")) === "true") {
      continue;
    }
    const mark = row.getByRole("button", { name: /^(Sign here|Add initials)$/ });
    const checkbox = row.getByRole("checkbox");
    const textBox = row.getByRole("textbox");
    if (await mark.isVisible()) {
      await mark.click();
    } else if (await checkbox.first().isVisible()) {
      await checkbox.first().check();
    } else if (await textBox.first().isVisible()) {
      await textBox.first().fill("Noted");
    }
    await expect(row).toHaveAttribute("data-done", "true");
  }
  await expect(frame.getByTestId("fields-progress")).toContainText(`${count} of ${count}`);
}

/**
 * The one press that signs (Addendum 3 A 3). It is the intent confirmation -- there is no
 * checkbox restating it -- and, for a role that needs re-authentication with nothing live, it is
 * also what asks the host for it.
 */
export async function signDocument(frame: FrameLocator): Promise<void> {
  const button = frame.getByTestId("sign-button");
  await button.scrollIntoViewIfNeeded();
  await expect(button).toContainText(/^Sign as /);
  await button.click();
}

/**
 * The host page's side of re-authentication, which now happens on the press: the press asks, the
 * EHR takes a password, and the signature goes by itself when the service has been told. No
 * second tap, which is the point of the addendum.
 *
 * Only for a signer the service is not already vouching for. Where it may be -- the demo runs
 * with a re-authentication span -- use `signAndConfirmIfAsked`.
 */
export async function signWithReauth(page: Page, frame: FrameLocator): Promise<void> {
  await expect(frame.getByTestId("reauth-needed")).toContainText("when you press the button");
  await signDocument(frame);
  await expect(frame.getByTestId("reauth-waiting")).toBeVisible();
  await expect(page.locator("#reauth")).toBeVisible();
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByTestId("reauth-confirm").click();
  await expect(frame.getByTestId("step-done")).toBeVisible({ timeout: 60_000 });
}

/**
 * Sign, and answer the host's password prompt if one is asked for.
 *
 * Whether it is asked for is the *service's* decision, not the spec's: with a re-authentication
 * span running, a confirmation this clinician made minutes ago on another document may still
 * cover this one, and then the press signs with no hand-off at all. The screen says which it will
 * be before the press -- "your records system will ask you to confirm it's you when you press
 * this", or a line saying when the confirmation was made -- so this reads that and then insists
 * on the half it named.
 */
export async function signAndConfirmIfAsked(
  page: Page,
  frame: FrameLocator,
): Promise<"handed off" | "already confirmed"> {
  const vouchedFor = (await frame.getByTestId("reauth-verified").count()) > 0;
  if (!vouchedFor) {
    await signWithReauth(page, frame);
    return "handed off";
  }
  await signDocument(frame);
  await expect(frame.getByTestId("step-done")).toBeVisible({ timeout: 60_000 });
  return "already confirmed";
}

// --------------------------------------------------------------------------- the host, afterwards

/**
 * Wait for something the EHR only finds out by asking again. Its pages are plain server-rendered
 * HTML with no polling of their own -- the webhook log and the chart know nothing after they were
 * sent -- so waiting for a delivery or a filing means reloading, exactly as a person would.
 */
export async function reloadUntilVisible(
  page: Page,
  locator: Locator,
  timeout = 120_000,
): Promise<void> {
  await expect(async () => {
    await page.reload();
    await expect(locator).toBeVisible({ timeout: 2_000 });
  }).toPass({ timeout, intervals: [1_000] });
}

export const waitForWebhook = (page: Page, event: string) =>
  reloadUntilVisible(
    page,
    page.locator(`[data-testid="webhook-row"][data-event="${event}"]`).first(),
  );

/** Every message that crossed the iframe boundary, as the host page recorded it. */
export const heard = (page: Page) =>
  page
    .locator("#log li")
    .evaluateAll((items) => items.map((item) => (item as HTMLElement).dataset.message));

/** A sealed PDF, as bytes, with the cheap structural checks a reader can do by eye. */
export function looksSealed(pdf: Buffer, envelopeId?: string): void {
  expect(pdf.subarray(0, 5).toString()).toBe("%PDF-");
  const text = pdf.toString("latin1");
  expect(text).toContain("/Type /Sig");
  // DocMDP level 1: no changes permitted after the seal.
  expect(text).toMatch(/\/DocMDP|\/P 1/);
  if (envelopeId !== undefined) {
    // SPEC section 5: the envelope id is bound into the signature dictionary.
    expect(text).toContain(`envelope:${envelopeId}`);
  }
}

/** A report on a clinician's Reports page (Addendum 2), by the EHR's own reference for it. */
export function report(page: Page, reference: string) {
  return page.locator(`[data-testid="report"][data-reference="${reference}"]`);
}

/**
 * Generate a report and open it for signing.
 *
 * Pressing this button is the whole of Addendum 2 from the outside: the EHR renders twenty-five or
 * thirty pages for this patient, uploads them to `POST /v1/envelopes` as multipart, and the
 * service hashes, checks, resolves the fields from the widget names and flattens them away before
 * the iframe below ever asks for a page. Longer than a template envelope, hence the timeout.
 */
export async function openReport(page: Page, reference: string): Promise<FrameLocator> {
  await report(page, reference).getByTestId("open-report").click();
  await expect(page).toHaveURL(/\/sign\//);
  const frame = ui(page);
  await expect(frame.getByTestId("step-read")).toBeVisible({ timeout: 90_000 });
  return frame;
}

/** A row of a clinician's signing queue, by the document's title. */
export function queueTask(page: Page, title: string) {
  return page
    .locator('[data-testid="queue-task"]')
    .filter({ has: page.getByRole("heading", { name: title }) });
}

/** Open a queue document, which from Addendum 3 B starts a run through the rest of them. */
export async function openFromQueue(page: Page, title: string): Promise<FrameLocator> {
  await queueTask(page, title).getByTestId("queue-sign").click();
  await expect(page).toHaveURL(/\/sign\//);
  const frame = ui(page);
  await expect(frame.getByTestId("step-read")).toBeVisible({ timeout: 45_000 });
  return frame;
}

// --------------------------------------------------------------------------- the evidence itself

/**
 * The audit trail of one envelope, from the Host API, with the key `make demo` wrote down.
 *
 * A spec that asserted on the screen alone would be checking what the EHR says happened. This is
 * the service's own hash-chained record, read the way a customer's backend reads it, and it is
 * where Addendum 3 C's claim can actually be checked: that every document in a sitting has its
 * own `consent.accepted`, and that the ones standing on an earlier agreement say which.
 */
export interface AuditEvent {
  event_type: string;
  data: Record<string, unknown>;
  actor: { user_id: string | null; role: string };
}

export async function auditTrail(page: Page, envelopeId: string): Promise<AuditEvent[]> {
  const key = demoApiKey();
  const response = await page.request.get(
    `${process.env.DEMO_ESIGN_API_URL ?? "http://localhost:8000"}/v1/envelopes/${envelopeId}/audit`,
    { headers: { Authorization: `Bearer ${key}` } },
  );
  expect(response.ok()).toBe(true);
  const body = (await response.json()) as { events: AuditEvent[] };
  return body.events;
}

let apiKey: string | null = null;

function demoApiKey(): string {
  if (apiKey === null) {
    const env = readFileSync(new URL("../../../.demo/env", import.meta.url), "utf8");
    const found = /^DEMO_ESIGN_API_KEY=(.+)$/m.exec(env)?.[1]?.trim();
    if (found === undefined) {
      throw new Error("no API key in .demo/env; the demo stack writes it when it registers");
    }
    apiKey = found;
  }
  return apiKey;
}
