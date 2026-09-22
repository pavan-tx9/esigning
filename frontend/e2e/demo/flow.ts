/**
 * Driving the real thing: the stand-in EHR in the page, the signing UI in its iframe, and the
 * actual API, worker, database and sealer behind both. These helpers do what a person does, so a
 * spec reads as a story rather than as a list of selectors.
 */

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
  await expect(frame.getByTestId("step-review")).toBeVisible({ timeout: 45_000 });
  return frame;
}

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

export async function agree(frame: FrameLocator): Promise<void> {
  await expect(frame.getByTestId("step-consent")).toBeVisible();
  await frame.getByRole("checkbox", { name: /I agree to sign electronically/ }).check();
  await frame.getByRole("button", { name: "Agree and continue" }).click();
}

/**
 * Get to the part of the adopt step where a signature is *made*.
 *
 * The signing service's database outlives a demo run -- only the demo host's worklist is fresh --
 * so a clinician who kept their signature in an earlier run is offered it again here, and the
 * ways of making a new one are behind "Create a new one" until they ask for them (SPEC section
 * 14 B). A helper that means "make one now" has to say so rather than assume nothing is on file.
 */
async function makeANewSignature(frame: FrameLocator): Promise<void> {
  await expect(frame.getByTestId("step-sign-adopt")).toBeVisible();
  const anotherOne = frame.getByRole("radio", { name: /Create a new one/ });
  if (await anotherOne.isVisible()) {
    await anotherOne.check();
  }
}

/** Adopt a signature by typing a name. Steadier than drawing, and exercises the font embedding. */
export async function adoptTyped(frame: FrameLocator, name: string): Promise<void> {
  await makeANewSignature(frame);
  await frame.getByRole("radio", { name: /Type it/ }).check();
  await frame.getByLabel("Type your full name").fill(name);
  await frame.getByRole("button", { name: "Use this signature" }).click();
}

export async function adoptDrawn(page: Page, frame: FrameLocator): Promise<void> {
  await makeANewSignature(frame);
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
  await frame.getByRole("button", { name: "Use this signature" }).click();
}

/**
 * Work through this signer's fields until the summary appears. Every template puts different
 * fields in front of a signer, so the loop reacts to whatever the step is asking for.
 */
export async function fillEveryField(frame: FrameLocator): Promise<void> {
  for (let guard = 0; guard < 12; guard += 1) {
    if (await frame.getByTestId("step-sign-summary").isVisible()) {
      return;
    }
    await expect(frame.getByTestId("step-sign-field")).toBeVisible();
    const signHere = frame.getByRole("button", { name: /^(Sign here|Add my initials here)$/ });
    const checkbox = frame.getByRole("checkbox");
    const textBox = frame.getByRole("textbox");
    if (await signHere.isVisible()) {
      await signHere.click();
    } else if (await checkbox.first().isVisible()) {
      await checkbox.first().check();
    } else if (await textBox.first().isVisible()) {
      await textBox.first().fill("Noted");
    }
    const next = frame.getByRole("button", { name: /^(Next|Check your answers)$/ });
    await next.click();
  }
  throw new Error("the signing step never reached the summary");
}

export async function confirmAndSign(frame: FrameLocator): Promise<void> {
  await expect(frame.getByTestId("step-sign-summary")).toBeVisible();
  await frame.getByRole("button", { name: "Continue" }).click();
  await expect(frame.getByTestId("step-confirm")).toBeVisible();
  await frame.getByRole("checkbox", { name: /I want to sign it as/ }).check();
  await frame.getByRole("button", { name: "Sign document" }).click();
}

/**
 * The host page's side of re-authentication: the UI asks, the EHR takes a password.
 *
 * The demo runs the service with a re-authentication span, so a confirmation this clinician made
 * for another document a few minutes ago may still cover this one; the button is then "Confirm
 * again", and pressing it exercises exactly the same hand-off.
 */
export async function reauthenticate(page: Page, frame: FrameLocator): Promise<void> {
  await expect(frame.getByTestId("step-confirm")).toBeVisible();
  await frame.getByRole("button", { name: /^(Confirm it's me|Confirm again)$/ }).click();
  await expect(frame.getByTestId("reauth-waiting")).toBeVisible();
  await expect(page.locator("#reauth")).toBeVisible();
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByTestId("reauth-confirm").click();
  await expect(frame.getByTestId("reauth-verified")).toBeVisible();
}

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

/** Adopt a typed signature and tick the box that keeps it for next time (SPEC section 14 B). */
export async function adoptTypedAndSave(frame: FrameLocator, name: string): Promise<void> {
  await makeANewSignature(frame);
  await frame.getByRole("radio", { name: /Type it/ }).check();
  await frame.getByLabel("Type your full name").fill(name);
  const keep = frame.getByRole("checkbox", { name: /Save this signature for next time/ });
  await expect(keep).not.toBeChecked();
  await keep.check();
  await frame.getByRole("button", { name: "Use this signature" }).click();
}

/** The signature saved last time is offered first; take it. Still placed per field afterwards. */
export async function useSavedSignature(frame: FrameLocator): Promise<void> {
  await expect(frame.getByTestId("step-sign-adopt")).toBeVisible();
  await expect(frame.getByTestId("saved-signature")).toBeVisible();
  await expect(frame.getByRole("radio", { name: /Use my saved signature/ })).toBeChecked();
  await frame.getByRole("button", { name: "Use this signature" }).click();
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
  await expect(frame.getByTestId("step-review")).toBeVisible({ timeout: 90_000 });
  return frame;
}

/** A queue document: open from the queue page, read, agree, sign with a typed name. */
export async function openFromQueue(page: Page, title: string): Promise<FrameLocator> {
  await page
    .locator('[data-testid="queue-task"]')
    .filter({ has: page.getByRole("heading", { name: title }) })
    .getByTestId("queue-sign")
    .click();
  await expect(page).toHaveURL(/\/sign\//);
  const frame = ui(page);
  await expect(frame.getByTestId("step-review")).toBeVisible({ timeout: 45_000 });
  return frame;
}
