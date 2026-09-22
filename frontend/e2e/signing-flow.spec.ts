import { expect, type FrameLocator, type Page, test } from "@playwright/test";

/**
 * The whole flow in a real browser at phone size, through the dev harness (which plays the host
 * page) and against the MSW mock of the Signer API. What this proves that the unit tests cannot:
 * the postMessage handshake across a real iframe boundary, pdf.js rendering with the locally
 * bundled worker, page-seen tracking by real scrolling, and a real drawn PNG reaching the API.
 *
 * Screenshots of every state land in test-results/screens/ for a human to look at.
 */

test.use({
  viewport: { width: 390, height: 844 },
  deviceScaleFactor: 2,
  hasTouch: true,
  screenshot: "only-on-failure",
  // Screenshots are for looking at: take them of settled screens, not mid-transition.
  reducedMotion: "reduce",
});

const shot = (page: Page, name: string) =>
  page.screenshot({ path: `test-results/screens/${name}.png` });

async function open(page: Page, scenario: string): Promise<FrameLocator> {
  await page.goto(`/src/dev/harness.html?scenario=${scenario}&latency=150`);
  return page.frameLocator("#frame");
}

async function readEveryPage(ui: FrameLocator, pages: number) {
  await expect(ui.getByTestId("step-review")).toBeVisible();
  await expect(ui.locator("canvas[data-rendered]").first()).toBeVisible();
  // Scroll like a person would: bring each page to the top and leave it there for a moment.
  for (let n = 1; n <= pages; n += 1) {
    await ui
      .locator(`[data-page="${n}"]`)
      .evaluate((node) => node.scrollIntoView({ block: "start" }));
    await expect
      .poll(async () =>
        (await ui.getByTestId("page-progress").getAttribute("data-seen"))?.split(","),
      )
      .toContain(String(n));
  }
  await expect(ui.getByTestId("page-progress")).toContainText("All pages seen");
}

async function agree(ui: FrameLocator) {
  await expect(ui.getByTestId("step-consent")).toBeVisible();
  await ui.getByRole("checkbox", { name: /I agree to sign electronically/ }).check();
  await ui.getByRole("button", { name: "Agree and continue" }).click();
}

async function drawSignature(page: Page, ui: FrameLocator) {
  const pad = ui.getByTestId("signature-pad");
  await pad.scrollIntoViewIfNeeded();
  const box = await pad.boundingBox();
  if (box === null) {
    throw new Error("signature pad is not on screen");
  }
  const at = (fx: number, fy: number) => [box.x + box.width * fx, box.y + box.height * fy] as const;
  const strokes = [
    [at(0.12, 0.62), at(0.2, 0.25), at(0.27, 0.66), at(0.34, 0.3), at(0.42, 0.62)],
    [at(0.48, 0.55), at(0.58, 0.35), at(0.66, 0.6), at(0.78, 0.4), at(0.88, 0.52)],
  ];
  for (const stroke of strokes) {
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

test("a patient reads, consents, draws a signature, signs and gets the sealed copy", async ({
  page,
}) => {
  const signRequests: { key: string | null; body: string }[] = [];
  const ui = await open(page, "single");

  // Review ------------------------------------------------------------------------------------
  await expect(ui.getByTestId("signing-as")).toContainText("Maria Alvarez");
  await expect(ui.getByTestId("step-progress")).toContainText("Step 1 of 5");
  await expect(ui.locator("canvas[data-rendered]").first()).toBeVisible();
  await shot(page, "01-review");

  // Continue is inert until every page has been displayed, and says why.
  // (aria-disabled rather than disabled, so it stays focusable; Playwright needs `force`.)
  await ui.getByRole("button", { name: "Continue" }).click({ force: true });
  await expect(ui.getByRole("alert")).toContainText(/Please look at page/);
  await expect(ui.getByTestId("page-progress")).toContainText(/Still to see: page/);
  // The keyboard path through the document: Next page moves to, and focuses, the next page.
  await ui.getByRole("button", { name: "Next page" }).click();
  await expect(ui.getByTestId("page-progress")).toContainText("Page 2 of 2");
  await readEveryPage(ui, 2);

  // The highlight sits on the signature rule of page 2, wherever the zoom puts it.
  const mark = ui.locator('[data-field-mark="patient_sig"]');
  await mark.scrollIntoViewIfNeeded();
  const markBox = await mark.boundingBox();
  const pageBox = await ui.locator('[data-page="2"] canvas').boundingBox();
  if (markBox === null || pageBox === null) {
    throw new Error("page 2 is not laid out");
  }
  const scale = pageBox.width / 612;
  expect(markBox.x - pageBox.x).toBeCloseTo(72 * scale, 0);
  expect(markBox.y - pageBox.y).toBeCloseTo((792 - 400 - 48) * scale, 0);
  expect(markBox.width).toBeCloseTo(220 * scale, 0);
  await shot(page, "02-review-all-seen");

  await ui.getByRole("button", { name: "Make the document larger" }).click();
  await expect(ui.locator('[data-page="2"] canvas')).toHaveJSProperty(
    "clientWidth",
    Math.floor(pageBox.width * 1.5),
  );
  const zoomedMark = await mark.boundingBox();
  const zoomedPage = await ui.locator('[data-page="2"] canvas').boundingBox();
  if (zoomedMark === null || zoomedPage === null) {
    throw new Error("page 2 is not laid out after zoom");
  }
  expect((zoomedMark.x - zoomedPage.x) / zoomedPage.width).toBeCloseTo(72 / 612, 2);
  await ui.getByRole("button", { name: "Make the document smaller" }).click();

  await ui.getByRole("button", { name: "Continue" }).click();

  // Consent -----------------------------------------------------------------------------------
  await expect(ui.getByTestId("step-consent")).toBeVisible();
  await expect(ui.getByRole("heading", { level: 1 })).toBeFocused();
  await expect(ui.getByRole("checkbox")).not.toBeChecked();
  await expect(ui.getByRole("button", { name: "I'd rather sign on paper" })).toBeVisible();
  await shot(page, "03-consent");
  await agree(ui);

  // Adopt a signature -------------------------------------------------------------------------
  await expect(ui.getByTestId("step-sign-adopt")).toBeVisible();
  await ui.getByRole("button", { name: "Use this signature" }).click();
  await expect(ui.getByRole("alert")).toContainText("The box is empty");
  await drawSignature(page, ui);
  await shot(page, "04-adopt-drawn");
  await ui.getByRole("button", { name: "Undo last stroke" }).click();
  await drawSignature(page, ui);
  await ui.getByRole("button", { name: "Use this signature" }).click();

  // Fields ------------------------------------------------------------------------------------
  await expect(ui.getByTestId("step-sign-field")).toBeVisible();
  await expect(ui.getByTestId("field-progress")).toContainText("1 of 2");
  await expect(ui.getByTestId("field-progress")).toContainText("2 left");
  await ui
    .getByRole("checkbox", { name: "I have received the Notice of Privacy Practices" })
    .check();
  await shot(page, "05-field-checkbox");
  await ui.getByRole("button", { name: "Next" }).click();

  await expect(ui.getByRole("heading", { name: "Patient signature" })).toBeVisible();
  await expect(ui.locator("[data-testid=field-closeup] canvas[data-rendered]")).toBeVisible();
  await shot(page, "06-field-signature");
  await ui.getByRole("button", { name: "Sign here" }).click();
  await expect(ui.getByText("Your signature is in place")).toBeVisible();
  await expect(ui.locator('[data-field-box="patient_sig"] img')).toBeVisible();
  await shot(page, "07-field-signed");
  await ui.getByRole("button", { name: "Check your answers" }).click();

  await expect(ui.getByTestId("step-sign-summary")).toBeVisible();
  await shot(page, "08-summary");
  await ui.getByRole("button", { name: "Continue" }).click();

  // Confirm -----------------------------------------------------------------------------------
  await expect(ui.getByTestId("step-confirm")).toBeVisible();
  page.on("request", (request) => {
    if (request.url().endsWith("/v1/signing/sign")) {
      signRequests.push({
        key: request.headers()["idempotency-key"] ?? null,
        body: request.postData() ?? "",
      });
    }
  });
  await ui.getByRole("checkbox", { name: /I want to sign it as Maria Alvarez/ }).check();
  await shot(page, "09-confirm");
  await ui.getByRole("button", { name: "Sign document" }).click();

  // Done --------------------------------------------------------------------------------------
  await expect(ui.getByTestId("step-done")).toBeVisible();
  await expect(ui.getByTestId("copy-sealing")).toBeVisible();
  await shot(page, "10-done-sealing");
  await expect(ui.getByTestId("copy-ready")).toBeVisible({ timeout: 20_000 });
  await expect(ui.getByRole("link", { name: "Save your signed copy" })).toBeVisible();
  await shot(page, "11-done-ready");

  // What actually went over the wire.
  expect(signRequests).toHaveLength(1);
  expect(signRequests[0]?.key).toMatch(/^[0-9a-f-]{36}$/);
  const sent = JSON.parse(signRequests[0]?.body ?? "{}");
  expect(sent.intent_confirmed).toBe(true);
  expect(sent.captures).toHaveLength(2);
  const drawn = sent.captures.find((c: { kind?: string }) => c.kind === "drawn");
  expect(drawn.field_id).toBe("patient_sig");
  // A real PNG, cropped to the ink: far smaller than the pad, and not blank.
  const png = Buffer.from(drawn.image_png_base64, "base64");
  expect(png.subarray(1, 4).toString()).toBe("PNG");
  const width = png.readUInt32BE(16);
  const height = png.readUInt32BE(20);
  expect(width).toBeGreaterThan(height * 1.5);
  expect(png[25]).toBe(6); // RGBA: a transparent background is possible at all
  // Nothing the client must never supply.
  expect(JSON.stringify(sent)).not.toMatch(/date|hash|timestamp|signed_at|display_name/);

  // The host page heard about each milestone, and the token never touched a URL or storage.
  const heard = await page
    .locator("#log li")
    .evaluateAll((items) => items.map((item) => (item as HTMLElement).dataset.message));
  expect(heard).toEqual(
    expect.arrayContaining(["esign:ready", "esign:init", "esign:signed", "esign:sealed"]),
  );
  const frame = page.frames().find((f) => f.url().includes("sign.html"));
  expect(frame?.url()).not.toContain("est_");
  const stored = await frame?.evaluate(() =>
    JSON.stringify([{ ...localStorage }, { ...sessionStorage }]),
  );
  expect(stored).not.toContain("est_");
});

test("a clinician is handed to the host to re-authenticate, then signs by typing", async ({
  page,
}) => {
  const ui = await open(page, "clinician");
  await readEveryPage(ui, 3);
  await ui.getByRole("button", { name: "Continue" }).click();
  await agree(ui);

  await ui.getByRole("radio", { name: /Type it/ }).check();
  await ui.getByLabel("Type your full name").fill("Priya Raman");
  await shot(page, "20-adopt-typed");
  await ui.getByRole("button", { name: "Use this signature" }).click();
  await ui.getByRole("button", { name: "Sign here" }).click();
  await shot(page, "21-field-typed");
  await ui.getByRole("button", { name: "Check your answers" }).click();
  await ui.getByRole("button", { name: "Continue" }).click();

  await expect(ui.getByTestId("step-confirm")).toBeVisible();
  await shot(page, "22-confirm-reauth-needed");
  await ui.getByRole("button", { name: "Confirm it's me" }).click();
  await expect(ui.getByTestId("reauth-waiting")).toBeVisible();
  await expect(page.locator("#reauth")).toBeVisible();
  await shot(page, "23-confirm-reauth-waiting");
  await page.getByRole("button", { name: "Password confirmed" }).click();
  await expect(ui.getByTestId("reauth-verified")).toBeVisible();
  await ui.getByRole("checkbox", { name: /I want to sign it as Dr. Priya Raman/ }).check();
  await shot(page, "24-confirm-reauth-verified");
  await ui.getByRole("button", { name: "Sign document" }).click();
  await expect(ui.getByTestId("copy-ready")).toBeVisible({ timeout: 20_000 });
});

test("the first of several signers is told the copy comes later; click-to-sign and initials", async ({
  page,
}) => {
  const ui = await open(page, "multi");
  await readEveryPage(ui, 3);
  await ui.getByRole("button", { name: "Continue" }).click();
  await agree(ui);
  await ui.getByRole("radio", { name: /Use my printed name/ }).check();
  await shot(page, "30-adopt-click");
  await ui.getByRole("button", { name: "Use this signature" }).click();
  await ui.getByRole("button", { name: "Add my initials here" }).click();
  await ui.getByRole("button", { name: "Next" }).click();
  await shot(page, "31-field-text-optional");
  await ui.getByRole("button", { name: "Skip" }).click();
  await ui.getByRole("button", { name: "Sign here" }).click();
  await ui.getByRole("button", { name: "Check your answers" }).click();
  await shot(page, "32-summary-multi");
  await ui.getByRole("button", { name: "Continue" }).click();
  await ui.getByRole("checkbox", { name: /I want to sign/ }).check();
  await ui.getByRole("button", { name: "Sign document" }).click();
  await expect(ui.getByTestId("waiting-on-others")).toContainText("the witness and the clinician");
  await shot(page, "33-done-waiting-on-others");
});

/**
 * A parallel envelope moving on under the signer. The co-signer commits a new revision while this
 * one is on the confirm screen, so the bytes they read are no longer the bytes the marks would
 * land on and the service refuses with 409 `not_viewed` (SPEC section 13, fourth round). The UI
 * owns the way out, because the signer's status is still `consented` and nothing else would send
 * them back: it drops the document it holds, returns to Review, and the fresh `POST /viewed` that
 * step already sends is what lets the signature through. The draft survives, so the summary comes
 * straight back with everything they filled in.
 */
test("a co-signer moves the document on: back to review, and the signature then stands", async ({
  page,
}) => {
  const ui = await open(page, "multi");
  await readEveryPage(ui, 3);
  await ui.getByRole("button", { name: "Continue" }).click();
  await agree(ui);
  await ui.getByRole("radio", { name: /Use my printed name/ }).check();
  await ui.getByRole("button", { name: "Use this signature" }).click();
  await ui.getByRole("button", { name: "Add my initials here" }).click();
  await ui.getByRole("button", { name: "Next" }).click();
  await ui.getByRole("button", { name: "Skip" }).click();
  await ui.getByRole("button", { name: "Sign here" }).click();
  await ui.getByRole("button", { name: "Check your answers" }).click();
  await ui.getByRole("button", { name: "Continue" }).click();
  await expect(ui.getByTestId("step-confirm")).toBeVisible();

  // The witness signs. This session still holds the revision it was served and confirmed reading.
  const frame = page.frames().find((f) => f.url().includes("sign.html"));
  if (frame === undefined) {
    throw new Error("the signing UI is not framed");
  }
  await frame.evaluate(() => window.__esignMock?.otherSignerSigned("multi"));

  await ui.getByRole("checkbox", { name: /I want to sign/ }).check();
  await ui.getByRole("button", { name: "Sign document" }).click();

  await expect(ui.getByTestId("review-again")).toBeVisible();
  await expect(ui.getByTestId("step-review")).toBeVisible();
  await shot(page, "34-review-again");

  // Reading what it says now is the whole recovery.
  await readEveryPage(ui, 3);
  await ui.getByRole("button", { name: "Continue" }).click();
  await agree(ui);
  await expect(ui.getByTestId("step-sign-summary")).toBeVisible();
  await ui.getByRole("button", { name: "Continue" }).click();
  await ui.getByRole("checkbox", { name: /I want to sign/ }).check();
  await ui.getByRole("button", { name: "Sign document" }).click();
  await expect(ui.getByTestId("waiting-on-others")).toBeVisible();

  const record = (await frame.evaluate(() => window.__esignMock?.peek("multi"))) as {
    signerStatus: string;
    presentedRevision: number;
    viewedRevision: number;
  };
  expect(record.signerStatus).toBe("signed");
  expect(record.presentedRevision).toBe(2);
  expect(record.viewedRevision).toBe(2);
});

/**
 * SPEC section 14 C: a host may let one re-authentication cover a clinician's next few documents.
 * The session then arrives already vouched for: no hand-off, a plain statement of what the record
 * will say, and "Confirm again" for a fresh one. Once the cover has run out, the hand-off is back.
 */
test("a clinician in a signing queue is not handed off again while the earlier confirmation covers them", async ({
  page,
}) => {
  const ui = await open(page, "span-valid");
  await readEveryPage(ui, 3);
  await ui.getByRole("button", { name: "Continue" }).click();
  await agree(ui);
  await ui.getByRole("radio", { name: /Use my printed name/ }).check();
  await ui.getByRole("button", { name: "Use this signature" }).click();
  await ui.getByRole("button", { name: "Sign here" }).click();
  await ui.getByRole("button", { name: "Check your answers" }).click();
  await ui.getByRole("button", { name: "Continue" }).click();

  await expect(ui.getByTestId("step-confirm")).toBeVisible();
  const covered = ui.getByTestId("reauth-verified");
  await expect(covered).toHaveAttribute("data-reauth-scope", "span");
  await expect(covered).toContainText(/You confirmed your identity at \d{1,2}:\d{2}/);
  await expect(covered).toContainText(/covers this signature until \d{1,2}:\d{2}/);
  await expect(ui.getByRole("button", { name: "Confirm it's me" })).toHaveCount(0);
  await expect(page.locator("#reauth")).toBeHidden();
  await shot(page, "25-confirm-span-covered");

  // A fresh confirmation is on offer, and backing out of it keeps the earlier one.
  await ui.getByRole("button", { name: "Confirm again" }).click();
  await expect(ui.getByTestId("reauth-waiting")).toBeVisible();
  await expect(page.locator("#reauth")).toBeVisible();
  await shot(page, "26-confirm-span-again");
  await page.getByRole("button", { name: "Do nothing" }).click();
  await ui.getByRole("button", { name: "Cancel" }).click();
  await expect(covered).toHaveAttribute("data-reauth-scope", "span");

  await ui.getByRole("checkbox", { name: /I want to sign it as Dr. Priya Raman/ }).check();
  await ui.getByRole("button", { name: "Sign document" }).click();
  await expect(ui.getByTestId("copy-ready")).toBeVisible({ timeout: 20_000 });
  await expect(page.locator('#log li[data-message="esign:reauth_required"]')).toHaveCount(1);
});

test("a clinician whose earlier confirmation has run out is handed off as usual", async ({
  page,
}) => {
  const ui = await open(page, "span-expired");
  await readEveryPage(ui, 3);
  await ui.getByRole("button", { name: "Continue" }).click();
  await agree(ui);
  await ui.getByRole("radio", { name: /Use my printed name/ }).check();
  await ui.getByRole("button", { name: "Use this signature" }).click();
  await ui.getByRole("button", { name: "Sign here" }).click();
  await ui.getByRole("button", { name: "Check your answers" }).click();
  await ui.getByRole("button", { name: "Continue" }).click();

  await expect(ui.getByTestId("step-confirm")).toBeVisible();
  await expect(ui.getByTestId("reauth-verified")).toHaveCount(0);
  await expect(ui.getByRole("button", { name: "Confirm it's me" })).toBeVisible();
  await shot(page, "27-confirm-span-expired");
  await ui.getByRole("button", { name: "Confirm it's me" }).click();
  await page.getByRole("button", { name: "Password confirmed" }).click();
  await expect(ui.getByTestId("reauth-verified")).toContainText("Confirmed, thank you");
});

/**
 * SPEC section 14 B: the signature saved last time is offered first, with using it, making a new
 * one and removing it as equal choices. Placing it is still one press per field, the request to
 * save a new one is an unchecked box, and the saved image never travels back to the server.
 */
test("a saved signature is offered first, placed per field, and sent as its id", async ({
  page,
}) => {
  const signRequests: string[] = [];
  page.on("request", (request) => {
    if (request.url().endsWith("/v1/signing/sign")) {
      signRequests.push(request.postData() ?? "");
    }
  });
  const ui = await open(page, "saved-signature");
  await readEveryPage(ui, 2);
  await ui.getByRole("button", { name: "Continue" }).click();
  await agree(ui);

  await expect(ui.getByTestId("saved-signature")).toBeVisible();
  await expect(ui.getByRole("img", { name: /Your saved signature/ })).toBeVisible();
  await expect(ui.getByRole("radio", { name: /Use my saved signature/ })).toBeChecked();
  await expect(ui.getByRole("radio", { name: /Create a new one/ })).toBeVisible();
  await expect(ui.getByRole("button", { name: /Remove saved signature/ })).toBeVisible();
  await expect(ui.getByTestId("signature-pad")).toHaveCount(0);
  await shot(page, "90-adopt-saved-offered");

  // The other two choices are as big as the first one.
  const [useBox, newBox, removeBox] = await Promise.all([
    ui
      .getByRole("radio", { name: /Use my saved signature/ })
      .locator("..")
      .boundingBox(),
    ui
      .getByRole("radio", { name: /Create a new one/ })
      .locator("..")
      .boundingBox(),
    ui.getByRole("button", { name: /Remove saved signature/ }).boundingBox(),
  ]);
  expect(useBox?.width).toBe(newBox?.width);
  expect(useBox?.width).toBe(removeBox?.width);

  await ui.getByRole("button", { name: "Use this signature" }).click();
  await ui.getByRole("checkbox").check();
  await ui.getByRole("button", { name: "Next" }).click();
  await expect(ui.getByRole("heading", { name: "Patient signature" })).toBeVisible();
  await ui.getByRole("button", { name: "Sign here" }).click();
  await expect(ui.locator('[data-field-box="patient_sig"] img')).toBeVisible();
  await shot(page, "91-field-saved-placed");
  await ui.getByRole("button", { name: "Check your answers" }).click();
  await expect(ui.getByTestId("summary-save-note")).toHaveCount(0);
  await shot(page, "92-summary-saved");
  await ui.getByRole("button", { name: "Continue" }).click();
  await ui.getByRole("checkbox", { name: /I want to sign/ }).check();
  await ui.getByRole("button", { name: "Sign document" }).click();
  await expect(ui.getByTestId("step-done")).toBeVisible();

  expect(signRequests).toHaveLength(1);
  const sent = JSON.parse(signRequests[0] ?? "{}");
  expect(sent.captures).toContainEqual({
    field_id: "patient_sig",
    kind: "adopted",
    adopted_signature_id: "9a1e5d2c-7b3f-4e8a-9c0d-1f2e3a4b5c6d",
  });
  expect(sent).not.toHaveProperty("save_adopted_signature");
  expect(signRequests[0]).not.toMatch(/image_png|iVBOR/);
});

test("a new signature can be drawn, saved for next time, and the saved one removed", async ({
  page,
}) => {
  const signRequests: string[] = [];
  page.on("request", (request) => {
    if (request.url().endsWith("/v1/signing/sign")) {
      signRequests.push(request.postData() ?? "");
    }
  });
  const ui = await open(page, "saved-signature");
  await readEveryPage(ui, 2);
  await ui.getByRole("button", { name: "Continue" }).click();
  await agree(ui);

  // Removing asks once more, and keeping it changes nothing.
  await ui.getByRole("button", { name: /Remove saved signature/ }).click();
  await expect(ui.getByTestId("remove-saved")).toBeVisible();
  await shot(page, "93-adopt-remove-asks");
  await ui.getByRole("button", { name: "Keep it" }).click();
  await expect(ui.getByTestId("remove-saved")).toHaveCount(0);
  await expect(ui.getByTestId("saved-signature")).toBeVisible();

  // Making a new one: the box to save it is there, and unticked.
  await ui.getByRole("radio", { name: /Create a new one/ }).check();
  await expect(ui.getByText("How would you like to make the new one?")).toBeVisible();
  const keep = ui.getByRole("checkbox", { name: /Save this signature for next time/ });
  await expect(keep).not.toBeChecked();
  await drawSignature(page, ui);
  await keep.check();
  await shot(page, "94-adopt-new-and-save");
  await ui.getByRole("button", { name: "Use this signature" }).click();
  await ui.getByRole("checkbox").check();
  await ui.getByRole("button", { name: "Next" }).click();
  await ui.getByRole("button", { name: "Sign here" }).click();
  await ui.getByRole("button", { name: "Check your answers" }).click();
  await expect(ui.getByTestId("summary-save-note")).toBeVisible();
  await shot(page, "95-summary-will-save");

  // Second thoughts: back to the signature, and the saved one can go after all.
  await ui.getByRole("button", { name: "Choose a different signature" }).click();
  await expect(ui.getByRole("radio", { name: /Create a new one/ })).toBeChecked();
  await ui.getByRole("button", { name: /Remove saved signature/ }).click();
  await ui.getByRole("button", { name: "Remove it" }).click();
  await expect(ui.getByTestId("saved-signature")).toHaveCount(0);
  await expect(ui.getByText("How would you like to sign?")).toBeVisible();
  await shot(page, "96-adopt-after-remove");

  // The drawing has to be made again (the pad is fresh), and saving is still on offer.
  await drawSignature(page, ui);
  await ui.getByRole("checkbox", { name: /Save this signature for next time/ }).check();
  await ui.getByRole("button", { name: "Use this signature" }).click();
  // The tick they gave earlier is still there; only the signature had to be placed again.
  await expect(ui.getByRole("checkbox")).toBeChecked();
  await ui.getByRole("button", { name: "Next" }).click();
  await ui.getByRole("button", { name: "Sign here" }).click();
  await ui.getByRole("button", { name: "Check your answers" }).click();
  await ui.getByRole("button", { name: "Continue" }).click();
  await ui.getByRole("checkbox", { name: /I want to sign/ }).check();
  await ui.getByRole("button", { name: "Sign document" }).click();
  await expect(ui.getByTestId("step-done")).toBeVisible();

  expect(signRequests).toHaveLength(1);
  const sent = JSON.parse(signRequests[0] ?? "{}");
  expect(sent.save_adopted_signature).toBe(true);
  expect(sent.captures.find((c: { kind?: string }) => c.kind === "drawn")?.field_id).toBe(
    "patient_sig",
  );

  const frame = page.frames().find((f) => f.url().includes("sign.html"));
  const record = (await frame?.evaluate(() => window.__esignMock?.peek("saved-signature"))) as {
    savedSignatures: { kind: string; revokeReason: string | null }[];
  };
  expect(record.savedSignatures.map((row) => row.revokeReason)).toEqual(["user", null]);
  expect(record.savedSignatures[1]?.kind).toBe("drawn");
});

test("a kiosk session ends by asking for the tablet back and forgets everything", async ({
  page,
}) => {
  const ui = await open(page, "kiosk");
  await readEveryPage(ui, 2);
  await ui.getByRole("button", { name: "Continue" }).click();
  await agree(ui);
  // The patient has a signature on file; a shared tablet is never offered it, nor asked to save.
  await expect(ui.getByTestId("saved-signature")).toHaveCount(0);
  await expect(ui.getByRole("checkbox", { name: /Save this signature/ })).toHaveCount(0);
  await ui.getByRole("radio", { name: /Use my printed name/ }).check();
  await ui.getByRole("button", { name: "Use this signature" }).click();
  await ui.getByRole("checkbox").check();
  await ui.getByRole("button", { name: "Next" }).click();
  await ui.getByRole("button", { name: "Sign here" }).click();
  await ui.getByRole("button", { name: "Check your answers" }).click();
  await ui.getByRole("button", { name: "Continue" }).click();
  await ui.getByRole("checkbox").check();
  await ui.getByRole("button", { name: "Sign document" }).click();
  await expect(ui.getByTestId("screen-handback")).toBeVisible();
  await expect(ui.getByText("Maria Alvarez")).toHaveCount(0);
  await shot(page, "40-kiosk-handback");
});

test("choosing paper leads to decline, and the host is told", async ({ page }) => {
  const ui = await open(page, "single");
  await readEveryPage(ui, 2);
  await ui.getByRole("button", { name: "Continue" }).click();
  await ui.getByRole("button", { name: "I'd rather sign on paper" }).click();
  await expect(ui.getByTestId("step-decline")).toBeVisible();
  await expect(ui.getByRole("radio", { name: "I would rather sign on paper" })).toBeChecked();
  await shot(page, "50-decline");
  await expect(ui.getByTestId("decline-consequence")).toContainText("closes the document");
  await ui.getByRole("button", { name: "Close this document and tell the clinic" }).click();
  await expect(ui.getByTestId("screen-declined")).toBeVisible();
  await shot(page, "51-declined");
  await expect(page.locator('#log li[data-message="esign:declined"]')).toHaveCount(1);
});

test("expired, withdrawn, failing and never-connected sessions each get their own screen", async ({
  page,
}) => {
  let ui = await open(page, "expired");
  await expect(ui.getByTestId("screen-expired")).toBeVisible();
  await shot(page, "60-expired");

  ui = await open(page, "voided");
  await expect(ui.getByTestId("screen-unavailable")).toBeVisible();
  await shot(page, "61-voided");

  ui = await open(page, "error");
  await expect(ui.getByTestId("screen-error")).toBeVisible({ timeout: 15_000 });
  await shot(page, "62-error");

  ui = await open(page, "document-error");
  await expect(ui.getByText("We couldn't show the document.")).toBeVisible({ timeout: 15_000 });
  await shot(page, "63-document-error");

  ui = await open(page, "ending-soon");
  await expect(ui.getByText(/this session closes in about/)).toBeVisible();
  await shot(page, "64-ending-soon");

  ui = await open(page, "no-token");
  await expect(ui.getByTestId("screen-connecting")).toBeVisible();
  await shot(page, "65-connecting");
  await expect(ui.getByTestId("screen-connect-failed")).toBeVisible({ timeout: 20_000 });
  await shot(page, "66-connect-failed");
});

/**
 * The review and consent screens are the two long scrollers, and the patient who needs the
 * "closing soon" warning is the one who has been reading for two minutes -- far below the top of
 * the page. The warning used to be an ordinary block at the top of `<main>`, so by the time it
 * appeared it was painted out of view, and the next thing that happened was the draft being lost.
 */
test("the session warning stays on screen while the patient scrolls and reads", async ({
  page,
}) => {
  const ui = await open(page, "ending-soon");
  const banner = ui.getByTestId("deadline-banner");
  await expect(banner).toBeVisible();
  await expect(banner).toBeInViewport();

  // Read the whole document: the banner is still there, not somewhere above the scroll.
  await readEveryPage(ui, 2);
  await expect(banner).toBeInViewport();
  await shot(page, "67-ending-soon-review-scrolled");

  await ui.getByRole("button", { name: "Continue" }).click();
  await expect(ui.getByTestId("step-consent")).toBeVisible();
  await ui
    .getByRole("checkbox", { name: /I agree to sign electronically/ })
    .scrollIntoViewIfNeeded();
  await expect(banner).toBeInViewport();
  await shot(page, "68-ending-soon-consent-scrolled");
});

test("dark mode and a 360px screen", async ({ browser }) => {
  const context = await browser.newContext({
    viewport: { width: 360, height: 740 },
    colorScheme: "dark",
    reducedMotion: "reduce",
  });
  const page = await context.newPage();
  const ui = await open(page, "single");
  await readEveryPage(ui, 2);
  await shot(page, "70-dark-review");
  await ui.getByRole("button", { name: "Continue" }).click();
  await expect(ui.getByTestId("step-consent")).toBeVisible();
  await shot(page, "71-dark-consent");
  await agree(ui);
  await drawSignature(page, ui);
  await shot(page, "72-dark-adopt");
  // Nothing may force the page to scroll sideways at 360px.
  const overflow = await page
    .frames()
    .find((f) => f.url().includes("sign.html"))
    ?.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBe(0);
  await context.close();
});

test("a clinic tablet in portrait", async ({ browser }) => {
  const context = await browser.newContext({
    viewport: { width: 834, height: 1112 },
    hasTouch: true,
    reducedMotion: "reduce",
  });
  const page = await context.newPage();
  const ui = await open(page, "kiosk");
  await readEveryPage(ui, 2);
  await shot(page, "80-tablet-review");
  await ui.getByRole("button", { name: "Continue" }).click();
  await agree(ui);
  await drawSignature(page, ui);
  await shot(page, "81-tablet-adopt");
  await ui.getByRole("button", { name: "Use this signature" }).click();
  await ui.getByRole("checkbox").check();
  await ui.getByRole("button", { name: "Next" }).click();
  await ui.getByRole("button", { name: "Sign here" }).click();
  await expect(ui.locator("[data-testid=field-closeup] canvas[data-rendered]")).toBeVisible();
  await shot(page, "82-tablet-field");
  await context.close();
});
