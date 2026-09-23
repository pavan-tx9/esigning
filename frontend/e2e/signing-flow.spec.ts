import { expect, type FrameLocator, type Page, test } from "@playwright/test";

/**
 * The whole flow in a real browser at phone size, through the dev harness (which plays the host
 * page) and against the MSW mock of the Signer API. What this proves that the unit tests cannot:
 * the postMessage handshake across a real iframe boundary, pdf.js rendering with the locally
 * bundled worker, page-seen tracking by real scrolling, a real drawn PNG reaching the API -- and,
 * for addendum 3, that the short path really is three presses of a real button in a real browser.
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
  page.screenshot({ path: `test-results/screens/${name}.png`, fullPage: true });

/**
 * Count every press of anything pressable inside the signing UI, so "three taps" is a measurement
 * of the shipped page and not an accounting convention.
 */
async function countTaps(page: Page) {
  await page.addInitScript(() => {
    (window as unknown as { __taps: string[] }).__taps = [];
    document.addEventListener(
      "click",
      (event) => {
        const hit = (event.target as HTMLElement | null)?.closest(
          "button, a, input, label, [role='button']",
        );
        if (hit) {
          (window as unknown as { __taps: string[] }).__taps.push(
            (hit.textContent ?? hit.nodeName).trim().slice(0, 40),
          );
        }
      },
      true,
    );
  });
}

const tapsIn = async (page: Page): Promise<string[]> => {
  const frame = page.frames().find((f) => f.url().includes("sign.html"));
  return (await frame?.evaluate(() => (window as unknown as { __taps: string[] }).__taps)) ?? [];
};

async function open(page: Page, scenario: string, extra = ""): Promise<FrameLocator> {
  await page.goto(`/src/dev/harness.html?scenario=${scenario}&latency=150${extra}`);
  return page.frameLocator("#frame");
}

async function readEveryPage(ui: FrameLocator, pages: number) {
  await expect(ui.getByTestId("step-read")).toBeVisible();
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

/**
 * A one-page document is displayed by being on the screen -- but only once it has been *painted*,
 * which is what the observer that marks it seen is watching for. Wait for that, never for a
 * button to stop being inert.
 */
async function readOnePage(ui: FrameLocator) {
  await expect(ui.getByTestId("step-read")).toBeVisible();
  await expect(ui.locator("canvas[data-rendered]").first()).toBeVisible();
  await expect(ui.getByTestId("page-progress")).toContainText("All pages seen");
}

/** Read it, tick the box that is in the same scroll as it, and go on to sign. */
async function readAndContinue(ui: FrameLocator, pages: number) {
  await readEveryPage(ui, pages);
  await expect(ui.getByTestId("consent-block")).toBeVisible();
  await ui.getByRole("checkbox", { name: /I agree to sign this document electronically/ }).check();
  await ui.getByRole("button", { name: "Continue to sign" }).click();
  await expect(ui.getByTestId("step-sign")).toBeVisible();
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

test("a patient reads, agrees, draws a signature, signs and gets the sealed copy", async ({
  page,
}) => {
  const signRequests: { key: string | null; body: string }[] = [];
  const ui = await open(page, "single");

  // Read ----------------------------------------------------------------------------------------
  await expect(ui.getByTestId("signing-as")).toContainText("Maria Alvarez");
  await expect(ui.getByTestId("step-progress")).toContainText("Step 1 of 3");
  await expect(ui.locator("canvas[data-rendered]").first()).toBeVisible();
  await shot(page, "01-read");

  // Continue is inert until every page has been displayed, and says why.
  // (aria-disabled rather than disabled, so it stays focusable; Playwright needs `force`.)
  await ui.getByRole("button", { name: "Continue to sign" }).click({ force: true });
  await expect(ui.getByRole("alert")).toContainText(/Please look at page/);
  await expect(ui.getByTestId("page-progress")).toContainText(/Still to see: page/);
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
  expect(markBox.width).toBeCloseTo(220 * scale, 0);

  await ui.getByRole("button", { name: "Make the document larger" }).click();
  await expect(ui.locator('[data-page="2"] canvas')).toHaveJSProperty(
    "clientWidth",
    Math.floor(pageBox.width * 1.5),
  );
  await ui.getByRole("button", { name: "Make the document smaller" }).click();

  // The consent block is in the same scroll as the document, and opens in place.
  const consent = ui.getByTestId("consent-block");
  await consent.scrollIntoViewIfNeeded();
  await expect(ui.getByTestId("disclosure")).toHaveAttribute("data-expanded", "false");
  await shot(page, "02-read-consent-collapsed");
  await ui.getByRole("button", { name: "Read the full notice" }).click();
  await expect(ui.getByTestId("disclosure")).toHaveAttribute("data-expanded", "true");
  await expect(ui.getByText(/You can also ask for a paper copy at any time/)).toBeVisible();
  await shot(page, "03-read-consent-open");
  await ui.getByRole("button", { name: "Hide the full notice" }).click();

  // Inert until the box is ticked as well, and it says which of the two is missing.
  await ui.getByRole("button", { name: "Continue to sign" }).click({ force: true });
  await expect(ui.getByRole("alert")).toContainText("tick the box");
  await ui.getByRole("checkbox", { name: /I agree to sign this document electronically/ }).check();
  await shot(page, "04-read-ready");
  await ui.getByRole("button", { name: "Continue to sign" }).click();

  // Sign ----------------------------------------------------------------------------------------
  await expect(ui.getByTestId("step-sign")).toBeVisible();
  await expect(ui.getByTestId("step-progress")).toContainText("Step 2 of 3");
  await expect(ui.getByTestId("fields-progress")).toContainText("0 of 2");
  await shot(page, "05-sign-empty");

  await drawSignature(page, ui);
  await shot(page, "06-sign-drawn");
  await ui.getByRole("button", { name: "Undo last stroke" }).click();
  await drawSignature(page, ui);

  await ui
    .getByRole("checkbox", { name: "I have received the Notice of Privacy Practices" })
    .check();
  await expect(ui.getByTestId("fields-progress")).toContainText("1 of 2");
  // Each row shows the part of the page its mark lands on, rendered from the same bytes the
  // Read screen used -- fetched once, parsed again, never re-requested.
  await expect(
    ui.locator("[data-testid=field-closeup] canvas[data-rendered]").first(),
  ).toBeVisible();
  await ui.getByRole("button", { name: "Sign here" }).click();
  await expect(ui.getByText("Signature in place")).toBeVisible();
  await expect(ui.locator('[data-field-box="patient_sig"] img')).toBeVisible();
  // Committing the signature collapses the chooser to what will be placed.
  await expect(ui.getByTestId("signature-showing")).toBeVisible();
  await expect(ui.getByTestId("fields-progress")).toContainText("2 of 2");
  await shot(page, "07-sign-complete");

  page.on("request", (request) => {
    if (request.url().endsWith("/v1/signing/sign")) {
      signRequests.push({
        key: request.headers()["idempotency-key"] ?? null,
        body: request.postData() ?? "",
      });
    }
  });
  await ui.getByRole("button", { name: "Sign as Maria Alvarez" }).click();

  // Done ----------------------------------------------------------------------------------------
  await expect(ui.getByTestId("step-done")).toBeVisible();
  await expect(ui.getByTestId("copy-sealing")).toBeVisible();
  await shot(page, "08-done-sealing");
  await expect(ui.getByTestId("copy-ready")).toBeVisible({ timeout: 20_000 });
  await expect(ui.getByRole("link", { name: "Save your signed copy" })).toBeVisible();
  await shot(page, "09-done-ready");

  // What actually went over the wire.
  expect(signRequests).toHaveLength(1);
  expect(signRequests[0]?.key).toMatch(/^[0-9a-f-]{36}$/);
  const sent = JSON.parse(signRequests[0]?.body ?? "{}");
  // The press is the intent confirmation (addendum 3 A 3): the flag is what it means.
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

/**
 * Addendum 3, measured. A clinician with a signature on file and an agreement already given in
 * this sitting signs a one-page order in three presses of a real button.
 */
test("the short path is three taps: Continue to sign, Sign here, Sign as ...", async ({ page }) => {
  await countTaps(page);
  const ui = await open(page, "queue");

  await expect(ui.getByTestId("queue-progress")).toContainText("1 of 3");
  await expect(ui.getByTestId("step-read")).toBeVisible();
  await expect(ui.locator("canvas[data-rendered]").first()).toBeVisible();
  // One page: it is displayed by being on the screen, and the agreement is already given.
  await expect(ui.getByTestId("page-progress")).toContainText("All pages seen");
  await expect(ui.getByTestId("standing-consent")).toContainText(
    /You agreed to sign electronically at \d{1,2}:\d{2}/,
  );
  await shot(page, "20-queue-read-standing");

  await ui.getByRole("button", { name: "Continue to sign" }).click(); // 1

  await expect(ui.getByTestId("step-sign")).toBeVisible();
  await expect(ui.getByTestId("signature-showing")).toBeVisible();
  await expect(ui.getByTestId("reauth-verified")).toHaveAttribute("data-reauth-scope", "span");
  await shot(page, "21-queue-sign");
  await ui.getByRole("button", { name: "Sign here" }).click(); // 2
  await ui.getByRole("button", { name: "Sign as Dr. Priya Raman" }).click(); // 3

  await expect(ui.getByTestId("step-done")).toBeVisible();
  const taps = await tapsIn(page);
  expect(taps).toHaveLength(3);
});

/** Addendum 3 B: the countdown, "Stay here", and the hand-back to the host. */
test("a signing queue advances by itself, and stops when asked", async ({ page }) => {
  const ui = await open(page, "queue");
  await readOnePage(ui);
  await ui.getByRole("button", { name: "Continue to sign" }).click();
  await ui.getByRole("button", { name: "Sign here" }).click();
  await ui.getByRole("button", { name: "Sign as Dr. Priya Raman" }).click();

  const next = ui.getByTestId("queue-next");
  await expect(next).toBeVisible();
  await expect(next.getByTestId("queue-position")).toContainText("Document 1 of 3");
  await expect(next.getByRole("heading")).toContainText("Next: Order for T. N.");
  await shot(page, "22-queue-countdown");

  // Staying is a button, not a timer that stops if you happen to touch the screen.
  await ui.getByRole("button", { name: "Stay here" }).click();
  await expect(ui.getByRole("button", { name: "Open Order for T. N." })).toBeVisible();
  await shot(page, "23-queue-stayed");
  await page.waitForTimeout(6_000);
  await expect(page.locator('#log li[data-message="esign:next"]')).toHaveCount(0);

  // Asking for it opens the next document, in the same frame, as its own session.
  await ui.getByRole("button", { name: "Open Order for T. N." }).click();
  await expect(page.locator('#log li[data-message="esign:next"]')).toHaveCount(1);
  await expect(ui.getByTestId("queue-progress")).toContainText("2 of 3");
  await expect(ui.getByTestId("signing-as")).toContainText("Dr. Priya Raman");
  await shot(page, "24-queue-second-document");

  // And left alone, it advances on its own.
  await readOnePage(ui);
  await ui.getByRole("button", { name: "Continue to sign" }).click();
  await ui.getByRole("button", { name: "Sign here" }).click();
  await ui.getByRole("button", { name: "Sign as Dr. Priya Raman" }).click();
  await expect(ui.getByTestId("queue-next")).toBeVisible();
  await expect(ui.getByTestId("queue-progress")).toContainText("3 of 3", { timeout: 15_000 });

  // The last one says so, and asks for nothing more.
  await readOnePage(ui);
  await ui.getByRole("button", { name: "Continue to sign" }).click();
  await ui.getByRole("button", { name: "Sign here" }).click();
  await ui.getByRole("button", { name: "Sign as Dr. Priya Raman" }).click();
  await expect(ui.getByTestId("queue-finished")).toContainText("That was the last of 3");
  await shot(page, "25-queue-finished");
});

/**
 * Addendum 3 A 4: re-authentication happens on the press. The press asks the host for it, the
 * page waits inline, and the signature goes by itself when the server vouches -- no second tap.
 */
test("a clinician is handed to the host on the press, then signs without pressing again", async ({
  page,
}) => {
  const ui = await open(page, "reauth-press");
  await readOnePage(ui);
  await ui.getByRole("button", { name: "Continue to sign" }).click();
  await expect(ui.getByTestId("reauth-needed")).toContainText("when you press this");
  await ui.getByRole("button", { name: "Sign here" }).click();
  await shot(page, "30-sign-before-reauth");

  await ui.getByRole("button", { name: "Sign as Dr. Priya Raman" }).click();
  await expect(ui.getByTestId("reauth-waiting")).toBeVisible();
  await expect(ui.getByTestId("sign-button")).toContainText("Confirming it's you");
  await expect(page.locator("#reauth")).toBeVisible();
  await shot(page, "31-sign-reauth-waiting");

  await page.getByRole("button", { name: "Password confirmed" }).click();
  // No second press: the one that asked is the one that signs.
  await expect(ui.getByTestId("step-done")).toBeVisible({ timeout: 15_000 });
  await expect(ui.getByTestId("copy-ready")).toBeVisible({ timeout: 20_000 });
});

test("a press the host never answers times out, and says nothing has been signed", async ({
  page,
}) => {
  const ui = await open(page, "reauth-timeout");
  await readOnePage(ui);
  await ui.getByRole("button", { name: "Continue to sign" }).click();
  await ui.getByRole("button", { name: "Sign here" }).click();
  await ui.getByRole("button", { name: "Sign as Dr. Priya Raman" }).click();
  await expect(ui.getByTestId("reauth-waiting")).toBeVisible();
  await page.getByRole("button", { name: "Do nothing" }).click();

  // Backing out of the wait leaves the button as it was, and nothing was sent.
  await ui.getByRole("button", { name: "Cancel" }).click();
  await expect(ui.getByTestId("reauth-waiting")).toHaveCount(0);
  await expect(ui.getByTestId("sign-button")).toContainText("Sign as Dr. Priya Raman");
  await shot(page, "32-sign-reauth-cancelled");
});

test("a confirmation that runs out before the signature lands asks once more", async ({ page }) => {
  const ui = await open(page, "reauth-lapsed");
  await readOnePage(ui);
  await ui.getByRole("button", { name: "Continue to sign" }).click();
  await expect(ui.getByTestId("reauth-verified")).toBeVisible();
  await ui.getByRole("button", { name: "Sign here" }).click();
  await ui.getByRole("button", { name: "Sign as Dr. Priya Raman" }).click();

  await expect(ui.getByText(/confirmation ran out before the document was signed/)).toBeVisible();
  await expect(ui.getByTestId("step-sign")).toBeVisible();
  await shot(page, "33-sign-reauth-lapsed");

  await ui.getByRole("button", { name: "Try again" }).click();
  await page.getByRole("button", { name: "Password confirmed" }).click();
  await expect(ui.getByTestId("step-done")).toBeVisible({ timeout: 15_000 });
});

/** Addendum 3 C: the fallback when the server will not honour the standing agreement. */
test("an agreement that has run out falls back to the checkbox, in place", async ({ page }) => {
  const ui = await open(page, "consent-lapsed");
  await readEveryPage(ui, 2);
  await expect(ui.getByTestId("standing-consent")).toBeVisible();
  await ui.getByRole("button", { name: "Continue to sign" }).click();

  await expect(ui.getByText("Please agree once more.")).toBeVisible();
  await expect(ui.getByTestId("step-read")).toBeVisible();
  await expect(ui.getByTestId("standing-consent")).toHaveCount(0);
  await shot(page, "34-read-consent-not-standing");

  await ui.getByRole("checkbox", { name: /I agree to sign this document electronically/ }).check();
  await ui.getByRole("button", { name: "Continue to sign" }).click();
  await expect(ui.getByTestId("step-sign")).toBeVisible();
});

test("the first of several signers is told the copy comes later; click-to-sign and initials", async ({
  page,
}) => {
  const ui = await open(page, "multi");
  await readAndContinue(ui, 3);
  await ui.getByRole("radio", { name: /Use my printed name/ }).check();
  await shot(page, "40-sign-printed-name");
  await ui.getByRole("button", { name: "Add initials" }).click();
  await ui.getByRole("textbox", { name: /Anything you would like to ask/ }).fill("No questions.");
  await ui.getByRole("button", { name: "Sign here" }).click();
  await expect(ui.getByTestId("fields-progress")).toContainText("3 of 3");
  await shot(page, "41-sign-multi-field");
  await ui.getByRole("button", { name: "Sign as Maria Alvarez" }).click();
  await expect(ui.getByTestId("waiting-on-others")).toContainText("the witness and the clinician");
  await shot(page, "42-done-waiting-on-others");
});

/**
 * A parallel envelope moving on under the signer. The co-signer commits a new revision while this
 * one is on the Sign screen, so the bytes they read are no longer the bytes the marks would land
 * on and the service refuses with 409 `not_viewed` (SPEC section 13, fourth round). The UI owns
 * the way out: it drops the document it holds and returns to Read, and the fresh `POST /viewed`
 * that step already sends is what lets the signature through. The draft survives.
 */
test("a co-signer moves the document on: back to read, and the signature then stands", async ({
  page,
}) => {
  const ui = await open(page, "multi");
  await readAndContinue(ui, 3);
  await ui.getByRole("radio", { name: /Use my printed name/ }).check();
  await ui.getByRole("button", { name: "Add initials" }).click();
  await ui.getByRole("button", { name: "Sign here" }).click();

  const frame = page.frames().find((f) => f.url().includes("sign.html"));
  if (frame === undefined) {
    throw new Error("the signing UI is not framed");
  }
  await frame.evaluate(() => window.__esignMock?.otherSignerSigned("multi"));

  await ui.getByRole("button", { name: "Sign as Maria Alvarez" }).click();

  await expect(ui.getByTestId("review-again")).toBeVisible();
  await expect(ui.getByTestId("step-read")).toBeVisible();
  await shot(page, "43-read-again");

  // Reading what it says now is the whole recovery, and the answers are still there.
  await readAndContinue(ui, 3);
  await expect(ui.getByTestId("fields-progress")).toContainText("2 of 3");
  await ui.getByRole("button", { name: "Sign as Maria Alvarez" }).click();
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
 * SPEC section 14 B on the new panel: the signature saved last time is what the panel shows,
 * "Change" is how to make another, placing it is still one press per field, and the saved image
 * never travels back to the server.
 */
test("a saved signature is what the panel shows, placed per field, and sent as its id", async ({
  page,
}) => {
  const signRequests: string[] = [];
  page.on("request", (request) => {
    if (request.url().endsWith("/v1/signing/sign")) {
      signRequests.push(request.postData() ?? "");
    }
  });
  const ui = await open(page, "saved-signature");
  await readAndContinue(ui, 2);

  await expect(ui.getByTestId("signature-showing")).toBeVisible();
  await expect(ui.getByRole("img", { name: /Your signature, as drawn/ })).toBeVisible();
  await expect(ui.getByTestId("saved-signature")).toContainText("only you can use it");
  await expect(ui.getByTestId("signature-pad")).toHaveCount(0);
  await expect(ui.getByTestId("save-signature")).toHaveCount(0);
  await shot(page, "50-sign-saved-offered");

  await ui.getByRole("checkbox", { name: /Notice of Privacy/ }).check();
  await ui.getByRole("button", { name: "Sign here" }).click();
  await expect(ui.locator('[data-field-box="patient_sig"] img')).toBeVisible();
  await shot(page, "51-sign-saved-placed");
  await ui.getByRole("button", { name: "Sign as Maria Alvarez" }).click();
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
  await readAndContinue(ui, 2);

  // Removing asks once more, and keeping it changes nothing.
  await ui.getByRole("button", { name: "Remove my saved signature" }).click();
  await expect(ui.getByTestId("remove-saved")).toBeVisible();
  await shot(page, "52-sign-remove-asks");
  await ui.getByRole("button", { name: "Keep it" }).click();
  await expect(ui.getByTestId("remove-saved")).toHaveCount(0);
  await expect(ui.getByTestId("saved-signature")).toBeVisible();

  // Making a new one: the box to save it is there, and unticked.
  await ui.getByRole("button", { name: "Change" }).click();
  await expect(ui.getByRole("radio", { name: /My saved signature/ })).toBeVisible();
  const keep = ui.getByRole("checkbox", { name: /Save this signature for next time/ });
  await expect(keep).not.toBeChecked();
  await drawSignature(page, ui);
  await keep.check();
  await shot(page, "53-sign-new-and-save");

  await ui.getByRole("checkbox", { name: /Notice of Privacy/ }).check();
  await ui.getByRole("button", { name: "Sign here" }).click();
  await expect(ui.getByTestId("signature-showing")).toBeVisible();

  // Second thoughts: the saved one can go after all, and the marks made with it go with it.
  await ui.getByRole("button", { name: "Remove my saved signature" }).click();
  await ui.getByRole("button", { name: "Remove it" }).click();
  await expect(ui.getByTestId("saved-signature")).toHaveCount(0);
  await expect(ui.getByText("How would you like to sign?")).toBeVisible();
  await shot(page, "54-sign-after-remove");

  // The drawing has to be made again (the pad is fresh), and saving is still on offer.
  await drawSignature(page, ui);
  await ui.getByRole("checkbox", { name: /Save this signature for next time/ }).check();
  await ui.getByRole("button", { name: "Sign here" }).click();
  // The tick they gave earlier is still there; only the signature had to be placed again.
  await expect(ui.getByRole("checkbox", { name: /Notice of Privacy/ })).toBeChecked();
  await ui.getByRole("button", { name: "Sign as Maria Alvarez" }).click();
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
  await readAndContinue(ui, 2);
  // The patient has a signature on file; a shared tablet is never offered it, nor asked to save.
  await expect(ui.getByTestId("saved-signature")).toHaveCount(0);
  await expect(ui.getByRole("checkbox", { name: /Save this signature/ })).toHaveCount(0);
  await ui.getByRole("radio", { name: /Use my printed name/ }).check();
  await ui.getByRole("checkbox", { name: /Notice of Privacy/ }).check();
  await ui.getByRole("button", { name: "Sign here" }).click();
  await ui.getByRole("button", { name: "Sign as Maria Alvarez" }).click();
  await expect(ui.getByTestId("screen-handback")).toBeVisible();
  await expect(ui.getByText("Maria Alvarez")).toHaveCount(0);
  await shot(page, "60-kiosk-handback");
});

/** Addendum 3 A: the paper path is a quiet link on both screens before Done. */
test("choosing paper is one link away from Read and from Sign", async ({ page }) => {
  const ui = await open(page, "single");
  await readEveryPage(ui, 2);
  await ui.getByRole("button", { name: "I'd rather sign on paper" }).click();
  await expect(ui.getByTestId("step-decline")).toBeVisible();
  await ui.getByRole("button", { name: "Go back to signing" }).click();
  await expect(ui.getByTestId("step-read")).toBeVisible();
  // Looking at the way out costs nothing: the pages already displayed are still displayed.
  await expect(ui.getByTestId("page-progress")).toContainText("All pages seen");

  await ui.getByRole("checkbox", { name: /I agree to sign this document electronically/ }).check();
  await ui.getByRole("button", { name: "Continue to sign" }).click();
  await expect(ui.getByTestId("step-sign")).toBeVisible();
  await ui.getByRole("button", { name: "I'd rather sign on paper" }).click();

  await expect(ui.getByTestId("step-decline")).toBeVisible();
  await expect(ui.getByRole("radio", { name: "I would rather sign on paper" })).toBeChecked();
  await shot(page, "70-decline");
  await expect(ui.getByTestId("decline-consequence")).toContainText("closes the document");
  await ui.getByRole("button", { name: "Close this document and tell the clinic" }).click();
  await expect(ui.getByTestId("screen-declined")).toBeVisible();
  await shot(page, "71-declined");
  await expect(page.locator('#log li[data-message="esign:declined"]')).toHaveCount(1);
});

test("expired, withdrawn, failing and never-connected sessions each get their own screen", async ({
  page,
}) => {
  let ui = await open(page, "expired");
  await expect(ui.getByTestId("screen-expired")).toBeVisible();
  await shot(page, "80-expired");

  ui = await open(page, "voided");
  await expect(ui.getByTestId("screen-unavailable")).toBeVisible();
  await shot(page, "81-voided");

  ui = await open(page, "error");
  await expect(ui.getByTestId("screen-error")).toBeVisible({ timeout: 15_000 });
  await shot(page, "82-error");

  ui = await open(page, "document-error");
  await expect(ui.getByText("We couldn't show the document.")).toBeVisible({ timeout: 15_000 });
  await shot(page, "83-document-error");

  ui = await open(page, "ending-soon");
  await expect(ui.getByText(/this session closes in about/)).toBeVisible();
  await shot(page, "84-ending-soon");

  ui = await open(page, "no-token");
  await expect(ui.getByTestId("screen-connecting")).toBeVisible();
  await shot(page, "85-connecting");
  await expect(ui.getByTestId("screen-connect-failed")).toBeVisible({ timeout: 20_000 });
  await shot(page, "86-connect-failed");
});

/**
 * The Read screen is the long scroller, and the patient who needs the "closing soon" warning is
 * the one who has been reading for two minutes -- far below the top of the page.
 */
test("the session warning stays on screen while the patient scrolls and reads", async ({
  page,
}) => {
  const ui = await open(page, "ending-soon");
  const banner = ui.getByTestId("deadline-banner");
  await expect(banner).toBeVisible();
  await expect(banner).toBeInViewport();

  await readEveryPage(ui, 2);
  await expect(banner).toBeInViewport();
  await ui.getByTestId("consent-block").scrollIntoViewIfNeeded();
  await expect(banner).toBeInViewport();
  await shot(page, "87-ending-soon-scrolled");
});

/**
 * Every screen at the narrowest size we support and in the dark, and then the same screens on a
 * desktop. These exist to be looked at: the assertions only keep them honest.
 */
for (const look of [
  { name: "360-dark", width: 360, height: 740, colorScheme: "dark" as const },
  { name: "desktop", width: 1280, height: 900, colorScheme: "light" as const },
]) {
  test(`every screen at ${look.name}`, async ({ browser }) => {
    const context = await browser.newContext({
      viewport: { width: look.width, height: look.height },
      colorScheme: look.colorScheme,
      reducedMotion: "reduce",
    });
    const page = await context.newPage();
    const noSidewaysScroll = async () => {
      const overflow = await page
        .frames()
        .find((f) => f.url().includes("sign.html"))
        ?.evaluate(
          () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
        );
      expect(overflow).toBeLessThanOrEqual(0);
    };

    // Read, with the consent block under the document.
    let ui = await open(page, "single");
    await readEveryPage(ui, 2);
    await shot(page, `90-${look.name}-read`);
    await ui.getByTestId("consent-block").scrollIntoViewIfNeeded();
    await shot(page, `91-${look.name}-read-consent`);
    await noSidewaysScroll();

    // Sign, first with the chooser open, then complete.
    await ui.getByRole("checkbox", { name: /I agree to sign this document/ }).check();
    await ui.getByRole("button", { name: "Continue to sign" }).click();
    await expect(ui.getByTestId("step-sign")).toBeVisible();
    await shot(page, `92-${look.name}-sign-chooser`);
    await drawSignature(page, ui);
    await ui.getByRole("checkbox", { name: /Notice of Privacy/ }).check();
    await ui.getByRole("button", { name: "Sign here" }).click();
    await expect(ui.getByTestId("fields-progress")).toContainText("2 of 2");
    await shot(page, `93-${look.name}-sign-complete`);
    await noSidewaysScroll();

    // Done, sealing and then ready.
    await ui.getByRole("button", { name: "Sign as Maria Alvarez" }).click();
    await expect(ui.getByTestId("copy-sealing")).toBeVisible();
    await shot(page, `94-${look.name}-done-sealing`);
    await expect(ui.getByTestId("copy-ready")).toBeVisible({ timeout: 20_000 });
    await shot(page, `95-${look.name}-done-ready`);
    await noSidewaysScroll();

    // The saved-signature panel and the queue screens, which the walk above never shows.
    ui = await open(page, "queue");
    await readOnePage(ui);
    await shot(page, `96-${look.name}-queue-read`);
    await ui.getByRole("button", { name: "Continue to sign" }).click();
    await expect(ui.getByTestId("signature-showing")).toBeVisible();
    await shot(page, `97-${look.name}-queue-sign`);
    await noSidewaysScroll();
    await ui.getByRole("button", { name: "Sign here" }).click();
    await ui.getByRole("button", { name: "Sign as Dr. Priya Raman" }).click();
    await expect(ui.getByTestId("queue-next")).toBeVisible();
    await shot(page, `98-${look.name}-queue-done`);
    await noSidewaysScroll();

    await context.close();
  });
}
