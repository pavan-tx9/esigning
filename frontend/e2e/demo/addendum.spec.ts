import { fileURLToPath } from "node:url";
import { expect, type FrameLocator, type Page, test } from "@playwright/test";
import {
  type AuditEvent,
  agreeAndContinue,
  auditTrail,
  drawSignature,
  looksSealed,
  openFromQueue,
  openTask,
  placeEveryField,
  queueTask,
  readAndContinue,
  readEveryPage,
  reloadUntilVisible,
  savedSignatureIsOffered,
  shot,
  signDocument,
  signIn,
  signWithReauth,
  typeSignature,
  typeSignatureAndSave,
  ui,
} from "./flow";

/**
 * Addenda 1 and 3 against the real stack: a paper document filed by the front desk, a clinician's
 * queue signed as one run on one confirmation of identity and one agreement to sign
 * electronically, a signature saved on one order and offered on the next, a shared tablet that is
 * never offered either, and the front desk taking the saved signature away.
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

// ------------------------------------------------- C + 3 B/C. the queue, signed as one run

const ORDERS = [
  "Order sign-off ORD-4471",
  "Order sign-off ORD-4472",
  "Order sign-off ORD-4473",
  "Order sign-off ORD-4474",
  "Order sign-off ORD-4475",
];

/** Every press of anything pressable inside the signing UI, since this document was opened. */
async function tapsOnThisDocument(page: Page): Promise<string[]> {
  const frame = page.frames().find((f) => f.url().includes("/sign?host="));
  return (await frame?.evaluate(() => (window as unknown as { __taps: string[] }).__taps)) ?? [];
}

/** A signature is on file, whatever earlier runs left in the service's database. */
async function haveASignatureOnFile(frame: FrameLocator, name: string): Promise<void> {
  if ((await frame.getByTestId("saved-signature").count()) > 0) {
    await savedSignatureIsOffered(frame);
    return;
  }
  await typeSignatureAndSave(frame, name);
}

const consentEvent = (events: AuditEvent[]) =>
  events.find((event) => event.event_type === "consent.accepted");

test("a clinician confirms once, agrees once, and signs five orders that open one after another", async ({
  page,
}) => {
  // Five documents, five seals, five webhook deliveries, all in one test because the run is the
  // thing being tested: it cannot be split without splitting the sitting.
  test.setTimeout(900_000);

  // The count is of real presses in the real browser, so "three taps" is measured rather than
  // asserted. The iframe reloads between documents, so each document starts the count again.
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

  await signIn(page, "priya");
  await page.getByRole("link", { name: "Signing queue" }).click();
  await expect(page.getByRole("heading", { name: "Signing queue" })).toBeVisible();
  // Her five orders, and the procedure consent that is hers to sign but not yet her turn.
  await expect(page.locator('[data-testid="queue-task"]')).toHaveCount(6);
  // A report is read, not run through: it has its own page and never joins the queue.
  await expect(page.getByText("Annual care summary")).toHaveCount(0);
  await shot(page, "60-queue");

  // One confirmation of identity, checked by the EHR and attested server to server on the first
  // document's session (Addendum 1 C).
  await page.locator("#queue-password").fill("demo1234");
  await page.getByTestId("queue-confirm").click();
  await expect(page.getByTestId("queue-confirmed")).toBeVisible();
  await shot(page, "61-queue-confirmed");

  const frame = await openFromQueue(page, ORDERS[0] as string);
  await expect(page.getByTestId("queue-run")).toContainText("Document 1 of 5 in this run");

  /** Per document: did the agreement stand on an earlier one, or was the notice displayed here? */
  const stood: boolean[] = [];

  for (const [index, title] of ORDERS.entries()) {
    // The host page and the signing UI agree about which document this is and where it sits.
    await expect(page.getByTestId("sign-title")).toContainText(title);
    await expect(frame.getByTestId("queue-progress")).toContainText(`${index + 1} of 5`);
    await readEveryPage(frame);

    // Addendum 3 C: the rest of the run says when the agreement was given instead of asking
    // again. Which document displays the notice is the database's to decide, not this spec's:
    // the span is measured from when the notice was last *displayed* and carried forward
    // unchanged, so a clinician who agreed in an earlier run against this same database is
    // still in that sitting (the first order then stands too), and a sitting that began before
    // this run can run out inside it (the notice comes back on that document, and the ones
    // after it stand on it). Exactly one of the two screens is right each time; which one
    // appeared is recorded here and checked against each envelope's own trail below.
    if ((await frame.getByTestId("standing-consent").count()) > 0 && !stood.some(Boolean)) {
      await shot(page, `62-order-${index + 1}-standing-consent`);
    }
    stood.push(await agreeAndContinue(frame));

    // No hand-off: the service vouches for her already, and the screen says on what grounds.
    const covered = frame.getByTestId("reauth-verified");
    await expect(covered).toHaveAttribute("data-reauth-scope", index === 0 ? "session" : "span");
    if (index > 0) {
      await expect(covered).toContainText("for an earlier document");
    }
    await expect(page.locator("#reauth")).toBeHidden();

    if (index === 0) {
      await haveASignatureOnFile(frame, "Priya Raman");
    } else {
      await savedSignatureIsOffered(frame);
    }
    await placeEveryField(frame);
    await signDocument(frame);
    await expect(frame.getByTestId("step-done")).toBeVisible();

    // Addendum 3 A, measured against the real service: read, place, sign. The tick is the fourth
    // tap on the document that displayed the notice, which is what the span removes from the
    // rest of the run -- so the three are counted after it, wherever it fell.
    if (index > 0) {
      const taps = await tapsOnThisDocument(page);
      if (!stood[index]) {
        expect(taps[0]).toMatch(/^I agree to sign this document/);
      }
      const presses = stood[index] ? taps : taps.slice(1);
      expect(presses).toHaveLength(3);
      expect(presses[0]).toBe("Continue to sign");
      expect(presses[1]).toBe("Sign here");
      expect(presses[2]).toMatch(/^Sign as /);
    }

    if (index < ORDERS.length - 1) {
      // It counts down in the open and then asks the host, which opens the next one into the
      // same frame as its own session. Nothing goes back to the list in between.
      await expect(frame.getByTestId("queue-next")).toBeVisible();
      if (index === 0) {
        await shot(page, "63-countdown-to-the-next-order");
      }
      await expect(frame.getByTestId("queue-progress")).toContainText(`${index + 2} of 5`, {
        timeout: 60_000,
      });
      await expect(page).toHaveURL(/\/sign\//);
    }
  }

  // The last one says so, and the host page ends the run rather than sending her back to a list.
  await expect(frame.getByTestId("queue-finished")).toContainText("That was the last of 5");
  await expect(page.getByTestId("queue-all-signed")).toContainText("All 5 signed");
  await shot(page, "64-all-five-signed");
  await expect(page.locator('#log li[data-message="esign:next"]')).toHaveCount(4);
  await expect(page.locator('#log li[data-message="esign:reauth_required"]')).toHaveCount(0);

  // ----------------------------------------------------------------- what each envelope records
  await page.goto("/queue");
  // The queue page knows nothing until it is asked again: each signature is the service's to
  // report, and each sealed copy arrives by webhook afterwards. Wait for all five to be filed.
  await expect
    .poll(
      async () => {
        await page.reload();
        let filed = 0;
        for (const title of ORDERS) {
          filed += await queueTask(page, title)
            .getByRole("link", { name: "See it in the chart" })
            .count();
        }
        return filed;
      },
      { timeout: 300_000, intervals: [3_000] },
    )
    .toBe(5);
  await shot(page, "65-queue-done");
  await expect(page.locator('[data-testid="queue-task"][data-status="signed"]')).toHaveCount(5);

  const envelopes: string[] = [];
  for (const title of ORDERS) {
    await queueTask(page, title).getByRole("link", { name: "See it in the chart" }).click();
    envelopes.push((await page.getByTestId("envelope-id").innerText()).trim());
    await page.goBack();
  }
  expect(new Set(envelopes).size).toBe(5);

  for (const [index, envelopeId] of envelopes.entries()) {
    const events = await auditTrail(page, envelopeId);
    const types = events.map((event) => event.event_type);
    // Every document in the sitting was read, agreed to and signed on its own. The span changed
    // whether the notice was displayed again, and nothing about what is on the record.
    expect(types).toContain("document.viewed");
    expect(types).toContain("consent.accepted");
    expect(types).toContain("signer.signed");
    // Nobody else is in this envelope's trail: every event that names a user names her, and the
    // rest are the host's own calls and the service's own work (sealing, the certificate).
    const named = [
      ...new Set(events.map((event) => event.actor.user_id).filter((id) => id !== null)),
    ];
    expect(named).toEqual(["u-priya"]);

    const consent = consentEvent(events);
    if (!stood[index]) {
      // The notice was displayed on this document, so the agreement rests on nothing else.
      expect(consent?.data.relied_on_envelope_id ?? null).toBeNull();
    } else if (index === 0) {
      // It stood before this run began, so it names an envelope from an earlier sitting -- never
      // one of these five, which did not exist yet.
      expect(consent?.data.relied_on_envelope_id).toEqual(expect.any(String));
      expect(envelopes).not.toContain(consent?.data.relied_on_envelope_id);
    } else {
      // It stands on the agreement given for the document before it, and says which and when.
      expect(consent?.data.relied_on_envelope_id).toBe(envelopes[index - 1]);
      expect(consent?.data.relied_on_accepted_at).toEqual(expect.any(String));
      expect(consent?.data.relied_on_root_accepted_at).toEqual(expect.any(String));
    }
  }

  // Whatever state the database was in, the run itself proves the shortcut: the notice is
  // displayed at most once in five documents, and the others stand on that agreement.
  expect(stood.filter((it) => !it).length).toBeLessThanOrEqual(1);

  // And the verifier is happy with both borrowings: the attestation and the agreement.
  await queueTask(page, ORDERS[2] as string)
    .getByRole("link", { name: "See it in the chart" })
    .click();
  await page.getByTestId("verify").click();
  await expect(page.getByTestId("verification-result")).toContainText("Verified.");
  await shot(page, "66-queue-order-verified");
});

// --------------------------------------------------------------------------- B. a saved signature

test("a clinician saves a signature on one order and is offered it on the next", async ({
  page,
}) => {
  test.setTimeout(420_000);
  await signIn(page, "tomas");
  await page.getByRole("link", { name: "Signing queue" }).click();

  // The first order: no confirmation made on the queue page, so the press asks the host for one.
  const frame = await openFromQueue(page, "Order sign-off ORD-4480");
  await readAndContinue(frame);
  await typeSignatureAndSave(frame, "Tomas Silva");
  await shot(page, "70-save-signature");
  await placeEveryField(frame);
  await signWithReauth(page, frame);

  // The second opens by itself, and offers what he kept rather than asking him to make it again.
  await expect(frame.getByTestId("queue-progress")).toContainText("2 of 2", { timeout: 60_000 });
  await expect(page.getByTestId("sign-title")).toContainText("ORD-4481");
  await readAndContinue(frame);
  await savedSignatureIsOffered(frame);
  await expect(frame.getByTestId("saved-signature")).toContainText(/Saved name · kept from/);
  await shot(page, "71-saved-signature-offered");
  await expect(frame.getByTestId("reauth-verified")).toHaveAttribute("data-reauth-scope", "span");
  await placeEveryField(frame);
  await signDocument(frame);

  await expect(frame.getByTestId("copy-ready")).toBeVisible({ timeout: 120_000 });
  await expect(page.getByTestId("queue-all-signed")).toContainText("All 2 signed");
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
    await readAndContinue(frame);
    await typeSignatureAndSave(frame, "Sam Okafor");
    await placeEveryField(frame);
    await signDocument(frame);
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
    await expect(frame.getByTestId("step-read")).toBeVisible({ timeout: 45_000 });
    await readEveryPage(frame);
    // Neither the agreement he gave a minute ago nor the signature he kept is offered here.
    await expect(frame.getByTestId("standing-consent")).toHaveCount(0);
    await agreeAndContinue(frame);
    await expect(frame.getByTestId("signature-panel")).toBeVisible();
    await expect(frame.getByTestId("saved-signature")).toHaveCount(0);
    await expect(frame.getByTestId("save-signature")).toHaveCount(0);
    await shot(page, "80-kiosk-nothing-saved-offered");
    await drawSignature(page, frame);
    await placeEveryField(frame);
    await signDocument(frame);
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
    await readAndContinue(frame);
    await expect(frame.getByTestId("signature-panel")).toBeVisible();
    await expect(frame.getByTestId("saved-signature")).toHaveCount(0);
    await typeSignature(frame, "Sam Okafor");
    await expect(frame.getByTestId("save-signature")).toBeVisible();
    await shot(page, "82-after-revoke-nothing-offered");
  });
});
