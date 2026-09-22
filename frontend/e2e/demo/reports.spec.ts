import { expect, test } from "@playwright/test";
import {
  adoptTyped,
  agree,
  fillEveryField,
  looksSealed,
  openReport,
  readEveryPage,
  reauthenticate,
  report,
  shot,
  signIn,
} from "./flow";

/**
 * Addendum 2 against the real stack: a document the *host* generated.
 *
 * Everything in the other demo specs starts from a template the service published. These two
 * start from a PDF the stand-in EHR renders for one patient -- thirty pages of their own record,
 * with a signature block at the end whose AcroForm widgets are named after the signing roles --
 * and uploads over its API key. From revision 1 onwards the product is identical, which is the
 * claim these specs exist to check: the same review gate, the same consent, the same
 * re-authentication, the same single seal, the same verification.
 *
 * Both run at phone width, because a thirty-page report is the case where "read every page before
 * you sign" stops being a formality, and a phone is the worst place to be asked to do it.
 *
 * On documents of their own (the two seeded reports), so the worklist and the queue the other
 * specs expect are untouched.
 */

test.describe.configure({ mode: "serial" });

test.describe("a thirty-page report, on a phone", () => {
  test.use({ viewport: { width: 390, height: 844 }, hasTouch: true, deviceScaleFactor: 2 });

  test("the clinician reads all thirty pages, confirms who she is, and signs it", async ({
    page,
  }) => {
    // Thirty pages rendered, uploaded, presented, read one by one and sealed.
    test.setTimeout(420_000);

    await signIn(page, "priya");
    await page.getByRole("link", { name: "Reports" }).click();
    await expect(page.getByRole("heading", { name: "Reports" })).toBeVisible();
    const card = report(page, "RPT-2291");
    await expect(card.getByTestId("report-pages")).toHaveText("30 pages");
    await shot(page, "90-reports");

    const frame = await openReport(page, "RPT-2291");
    await expect(frame.getByTestId("signing-as")).toContainText("Priya Raman");

    // The gate holds on a long document, and the copy that explains it stays readable: runs of
    // pages are named as a range, not as twenty-nine numbers filling a phone screen.
    const progress = frame.getByTestId("page-progress");
    await expect(progress).toContainText("of 30");
    await expect(progress).toContainText(/Still to see: pages \d+ to 30/);
    expect((await progress.innerText()).length).toBeLessThan(80);
    await frame.getByRole("button", { name: "Continue" }).click({ force: true });
    await expect(frame.getByRole("alert")).toContainText(/Please look at pages \d+ to 30/);
    await expect(frame.getByTestId("step-consent")).toHaveCount(0);
    await shot(page, "91-long-document-gate");

    const pages = await readEveryPage(frame);
    expect(pages).toBe(30);
    await expect(progress).toContainText("All pages seen");
    await shot(page, "92-all-thirty-pages-seen");

    await frame.getByRole("button", { name: "Continue" }).click();
    await agree(frame);
    await adoptTyped(frame, "Priya Raman");
    // One signature field and nothing else: the date beside it is the server's to fill.
    await fillEveryField(frame);
    await frame.getByRole("button", { name: "Continue" }).click();
    await reauthenticate(page, frame);
    await frame.getByRole("checkbox", { name: /I want to sign it as/ }).check();
    await frame.getByRole("button", { name: "Sign document" }).click();
    await expect(frame.getByTestId("copy-ready")).toBeVisible({ timeout: 180_000 });
    await shot(page, "93-report-signed-and-sealed");

    // Filed in the chart by webhook, like any other envelope, and saying where it came from.
    await expect(page.getByTestId("filed-link")).toBeVisible({ timeout: 120_000 });
    await page.getByTestId("filed-link").click();
    await expect(page.getByTestId("document-kind")).toContainText(
      "Report supplied by this records system, 30 pages",
    );
    await page.getByTestId("verify").click();
    await expect(page.getByTestId("verification-result")).toContainText("Verified.");
    await shot(page, "94-report-verified");

    // The chart's record of what was uploaded is the hash of the bytes the EHR actually sent.
    const uploaded = (await page.getByTestId("upload-hash").innerText()).trim();
    expect(uploaded).toMatch(/^[0-9a-f]{64}$/);
    const sealed = await page.getByTestId("download-sealed").getAttribute("href");
    const pdf = await page.request.get(sealed ?? "");
    expect(pdf.ok()).toBe(true);
    looksSealed(Buffer.from(await pdf.body()));

    await page.getByRole("link", { name: "Reports" }).click();
    await expect(report(page, "RPT-2291").getByTestId("upload-hash")).toHaveText(uploaded);
    await expect(report(page, "RPT-2291").getByTestId("report-done")).toBeVisible();
  });
});

test.describe("a report two clinicians sign in turn, on a phone", () => {
  test.use({ viewport: { width: 390, height: 844 }, hasTouch: true, deviceScaleFactor: 2 });

  test("the consultant signs, then the registrar co-signs, and not the other way round", async ({
    page,
  }) => {
    test.setTimeout(420_000);

    // Two signature blocks on the last page mean two roles, in the order the report puts them.
    // The registrar's turn has not come.
    await signIn(page, "tomas");
    await page.getByRole("link", { name: "Reports" }).click();
    await expect(report(page, "RPT-2292").getByTestId("report-waiting")).toContainText(
      "responsible clinician",
    );
    await shot(page, "95-cosigner-waits");

    await signIn(page, "priya");
    await page.getByRole("link", { name: "Reports" }).click();
    let frame = await openReport(page, "RPT-2292");
    let pages = await readEveryPage(frame);
    expect(pages).toBe(25);
    await frame.getByRole("button", { name: "Continue" }).click();
    await agree(frame);
    await adoptTyped(frame, "Priya Raman");
    await fillEveryField(frame);
    await frame.getByRole("button", { name: "Continue" }).click();
    await reauthenticate(page, frame);
    await frame.getByRole("checkbox", { name: /I want to sign it as/ }).check();
    await frame.getByRole("button", { name: "Sign document" }).click();

    // Signed, and honest that it is not finished: somebody else still has to co-sign it.
    await expect(frame.getByTestId("waiting-on-others")).toContainText("co-signing clinician");
    await shot(page, "96-waiting-on-the-cosigner");
    await expect(page.getByTestId("back-link")).toBeVisible();
    await page.getByTestId("back-link").click();
    await expect(page.getByRole("heading", { name: "Reports" })).toBeVisible();

    // Now the registrar. Same document, same thirty-second-page signature block, his own field.
    await signIn(page, "tomas");
    await page.getByRole("link", { name: "Reports" }).click();
    frame = await openReport(page, "RPT-2292");
    await expect(frame.getByTestId("signing-as")).toContainText("Tomas Silva");
    pages = await readEveryPage(frame);
    expect(pages).toBe(25);
    await frame.getByRole("button", { name: "Continue" }).click();
    await agree(frame);
    await adoptTyped(frame, "Tomas Silva");
    await fillEveryField(frame);
    await frame.getByRole("button", { name: "Continue" }).click();
    await reauthenticate(page, frame);
    await frame.getByRole("checkbox", { name: /I want to sign it as/ }).check();
    await frame.getByRole("button", { name: "Sign document" }).click();
    await expect(frame.getByTestId("copy-ready")).toBeVisible({ timeout: 180_000 });
    await shot(page, "97-cosigned-and-sealed");

    await expect(page.getByTestId("filed-link")).toBeVisible({ timeout: 120_000 });
    await page.getByTestId("filed-link").click();
    await expect(page.getByTestId("document-kind")).toContainText(
      "Report supplied by this records system, 25 pages",
    );
    await page.getByTestId("verify").click();
    await expect(page.getByTestId("verification-result")).toContainText("Verified.");
    await shot(page, "98-cosigned-report-verified");
  });
});
