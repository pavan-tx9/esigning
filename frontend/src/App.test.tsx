import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "@/App";
import { CONNECT_TIMEOUT_MS } from "@/flow/SigningFlow";
import { hasSessionToken, setSessionToken } from "@/lib/api";
import { ParentChannel } from "@/lib/embed";
import {
  liveSavedSignature,
  type MockRecord,
  mockDb,
  SAVED_SIGNATURE_ID,
  type Scenario,
  tokenFor,
} from "@/mocks/db";
import { signerApiHandlers } from "@/mocks/handlers";
import { server } from "@/test/server";

/**
 * The flow end to end in jsdom: the real App, the real fetch seam and query layer, the MSW mock
 * of the Signer API, and a stand-in parent window speaking the embedding protocol. Only the
 * canvas-bound pieces are replaced (jsdom has no canvas, no layout and no IntersectionObserver);
 * those are covered by the Playwright run. The stand-in viewer reports pages as displayed only
 * when the test says so, which is exactly the contract the real one has with the review step.
 */

vi.mock("@/lib/use-pdf", async (original) => ({
  ...(await original<typeof import("@/lib/use-pdf")>()),
  usePdf: (bytes: Uint8Array | undefined) =>
    bytes === undefined
      ? { status: "loading" }
      : { status: "ready", pdf: { doc: {}, pages: [], destroy: () => {} } },
}));

vi.mock("@/components/DocumentViewer", () => ({
  DocumentViewer: ({ onSeen }: { onSeen: (seen: ReadonlySet<number>) => void }) => (
    <div>
      <button type="button" onClick={() => onSeen(new Set([1]))}>
        test: display page 1 only
      </button>
      <button type="button" onClick={() => onSeen(new Set([1, 2, 3]))}>
        test: display every page
      </button>
    </div>
  ),
}));

vi.mock("@/components/FieldCloseUp", () => ({ FieldCloseUp: () => null }));

const HOST = "https://ehr.example";

function embed() {
  const frame = document.createElement("iframe");
  document.body.append(frame);
  const parent = frame.contentWindow as Window;
  const posted: { type: string; [key: string]: unknown }[] = [];
  const targets: string[] = [];
  parent.postMessage = ((message: { type: string }, target: string) => {
    posted.push(message);
    targets.push(target);
  }) as typeof parent.postMessage;
  const send = (data: unknown, origin = HOST, source: Window | null = parent) =>
    act(() => {
      window.dispatchEvent(new MessageEvent("message", { data, origin, source }));
    });
  return { channel: new ParentChannel([HOST], parent), posted, targets, send, frame };
}

async function start(scenario: Scenario) {
  const host = embed();
  render(<App channel={host.channel} />);
  await host.send({ type: "esign:init", token: tokenFor(scenario) });
  return host;
}

const user = userEvent.setup();
const click = (name: string | RegExp) => user.click(screen.getByRole("button", { name }));
const types = (host: ReturnType<typeof embed>) => host.posted.map((message) => message.type);

async function throughConsent() {
  await screen.findByTestId("step-review");
  await user.click(await screen.findByRole("button", { name: "test: display every page" }));
  await click("Continue");
  await screen.findByTestId("step-consent");
  await user.click(screen.getByRole("checkbox", { name: /I agree to sign electronically/ }));
  await click("Agree and continue");
  await screen.findByTestId("step-sign-adopt");
}

async function adoptPrintedName() {
  await user.click(screen.getByRole("radio", { name: /Use my printed name/ }));
  await click("Use this signature");
}

beforeEach(() => {
  // jsdom implements neither; the app only needs them not to throw.
  window.scrollTo = vi.fn() as unknown as typeof window.scrollTo;
  HTMLCanvasElement.prototype.getContext = vi.fn(() => null) as never;
  mockDb.reset();
  setSessionToken(null);
  server.use(...signerApiHandlers());
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  document.body.replaceChildren();
});

describe("connecting", () => {
  it("announces itself only to allowed origins and waits for a token", () => {
    const host = embed();
    render(<App channel={host.channel} />);
    expect(screen.getByTestId("screen-connecting")).toBeInTheDocument();
    expect(host.posted[0]).toEqual({ type: "esign:ready" });
    expect(new Set(host.targets)).toEqual(new Set([HOST]));
    expect(hasSessionToken()).toBe(false);
  });

  it("ignores a token from the wrong origin or the wrong window, then accepts the right one", async () => {
    const host = embed();
    render(<App channel={host.channel} />);
    const init = { type: "esign:init", token: tokenFor("single") };

    await host.send(init, "https://evil.example");
    await host.send(init, HOST, window);
    await host.send(init, HOST, null);
    expect(hasSessionToken()).toBe(false);
    expect(screen.getByTestId("screen-connecting")).toBeInTheDocument();

    await host.send(init);
    expect(hasSessionToken()).toBe(true);
    expect(await screen.findByTestId("step-review")).toBeInTheDocument();
  });

  it("will not swap identities: a second init is ignored", async () => {
    const host = await start("single");
    await screen.findByTestId("signing-as");
    await host.send({ type: "esign:init", token: tokenFor("clinician") });
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(screen.getByTestId("signing-as")).toHaveTextContent("Maria Alvarez");
    expect(mockDb.peek("clinician")).toBeUndefined();
  });

  it("says so plainly when the token never arrives, and can try again", async () => {
    vi.useFakeTimers();
    const host = embed();
    render(<App channel={host.channel} />);
    act(() => {
      vi.advanceTimersByTime(CONNECT_TIMEOUT_MS + 10);
    });
    expect(screen.getByTestId("screen-connect-failed")).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 1 })).toHaveFocus();
    const before = host.posted.length;
    vi.useRealTimers();
    await click("Try again");
    expect(screen.getByTestId("screen-connecting")).toBeInTheDocument();
    expect(host.posted.length).toBeGreaterThan(before);
  });
});

describe("the whole flow for one patient", () => {
  it("review, consent, sign by typing, confirm, and the sealed copy", async () => {
    const host = await start("single");

    // Review: continue stays shut until every page has been displayed.
    await screen.findByTestId("step-review");
    expect(screen.getByRole("heading", { level: 1 })).toHaveFocus();
    expect(screen.getByTestId("step-progress")).toHaveTextContent("Step 1 of 5");
    expect(screen.getByText(/A member of staff can give you a printed copy/)).toBeInTheDocument();
    await user.click(await screen.findByRole("button", { name: "test: display page 1 only" }));
    await click("Continue");
    expect(screen.getByRole("alert")).toHaveTextContent("Please look at page 2");
    expect(mockDb.peek("single")?.signerStatus).toBe("pending");
    await user.click(screen.getByRole("button", { name: "test: display every page" }));
    await click("Continue");

    // Consent: unchecked by default, paper is as visible as agreeing.
    await screen.findByTestId("step-consent");
    expect(screen.getByRole("heading", { level: 1 })).toHaveFocus();
    const agree = screen.getByRole("checkbox", { name: /I agree to sign electronically/ });
    expect(agree).not.toBeChecked();
    expect(screen.getByRole("button", { name: "I'd rather sign on paper" })).toBeInTheDocument();
    await click("Agree and continue");
    expect(screen.getByRole("alert")).toHaveTextContent("tick the box");
    expect(mockDb.peek("single")?.signerStatus).toBe("viewed");
    await user.click(agree);
    await click("Agree and continue");

    // Adopt: typing is a first-class option, and an empty drawing is refused.
    await screen.findByTestId("step-sign-adopt");
    expect(screen.getAllByRole("radio")).toHaveLength(3);
    await click("Use this signature");
    expect(screen.getByRole("alert")).toHaveTextContent("The box is empty");
    await user.click(screen.getByRole("radio", { name: /Type it/ }));
    await click("Use this signature");
    expect(screen.getByRole("alert")).toHaveTextContent("type your full name");
    await user.type(screen.getByLabelText("Type your full name"), "Maria Alvarez");
    await click("Use this signature");

    // Fields, in order, each with its own explicit action; labels come from field.label.
    await screen.findByRole("heading", {
      level: 1,
      name: "I have received the Notice of Privacy Practices",
    });
    expect(screen.getByTestId("field-progress")).toHaveTextContent("1 of 2");
    expect(screen.getByTestId("field-progress")).toHaveTextContent("2 left to complete");
    await click("Next");
    expect(screen.getByRole("alert")).toHaveTextContent("needs to be ticked");
    await user.click(
      screen.getByRole("checkbox", { name: "I have received the Notice of Privacy Practices" }),
    );
    await click("Next");

    await screen.findByRole("heading", { level: 1, name: "Patient signature" });
    expect(screen.getByTestId("field-progress")).toHaveTextContent("1 left to complete");
    await click("Check your answers");
    expect(screen.getByRole("alert")).toHaveTextContent("add your signature here");
    await click("Sign here");
    expect(screen.getByTestId("announcer")).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Check your answers" })).toHaveFocus(),
    );
    await click("Check your answers");

    // Review of answers, including what the server will add by itself.
    const summary = await screen.findByTestId("step-sign-summary");
    expect(within(summary).getByText("Maria Alvarez")).toBeInTheDocument();
    expect(within(summary).getByText(/Added automatically when you sign/)).toBeInTheDocument();
    await click("Continue");

    // Confirm: intent is explicit, and a double click cannot submit twice.
    await screen.findByTestId("step-confirm");
    await click("Sign document");
    expect(screen.getByRole("alert")).toHaveTextContent("Tick the box");
    expect(mockDb.peek("single")?.signRequests).toHaveLength(0);
    await user.click(screen.getByRole("checkbox", { name: /I want to sign it as Maria Alvarez/ }));
    await user.dblClick(screen.getByRole("button", { name: "Sign document" }));

    // Done: honest about sealing, then the copy.
    await screen.findByTestId("step-done");
    expect(screen.getByTestId("copy-sealing")).toHaveTextContent("being locked and time-stamped");
    const record = mockDb.peek("single");
    expect(record?.signRequests).toHaveLength(1);
    expect(record?.signRequests[0]?.key).toMatch(/^[0-9a-f-]{36}$/);
    expect(JSON.parse(record?.signRequests[0]?.body ?? "{}")).toEqual({
      intent_confirmed: true,
      captures: [
        { field_id: "ack_received", checked: true },
        { field_id: "patient_sig", kind: "typed", typed_text: "Maria Alvarez" },
      ],
    });
    expect(types(host)).toContain("esign:signed");
    expect(types(host)).not.toContain("esign:sealed");

    URL.createObjectURL = vi.fn(() => "blob:signed-copy");
    URL.revokeObjectURL = vi.fn();
    const save = await screen.findByRole(
      "link",
      { name: "Save your signed copy" },
      { timeout: 12_000 },
    );
    expect(save).toHaveAttribute("download");
    expect(types(host).filter((type) => type === "esign:sealed")).toHaveLength(1);
    expect(record?.downloads).toBe(1);
    expect(record?.presented).toBe(1);
  }, 25_000);

  it("retries a lost sign reply with the same Idempotency-Key and signs exactly once", async () => {
    await start("flaky-sign");
    await throughConsent();
    await adoptPrintedName();
    await user.click(await screen.findByRole("checkbox"));
    await click("Next");
    await click("Sign here");
    await click("Check your answers");
    await click("Continue");
    await user.click(await screen.findByRole("checkbox", { name: /I want to sign/ }));
    await click("Sign document");

    await screen.findByTestId("step-done", {}, { timeout: 8_000 });
    const record = mockDb.peek("flaky-sign");
    expect(record?.signRequests.length).toBe(2);
    expect(new Set(record?.signRequests.map((request) => request.key)).size).toBe(1);
    expect(record?.revisions).toBe(2);
  }, 20_000);

  it("tells the first of several signers that the copy comes when everyone has signed", async () => {
    const host = await start("multi");
    await throughConsent();
    await adoptPrintedName();
    await click("Add my initials here");
    await click("Next");
    await click("Skip");
    await click("Sign here");
    await click("Check your answers");
    await click("Continue");
    await user.click(await screen.findByRole("checkbox", { name: /I want to sign/ }));
    await click("Sign document");

    expect(await screen.findByTestId("waiting-on-others")).toHaveTextContent(
      "the witness and the clinician",
    );
    expect(screen.queryByTestId("copy-sealing")).not.toBeInTheDocument();
    expect(types(host)).toContain("esign:signed");
    const sent = JSON.parse(mockDb.peek("multi")?.signRequests[0]?.body ?? "{}");
    expect(sent.captures).toEqual([
      { field_id: "patient_initials_risks", kind: "typed", typed_text: "MA" },
      { field_id: "patient_sig", kind: "click" },
    ]);
  }, 20_000);
});

describe("when the document moves on under the signer", () => {
  /**
   * The service refuses a signature unless the bytes this session was served are the bytes the
   * signer said they had read (SPEC section 3, `signers.viewed_sha256`): 409 `not_viewed`. Their
   * signer status is still `consented`, so nothing in `placeFor` would send them back to the
   * review step -- without this, the refusal is a dead "Try again" button.
   */
  it("sends them back to read it again, and then the signature stands", async () => {
    // A first visit, in which the patient reads and agrees to the document as it stood.
    const before = embed();
    const firstVisit = render(<App channel={before.channel} />);
    await before.send({ type: "esign:init", token: tokenFor("multi") });
    await throughConsent();

    // The witness signs, so the current revision moves on.
    mockDb.otherSignerSigned("multi");

    // The tablet is reloaded: a fresh page with the same token, so the UI is served the *new*
    // revision, and nothing on the server says this signer has read it.
    firstVisit.unmount();
    setSessionToken(null);
    const host = embed();
    render(<App channel={host.channel} />);
    await host.send({ type: "esign:init", token: tokenFor("multi") });

    // The server says "consented", so the flow resumes at the signing step.
    await screen.findByTestId("step-sign-adopt");
    await adoptPrintedName();
    await click("Add my initials here");
    await click("Next");
    await click("Skip");
    await click("Sign here");
    await click("Check your answers");
    await click("Continue");
    await screen.findByTestId("step-confirm");
    await user.click(await screen.findByRole("checkbox", { name: /I want to sign/ }));
    await click("Sign document");

    // Refused, and the signer is put where they can do something about it.
    await screen.findByTestId("review-again");
    expect(screen.getByTestId("step-review")).toBeInTheDocument();
    expect(mockDb.peek("multi")?.signerStatus).toBe("consented");

    // Reading it again is all it takes. The answers they already gave are still there, so the
    // signing step goes straight to the summary.
    await user.click(await screen.findByRole("button", { name: "test: display every page" }));
    await click("Continue");
    await screen.findByTestId("step-consent");
    await user.click(screen.getByRole("checkbox", { name: /I agree to sign electronically/ }));
    await click("Agree and continue");
    await screen.findByTestId("step-sign-summary");
    await click("Continue");
    await screen.findByTestId("step-confirm");
    await user.click(await screen.findByRole("checkbox", { name: /I want to sign/ }));
    await click("Sign document");

    await screen.findByTestId("waiting-on-others");
    const record = mockDb.peek("multi");
    expect(record?.signerStatus).toBe("signed");
    expect(record?.viewedRevision).toBe(2);
    expect(types(host)).toContain("esign:signed");
  }, 30_000);

  /**
   * The same refusal without a reload, which is the shape it actually takes in a parallel envelope:
   * the signer is on the confirm screen when a co-signer commits a new revision. The bytes this
   * session was served and the bytes it confirmed reading are still the same revision, so only the
   * *current* revision says the marks would land on something nobody showed them (SPEC section 13,
   * fourth round). The way out is the same one.
   */
  it("refuses when a co-signer moves the document on under the confirm screen", async () => {
    const host = await start("multi");
    await throughConsent();
    await adoptPrintedName();
    await click("Add my initials here");
    await click("Next");
    await click("Skip");
    await click("Sign here");
    await click("Check your answers");
    await click("Continue");
    await screen.findByTestId("step-confirm");

    // The witness signs. Nothing about this signer's session changes: it holds revision 1, and it
    // is revision 1 that they read.
    mockDb.otherSignerSigned("multi");
    const held = mockDb.peek("multi");
    expect(held?.presentedRevision).toBe(1);
    expect(held?.viewedRevision).toBe(1);

    await user.click(await screen.findByRole("checkbox", { name: /I want to sign/ }));
    await click("Sign document");

    await screen.findByTestId("review-again");
    expect(screen.getByTestId("step-review")).toBeInTheDocument();
    expect(mockDb.peek("multi")?.signerStatus).toBe("consented");

    // The review step was handed fresh bytes, so reading them through is all it takes.
    await user.click(await screen.findByRole("button", { name: "test: display every page" }));
    await click("Continue");
    await screen.findByTestId("step-consent");
    await user.click(screen.getByRole("checkbox", { name: /I agree to sign electronically/ }));
    await click("Agree and continue");
    await screen.findByTestId("step-sign-summary");
    await click("Continue");
    await screen.findByTestId("step-confirm");
    await user.click(await screen.findByRole("checkbox", { name: /I want to sign/ }));
    await click("Sign document");

    await screen.findByTestId("waiting-on-others");
    const record = mockDb.peek("multi");
    expect(record?.signerStatus).toBe("signed");
    expect(record?.presentedRevision).toBe(2);
    expect(record?.viewedRevision).toBe(2);
    expect(types(host)).toContain("esign:signed");
  }, 30_000);
});

describe("re-authentication", () => {
  async function toConfirm() {
    const host = await start("clinician");
    await throughConsent();
    await adoptPrintedName();
    await click("Sign here");
    await click("Check your answers");
    await click("Continue");
    await screen.findByTestId("step-confirm");
    return host;
  }

  it("hands off to the host, waits, and believes the server rather than the message", async () => {
    const host = await toConfirm();
    await user.click(screen.getByRole("checkbox", { name: /I want to sign/ }));

    // Signing is not possible before re-authentication, and pressing the greyed button says so
    // on screen -- not only to the live region, where a sighted clinician never sees it.
    await click("Sign document");
    expect(mockDb.peek("clinician")?.signRequests).toHaveLength(0);
    expect(screen.getByRole("alert")).toHaveTextContent("Confirm it's you first");
    expect(screen.getByRole("button", { name: "Confirm it's me" })).toHaveFocus();

    await click("Confirm it's me");
    expect(screen.queryByText(/Confirm it's you first/)).toBeNull();
    // The host is told *which* session to re-authenticate: its backend needs the id for the
    // server-to-server call, and it can refuse a message about a session it did not start.
    expect(host.posted.at(-1)).toEqual({
      type: "esign:reauth_required",
      session_id: "5c4b3a29-1d8e-4f70-9b61-2a3c4d5e6f70",
    });
    expect(screen.getByTestId("reauth-waiting")).toHaveTextContent("Waiting for you to confirm");

    // The host page claims it is done, but its backend never attested: not believed.
    await host.send({ type: "esign:reauth_done" });
    expect(await screen.findByText(/We couldn't confirm that/)).toBeInTheDocument();

    await click("Try again");
    mockDb.attestReauth("clinician");
    await host.send({ type: "esign:reauth_done" });
    expect(await screen.findByTestId("reauth-verified")).toBeInTheDocument();

    await click("Sign document");
    await screen.findByTestId("step-done");
    expect(mockDb.peek("clinician")?.signerStatus).toBe("signed");
  }, 20_000);

  it("gives up waiting after a while and offers another try", async () => {
    await toConfirm();
    await click("Confirm it's me");
    const realNow = Date.now;
    vi.spyOn(Date, "now").mockImplementation(() => realNow() + 125_000);
    expect(
      await screen.findByText(/We didn't hear back in time/, {}, { timeout: 4_000 }),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
  }, 20_000);
});

/**
 * SPEC section 14 C: a host may let one re-authentication cover a clinician's next few documents
 * (a signing queue). The session then arrives already vouched for, so the hand-off is skipped,
 * the screen says what the record will say, and a fresh confirmation is one press away.
 */
describe("a re-authentication carried over from an earlier document", () => {
  async function toConfirm(scenario: Scenario) {
    const host = await start(scenario);
    await throughConsent();
    await adoptPrintedName();
    await click("Sign here");
    await click("Check your answers");
    await click("Continue");
    await screen.findByTestId("step-confirm");
    return host;
  }

  it("skips the hand-off, says when the cover runs out, and signs straight away", async () => {
    const host = await toConfirm("span-valid");

    const covered = screen.getByTestId("reauth-verified");
    expect(covered).toHaveAttribute("data-reauth-scope", "span");
    expect(covered).toHaveTextContent(/You confirmed your identity at \d{1,2}:\d{2}/);
    expect(covered).toHaveTextContent("for an earlier document");
    expect(covered).toHaveTextContent("recorded under that confirmation");
    expect(covered).toHaveTextContent(/covers this signature until \d{1,2}:\d{2}/);
    expect(screen.queryByRole("button", { name: "Confirm it's me" })).toBeNull();
    expect(screen.queryByTestId("reauth-waiting")).toBeNull();
    expect(screen.getByRole("button", { name: "Confirm again" })).toBeInTheDocument();

    await user.click(screen.getByRole("checkbox", { name: /I want to sign/ }));
    await click("Sign document");
    await screen.findByTestId("step-done");
    expect(mockDb.peek("span-valid")?.signerStatus).toBe("signed");
    // Nothing was ever asked of the host page.
    expect(types(host)).not.toContain("esign:reauth_required");
  }, 20_000);

  it("can still be confirmed again for this document, and cancelling keeps the cover", async () => {
    const host = await toConfirm("span-valid");

    await click("Confirm again");
    expect(host.posted.at(-1)).toEqual({
      type: "esign:reauth_required",
      session_id: "5c4b3a29-1d8e-4f70-9b61-2a3c4d5e6f70",
    });
    expect(screen.getByTestId("reauth-waiting")).toBeInTheDocument();

    // Changing their mind costs nothing: the earlier confirmation still stands.
    await click("Cancel");
    expect(screen.getByTestId("reauth-verified")).toHaveAttribute("data-reauth-scope", "span");

    await click("Confirm again");
    mockDb.attestReauth("span-valid");
    await host.send({ type: "esign:reauth_done" });
    const fresh = await screen.findByText(/Confirmed, thank you/);
    expect(fresh).toHaveTextContent("please sign now");
    expect(mockDb.peek("span-valid")?.reauthScope).toBe("session");
  }, 20_000);

  it("asks for the hand-off as usual once the earlier confirmation has run out", async () => {
    await toConfirm("span-expired");
    expect(screen.queryByTestId("reauth-verified")).toBeNull();
    expect(screen.getByRole("button", { name: "Confirm it's me" })).toBeInTheDocument();
    await user.click(screen.getByRole("checkbox", { name: /I want to sign/ }));
    await click("Sign document");
    expect(screen.getByRole("alert")).toHaveTextContent("Confirm it's you first");
    expect(mockDb.peek("span-expired")?.signRequests).toHaveLength(0);
  }, 20_000);
});

/**
 * SPEC section 14 B: a signature saved in an earlier session is offered first, with using it,
 * making a new one and removing it as equal choices. Placing it stays one explicit action per
 * field; saving a new one is an unchecked box; and a kiosk sees and sends none of this.
 */
describe("a saved signature", () => {
  const sent = (scenario: Scenario) =>
    JSON.parse(mockDb.peek(scenario)?.signRequests[0]?.body ?? "{}");

  async function placeAndSign() {
    await user.click(await screen.findByRole("checkbox"));
    await click("Next");
    await click("Sign here");
    await click("Check your answers");
    await screen.findByTestId("step-sign-summary");
    await click("Continue");
    await user.click(await screen.findByRole("checkbox", { name: /I want to sign/ }));
    await click("Sign document");
  }

  it("is offered first and, once placed, goes over the wire as its id alone", async () => {
    await start("saved-signature");
    await throughConsent();

    const offer = screen.getByTestId("saved-signature");
    expect(within(offer).getByRole("img", { name: /Your saved signature/ })).toHaveAttribute(
      "src",
      expect.stringMatching(/^data:image\/png;base64,/),
    );
    expect(within(offer).getByText(/saved on/)).toHaveTextContent(/Drawn · saved on .*2026/);
    expect(screen.getByRole("radio", { name: /Use my saved signature/ })).toBeChecked();
    expect(screen.getByRole("radio", { name: /Create a new one/ })).not.toBeChecked();
    expect(screen.getByRole("button", { name: /Remove saved signature/ })).toBeInTheDocument();
    // Nothing to draw or type while the saved one is chosen, and nothing to save either.
    expect(screen.queryByRole("radio", { name: /^Draw it/ })).toBeNull();
    expect(screen.queryByTestId("save-signature")).toBeNull();

    await click("Use this signature");
    await screen.findByRole("heading", {
      level: 1,
      name: "I have received the Notice of Privacy Practices",
    });
    await placeAndSign();

    await screen.findByTestId("step-done");
    const body = sent("saved-signature");
    expect(body.captures).toEqual([
      { field_id: "ack_received", checked: true },
      { field_id: "patient_sig", kind: "adopted", adopted_signature_id: SAVED_SIGNATURE_ID },
    ]);
    expect(body).not.toHaveProperty("save_adopted_signature");
    expect(JSON.stringify(body)).not.toMatch(/image_png|typed_text/);
  }, 25_000);

  it("can be replaced by a new one, saved on request, and the old one is revoked", async () => {
    await start("saved-signature");
    await throughConsent();
    await user.click(screen.getByRole("radio", { name: /Create a new one/ }));
    expect(screen.getByText("How would you like to make the new one?")).toBeInTheDocument();
    // Drawing is the default and offers to save; the printed name has nothing to save.
    expect(screen.getByRole("radio", { name: /^Draw it/ })).toBeChecked();
    expect(screen.getByTestId("save-signature")).toBeInTheDocument();
    await user.click(screen.getByRole("radio", { name: /Use my printed name/ }));
    expect(screen.queryByTestId("save-signature")).toBeNull();

    await user.click(screen.getByRole("radio", { name: /Type it/ }));
    await user.type(screen.getByLabelText("Type your full name"), "Maria Alvarez");
    const keep = screen.getByRole("checkbox", { name: /Save this signature for next time/ });
    expect(keep).not.toBeChecked();
    expect(screen.getByTestId("save-signature")).toHaveTextContent("replaces the one you saved");
    await user.click(keep);
    await click("Use this signature");

    await user.click(await screen.findByRole("checkbox"));
    await click("Next");
    await click("Sign here");
    await click("Check your answers");
    expect(await screen.findByTestId("summary-save-note")).toHaveTextContent("also be saved");
    await click("Continue");
    await user.click(await screen.findByRole("checkbox", { name: /I want to sign/ }));
    await click("Sign document");

    await screen.findByTestId("step-done");
    const body = sent("saved-signature");
    expect(body.save_adopted_signature).toBe(true);
    expect(body.captures).toContainEqual({
      field_id: "patient_sig",
      kind: "typed",
      typed_text: "Maria Alvarez",
    });
    const record = mockDb.peek("saved-signature");
    const live = record === undefined ? null : liveSavedSignature(record);
    expect(live?.kind).toBe("typed");
    expect(live?.typedText).toBe("Maria Alvarez");
    expect(live?.id).not.toBe(SAVED_SIGNATURE_ID);
    expect(record?.savedSignatures[0]?.revokeReason).toBe("replaced");
  }, 25_000);

  it("is offered to a first-time signer too: the box is there, unticked, and kept when ticked", async () => {
    // Nothing saved yet ("single"): drawing or typing a signature still offers to keep it. The
    // checkbox was only ever shown beside an existing saved signature before, so a clinician
    // could never save their first one.
    await start("single");
    await throughConsent();
    expect(screen.getByRole("radio", { name: /^Draw it/ })).toBeChecked();
    expect(screen.getByTestId("save-signature")).toBeInTheDocument();
    await user.click(screen.getByRole("radio", { name: /Use my printed name/ }));
    expect(screen.queryByTestId("save-signature")).toBeNull();
    await user.click(screen.getByRole("radio", { name: /Type it/ }));
    await user.type(screen.getByLabelText("Type your full name"), "Maria Alvarez");
    const keep = screen.getByRole("checkbox", { name: /Save this signature for next time/ });
    expect(keep).not.toBeChecked();
    expect(screen.getByTestId("save-signature")).not.toHaveTextContent(
      "replaces the one you saved",
    );
    await user.click(keep);
    await click("Use this signature");
    await placeAndSign();
    await screen.findByTestId("step-done");
    expect(sent("single").save_adopted_signature).toBe(true);
    expect(liveSavedSignature(mockDb.peek("single") as MockRecord)?.typedText).toBe(
      "Maria Alvarez",
    );
  }, 25_000);

  it("is not offered where the document asks only for initials", async () => {
    // Initials are never the saved signature: they go over as their own typed text, and the
    // service refuses `save_adopted_signature` from a request with no signature field in it
    // (`no_signature_to_save`). A box offering to keep a signature that would never be kept is
    // worse than no box, so this signer is not shown one.
    await start("initials-only");
    await throughConsent();
    await user.click(screen.getByRole("radio", { name: /Type it/ }));
    await user.type(screen.getByLabelText("Type your full name"), "Maria Alvarez");
    expect(screen.queryByTestId("save-signature")).toBeNull();
    expect(screen.queryByRole("checkbox", { name: /Save this signature/ })).toBeNull();
    await click("Use this signature");

    await click("Add my initials here");
    await click("Next");
    await click("Check your answers");
    await screen.findByTestId("step-sign-summary");
    expect(screen.queryByTestId("summary-save-note")).toBeNull();
    await click("Continue");
    await user.click(await screen.findByRole("checkbox", { name: /I want to sign/ }));
    await click("Sign document");

    await screen.findByTestId("step-done");
    expect(sent("initials-only")).not.toHaveProperty("save_adopted_signature");
    expect(mockDb.peek("initials-only")?.savedSignatures).toHaveLength(0);
  }, 25_000);

  it("can be removed, after a second look, and then the plain choices remain", async () => {
    await start("saved-signature");
    await throughConsent();

    await click(/Remove saved signature/);
    const confirm = screen.getByTestId("remove-saved");
    expect(confirm).toHaveTextContent("Remove your saved signature?");
    expect(mockDb.peek("saved-signature")?.savedSignatures[0]?.revokedAt).toBeNull();
    await click("Keep it");
    expect(screen.queryByTestId("remove-saved")).toBeNull();

    await click(/Remove saved signature/);
    await click("Remove it");
    await waitFor(() => expect(screen.queryByTestId("saved-signature")).toBeNull());
    expect(screen.getByText("How would you like to sign?")).toBeInTheDocument();
    expect(screen.getAllByRole("radio")).toHaveLength(3);
    await waitFor(() =>
      expect(screen.getByTestId("announcer")).toHaveTextContent("saved signature has been removed"),
    );
    const record = mockDb.peek("saved-signature");
    expect(record === undefined ? null : liveSavedSignature(record)).toBeNull();
    expect(record?.savedSignatures[0]?.revokeReason).toBe("user");

    // Signing still works, with a signature made here, and nothing is saved unasked.
    await user.click(screen.getByRole("radio", { name: /Type it/ }));
    await user.type(screen.getByLabelText("Type your full name"), "Maria Alvarez");
    expect(screen.getByTestId("save-signature")).not.toHaveTextContent("replaces");
    await click("Use this signature");
    await placeAndSign();
    await screen.findByTestId("step-done");
    expect(sent("saved-signature")).not.toHaveProperty("save_adopted_signature");
  }, 25_000);

  it("is never offered to, or saved from, a shared tablet", async () => {
    // The patient on this kiosk has a signature on file; the session does not say so.
    await start("kiosk");
    await throughConsent();
    expect(mockDb.peek("kiosk")?.savedSignatures).toHaveLength(1);
    expect(screen.queryByTestId("saved-signature")).toBeNull();
    expect(screen.queryByRole("radio", { name: /Use my saved signature/ })).toBeNull();
    expect(screen.getByText("How would you like to sign?")).toBeInTheDocument();

    await user.click(screen.getByRole("radio", { name: /Type it/ }));
    await user.type(screen.getByLabelText("Type your full name"), "Maria Alvarez");
    expect(screen.queryByTestId("save-signature")).toBeNull();
    expect(screen.queryByRole("checkbox", { name: /Save this signature/ })).toBeNull();
    await click("Use this signature");
    await user.click(await screen.findByRole("checkbox"));
    await click("Next");
    await click("Sign here");
    await click("Check your answers");
    expect(screen.queryByTestId("summary-save-note")).toBeNull();
    await click("Continue");
    await user.click(await screen.findByRole("checkbox", { name: /I want to sign/ }));
    await click("Sign document");

    await screen.findByTestId("screen-handback");
    const body = sent("kiosk");
    expect(body).not.toHaveProperty("save_adopted_signature");
    expect(JSON.stringify(body)).not.toContain("adopted");
    expect(mockDb.peek("kiosk")?.savedSignatures).toHaveLength(1);
  }, 25_000);
});

/**
 * SPEC section 14 B: a saved signature can stop being available between the session being read
 * and the signature being sent -- the host revokes it, or another session of this person's
 * replaces it. The server refuses that signature with 403 `adopted_signature_unavailable`, which
 * shares its status with a lapsed re-authentication and means the opposite thing: no amount of
 * confirming who you are will make a revoked signature usable again. The only way on is a
 * different signature, so the flow hands the signer back to choosing one and says so.
 */
describe("a saved signature revoked before the signature lands", () => {
  it("sends a clinician back to choose a signature instead of looping on re-authentication", async () => {
    const host = await start("span-saved");
    await throughConsent();
    // Their saved signature is the one on offer, and the queue's earlier confirmation covers
    // this document, so the confirm screen has no hand-off to make.
    expect(screen.getByTestId("saved-signature")).toBeInTheDocument();
    await click("Use this signature");
    await click("Sign here");
    await click("Check your answers");
    await click("Continue");
    await screen.findByTestId("step-confirm");
    expect(screen.getByTestId("reauth-verified")).toHaveAttribute("data-reauth-scope", "span");

    // The host takes the signature off the file while the clinician is on the last screen.
    mockDb.hostRevokedSignature("span-saved");
    await user.click(screen.getByRole("checkbox", { name: /I want to sign/ }));
    await click("Sign document");

    // Not "confirm it's you again": that hand-off would succeed and the signature still fail.
    expect(await screen.findByTestId("step-sign-adopt")).toBeInTheDocument();
    expect(screen.getByTestId("signature-gone")).toHaveTextContent(
      "saved signature is no longer available",
    );
    expect(screen.queryByText(/confirm once more/i)).toBeNull();
    expect(screen.queryByText(/confirm it's you once more/i)).toBeNull();
    expect(types(host)).not.toContain("esign:reauth_required");
    expect(mockDb.peek("span-saved")?.signerStatus).toBe("consented");
    // The refetched session no longer offers it, so the plain choices are what is left.
    await waitFor(() => expect(screen.queryByTestId("saved-signature")).toBeNull());
    expect(screen.getByText("How would you like to sign?")).toBeInTheDocument();

    // And the way out works: a signature made here and now, placed again, signs.
    await user.click(screen.getByRole("radio", { name: /Use my printed name/ }));
    await click("Use this signature");
    await click("Sign here");
    await click("Check your answers");
    await click("Continue");
    await user.click(await screen.findByRole("checkbox", { name: /I want to sign/ }));
    await click("Sign document");
    await screen.findByTestId("step-done");
    expect(mockDb.peek("span-saved")?.signerStatus).toBe("signed");
    const captures = JSON.parse(
      mockDb.peek("span-saved")?.signRequests.at(-1)?.body ?? "{}",
    ).captures;
    expect(captures).toEqual([{ field_id: "clinician_sig", kind: "click" }]);
  }, 30_000);

  it("never tells a patient, who has no re-authentication at all, to confirm their identity", async () => {
    await start("saved-signature");
    await throughConsent();
    await click("Use this signature");
    await user.click(await screen.findByRole("checkbox"));
    await click("Next");
    await click("Sign here");
    await click("Check your answers");
    await click("Continue");
    await screen.findByTestId("step-confirm");

    mockDb.hostRevokedSignature("saved-signature");
    await user.click(screen.getByRole("checkbox", { name: /I want to sign/ }));
    await click("Sign document");

    expect(await screen.findByTestId("step-sign-adopt")).toBeInTheDocument();
    expect(screen.queryByText(/confirm it's you/i)).toBeNull();
    expect(screen.getByTestId("signature-gone")).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.getByTestId("announcer")).toHaveTextContent("no longer available"),
    );
    // Nothing signed, and the box they ticked is still ticked: only the signature was dropped.
    expect(mockDb.peek("saved-signature")?.signerStatus).toBe("consented");
    await user.click(screen.getByRole("radio", { name: /Use my printed name/ }));
    await click("Use this signature");
    await click("Next");
    await click("Sign here");
    await click("Check your answers");
    expect(screen.getByTestId("step-sign-summary")).toHaveTextContent("✓ Ticked");
  }, 30_000);

  it("still treats a re-authentication that lapses at the last moment as one", async () => {
    const host = await start("span-valid");
    await throughConsent();
    await adoptPrintedName();
    await click("Sign here");
    await click("Check your answers");
    await click("Continue");
    await screen.findByTestId("step-confirm");
    expect(screen.getByTestId("reauth-verified")).toBeInTheDocument();

    // The attestation runs out on the server while they are reading this screen.
    mockDb.lapseReauth("span-valid");
    await user.click(screen.getByRole("checkbox", { name: /I want to sign/ }));
    await click("Sign document");

    expect(
      await screen.findByText(/confirmation ran out before the document was signed/),
    ).toBeInTheDocument();
    expect(screen.queryByTestId("signature-gone")).toBeNull();
    expect(screen.getByTestId("step-confirm")).toBeInTheDocument();
    // The hand-off is back, and it is the way out of this one.
    const [tryAgain] = screen.getAllByRole("button", { name: "Try again" });
    await user.click(tryAgain as HTMLElement);
    expect(host.posted.at(-1)).toEqual({
      type: "esign:reauth_required",
      session_id: "5c4b3a29-1d8e-4f70-9b61-2a3c4d5e6f70",
    });
  }, 30_000);
});

/**
 * Both deadlines in the flow -- the session's and the re-authentication's -- are server time.
 * The clock on a clinic tablet is nobody's promise: a device a few minutes fast used to read every
 * successful re-authentication as lapsed (so "Sign document" stayed inert for ever), and one more
 * than the session TTL fast landed the signer on "this session has ended" as the session loaded,
 * wiping the draft. The server enforces both limits itself, and says so with 403 and 401.
 */
/**
 * The host embeds the UI with a locale (SPEC section 9: `?locale=` picks the disclosure language,
 * and consent carries the locale as shown in the session payload). It used to be used for one
 * thing only -- stamping `<html lang>` -- so a host asking for Spanish got the English disclosure
 * on a page that told assistive technology it was Spanish.
 */
describe("the locale the host asked for", () => {
  it("asks the server for it, and declares the language actually served", async () => {
    document.documentElement.lang = "en";
    const host = embed();
    render(<App channel={host.channel} />);
    await host.send({ type: "esign:init", token: tokenFor("single"), locale: "es-MX" });

    await screen.findByTestId("step-review");
    expect(mockDb.peek("single")?.requestedLocale).toBe("es-MX");
    // Only en-US is seeded, so that is what was served -- and what the page declares. Claiming
    // "es-MX" over English copy would have a screen reader pronounce it with Spanish rules.
    expect(document.documentElement.lang).toBe("en-US");
  });

  it("posts consent in the locale the disclosure was served in", async () => {
    await start("single");
    await user.click(await screen.findByRole("button", { name: "test: display every page" }));
    await click("Continue");
    await screen.findByTestId("step-consent");
    await user.click(screen.getByRole("checkbox", { name: /I agree to sign electronically/ }));
    await click("Agree and continue");

    await screen.findByTestId("step-sign-adopt");
    expect(mockDb.peek("single")?.consentLocale).toBe("en-US");
  }, 15_000);
});

describe("reading the document", () => {
  it("tells a screen reader what the zoom is, and when a press changed nothing", async () => {
    await start("single");
    await screen.findByTestId("step-review");

    const readout = await screen.findByTestId("zoom-level");
    expect(readout).toHaveTextContent("Zoom 100%");
    expect(readout).toHaveAttribute("role", "status");
    expect(readout).not.toHaveAttribute("aria-hidden");
    const smaller = screen.getByRole("button", { name: "Make the document smaller" });
    const larger = screen.getByRole("button", { name: "Make the document larger" });
    expect(smaller).toHaveAttribute("aria-describedby", readout.id);
    expect(larger).toHaveAttribute("aria-describedby", readout.id);

    // At the smallest size the press is a no-op, and silence would leave a blind user guessing.
    await user.click(smaller);
    await waitFor(() =>
      expect(screen.getByTestId("announcer")).toHaveTextContent("already at the smallest size"),
    );
    expect(readout).toHaveTextContent("Zoom 100%");

    await user.click(larger);
    expect(readout).toHaveTextContent("Zoom 150%");
    await waitFor(() =>
      expect(screen.getByTestId("announcer")).toHaveTextContent("Zoom 150 percent"),
    );
  }, 15_000);
});

describe("a device whose clock is wrong", () => {
  it("does not end a live session because the tablet is running fast", async () => {
    mockDb.setDeviceClockSkew(45 * 60_000);
    const host = await start("single");

    // The session (30 minutes) looks long over by this device's clock; the server disagrees.
    expect(await screen.findByTestId("step-review")).toBeInTheDocument();
    expect(screen.queryByTestId("screen-expired")).toBeNull();
    expect(types(host)).not.toContain("esign:expired");
    // The warning is advisory, and it says what it does not know.
    expect(screen.getByTestId("deadline-banner")).toHaveTextContent("due to close");

    // And the flow still works: the server is the one that decides.
    await user.click(await screen.findByRole("button", { name: "test: display every page" }));
    await click("Continue");
    expect(await screen.findByTestId("step-consent")).toBeInTheDocument();
    expect(mockDb.peek("single")?.signerStatus).toBe("viewed");
  }, 15_000);

  it("lets a clinician sign on a fast tablet once the server has confirmed them", async () => {
    mockDb.setDeviceClockSkew(10 * 60_000);
    const host = await start("clinician");
    await throughConsent();
    await adoptPrintedName();
    await click("Sign here");
    await click("Check your answers");
    await click("Continue");
    await screen.findByTestId("step-confirm");

    await click("Confirm it's me");
    mockDb.attestReauth("clinician");
    await host.send({ type: "esign:reauth_done" });
    // The attestation is good for two minutes of *server* time, ten minutes behind this device.
    await screen.findByTestId("reauth-verified");

    await user.click(screen.getByRole("checkbox", { name: /I want to sign/ }));
    await click("Sign document");
    await screen.findByTestId("step-done");
    expect(mockDb.peek("clinician")?.signerStatus).toBe("signed");
  }, 20_000);
});

describe("the session-deadline warning", () => {
  it("stays on screen while the patient reads, rather than scrolling off the top", async () => {
    await start("ending-soon");
    const banner = await screen.findByTestId("deadline-banner");

    expect(banner).toHaveTextContent(/this session closes in about \d+ minutes?/);
    expect(banner.className).toContain("sticky");
    // Above the document pages and the review step's own sticky footer (z-10).
    expect(banner.className).toMatch(/\bz-30\b/);
    // Announced when it first appears, not only when someone happens to look up.
    expect(within(banner).getByRole("alert")).toBeInTheDocument();
  });
});

describe("endings", () => {
  it("an expired token gets its own screen, tells the host, and forgets the token", async () => {
    const host = await start("expired");
    expect(await screen.findByTestId("screen-expired")).toBeInTheDocument();
    expect(screen.getByText("What to do next")).toBeInTheDocument();
    expect(types(host)).toContain("esign:expired");
    expect(hasSessionToken()).toBe(false);
  });

  it("a session that lapses mid-flow is caught wherever it happens", async () => {
    const host = await start("single");
    await user.click(await screen.findByRole("button", { name: "test: display every page" }));
    mockDb.expireSession("single");
    await click("Continue");
    expect(await screen.findByTestId("screen-expired")).toBeInTheDocument();
    expect(types(host)).toContain("esign:expired");
  });

  it("choosing paper declines with that reason and tells the host", async () => {
    const host = await start("single");
    await user.click(await screen.findByRole("button", { name: "test: display every page" }));
    await click("Continue");
    await screen.findByTestId("step-consent");
    await click("I'd rather sign on paper");
    await screen.findByTestId("step-decline");
    expect(screen.getByRole("radio", { name: "I would rather sign on paper" })).toBeChecked();
    await click("Go back to signing");
    await screen.findByTestId("step-consent");
    await click("I'd rather sign on paper");
    await click("Close this document and tell the clinic");
    expect(await screen.findByTestId("screen-declined")).toBeInTheDocument();
    expect(mockDb.peek("single")?.declineReason).toBe("prefers_paper");
    expect(types(host)).toContain("esign:declined");
    expect(hasSessionToken()).toBe(false);
  });

  /**
   * A decline ends the envelope for everyone and can only be undone by issuing a new document
   * (SPEC section 3). It is the only irreversible action in the flow, and several of the reasons
   * on offer read like "not now", so both the screen that does it and the screen after it have to
   * say what it costs.
   */
  it("says that declining closes the document, before and after it happens", async () => {
    await start("single");
    await user.click(await screen.findByRole("button", { name: "test: display every page" }));
    await click("Continue");
    await screen.findByTestId("step-consent");
    await click("I'd rather sign on paper");
    await screen.findByTestId("step-decline");

    expect(screen.getByTestId("decline-consequence")).toHaveTextContent(
      "closes the document, so it can't be signed here later",
    );
    expect(
      screen.getByRole("button", { name: "Close this document and tell the clinic" }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Stop and tell the clinic" })).toBeNull();

    // "I need more time" is not a reason to end the envelope, and the screen says so.
    await user.click(screen.getByRole("radio", { name: "I need more time to read this" }));
    expect(screen.getByTestId("decline-pause-hint")).toHaveTextContent(
      "You don't have to close the document for that",
    );

    await user.click(screen.getByRole("radio", { name: "I would rather sign on paper" }));
    expect(screen.queryByTestId("decline-pause-hint")).toBeNull();
    await click("Close this document and tell the clinic");

    expect(await screen.findByTestId("declined-consequence")).toHaveTextContent(
      "This document is now closed",
    );
    expect(screen.getByText(/ask a member of staff for a paper copy/)).toBeInTheDocument();
  }, 15_000);

  it("a kiosk session ends on hand-back with every trace of the patient gone", async () => {
    const host = await start("kiosk");
    await throughConsent();
    await adoptPrintedName();
    await user.click(await screen.findByRole("checkbox"));
    await click("Next");
    await click("Sign here");
    await click("Check your answers");
    await click("Continue");
    await user.click(await screen.findByRole("checkbox", { name: /I want to sign/ }));
    await click("Sign document");

    expect(await screen.findByTestId("screen-handback")).toHaveTextContent(
      "Please hand this tablet back to a member of staff",
    );
    expect(types(host)).toContain("esign:signed");
    expect(hasSessionToken()).toBe(false);
    expect(document.body).not.toHaveTextContent("Maria");
    expect(document.body).not.toHaveTextContent("Privacy notice");
    // Nothing can wake it up again.
    await host.send({ type: "esign:init", token: tokenFor("single") });
    expect(hasSessionToken()).toBe(false);
  }, 20_000);

  it("a withdrawn document and a failing server each say what to do next", async () => {
    await start("voided");
    expect(await screen.findByText("This document was withdrawn")).toBeInTheDocument();
    expect(screen.getByText("What to do next")).toBeInTheDocument();
  });

  it("shows an error screen with a retry when the session cannot be loaded", async () => {
    await start("error");
    expect(await screen.findByTestId("screen-error", {}, { timeout: 10_000 })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
  }, 15_000);
});
