import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "@/App";
import { CONNECT_TIMEOUT_MS } from "@/flow/SigningFlow";
import { hasSessionToken, setSessionToken } from "@/lib/api";
import { ParentChannel } from "@/lib/embed";
import { mockDb, type Scenario, tokenFor } from "@/mocks/db";
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

    // Signing is not possible before re-authentication.
    await click("Sign document");
    expect(mockDb.peek("clinician")?.signRequests).toHaveLength(0);

    await click("Confirm it's me");
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
    await click("Stop and tell the clinic");
    expect(await screen.findByTestId("screen-declined")).toBeInTheDocument();
    expect(mockDb.peek("single")?.declineReason).toBe("prefers_paper");
    expect(types(host)).toContain("esign:declined");
    expect(hasSessionToken()).toBe(false);
  });

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
