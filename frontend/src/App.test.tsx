import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "@/App";
import { CONNECT_TIMEOUT_MS } from "@/flow/SigningFlow";
import { hasSessionToken, setSessionToken } from "@/lib/api";
import { ParentChannel } from "@/lib/embed";
import {
  EARLIER_ENVELOPE_ID,
  GUARDIAN_CHILD_NAME,
  liveSavedSignature,
  type MockRecord,
  mockDb,
  QUEUE_TITLES,
  QUEUE_TOTAL,
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
 * those are covered by the Playwright run.
 *
 * The stand-in viewer reports page 1 as displayed the moment it renders, which is what the real
 * one does, and leaves every other page to the test -- exactly the contract the real viewer has
 * with the Read step. That matters for the tap counts below: a one-page document needs no
 * scrolling from anybody, and must not be charged a tap for it here either.
 */

vi.mock("@/lib/use-pdf", async (original) => ({
  ...(await original<typeof import("@/lib/use-pdf")>()),
  usePdf: (bytes: Uint8Array | undefined) =>
    bytes === undefined
      ? { status: "loading" }
      : { status: "ready", pdf: { doc: {}, pages: [], destroy: () => {} } },
}));

vi.mock("@/components/DocumentViewer", async () => {
  const { useEffect, useRef } = await import("react");
  return {
    DocumentViewer: ({
      onSeen,
      leading,
      trailing,
    }: {
      onSeen: (seen: ReadonlySet<number>) => void;
      leading?: React.ReactNode;
      trailing?: React.ReactNode;
    }) => {
      // The real viewer holds this in a stable callback, so a fresh identity each render does
      // not re-fire it. Do the same here, or the report becomes a render loop.
      const report = useRef(onSeen);
      report.current = onSeen;
      // A real viewer paints page 1 immediately and the observer marks it seen.
      useEffect(() => report.current(new Set([1])), []);
      // The real viewer puts what the step hands it before the first page and after the last,
      // in the same scroll: the "document changed" notice and the consent block.
      return (
        <div className="doc-scroller" data-testid="document-viewer">
          {leading}
          <button type="button" onClick={() => onSeen(new Set([1]))}>
            test: display page 1 only
          </button>
          <button type="button" onClick={() => onSeen(new Set([1, 2, 3]))}>
            test: display every page
          </button>
          {trailing}
        </div>
      );
    },
  };
});

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

interface StartOptions {
  /** Extra keys on `esign:init`: the locale, or a queue position (addendum 3 B). */
  init?: Record<string, unknown>;
  /** Which document of a `queue` run this is. */
  position?: number;
}

async function start(scenario: Scenario, options: StartOptions = {}) {
  const host = embed();
  render(<App channel={host.channel} />);
  await host.send({
    type: "esign:init",
    token: tokenFor(scenario, options.position),
    ...options.init,
  });
  return host;
}

const user = userEvent.setup();
const click = (name: string | RegExp) => user.click(screen.getByRole("button", { name }));
const types = (host: ReturnType<typeof embed>) => host.posted.map((message) => message.type);
const sent = (scenario: Scenario, position?: number) =>
  JSON.parse(mockDb.peek(scenario, position)?.signRequests[0]?.body ?? "{}");

const agreeBox = () =>
  screen.getByRole("checkbox", { name: /I agree to sign this document electronically/ });

/** Read every page, agree where asked, and press the one button out of the Read screen. */
async function readAndContinue({ multiPage = true } = {}) {
  await screen.findByTestId("step-read");
  // The consent block sits under the last page, so it arrives with the document bytes.
  await screen.findByTestId("consent-block");
  if (multiPage) {
    await user.click(await screen.findByRole("button", { name: "test: display every page" }));
  }
  const box = screen.queryByRole("checkbox", {
    name: /I agree to sign this document electronically/,
  });
  if (box !== null) {
    await user.click(box);
  }
  await click("Continue to sign");
  await screen.findByTestId("step-sign");
}

/** Choose the printed name in the signature panel, which needs no drawing in jsdom. */
async function choosePrintedName() {
  await screen.findByTestId("signature-panel");
  const change = screen.queryByRole("button", { name: "Change" });
  if (change !== null) {
    await user.click(change);
  }
  await user.click(screen.getByRole("radio", { name: /Use my printed name/ }));
}

/** Count every press of anything pressable, so "three taps" is a measurement, not a claim. */
function countTaps() {
  const seen: string[] = [];
  const listener = (event: Event) => {
    const target = event.target as HTMLElement | null;
    const hit = target?.closest("button, a, input, label, [role='button']");
    if (hit !== null && hit !== undefined) {
      seen.push((hit.textContent ?? hit.nodeName).trim().slice(0, 40));
    }
  };
  document.addEventListener("click", listener, true);
  return {
    get taps() {
      return seen.length;
    },
    get labels() {
      return seen;
    },
    stop: () => document.removeEventListener("click", listener, true),
  };
}

beforeEach(() => {
  // jsdom implements none of these; the app only needs them not to throw. Object URLs matter:
  // any test that stays on the Done screen long enough for the copy to seal reaches them, and an
  // exception there takes the whole tree down rather than failing one assertion.
  window.scrollTo = vi.fn() as unknown as typeof window.scrollTo;
  HTMLCanvasElement.prototype.getContext = vi.fn(() => null) as never;
  URL.createObjectURL = vi.fn(() => "blob:signed-copy");
  URL.revokeObjectURL = vi.fn();
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
    expect(await screen.findByTestId("step-read")).toBeInTheDocument();
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

/**
 * Addendum 3 A. Two screens before Done, and the acts that produce evidence are all still there:
 * every page displayed, consent given explicitly, one act per field, one act that signs.
 */
describe("the whole flow for one patient", () => {
  it("reads, agrees, signs by typing, and gets the sealed copy -- in three screens", async () => {
    const host = await start("single");

    // Read ---------------------------------------------------------------------------------
    await screen.findByTestId("step-read");
    expect(screen.getByRole("heading", { level: 1 })).toHaveFocus();
    expect(screen.getByTestId("step-progress")).toHaveTextContent("Step 1 of 3");
    // The paper alternative, in words and as the press that takes it, on this screen and the next.
    expect(screen.getByText(/A member of staff can give you a printed copy/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "I'd rather sign on paper" })).toBeInTheDocument();

    // The consent block is in the same scroll as the document, not a screen after it.
    expect(await screen.findByTestId("consent-block")).toBeInTheDocument();
    expect(screen.getByTestId("disclosure")).toHaveAttribute("data-expanded", "false");
    await click("Read the full notice");
    expect(screen.getByTestId("disclosure")).toHaveAttribute("data-expanded", "true");
    expect(screen.getByText(/You can also ask for a paper copy at any time/)).toBeInTheDocument();

    // Until every page has been displayed the one button is the way to the next page that has
    // not been, and "Continue to sign" is not on the screen at all.
    expect(screen.getByRole("button", { name: "Next unseen page (2)" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Continue to sign" })).toBeNull();
    expect(screen.getByTestId("page-progress")).toHaveTextContent("1 of 2 seen");
    expect(mockDb.peek("single")?.signerStatus).toBe("pending");
    await user.click(screen.getByRole("button", { name: "test: display every page" }));
    expect(screen.getByTestId("page-progress")).toHaveTextContent("All pages seen");
    // `POST /viewed` goes when the pages have been displayed, not when the button is pressed.
    await waitFor(() => expect(mockDb.peek("single")?.signerStatus).toBe("viewed"));
    await click("Continue to sign");
    expect(screen.getByRole("alert")).toHaveTextContent("tick the box");
    expect(mockDb.peek("single")?.consentLocale).toBeNull();

    await user.click(agreeBox());
    await click("Continue to sign");

    // Sign ---------------------------------------------------------------------------------
    await screen.findByTestId("step-sign");
    expect(screen.getByTestId("step-progress")).toHaveTextContent("Step 2 of 3");
    expect(mockDb.peek("single")?.consentLocale).toBe("en-US");
    // Nothing on file, so the panel opens on the chooser with drawing selected.
    expect(screen.getByRole("radio", { name: /^Draw it/ })).toBeChecked();
    expect(screen.getByTestId("save-signature")).toBeInTheDocument();
    await user.click(screen.getByRole("radio", { name: /Type it/ }));
    await user.type(screen.getByLabelText("Type your full name"), "Maria Alvarez");

    // The fields, each with one thing to do, and a running count.
    expect(screen.getByTestId("fields-progress")).toHaveTextContent("0 of 2");
    expect(screen.getAllByTestId("field-row")).toHaveLength(2);
    expect(screen.getByText(/Added automatically when you sign/)).toBeInTheDocument();

    // The one button that signs is inert until every required field is done, and says what is
    // missing rather than doing nothing.
    await click("Sign as Maria Alvarez");
    expect(screen.getByRole("alert")).toHaveTextContent("2 things are still needed");
    expect(mockDb.peek("single")?.signRequests).toHaveLength(0);

    await user.click(
      screen.getByRole("checkbox", { name: "I have received the Notice of Privacy Practices" }),
    );
    await click("Sign here");
    expect(await screen.findByText("Signature in place")).toBeInTheDocument();
    expect(screen.getByTestId("fields-progress")).toHaveTextContent("2 of 2");

    // A double press cannot submit twice.
    await user.dblClick(screen.getByRole("button", { name: "Sign as Maria Alvarez" }));

    // Done ---------------------------------------------------------------------------------
    await screen.findByTestId("step-done");
    expect(screen.getByTestId("copy-sealing")).toHaveTextContent("being locked and time-stamped");
    const record = mockDb.peek("single");
    expect(record?.signRequests).toHaveLength(1);
    expect(record?.signRequests[0]?.key).toMatch(/^[0-9a-f-]{36}$/);
    // The press is the intent confirmation: the request says so, as it always did.
    expect(JSON.parse(record?.signRequests[0]?.body ?? "{}")).toEqual({
      intent_confirmed: true,
      captures: [
        { field_id: "ack_received", checked: true },
        { field_id: "patient_sig", kind: "typed", typed_text: "Maria Alvarez" },
      ],
    });
    expect(types(host)).toContain("esign:signed");
    expect(types(host)).not.toContain("esign:sealed");

    const save = await screen.findByRole(
      "link",
      { name: "Save your signed copy" },
      { timeout: 12_000 },
    );
    expect(save).toHaveAttribute("download");
    expect(types(host).filter((type) => type === "esign:sealed")).toHaveLength(1);
    expect(record?.downloads).toBe(1);
    // One fetch of the bytes for both screens: the Sign step reuses what Read already has.
    expect(record?.presented).toBe(1);
  }, 25_000);

  it("retries a lost sign reply with the same Idempotency-Key and signs exactly once", async () => {
    await start("flaky-sign");
    await readAndContinue();
    await choosePrintedName();
    await user.click(await screen.findByRole("checkbox", { name: /Notice of Privacy/ }));
    await click("Sign here");
    await click("Sign as Maria Alvarez");

    await screen.findByTestId("step-done", {}, { timeout: 8_000 });
    const record = mockDb.peek("flaky-sign");
    expect(record?.signRequests.length).toBe(2);
    expect(new Set(record?.signRequests.map((request) => request.key)).size).toBe(1);
    expect(record?.revisions).toBe(2);
  }, 20_000);

  it("a multi-field document: one explicit act each, optional fields skippable", async () => {
    const host = await start("multi");
    await readAndContinue();
    await choosePrintedName();

    expect(screen.getByTestId("fields-progress")).toHaveTextContent("0 of 3");
    await click("Sign as Maria Alvarez");
    expect(screen.getByRole("alert")).toHaveTextContent("2 things are still needed");

    await click("Add initials");
    expect(screen.getByTestId("fields-progress")).toHaveTextContent("1 of 3");
    await click("Sign here");
    expect(screen.getByTestId("fields-progress")).toHaveTextContent("2 of 3");
    // The optional text field is not in the way of signing.
    await click("Sign as Maria Alvarez");

    expect(await screen.findByTestId("waiting-on-others")).toHaveTextContent(
      "the witness and the clinician",
    );
    expect(screen.queryByTestId("copy-sealing")).not.toBeInTheDocument();
    expect(types(host)).toContain("esign:signed");
    expect(sent("multi").captures).toEqual([
      { field_id: "patient_initials_risks", kind: "typed", typed_text: "MA" },
      { field_id: "patient_sig", kind: "click" },
    ]);
  }, 25_000);

  /**
   * "2 of 3 done" is the count the sign button uses, or it is a lie: a value in a field is not
   * the same as a field that is finished. An unticked required box keeps its value rather than
   * clearing it, so it used to keep counting as done while the button stayed inert underneath.
   */
  it("counts a field as done only where the sign button agrees it is", async () => {
    await start("single");
    await readAndContinue();
    await choosePrintedName();
    const box = screen.getByRole("checkbox", { name: /Notice of Privacy/ });
    await user.click(box);
    await click("Sign here");
    expect(screen.getByTestId("fields-progress")).toHaveTextContent("2 of 2");

    await user.click(box);
    expect(box).not.toBeChecked();
    expect(screen.getByTestId("fields-progress")).toHaveTextContent("1 of 2");
    await click("Sign as Maria Alvarez");
    expect(screen.getByTestId("sign-nudge")).toHaveTextContent("One thing is still needed");
    expect(mockDb.peek("single")?.signRequests).toHaveLength(0);
  }, 20_000);

  /**
   * An initials mark stands for the typed initials and nothing else. Emptying the box used to
   * leave the row saying "Initials in place", the counter saying everything was done, and the
   * server refusing `typed_text: ""` with a 422 whose advice named the wrong box entirely.
   */
  it("clearing the initials box un-places them instead of sending empty text", async () => {
    await start("multi");
    await readAndContinue();
    await choosePrintedName();
    await click("Add initials");
    await click("Sign here");
    expect(screen.getByTestId("fields-progress")).toHaveTextContent("2 of 3");

    await user.clear(screen.getByLabelText("Your initials"));
    expect(screen.queryByText("Initials in place")).toBeNull();
    expect(screen.getByTestId("fields-progress")).toHaveTextContent("1 of 3");

    await click("Sign as Maria Alvarez");
    expect(screen.getByTestId("sign-nudge")).toHaveTextContent(/One thing is still needed/);
    expect(mockDb.peek("multi")?.signRequests).toHaveLength(0);

    // Typing them again is all it takes, and the mark has to be made again on purpose.
    await user.type(screen.getByLabelText("Your initials"), "MA");
    await click("Add initials");
    await click("Sign as Maria Alvarez");
    await screen.findByTestId("waiting-on-others");
    expect(sent("multi").captures).toContainEqual({
      field_id: "patient_initials_risks",
      kind: "typed",
      typed_text: "MA",
    });
  }, 25_000);

  /** Pressing a field's button swaps it for another one; focus must not fall to the document. */
  it("leaves focus in the row whose button was pressed", async () => {
    await start("single");
    await readAndContinue();
    await choosePrintedName();
    await click("Sign here");
    const remove = screen.getByRole("button", { name: "Remove" });
    expect(remove).toHaveFocus();

    await user.click(remove);
    expect(screen.getByRole("button", { name: "Sign here" })).toHaveFocus();
  }, 20_000);

  it("a field can be undone, and the count and the sign button follow", async () => {
    await start("single");
    await readAndContinue();
    await choosePrintedName();
    await user.click(screen.getByRole("checkbox", { name: /Notice of Privacy/ }));
    await click("Sign here");
    expect(screen.getByTestId("fields-progress")).toHaveTextContent("2 of 2");

    await click("Remove");
    expect(screen.getByTestId("fields-progress")).toHaveTextContent("1 of 2");
    await click("Sign as Maria Alvarez");
    expect(screen.getByRole("alert")).toHaveTextContent("One thing is still needed");
    expect(mockDb.peek("single")?.signRequests).toHaveLength(0);
  }, 20_000);
});

/**
 * Addendum 3, the whole point of it: a clinician working a queue, with a signature on file and
 * an agreement already given in this sitting, signs a one-page order in three presses.
 */
describe("the short path", () => {
  it("is three taps: Continue to sign, Sign here, Sign as ...", async () => {
    const host = await start("queue", {
      position: 1,
      init: { queue: { index: 1, total: QUEUE_TOTAL, next_title: QUEUE_TITLES[1] } },
    });
    const tapped = countTaps();

    // Read: one page, so it is displayed already; the agreement was given earlier in the sitting.
    await screen.findByTestId("step-read");
    expect(await screen.findByTestId("standing-consent")).toHaveTextContent(
      /You agreed to sign electronically at \d{1,2}:\d{2}/,
    );
    expect(
      screen.queryByRole("checkbox", { name: /I agree to sign this document electronically/ }),
    ).toBeNull();
    await click("Continue to sign"); // 1

    // Sign: the signature on file is already what the panel shows, and the queue's earlier
    // confirmation of identity covers this document, so neither costs a press.
    await screen.findByTestId("step-sign");
    expect(screen.getByTestId("signature-showing")).toBeInTheDocument();
    expect(screen.getByTestId("reauth-verified")).toHaveAttribute("data-reauth-scope", "span");
    expect(screen.getAllByTestId("field-row")).toHaveLength(1);
    await click("Sign here"); // 2
    await click("Sign as Dr. Priya Raman"); // 3

    await screen.findByTestId("step-done");
    tapped.stop();
    expect(tapped.labels).toHaveLength(3);
    expect(tapped.taps).toBe(3);

    const record = mockDb.peek("queue", 1);
    expect(record?.signerStatus).toBe("signed");
    expect(record?.reliedOnEnvelopeId).toBe(EARLIER_ENVELOPE_ID);
    expect(sent("queue", 1)).toEqual({
      intent_confirmed: true,
      captures: [
        { field_id: "clinician_sig", kind: "adopted", adopted_signature_id: SAVED_SIGNATURE_ID },
      ],
    });
    // Nothing was ever asked of the host page beyond the queue itself.
    expect(types(host)).not.toContain("esign:reauth_required");
  }, 25_000);
});

/**
 * Addendum 3 A made the press of "Sign as ..." the single act that signs the document and the
 * whole of the intent confirmation. For a parent that sentence names their child, so it has to be
 * a sentence they can read: the host sends `on_behalf_of_display` and the UI shows those words.
 * Nothing about the record moves -- the trail's attribution is still the opaque `on_behalf_of`.
 */
describe("a parent signing for a child", () => {
  it("names the child in the sentence the press confirms", async () => {
    await start("guardian");
    const signAs = `Sign as Grace Okafor, on behalf of ${GUARDIAN_CHILD_NAME}`;

    expect(await screen.findByTestId("signing-as")).toHaveTextContent(
      `Signing as Grace Okafor · Patient or guardian, on behalf of ${GUARDIAN_CHILD_NAME}`,
    );
    await readAndContinue();
    await choosePrintedName();
    await user.click(await screen.findByRole("checkbox", { name: /Notice of Privacy/ }));
    await click("Sign here");
    await click(signAs);

    await screen.findByTestId("step-done");
    const record = mockDb.peek("guardian");
    expect(record?.signerStatus).toBe("signed");
    // The words are a display decision and only that: nothing about the child goes over the wire.
    expect(record?.signRequests[0]?.body).not.toContain(GUARDIAN_CHILD_NAME);
    expect(JSON.parse(record?.signRequests[0]?.body ?? "{}")).toEqual({
      intent_confirmed: true,
      captures: [
        { field_id: "ack_received", checked: true },
        { field_id: "patient_sig", kind: "click" },
      ],
    });
  }, 25_000);

  /**
   * A host that sends no display name leaves the opaque `on_behalf_of` as the label. Reciting a
   * chart reference is not an intent anybody can check, so the sentence points at the document,
   * which is open above it and does name the patient.
   */
  it("points at the document when all the host sent was a reference", async () => {
    await start("guardian-ref");
    expect(await screen.findByTestId("signing-as")).toHaveTextContent(
      "Signing as Grace Okafor · Patient or guardian, for the patient named in this document",
    );
    await readAndContinue();
    await choosePrintedName();
    await user.click(await screen.findByRole("checkbox", { name: /Notice of Privacy/ }));
    await click("Sign here");
    expect(
      screen.getByRole("button", {
        name: "Sign as Grace Okafor, for the patient named in this document",
      }),
    ).toBeInTheDocument();
  }, 25_000);
});

/** Addendum 3 C: consent once per run, and the fallback when the server will not honour it. */
describe("an agreement already given in this sitting", () => {
  it("is stated instead of asked for, and the consent event says what it leans on", async () => {
    await start("standing-consent");
    await screen.findByTestId("step-read");
    const line = await screen.findByTestId("standing-consent");
    expect(line).toHaveTextContent("for an earlier document in this sitting");
    expect(screen.queryByTestId("save-signature")).toBeNull();

    await user.click(await screen.findByRole("button", { name: "test: display every page" }));
    await click("Continue to sign");
    await screen.findByTestId("step-sign");
    const record = mockDb.peek("standing-consent");
    expect(record?.signerStatus).toBe("consented");
    expect(record?.reliedOnEnvelopeId).toBe(EARLIER_ENVELOPE_ID);
  }, 20_000);

  it("falls back to the checkbox when the server says it is no longer standing", async () => {
    await start("consent-lapsed");
    await screen.findByTestId("step-read");
    expect(await screen.findByTestId("standing-consent")).toBeInTheDocument();
    await user.click(await screen.findByRole("button", { name: "test: display every page" }));

    await click("Continue to sign");

    // 409 consent_not_standing: still on the Read screen, told plainly, and asked for the tick.
    expect(
      await screen.findByText(/The agreement you gave earlier no longer covers this document/),
    ).toBeInTheDocument();
    expect(screen.getByTestId("step-read")).toBeInTheDocument();
    expect(screen.queryByTestId("standing-consent")).toBeNull();
    expect(mockDb.peek("consent-lapsed")?.signerStatus).toBe("viewed");

    await user.click(agreeBox());
    await click("Continue to sign");
    await screen.findByTestId("step-sign");
    const record = mockDb.peek("consent-lapsed");
    expect(record?.signerStatus).toBe("consented");
    // The fallback acceptance stands on its own; it leans on nothing.
    expect(record?.reliedOnEnvelopeId).toBeNull();
  }, 20_000);

  it("is never offered on a shared tablet, however the session is shaped", async () => {
    await start("kiosk");
    await screen.findByTestId("consent-block");
    expect(screen.queryByTestId("standing-consent")).toBeNull();
    expect(agreeBox()).not.toBeChecked();
  }, 15_000);
});

/**
 * Addendum 3 B: the host owns the queue and the tokens. The UI shows the position, names what is
 * next, counts down in the open, and asks with `esign:next`.
 */
describe("a signing queue", () => {
  const queueInit = (index: number) => ({
    position: index,
    init: {
      queue: {
        index,
        total: QUEUE_TOTAL,
        ...(index < QUEUE_TOTAL ? { next_title: QUEUE_TITLES[index] } : {}),
      },
    },
  });

  async function signIt(host: ReturnType<typeof embed>) {
    await readAndContinue({ multiPage: false });
    await click("Sign here");
    await click("Sign as Dr. Priya Raman");
    await screen.findByTestId("step-done");
    return host;
  }

  it("shows the position, counts down, and asks the host for the next document", async () => {
    const host = await start("queue", queueInit(2));
    expect(await screen.findByTestId("queue-progress")).toHaveTextContent("2 of 3");
    await signIt(host);

    const next = screen.getByTestId("queue-next");
    expect(within(next).getByTestId("queue-position")).toHaveTextContent("Document 2 of 3");
    expect(within(next).getByRole("heading", { level: 2 })).toHaveTextContent(
      `Next: ${QUEUE_TITLES[2]}`,
    );
    await waitFor(() => expect(types(host)).toContain("esign:next"), { timeout: 10_000 });
    expect(host.posted.find((message) => message.type === "esign:next")).toEqual({
      type: "esign:next",
      envelope_id: mockDb.peek("queue", 2)?.envelopeId,
    });
  }, 25_000);

  it("stays put when asked to, and then opens the next one only on request", async () => {
    const host = await start("queue", queueInit(1));
    await signIt(host);

    // The copy of this one is still sealing, and staying is what saves it: the button says so.
    await click("Stay and save my copy");
    expect(screen.queryByText(/Opening in/)).toBeNull();
    // Well past the countdown, and nothing was asked of the host.
    await new Promise((resolve) => setTimeout(resolve, QUEUE_COUNTDOWN_WAIT_MS));
    expect(types(host)).not.toContain("esign:next");

    await click(`Open ${QUEUE_TITLES[1]}`);
    expect(types(host)).toContain("esign:next");
  }, 25_000);

  it("says so when the last one is signed, and asks for nothing more", async () => {
    const host = await start("queue", queueInit(QUEUE_TOTAL));
    await signIt(host);
    expect(screen.getByTestId("queue-finished")).toHaveTextContent("That was the last of 3");
    expect(screen.queryByTestId("queue-next")).toBeNull();
    await new Promise((resolve) => setTimeout(resolve, QUEUE_COUNTDOWN_WAIT_MS));
    expect(types(host)).not.toContain("esign:next");
  }, 25_000);

  /**
   * INTEGRATION.md section 9: "post a fresh `esign:init` into the same iframe". Nothing there
   * says the frame is reloaded first, and a host that did exactly what it says used to get
   * silence -- the second init was dropped and the signer sat on the Done screen for ever.
   */
  it("accepts the next document's token posted into the same frame", async () => {
    const host = await start("queue", queueInit(1));
    await signIt(host);
    await waitFor(() => expect(types(host)).toContain("esign:next"), { timeout: 10_000 });

    await host.send({
      type: "esign:init",
      token: tokenFor("queue", 2),
      queue: { index: 2, total: QUEUE_TOTAL, next_title: QUEUE_TITLES[2] },
    });

    expect(await screen.findByTestId("step-read")).toBeInTheDocument();
    expect(screen.getByTestId("queue-progress")).toHaveTextContent("2 of 3");
    // A fresh session in every way: nothing of the last document is carried over.
    expect(screen.getByTestId("step-progress")).toHaveTextContent("Step 1 of 3");
    await waitFor(() => expect(mockDb.peek("queue", 2)?.signerStatus).toBe("viewed"));

    await click("Continue to sign");
    await screen.findByTestId("step-sign");
    expect(screen.getByTestId("fields-progress")).toHaveTextContent("0 of 1");
  }, 30_000);

  it("will not take a second token while a signature is still being made", async () => {
    const host = await start("queue", queueInit(1));
    await readAndContinue({ multiPage: false });
    await host.send({ type: "esign:init", token: tokenFor("queue", 2) });
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(screen.getByTestId("step-sign")).toBeInTheDocument();
    expect(mockDb.peek("queue", 2)).toBeUndefined();
  }, 20_000);

  /**
   * Four seconds is long enough only if the way to stop it is where a non-pointer user already
   * is. Focus arrives on "Stay here", and focus coming back into the card holds the countdown.
   */
  it("puts focus on the way to stop it, and holds while focus is back in the card", async () => {
    const host = await start("queue", queueInit(1));
    await signIt(host);
    const stay = screen.getByRole("button", { name: /^Stay/ });
    expect(stay).toHaveFocus();

    // Focus leaving and coming back is the signer reaching for it, and holds the clock.
    act(() => {
      stay.blur();
      stay.focus();
    });
    await new Promise((resolve) => setTimeout(resolve, QUEUE_COUNTDOWN_WAIT_MS));
    expect(types(host)).not.toContain("esign:next");
    expect(screen.getByTestId("queue-next")).toHaveTextContent("Held while you're here");
  }, 25_000);

  /**
   * "Reduce motion" is a preference about movement, not about who gets the short path: the bar
   * that empties goes, the count and the advance stay, and the way to stop it is still the first
   * thing under the signer's hands. (`prefersReducedMotion` is read once, at mount, so the stub
   * goes in before the flow is started.)
   */
  it("drops the moving bar for reduced motion, and keeps the countdown", async () => {
    vi.spyOn(window, "matchMedia").mockReturnValue({ matches: true } as MediaQueryList);
    const host = await start("queue", queueInit(1));
    await signIt(host);

    expect(screen.queryByTestId("queue-countdown-bar")).toBeNull();
    expect(screen.getByTestId("queue-next")).toHaveTextContent(/Opening in \d second/);
    expect(screen.getByRole("button", { name: /^Stay/ })).toHaveFocus();
    await waitFor(() => expect(types(host)).toContain("esign:next"), { timeout: 10_000 });
  }, 25_000);

  /**
   * After the countdown fires there is nothing left for the card to count, and if the host never
   * opens anything the frame must stop asserting progress it cannot see.
   */
  it("says it is opening, and its button still works when nothing arrives", async () => {
    const host = await start("queue", queueInit(1));
    await signIt(host);
    await waitFor(() => expect(types(host)).toContain("esign:next"), { timeout: 10_000 });

    expect(screen.getByTestId("queue-opening")).toBeInTheDocument();
    expect(screen.queryByText(/Opening in 0 second/)).toBeNull();
    expect(screen.queryByRole("button", { name: /^Stay/ })).toBeNull();

    // The explicit press is not the automatic path, so it is not latched shut by it.
    await click(`Open ${QUEUE_TITLES[1]}`);
    expect(types(host).filter((type) => type === "esign:next")).toHaveLength(2);

    await screen.findByTestId("queue-stalled", {}, { timeout: 16_000 });
    expect(screen.getByTestId("queue-stalled")).toHaveTextContent("That didn't open");
  }, 40_000);

  /** The copy of this one is still sealing when the frame is about to move on. Say so. */
  it("says what is being left behind when the copy is not sealed yet", async () => {
    const host = await start("queue", queueInit(1));
    await signIt(host);
    expect(screen.getByTestId("queue-copy-pending")).toHaveTextContent("still being finalised");
    expect(screen.getByRole("button", { name: "Stay and save my copy" })).toBeInTheDocument();
  }, 25_000);

  it("ignores a position the host could not have meant", async () => {
    await start("queue", { position: 1, init: { queue: { index: 9, total: 3 } } });
    await screen.findByTestId("consent-block");
    expect(screen.queryByTestId("queue-progress")).toBeNull();
  }, 15_000);
});

const QUEUE_COUNTDOWN_WAIT_MS = 6_000;

describe("when the document moves on under the signer", () => {
  /**
   * The service refuses a signature unless the bytes this session was served are the bytes the
   * signer said they had read (SPEC section 3, `signers.viewed_sha256`): 409 `not_viewed`. Their
   * signer status is still `consented`, so nothing in `placeFor` would send them back to the
   * Read step -- without this, the refusal is a dead "Try again" button.
   */
  it("sends them back to read it again, and then the signature stands", async () => {
    const before = embed();
    const firstVisit = render(<App channel={before.channel} />);
    await before.send({ type: "esign:init", token: tokenFor("multi") });
    await readAndContinue();

    // The witness signs, so the current revision moves on.
    mockDb.otherSignerSigned("multi");

    // The tablet is reloaded: a fresh page with the same token, so the UI is served the *new*
    // revision, and nothing on the server says this signer has read it.
    firstVisit.unmount();
    setSessionToken(null);
    const host = embed();
    render(<App channel={host.channel} />);
    await host.send({ type: "esign:init", token: tokenFor("multi") });

    // The server says "consented", so the flow resumes on the Sign screen.
    await screen.findByTestId("step-sign");
    await choosePrintedName();
    await click("Add initials");
    await click("Sign here");
    await click("Sign as Maria Alvarez");

    // Refused, and the signer is put where they can do something about it.
    await screen.findByTestId("review-again");
    expect(screen.getByTestId("step-read")).toBeInTheDocument();
    expect(mockDb.peek("multi")?.signerStatus).toBe("consented");

    // Reading it again is all it takes; their answers are still in the draft.
    await user.click(await screen.findByRole("button", { name: "test: display every page" }));
    await user.click(agreeBox());
    await click("Continue to sign");
    await screen.findByTestId("step-sign");
    expect(screen.getByTestId("fields-progress")).toHaveTextContent("2 of 3");
    await click("Sign as Maria Alvarez");

    await screen.findByTestId("waiting-on-others");
    const record = mockDb.peek("multi");
    expect(record?.signerStatus).toBe("signed");
    expect(record?.viewedRevision).toBe(2);
    expect(types(host)).toContain("esign:signed");
  }, 30_000);

  it("refuses when a co-signer moves the document on under the sign screen", async () => {
    const host = await start("multi");
    await readAndContinue();
    await choosePrintedName();
    await click("Add initials");
    await click("Sign here");

    // The witness signs. Nothing about this signer's session changes: it holds revision 1, and it
    // is revision 1 that they read.
    mockDb.otherSignerSigned("multi");
    const held = mockDb.peek("multi");
    expect(held?.presentedRevision).toBe(1);
    expect(held?.viewedRevision).toBe(1);

    await click("Sign as Maria Alvarez");

    await screen.findByTestId("review-again");
    expect(screen.getByTestId("step-read")).toBeInTheDocument();
    expect(mockDb.peek("multi")?.signerStatus).toBe("consented");

    await user.click(await screen.findByRole("button", { name: "test: display every page" }));
    await user.click(agreeBox());
    await click("Continue to sign");
    await screen.findByTestId("step-sign");
    await click("Sign as Maria Alvarez");

    await screen.findByTestId("waiting-on-others");
    const record = mockDb.peek("multi");
    expect(record?.signerStatus).toBe("signed");
    expect(record?.presentedRevision).toBe(2);
    expect(record?.viewedRevision).toBe(2);
    expect(types(host)).toContain("esign:signed");
  }, 30_000);
});

/**
 * Addendum 3 A 4: re-authentication happens on the press, not on a screen of its own. The press
 * asks for it, the page waits, and the signature goes by itself when the server vouches. Every
 * failure state the confirm screen used to own is rendered here instead.
 */
describe("re-authentication, on the press", () => {
  async function toSign(scenario: Scenario = "reauth-press") {
    const host = await start(scenario);
    await readAndContinue({ multiPage: false });
    await click("Sign here");
    return host;
  }

  it("hands off, waits, believes the server, and then signs without another tap", async () => {
    const host = await toSign();
    expect(screen.getByTestId("reauth-needed")).toHaveTextContent(
      "will ask you to confirm it's you when you press the button",
    );

    await click("Sign as Dr. Priya Raman");
    // The press asked for it. Nothing has been sent to the sign route.
    expect(mockDb.peek("reauth-press")?.signRequests).toHaveLength(0);
    expect(host.posted.at(-1)).toEqual({
      type: "esign:reauth_required",
      session_id: "5c4b3a29-1d8e-4f70-9b61-2a3c4d5e6f70",
    });
    expect(screen.getByTestId("reauth-waiting")).toHaveTextContent("Confirming it's you");

    // The host page claims it is done, but its backend never attested: not believed.
    await host.send({ type: "esign:reauth_done" });
    expect(await screen.findByText(/We couldn't confirm that/)).toBeInTheDocument();
    expect(mockDb.peek("reauth-press")?.signRequests).toHaveLength(0);

    // Try again -- and this time the host's backend really did attest.
    await click("Try again");
    mockDb.attestReauth("reauth-press");
    await host.send({ type: "esign:reauth_done" });

    // No second press: the one that asked for the confirmation is the one that signs.
    await screen.findByTestId("step-done", {}, { timeout: 8_000 });
    expect(mockDb.peek("reauth-press")?.signerStatus).toBe("signed");
    expect(mockDb.peek("reauth-press")?.signRequests).toHaveLength(1);
  }, 25_000);

  /**
   * The queued press is the one piece of state on this screen that acts without a press. It was
   * made about answers that have since changed, so it goes with them: otherwise the hand-off
   * comes back, the effect fires, and whatever the draft has become -- in the reported case an
   * empty one -- is sent and refused, over a visibly empty field.
   */
  it("cancels a press waiting on the hand-off when the answers change under it", async () => {
    const host = await toSign();
    await click("Sign as Dr. Priya Raman");
    expect(screen.getByTestId("reauth-waiting")).toBeInTheDocument();

    await click("Remove");
    expect(screen.queryByTestId("reauth-waiting")).toBeNull();
    expect(screen.getByTestId("sign-nudge")).toHaveTextContent("that press was cancelled");

    // The host's backend really did attest, and the answer still sends nothing.
    mockDb.attestReauth("reauth-press");
    await host.send({ type: "esign:reauth_done" });
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(mockDb.peek("reauth-press")?.signRequests).toHaveLength(0);
    expect(screen.getByTestId("step-sign")).toBeInTheDocument();

    // ...and the button says what is missing rather than refusing something nobody can mend.
    await click("Sign as Dr. Priya Raman");
    expect(screen.getByTestId("sign-nudge")).toHaveTextContent("One thing is still needed");

    // Placing it again and pressing is the way through: one more hand-off, then the signature.
    await click("Sign here");
    await click("Sign as Dr. Priya Raman");
    expect(screen.getByTestId("reauth-waiting")).toBeInTheDocument();
    await host.send({ type: "esign:reauth_done" });
    await screen.findByTestId("step-done", {}, { timeout: 8_000 });
    expect(mockDb.peek("reauth-press")?.signerStatus).toBe("signed");
    expect(JSON.parse(mockDb.peek("reauth-press")?.signRequests[0]?.body ?? "{}").captures).toEqual(
      [{ field_id: "clinician_sig", kind: "adopted", adopted_signature_id: SAVED_SIGNATURE_ID }],
    );
  }, 25_000);

  it("gives up waiting after a while, and says nothing has been signed", async () => {
    await toSign("reauth-timeout");
    await click("Sign as Dr. Priya Raman");
    const realNow = Date.now;
    vi.spyOn(Date, "now").mockImplementation(() => realNow() + 125_000);
    expect(
      await screen.findByText(/We didn't hear back in time/, {}, { timeout: 4_000 }),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
    expect(mockDb.peek("reauth-timeout")?.signRequests).toHaveLength(0);
  }, 25_000);

  it("cancelling the hand-off leaves everything as it was", async () => {
    const host = await toSign();
    await click("Sign as Dr. Priya Raman");
    expect(screen.getByTestId("reauth-waiting")).toBeInTheDocument();
    await click("Cancel");
    expect(screen.queryByTestId("reauth-waiting")).toBeNull();
    expect(screen.getByRole("button", { name: "Sign as Dr. Priya Raman" })).toBeInTheDocument();
    expect(mockDb.peek("reauth-press")?.signRequests).toHaveLength(0);
    expect(types(host).filter((type) => type === "esign:reauth_required")).toHaveLength(1);
  }, 20_000);

  it("a confirmation that lapses between the screen and the signature asks once more", async () => {
    const host = await toSign("reauth-lapsed");
    // Covered when the screen opened: no hand-off was needed to get here.
    expect(screen.getByTestId("reauth-verified")).toHaveAttribute("data-reauth-scope", "span");

    await click("Sign as Dr. Priya Raman");
    expect(
      await screen.findByText(/confirmation ran out before the document was signed/),
    ).toBeInTheDocument();
    expect(screen.getByTestId("step-sign")).toBeInTheDocument();
    expect(screen.queryByTestId("signature-gone")).toBeNull();

    // And pressing again is the way out of it: the hand-off, then the signature.
    await click("Try again");
    expect(host.posted.at(-1)).toEqual({
      type: "esign:reauth_required",
      session_id: "5c4b3a29-1d8e-4f70-9b61-2a3c4d5e6f70",
    });
    mockDb.attestReauth("reauth-lapsed");
    await host.send({ type: "esign:reauth_done" });
    await screen.findByTestId("step-done", {}, { timeout: 8_000 });
    expect(mockDb.peek("reauth-lapsed")?.signerStatus).toBe("signed");
  }, 25_000);

  it("asks for the hand-off as usual once an earlier confirmation has run out", async () => {
    await start("span-expired");
    await readAndContinue();
    await choosePrintedName();
    await click("Sign here");
    expect(screen.queryByTestId("reauth-verified")).toBeNull();
    expect(screen.getByTestId("reauth-needed")).toBeInTheDocument();
  }, 25_000);

  it("a confirmation carried over from an earlier document asks for nothing at all", async () => {
    const host = await start("span-valid");
    await readAndContinue();
    await choosePrintedName();
    await click("Sign here");

    const covered = screen.getByTestId("reauth-verified");
    expect(covered).toHaveAttribute("data-reauth-scope", "span");
    expect(covered).toHaveTextContent(/You confirmed your identity at \d{1,2}:\d{2}/);
    expect(covered).toHaveTextContent("for an earlier document");
    expect(covered).toHaveTextContent("recorded under that confirmation");
    expect(covered).toHaveTextContent(/covers this signature until \d{1,2}:\d{2}/);

    await click("Sign as Dr. Priya Raman");
    await screen.findByTestId("step-done");
    expect(mockDb.peek("span-valid")?.signerStatus).toBe("signed");
    expect(types(host)).not.toContain("esign:reauth_required");
  }, 25_000);
});

/**
 * SPEC section 14 B, on the new panel: a signature saved in an earlier session is what the panel
 * shows, "Change" is how to make another, and a kiosk sees and sends none of this.
 */
describe("a saved signature", () => {
  it("is what the panel shows, and goes over the wire as its id alone", async () => {
    await start("saved-signature");
    await readAndContinue();

    const panel = screen.getByTestId("signature-panel");
    expect(within(panel).getByRole("img", { name: /Your signature, as drawn/ })).toHaveAttribute(
      "src",
      expect.stringMatching(/^data:image\/png;base64,/),
    );
    expect(screen.getByTestId("saved-signature")).toHaveTextContent(/kept from .*2026/);
    expect(within(panel).getByRole("button", { name: "Change" })).toBeInTheDocument();
    // Nothing to draw or type while the saved one is what will be placed, and nothing to save.
    expect(screen.queryByRole("radio", { name: /^Draw it/ })).toBeNull();
    expect(screen.queryByTestId("save-signature")).toBeNull();

    await user.click(screen.getByRole("checkbox", { name: /Notice of Privacy/ }));
    await click("Sign here");
    await click("Sign as Maria Alvarez");

    await screen.findByTestId("step-done");
    const body = sent("saved-signature");
    expect(body.captures).toEqual([
      { field_id: "ack_received", checked: true },
      { field_id: "patient_sig", kind: "adopted", adopted_signature_id: SAVED_SIGNATURE_ID },
    ]);
    expect(body).not.toHaveProperty("save_adopted_signature");
    expect(JSON.stringify(body)).not.toMatch(/image_png|typed_text/);
  }, 25_000);

  /**
   * Changing your mind after the first field is placed. The panel used to be asked for a
   * signature only while nothing had been adopted yet, so a signature chosen afterwards was shown
   * in the panel, offered to be saved -- and silently left out: the submission carried the id of
   * the old one, and the screen showed two different signatures at the moment of signing.
   */
  it("signs the signature chosen last, even when one was already placed", async () => {
    await start("saved-signature");
    await readAndContinue();
    await user.click(screen.getByRole("checkbox", { name: /Notice of Privacy/ }));
    await click("Sign here");
    expect(screen.getByTestId("fields-progress")).toHaveTextContent("2 of 2");

    // Choosing again makes the placed mark stale, so it comes off and has to be made again.
    await click("Change");
    expect(screen.getByTestId("fields-progress")).toHaveTextContent("1 of 2");
    expect(screen.queryByText("Signature in place")).toBeNull();

    await user.click(screen.getByRole("radio", { name: /Type it/ }));
    await user.type(screen.getByLabelText("Type your full name"), "Maria Alvarez");
    await user.click(screen.getByRole("checkbox", { name: /Save this signature for next time/ }));

    // Nothing is signed while the new signature is nowhere on the document.
    await click("Sign as Maria Alvarez");
    expect(screen.getByTestId("sign-nudge")).toHaveTextContent("One thing is still needed");
    expect(mockDb.peek("saved-signature")?.signRequests).toHaveLength(0);

    await click("Sign here");
    await click("Sign as Maria Alvarez");
    await screen.findByTestId("step-done");

    const body = sent("saved-signature");
    expect(body.captures).toContainEqual({
      field_id: "patient_sig",
      kind: "typed",
      typed_text: "Maria Alvarez",
    });
    expect(JSON.stringify(body)).not.toContain(SAVED_SIGNATURE_ID);
    expect(body.save_adopted_signature).toBe(true);
    expect(liveSavedSignature(mockDb.peek("saved-signature") as MockRecord)?.typedText).toBe(
      "Maria Alvarez",
    );
  }, 30_000);

  it("can be replaced by a new one, saved on request, and the old one is revoked", async () => {
    await start("saved-signature");
    await readAndContinue();
    await click("Change");
    expect(screen.getByRole("radio", { name: /My saved signature/ })).toBeInTheDocument();
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

    await user.click(screen.getByRole("checkbox", { name: /Notice of Privacy/ }));
    await click("Sign here");
    await click("Sign as Maria Alvarez");

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
    await start("first-time");
    await readAndContinue();
    // Nothing on file and nothing standing: the chooser is open and the box is unticked.
    expect(screen.queryByTestId("saved-signature")).toBeNull();
    expect(screen.queryByTestId("standing-consent")).toBeNull();
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

    await user.click(screen.getByRole("checkbox", { name: /Notice of Privacy/ }));
    await click("Sign here");
    // The signature is committed by the act that places it, and then the panel shows it.
    expect(await screen.findByTestId("signature-showing")).toBeInTheDocument();
    await click("Sign as Maria Alvarez");

    await screen.findByTestId("step-done");
    expect(sent("first-time").save_adopted_signature).toBe(true);
    expect(liveSavedSignature(mockDb.peek("first-time") as MockRecord)?.typedText).toBe(
      "Maria Alvarez",
    );
  }, 25_000);

  it("will not place a signature that is not there yet, and says why", async () => {
    const scrolled = vi.fn();
    Element.prototype.scrollIntoView = scrolled;
    await start("first-time");
    await readAndContinue();
    // Drawing is selected and the pad is empty: the field's own button is what refuses.
    await click("Sign here");
    expect(screen.getByTestId("signature-problem")).toHaveTextContent("The box is empty");
    // The panel is a long way above the button that was pressed, so the refusal is said beside
    // that button too, and the panel's own copy is brought into view.
    expect(screen.getByTestId("sign-nudge")).toHaveTextContent("The box is empty");
    expect(scrolled).toHaveBeenCalled();
    expect(screen.getByTestId("fields-progress")).toHaveTextContent("0 of 2");

    await user.click(screen.getByRole("radio", { name: /Type it/ }));
    await click("Sign here");
    expect(screen.getByTestId("signature-problem")).toHaveTextContent("type your full name");
    expect(screen.getByTestId("sign-nudge")).toHaveTextContent("type your full name");
    expect(screen.getByTestId("fields-progress")).toHaveTextContent("0 of 2");
  }, 20_000);

  it("is not offered where the document asks only for initials", async () => {
    await start("initials-only");
    await readAndContinue();
    await user.click(screen.getByRole("radio", { name: /Type it/ }));
    await user.type(screen.getByLabelText("Type your full name"), "Maria Alvarez");
    expect(screen.queryByTestId("save-signature")).toBeNull();
    expect(screen.queryByRole("checkbox", { name: /Save this signature/ })).toBeNull();

    await click("Add initials");
    await click("Sign as Maria Alvarez");

    await screen.findByTestId("step-done");
    expect(sent("initials-only")).not.toHaveProperty("save_adopted_signature");
    expect(mockDb.peek("initials-only")?.savedSignatures).toHaveLength(0);
  }, 25_000);

  it("can be removed, after a second look, and then the plain choices remain", async () => {
    await start("saved-signature");
    await readAndContinue();

    await click("Remove my saved signature");
    expect(screen.getByTestId("remove-saved")).toHaveTextContent("Remove your saved signature?");
    expect(mockDb.peek("saved-signature")?.savedSignatures[0]?.revokedAt).toBeNull();
    await click("Keep it");
    expect(screen.queryByTestId("remove-saved")).toBeNull();

    await click("Remove my saved signature");
    await click("Remove it");
    await waitFor(() => expect(screen.queryByTestId("saved-signature")).toBeNull());
    expect(screen.getByText("How would you like to sign?")).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.getByTestId("announcer")).toHaveTextContent("saved signature has been removed"),
    );
    const record = mockDb.peek("saved-signature");
    expect(record === undefined ? null : liveSavedSignature(record)).toBeNull();
    expect(record?.savedSignatures[0]?.revokeReason).toBe("user");

    // Signing still works, with a signature made here, and nothing is saved unasked.
    await user.click(screen.getByRole("radio", { name: /Type it/ }));
    await user.type(screen.getByLabelText("Type your full name"), "Maria Alvarez");
    await user.click(screen.getByRole("checkbox", { name: /Notice of Privacy/ }));
    await click("Sign here");
    await click("Sign as Maria Alvarez");
    await screen.findByTestId("step-done");
    expect(sent("saved-signature")).not.toHaveProperty("save_adopted_signature");
  }, 25_000);

  it("is never offered to, or saved from, a shared tablet", async () => {
    // The patient on this kiosk has a signature on file; the session does not say so.
    await start("kiosk");
    await readAndContinue();
    expect(mockDb.peek("kiosk")?.savedSignatures).toHaveLength(1);
    expect(screen.queryByTestId("saved-signature")).toBeNull();
    expect(screen.queryByRole("radio", { name: /My saved signature/ })).toBeNull();
    expect(screen.getByText("How would you like to sign?")).toBeInTheDocument();

    await user.click(screen.getByRole("radio", { name: /Type it/ }));
    await user.type(screen.getByLabelText("Type your full name"), "Maria Alvarez");
    expect(screen.queryByTestId("save-signature")).toBeNull();
    expect(screen.queryByRole("checkbox", { name: /Save this signature/ })).toBeNull();

    await user.click(screen.getByRole("checkbox", { name: /Notice of Privacy/ }));
    await click("Sign here");
    await click("Sign as Maria Alvarez");

    await screen.findByTestId("screen-handback");
    const body = sent("kiosk");
    expect(body).not.toHaveProperty("save_adopted_signature");
    expect(JSON.stringify(body)).not.toContain("adopted");
    expect(mockDb.peek("kiosk")?.savedSignatures).toHaveLength(1);
  }, 25_000);
});

/**
 * SPEC section 14 B: a saved signature can stop being available between the session being read
 * and the signature being sent. The server refuses it with 403 `adopted_signature_unavailable`,
 * which shares its status with a lapsed re-authentication and means the opposite thing. The panel
 * is where the way out is, so the flow stays on this screen and says so there.
 */
describe("a saved signature revoked before the signature lands", () => {
  it("asks for another signature instead of looping on re-authentication", async () => {
    const host = await start("span-saved");
    await readAndContinue();
    expect(screen.getByTestId("saved-signature")).toBeInTheDocument();
    await click("Sign here");
    expect(screen.getByTestId("reauth-verified")).toHaveAttribute("data-reauth-scope", "span");

    // The host takes the signature off the file just before the press.
    mockDb.hostRevokedSignature("span-saved");
    await click("Sign as Dr. Priya Raman");

    // Not "confirm it's you again": that hand-off would succeed and the signature still fail.
    expect(await screen.findByTestId("signature-gone")).toHaveTextContent(
      "saved signature is no longer available",
    );
    expect(screen.getByTestId("step-sign")).toBeInTheDocument();
    expect(screen.queryByText(/confirmation ran out/i)).toBeNull();
    expect(types(host)).not.toContain("esign:reauth_required");
    expect(mockDb.peek("span-saved")?.signerStatus).toBe("consented");
    // The refetched session no longer offers it, so the plain choices are what is left.
    await waitFor(() => expect(screen.queryByTestId("saved-signature")).toBeNull());
    expect(screen.getByText("How would you like to sign?")).toBeInTheDocument();
    expect(screen.getByTestId("fields-progress")).toHaveTextContent("0 of 1");

    // And the way out works: a signature made here and now, placed again, signs.
    await user.click(screen.getByRole("radio", { name: /Use my printed name/ }));
    await click("Sign here");
    await click("Sign as Dr. Priya Raman");
    await screen.findByTestId("step-done");
    expect(mockDb.peek("span-saved")?.signerStatus).toBe("signed");
    expect(
      JSON.parse(mockDb.peek("span-saved")?.signRequests.at(-1)?.body ?? "{}").captures,
    ).toEqual([{ field_id: "clinician_sig", kind: "click" }]);
  }, 30_000);

  it("never tells a patient, who has no re-authentication at all, to confirm their identity", async () => {
    await start("saved-signature");
    await readAndContinue();
    await user.click(screen.getByRole("checkbox", { name: /Notice of Privacy/ }));
    await click("Sign here");

    mockDb.hostRevokedSignature("saved-signature");
    await click("Sign as Maria Alvarez");

    expect(await screen.findByTestId("signature-gone")).toBeInTheDocument();
    expect(screen.queryByText(/confirm it's you/i)).toBeNull();
    await waitFor(() =>
      expect(screen.getByTestId("announcer")).toHaveTextContent("no longer available"),
    );
    // Nothing signed, and the box they ticked is still ticked: only the signature was dropped.
    expect(mockDb.peek("saved-signature")?.signerStatus).toBe("consented");
    expect(screen.getByRole("checkbox", { name: /Notice of Privacy/ })).toBeChecked();
    expect(screen.getByTestId("fields-progress")).toHaveTextContent("1 of 2");
  }, 30_000);
});

/**
 * The host embeds the UI with a locale (SPEC section 9: `?locale=` picks the disclosure language,
 * and consent carries the locale as shown in the session payload).
 */
describe("the locale the host asked for", () => {
  it("asks the server for it, and declares the language actually served", async () => {
    document.documentElement.lang = "en";
    const host = embed();
    render(<App channel={host.channel} />);
    await host.send({ type: "esign:init", token: tokenFor("single"), locale: "es-MX" });

    await screen.findByTestId("step-read");
    expect(mockDb.peek("single")?.requestedLocale).toBe("es-MX");
    // Only en-US is seeded, so that is what was served -- and what the page declares.
    expect(document.documentElement.lang).toBe("en-US");
  });

  it("posts consent in the locale the disclosure was served in", async () => {
    await start("single");
    await readAndContinue();
    expect(mockDb.peek("single")?.consentLocale).toBe("en-US");
  }, 15_000);
});

describe("reading the document", () => {
  it("tells a screen reader what the zoom is, and when a press changed nothing", async () => {
    await start("single");
    await screen.findByTestId("step-read");

    const readout = await screen.findByTestId("zoom-level");
    expect(readout).toHaveTextContent("Zoom 100%");
    // One channel per fact: the readout is named by both buttons and spoken by the announcer.
    // A live region here as well made every press say the same thing twice.
    expect(readout).not.toHaveAttribute("role");
    const smaller = screen.getByRole("button", { name: "Make the document smaller" });
    const larger = screen.getByRole("button", { name: "Make the document larger" });
    expect(smaller).toHaveAttribute("aria-describedby", readout.id);
    expect(larger).toHaveAttribute("aria-describedby", readout.id);

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

    expect(await screen.findByTestId("step-read")).toBeInTheDocument();
    expect(screen.queryByTestId("screen-expired")).toBeNull();
    expect(types(host)).not.toContain("esign:expired");
    expect(screen.getByTestId("deadline-banner")).toHaveTextContent("due to close");

    await readAndContinue();
    expect(mockDb.peek("single")?.signerStatus).toBe("consented");
  }, 20_000);

  it("lets a clinician sign on a fast tablet once the server has confirmed them", async () => {
    mockDb.setDeviceClockSkew(10 * 60_000);
    const host = await start("reauth-press");
    await readAndContinue({ multiPage: false });
    await click("Sign here");

    await click("Sign as Dr. Priya Raman");
    mockDb.attestReauth("reauth-press");
    await host.send({ type: "esign:reauth_done" });
    // The attestation is good for two minutes of *server* time, ten minutes behind this device.
    await screen.findByTestId("step-done", {}, { timeout: 8_000 });
    expect(mockDb.peek("reauth-press")?.signerStatus).toBe("signed");
  }, 25_000);
});

describe("the session-deadline warning", () => {
  it("stays on screen while the patient reads, rather than scrolling off the top", async () => {
    await start("ending-soon");
    const banner = await screen.findByTestId("deadline-banner");

    expect(banner).toHaveTextContent(/this session closes in about \d+ minutes?/);
    // It floats over the document region rather than sitting in the scroll, so it is on screen
    // however far down a long report the reader is, and nothing moves when it appears.
    expect(banner.className).toContain("absolute");
    expect(banner.className).toMatch(/\bz-30\b/);
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
    await user.click(agreeBox());
    mockDb.expireSession("single");
    await click("Continue to sign");
    expect(await screen.findByTestId("screen-expired")).toBeInTheDocument();
    expect(types(host)).toContain("esign:expired");
  }, 15_000);

  /** Addendum 3 A: the paper path is a quiet link on both screens before Done. */
  it("the paper path is reachable from Read and from Sign", async () => {
    const host = await start("single");
    await screen.findByTestId("step-read");
    await click("I'd rather sign on paper");
    await screen.findByTestId("step-decline");
    await click("Go back to signing");
    await screen.findByTestId("step-read");

    await readAndContinue();
    await screen.findByTestId("step-sign");
    await click("I'd rather sign on paper");
    await screen.findByTestId("step-decline");
    expect(screen.getByRole("radio", { name: "I would rather sign on paper" })).toBeChecked();
    await click("Close this document and tell the clinic");

    expect(await screen.findByTestId("screen-declined")).toBeInTheDocument();
    expect(mockDb.peek("single")?.declineReason).toBe("prefers_paper");
    expect(types(host)).toContain("esign:declined");
    expect(hasSessionToken()).toBe(false);
  }, 25_000);

  /**
   * The paper path is a detour, not a step: the step stays mounted behind it. Everything the
   * step is holding that the draft is not -- ink on the pad, a name half typed -- used to go
   * with it, so reading what "sign on paper" means cost a signature.
   */
  it("keeps a signature being made when the paper path is opened and closed", async () => {
    await start("first-time");
    await readAndContinue();
    await user.click(screen.getByRole("radio", { name: /Type it/ }));
    await user.type(screen.getByLabelText("Type your full name"), "Maria Alvarez");

    await click("I'd rather sign on paper");
    await screen.findByTestId("step-decline");
    await click("Go back to signing");

    await screen.findByTestId("step-sign");
    expect(screen.getByRole("radio", { name: /Type it/ })).toBeChecked();
    expect(screen.getByLabelText("Type your full name")).toHaveValue("Maria Alvarez");
  }, 25_000);

  it("says that declining closes the document, before and after it happens", async () => {
    await start("single");
    await screen.findByTestId("step-read");
    await click("I'd rather sign on paper");
    await screen.findByTestId("step-decline");

    expect(screen.getByTestId("decline-consequence")).toHaveTextContent(
      "closes the document, so it can't be signed here later",
    );

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
  }, 20_000);

  it("a kiosk session ends on hand-back with every trace of the patient gone", async () => {
    const host = await start("kiosk");
    await readAndContinue();
    await choosePrintedName();
    await user.click(screen.getByRole("checkbox", { name: /Notice of Privacy/ }));
    await click("Sign here");
    await click("Sign as Maria Alvarez");

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
  }, 25_000);

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
