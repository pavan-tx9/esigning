import { describe, expect, it } from "vitest";
import { type FlowState, flowReducer, initialFlowState, placeFor, type Step } from "@/flow/machine";
import type { SigningSession } from "@/lib/signing-api";
import { mockDb, sessionBody, tokenFor } from "@/mocks/db";

function session(patch: {
  signer?: Partial<SigningSession["signer"]>;
  envelope?: Partial<SigningSession["envelope"]>;
}): SigningSession {
  mockDb.reset();
  const body = sessionBody(mockDb.authenticate(`Bearer ${tokenFor("single")}`)) as SigningSession;
  return {
    ...body,
    signer: { ...body.signer, ...patch.signer },
    envelope: { ...body.envelope, ...patch.envelope },
  };
}

const active = (step: Step): FlowState => ({
  phase: "active",
  step,
  declining: false,
});

describe("where the server says the signer is", () => {
  // Addendum 3: `viewed` means the pages were seen but consent was not given, and consent now
  // lives on the Read screen -- so it resumes there, with the document above it, rather than on a
  // consent screen of its own that no longer exists.
  it.each([
    ["pending", "read"],
    ["viewed", "read"],
    ["consented", "sign"],
    ["signed", "done"],
  ] as const)("a %s signer resumes at %s", (status, step) => {
    expect(placeFor(session({ signer: { status } }))).toEqual(active(step));
  });

  it("ended envelopes win over the signer's own progress", () => {
    expect(placeFor(session({ envelope: { status: "voided" } })).phase).toBe("unavailable");
    expect(placeFor(session({ envelope: { status: "expired" } })).phase).toBe("unavailable");
    expect(placeFor(session({ envelope: { status: "declined" } }))).toEqual({
      phase: "unavailable",
      reason: "declined_by_other",
    });
    expect(
      placeFor(session({ signer: { status: "declined" }, envelope: { status: "declined" } })),
    ).toEqual({
      phase: "declined",
    });
  });
});

describe("the flow", () => {
  it("connects, times out, and can retry", () => {
    const failed = flowReducer(initialFlowState, { type: "CONNECT_TIMED_OUT" });
    expect(failed.phase).toBe("connect_failed");
    expect(flowReducer(failed, { type: "RETRY_CONNECT" }).phase).toBe("connecting");
    expect(flowReducer(failed, { type: "TOKEN_RECEIVED" }).phase).toBe("loading");
  });

  it("a timeout after the token arrived changes nothing", () => {
    const loading = flowReducer(initialFlowState, { type: "TOKEN_RECEIVED" });
    expect(flowReducer(loading, { type: "CONNECT_TIMED_OUT" })).toBe(loading);
  });

  it("a background refetch never drags the signer backwards or forwards mid-step", () => {
    const state = active("sign");
    const next = flowReducer(state, {
      type: "SESSION_LOADED",
      session: session({ signer: { status: "consented" } }),
    });
    expect(next).toBe(state);
  });

  it("but it does move them when the server is past them", () => {
    const signed = session({
      signer: { status: "signed" },
      envelope: { status: "completed_pending_seal" },
    });
    expect(flowReducer(active("sign"), { type: "SESSION_LOADED", session: signed })).toEqual(
      active("done"),
    );
    const voided = session({ envelope: { status: "voided" } });
    expect(flowReducer(active("sign"), { type: "SESSION_LOADED", session: voided }).phase).toBe(
      "unavailable",
    );
  });

  it("decline can be opened from any step before done, and closed again", () => {
    const open = flowReducer(active("sign"), { type: "DECLINE_OPENED" });
    expect(open).toEqual({ phase: "active", step: "sign", declining: true });
    expect(flowReducer(open, { type: "DECLINE_CLOSED" })).toEqual(active("sign"));
    expect(flowReducer(active("done"), { type: "DECLINE_OPENED" })).toEqual(active("done"));
  });

  it("kiosk sessions end on hand-back, whether signed or declined", () => {
    expect(flowReducer(active("sign"), { type: "SIGNED", kiosk: true })).toEqual({
      phase: "handed_back",
      outcome: "signed",
    });
    expect(flowReducer(active("read"), { type: "DECLINED", kiosk: true })).toEqual({
      phase: "handed_back",
      outcome: "declined",
    });
    expect(flowReducer(active("sign"), { type: "SIGNED", kiosk: false })).toEqual(active("done"));
  });

  it("expiry ends any live state, and nothing restarts a finished session", () => {
    for (const state of [initialFlowState, { phase: "loading" } as const, active("sign")]) {
      expect(flowReducer(state, { type: "SESSION_EXPIRED" }).phase).toBe("expired");
    }
    const over: FlowState = { phase: "handed_back", outcome: "signed" };
    expect(flowReducer(over, { type: "TOKEN_RECEIVED" })).toBe(over);
    expect(flowReducer(over, { type: "SESSION_EXPIRED" })).toBe(over);
    expect(flowReducer({ phase: "expired" }, { type: "GO", step: "sign" })).toEqual({
      phase: "expired",
    });
  });
});
