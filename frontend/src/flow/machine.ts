/**
 * The flow as a pure state machine. Where the signer stands is decided by the server's view of
 * them (so a reload, or a second tablet, resumes in the right place) plus the few things only
 * this page knows: whether the token has arrived, and whether the decline sheet is open.
 *
 * Addendum 3: three steps, not five. Consent moved onto Read and the confirm screen was folded
 * into Sign, so the server's `signers.status` progression (`pending -> viewed -> consented ->
 * signed`) now maps onto fewer places: `viewed` still means "read it, has not agreed yet", which
 * is the Read screen, and `consented` is the Sign screen.
 */

import type { SigningSession } from "@/lib/signing-api";

export type Step = "read" | "sign" | "done";
export const STEPS: readonly Step[] = ["read", "sign", "done"];

export type UnavailableReason = "voided" | "declined_by_other" | "expired_envelope";

export type FlowState =
  | { phase: "connecting" }
  | { phase: "connect_failed" }
  | { phase: "loading" }
  | { phase: "active"; step: Step; declining: boolean }
  | { phase: "declined" }
  | { phase: "expired" }
  | { phase: "unavailable"; reason: UnavailableReason }
  | { phase: "handed_back"; outcome: "signed" | "declined" };

export type FlowEvent =
  | { type: "TOKEN_RECEIVED" }
  | { type: "CONNECT_TIMED_OUT" }
  | { type: "RETRY_CONNECT" }
  | { type: "SESSION_LOADED"; session: SigningSession }
  | { type: "GO"; step: Step }
  | { type: "DECLINE_OPENED" }
  | { type: "DECLINE_CLOSED" }
  | { type: "DECLINED"; kiosk: boolean }
  | { type: "SIGNED"; kiosk: boolean }
  | { type: "SESSION_EXPIRED" };

export const initialFlowState: FlowState = { phase: "connecting" };

/** Where the server says this signer is. Terminal envelope states win over everything. */
export function placeFor(session: SigningSession): FlowState {
  const { envelope, signer } = session;
  if (signer.status === "declined") {
    return { phase: "declined" };
  }
  if (envelope.status === "expired") {
    return { phase: "unavailable", reason: "expired_envelope" };
  }
  if (envelope.status === "voided") {
    return { phase: "unavailable", reason: "voided" };
  }
  if (envelope.status === "declined") {
    return { phase: "unavailable", reason: "declined_by_other" };
  }
  switch (signer.status) {
    case "signed":
      return { phase: "active", step: "done", declining: false };
    case "consented":
      return { phase: "active", step: "sign", declining: false };
    // `viewed` means the pages were displayed but consent was not given, and consent is now part
    // of the Read screen: that is where the signer belongs, with the document above it.
    case "viewed":
      return { phase: "active", step: "read", declining: false };
    default:
      return { phase: "active", step: "read", declining: false };
  }
}

const isTerminal = (state: FlowState) =>
  state.phase === "declined" ||
  state.phase === "expired" ||
  state.phase === "unavailable" ||
  state.phase === "handed_back";

export function flowReducer(state: FlowState, event: FlowEvent): FlowState {
  // Once it is over it stays over. A late message or refetch cannot restart a finished session.
  if (isTerminal(state)) {
    return state;
  }
  switch (event.type) {
    case "TOKEN_RECEIVED":
      // ...and from the Done screen, which is the host opening the next document of a run into
      // the same iframe (addendum 3 B). Nowhere else: a token arriving mid-signature would be a
      // swap of identities under somebody's hands.
      return state.phase === "connecting" ||
        state.phase === "connect_failed" ||
        (state.phase === "active" && state.step === "done")
        ? { phase: "loading" }
        : state;
    case "CONNECT_TIMED_OUT":
      return state.phase === "connecting" ? { phase: "connect_failed" } : state;
    case "RETRY_CONNECT":
      return state.phase === "connect_failed" ? { phase: "connecting" } : state;
    case "SESSION_LOADED": {
      const place = placeFor(event.session);
      if (state.phase === "loading") {
        return place;
      }
      if (state.phase !== "active") {
        return state;
      }
      // A background refetch only moves the signer when the server has moved past them:
      // the envelope ended, or their signature is already recorded.
      if (place.phase !== "active") {
        return place;
      }
      return place.step === "done" && state.step !== "done" ? place : state;
    }
    case "GO":
      return state.phase === "active"
        ? { phase: "active", step: event.step, declining: false }
        : state;
    case "DECLINE_OPENED":
      return state.phase === "active" && state.step !== "done"
        ? { ...state, declining: true }
        : state;
    case "DECLINE_CLOSED":
      return state.phase === "active" ? { ...state, declining: false } : state;
    case "DECLINED":
      return event.kiosk ? { phase: "handed_back", outcome: "declined" } : { phase: "declined" };
    case "SIGNED":
      return event.kiosk
        ? { phase: "handed_back", outcome: "signed" }
        : { phase: "active", step: "done", declining: false };
    case "SESSION_EXPIRED":
      return { phase: "expired" };
  }
}
