import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useId, useMemo, useRef, useState } from "react";
import { FieldCloseUp } from "@/components/FieldCloseUp";
import {
  ActionBar,
  Button,
  CheckIcon,
  CheckRow,
  Dots,
  Notice,
  StepHeading,
  useAnnounce,
} from "@/components/ui";
import { useHostLink, useNow } from "@/flow/context";
import { useWorkspace } from "@/flow/DocumentWorkspace";
import {
  actionableFields,
  buildSignRequest,
  type Draft,
  type FieldValue,
  initialsFrom,
  isFieldComplete,
  isMarkField,
  remainingRequired,
  serverFilledFields,
  TEXT_FIELD_HINT_AT,
  TEXT_FIELD_MAX,
  withAdopted,
  withValue,
} from "@/flow/draft";
import { MarkPreview } from "@/flow/steps/MarkPreview";
import { SignaturePanel, type SignaturePanelHandle } from "@/flow/steps/SignaturePanel";
import { ApiError } from "@/lib/api";
import {
  isNetworkError,
  isReauthLapsed,
  isSessionGone,
  isSignatureUnavailable,
  mustReadAgain,
  onBehalfOfPhrase,
  postSign,
  type SigningField,
  type SigningSession,
  type SignRequest,
  type SubmissionKeys,
  sessionQueryOptions,
  signingKeys,
} from "@/lib/signing-api";
import { clockTime } from "@/lib/time";
import type { PdfState } from "@/lib/use-pdf";

export const REAUTH_TIMEOUT_MS = 120_000;

type Reauth =
  | { status: "idle" }
  | { status: "waiting"; since: number }
  | { status: "checking" }
  | { status: "timed_out" }
  | { status: "not_confirmed" }
  | { status: "lapsed" };

const FALLBACK_LABELS: Record<SigningField["type"], string> = {
  signature: "Signature",
  initials: "Initials",
  checkbox: "Confirmation",
  text: "Your answer",
  date_signed: "Date signed",
};

export const labelOf = (field: SigningField) => field.label.trim() || FALLBACK_LABELS[field.type];

/** Said wherever a press would otherwise act on a signature the signer has not placed anywhere. */
const UNPLACED_SIGNATURE =
  "Your new signature hasn't been placed yet. Press the button on each field to put it where the document asks.";

interface SignStepProps {
  session: SigningSession;
  locale?: string | null;
  draft: Draft;
  submissionKeys: SubmissionKeys;
  signatureGone?: boolean;
  onDraft: (draft: Draft) => void;
  onSigned: () => void;
  /** The document moved on under this signer: they have to read it again before they can sign. */
  onReadAgain: () => void;
  /**
   * The saved signature they applied is no longer theirs to use -- the host revoked it, or
   * another session of theirs replaced it (SPEC section 14 B). Nothing here can mend that, so the
   * marks made with it are dropped and the panel says why.
   */
  onSignatureUnavailable: () => void;
  onPaper: () => void;
}

/**
 * Screen 2 of 3 (addendum 3 A): the signature, the fields, and the one press that signs.
 *
 * Every act that produces evidence is its own explicit act: one press per field, and one press
 * that signs the document. On a wide frame this is a panel beside the document, whose pages show
 * each mark in place as it is applied; on a narrow one it takes the frame, and each field row
 * carries a close-up of where on the page its mark goes.
 */
export function SignStep({
  session,
  locale,
  draft,
  submissionKeys,
  signatureGone = false,
  onDraft,
  onSigned,
  onReadAgain,
  onSignatureUnavailable,
  onPaper,
}: SignStepProps) {
  const queryClient = useQueryClient();
  const host = useHostLink();
  const announce = useAnnounce();
  const now = useNow(1_000);
  const live = useQuery(sessionQueryOptions(locale));
  const signer = live.data?.signer ?? session.signer;
  const { pdf, goToPage } = useWorkspace();

  const fields = actionableFields(session.fields);
  const auto = serverFilledFields(session.fields);
  const needsInitials = fields.some((field) => field.type === "initials");
  // Only a signature field can hold the signature they adopt: initials are their own typed text,
  // so a signer asked for initials alone has nothing to save for next time.
  const hasSignatureField = fields.some((field) => field.type === "signature");
  const remaining = remainingRequired(session.fields, draft);
  // Counted with the predicate the button uses, not by "this field holds something": an unticked
  // required box and a whitespace-only answer both hold a value, and a header reading "2 of 2
  // done" over an inert button saying one thing is still needed is the screen calling itself a
  // liar.
  const done = fields.filter(
    (field) =>
      draft.values[field.id] !== undefined && isFieldComplete(field, draft.values[field.id], draft),
  ).length;

  const panel = useRef<SignaturePanelHandle>(null);
  const seededInitials = useRef(false);

  // The document beside the panel opens on the page the first mark goes on, so what "Sign here"
  // is about is in view before it is pressed. Once, quietly: it is the screen arranging itself,
  // not the signer moving, and the live region should not say "Page 3 of 3" over the heading.
  const firstFieldPage = fields[0]?.page;
  const arrived = useRef(false);
  useEffect(() => {
    if (!arrived.current && firstFieldPage !== undefined) {
      arrived.current = true;
      goToPage(firstFieldPage, { silent: true });
    }
  }, [firstFieldPage, goToPage]);
  const [reauth, setReauth] = useState<Reauth>({ status: "idle" });
  /** Re-authenticated through the hand-off on this screen, as opposed to arriving already covered. */
  const [confirmedHere, setConfirmedHere] = useState(false);
  /** A press of "Sign as ..." waiting on the hand-off: it sends itself when the server vouches. */
  const [pressPending, setPressPending] = useState(false);
  const [nudge, setNudge] = useState<string | null>(null);
  /**
   * The field whose button was last pressed. Pressing "Sign here" replaces that button with
   * "Remove", so React unmounts the thing that had focus and the browser drops focus to the
   * document: the next Tab starts again at the top of the screen, once per field. The row that
   * was acted in takes focus instead -- and only that row, because applying a different signature
   * un-places the others and they must not fight over it.
   */
  const [acted, setActed] = useState<string | null>(null);
  const signHint = useId();

  /**
   * Whether the server holds a live re-authentication for this signer. The answer is the server's,
   * not this device's: `reauth_valid_until` is server time plus the maximum age, so a tablet whose
   * clock runs two minutes fast would read every successful confirmation as already lapsed and
   * refuse to let anyone sign. The countdown below is advisory; the server's 403 is what decides.
   *
   * SPEC section 14 C: the value covers an attestation borrowed from an earlier session of this
   * person's (a signing queue) as well as one made for this session, and `reauth_scope` says which.
   */
  const validUntil = signer.reauth_valid_until ? Date.parse(signer.reauth_valid_until) : 0;
  const secondsLeft = Math.floor((validUntil - now) / 1000);
  const serverVouches = !signer.requires_reauth || signer.reauth_valid_until !== null;
  const verified = serverVouches && reauth.status !== "lapsed";
  const coveredUntil = signer.reauth_valid_until
    ? clockTime(signer.reauth_valid_until, session.consent.locale)
    : null;
  const confirmedAt = signer.reauth_at ? clockTime(signer.reauth_at, session.consent.locale) : null;

  const request = useMemo<SignRequest>(
    () => buildSignRequest(session.fields, draft, { kiosk: session.session.kiosk }),
    [session.fields, draft, session.session.kiosk],
  );

  const sign = useMutation({
    // The key is looked up at send time: the same submission always gets the same key, whether
    // the retry is automatic (below) or the signer pressing the button again.
    mutationFn: () => postSign(request, submissionKeys.keyFor(request)),
    retry: (failures, error) => isNetworkError(error) && failures < 2,
    retryDelay: (attempt) => 800 * 2 ** attempt,
    onSuccess: async () => {
      submissionKeys.reset();
      await queryClient.invalidateQueries({ queryKey: signingKeys.session });
      onSigned();
    },
    onError: (error) => {
      // Which 403 it is, by the server's code and never by the status: this route refuses a
      // lapsed re-authentication and an unusable saved signature with the same status, and the
      // two want opposite things from the signer.
      if (isReauthLapsed(error) && signer.requires_reauth) {
        setReauth({ status: "lapsed" });
        // The server has stopped vouching for them; the cached session still says otherwise.
        void queryClient.invalidateQueries({ queryKey: signingKeys.session });
      }
      if (isSignatureUnavailable(error)) {
        void queryClient.invalidateQueries({ queryKey: signingKeys.session });
        onSignatureUnavailable();
      }
      if (error instanceof ApiError && error.status === 409) {
        // Already signed from another attempt, or the envelope moved on. The session knows.
        void queryClient.invalidateQueries({ queryKey: signingKeys.session });
      }
      if (mustReadAgain(error)) {
        // The bytes held in the cache are last revision's; the read step must show what is
        // actually being signed now, so they are dropped rather than invalidated.
        queryClient.removeQueries({ queryKey: signingKeys.document });
        onReadAgain();
      }
    },
  });

  /**
   * Initials are their own typed text on the wire, so the draft has to carry them, not only the
   * box that shows them. Seeded once, from the name, and never again: a signer who clears the box
   * to type their own is not fighting a default that keeps coming back.
   */
  useEffect(() => {
    if (!seededInitials.current && needsInitials && draft.initials === "") {
      seededInitials.current = true;
      onDraft({ ...draft, initials: initialsFrom(session.signer.display_name) });
    }
  });

  // Host says re-authentication finished: believe the server, not the message.
  useEffect(
    () =>
      host.onReauthDone(() => {
        setReauth((current) => (current.status === "waiting" ? { status: "checking" } : current));
      }),
    [host],
  );

  useEffect(() => {
    if (reauth.status !== "checking") {
      return;
    }
    let cancelled = false;
    queryClient.fetchQuery({ ...sessionQueryOptions(locale), staleTime: 0 }).then(
      (fresh) => {
        if (cancelled) {
          return;
        }
        // An attestation the server is still willing to vouch for. Comparing it against this
        // device's clock would turn a fast tablet into an endless "try again".
        if (fresh.signer.reauth_valid_until !== null) {
          setReauth({ status: "idle" });
          setConfirmedHere(true);
          announce("Thank you. We've confirmed it's you. Signing now.");
        } else {
          setPressPending(false);
          setReauth({ status: "not_confirmed" });
        }
      },
      () => {
        if (!cancelled) {
          setPressPending(false);
          setReauth({ status: "not_confirmed" });
        }
      },
    );
    return () => {
      cancelled = true;
    };
  }, [reauth.status, queryClient, announce, locale]);

  // The press is what asked for the hand-off, so the press is what it completes: once the server
  // vouches, the signature goes without asking for a second tap. What it sends is still checked
  // first -- `updateDraft` cancels a queued press, and this is the belt to that braces: the one
  // thing on this screen that acts without a press must never send a submission nobody looked at.
  useEffect(() => {
    if (pressPending && verified && reauth.status === "idle" && !sign.isPending) {
      setPressPending(false);
      if (remaining.length > 0) {
        nudgeWhatIsMissing();
        return;
      }
      sign.mutate();
    }
  });

  useEffect(() => {
    if (reauth.status === "waiting" && now - reauth.since > REAUTH_TIMEOUT_MS) {
      setPressPending(false);
      setReauth({ status: "timed_out" });
    }
  }, [reauth, now]);

  const startReauth = () => {
    sign.reset();
    setPressPending(true);
    setReauth({ status: "waiting", since: Date.now() });
    host.post({ type: "esign:reauth_required", session_id: session.session.id });
  };

  /**
   * Any change to what would be signed. The last refusal described the *old* submission, so it
   * goes: leaving "Try again" on the button after the signer has mended what was wrong would name
   * the wrong action, and the message under it would be about a request nobody is sending.
   *
   * A press waiting on the hand-off goes with it. That press is the one piece of state here that
   * acts on its own, and it was made about answers that no longer exist: letting it fire would
   * send whatever the draft became -- in the worst case an empty one -- and answer it with a
   * refusal naming the wrong problem.
   */
  const updateDraft = (next: Draft) => {
    sign.reset();
    setPressPending(false);
    if (reauth.status === "waiting" || reauth.status === "checking") {
      setReauth({ status: "idle" });
      setNudge(
        "Your answers changed, so that press was cancelled. Press the button again when you're ready.",
      );
    } else {
      setNudge(null);
    }
    onDraft(next);
  };

  /** Place the signature the panel is showing in one field. The panel decides what that is. */
  const applyMark = (field: SigningField) => {
    // Asked on every apply, never only the first time. The panel is where a signature is chosen
    // and it can be chosen again at any point on this screen; a guard that stopped asking after
    // the first mark meant a signature drawn afterwards was shown, saved-looking, and silently
    // left out of the submission while the earlier one was signed.
    const chosen = panel.current?.commit();
    if (chosen === undefined || !chosen.ok) {
      // The refusal is said in the panel, which can be a screen away. Say it here too, beside the
      // button that was actually pressed.
      setNudge(chosen?.reason ?? "Please choose a signature first.");
      return;
    }
    // The same signature handed back is not a fresh choice: re-adopting would drop the marks
    // already placed with it and make the signer place every one of them again.
    const chose =
      chosen.adopted === draft.adopted
        ? draft
        : withAdopted(draft, chosen.adopted, draft.initials, draft.save);
    const next = withValue(chose, field.id, { type: "mark" });
    updateDraft(next);
    setActed(field.id);
    const left = remainingRequired(session.fields, next).length;
    announce(
      `${field.type === "initials" ? "Initials" : "Signature"} added. ${
        left === 0 ? "Everything that's needed is filled in." : `${left} left to complete.`
      }`,
    );
  };

  const setValue = (field: SigningField, value: FieldValue | null) => {
    if (isMarkField(field)) {
      setActed(field.id);
    }
    updateDraft(withValue(draft, field.id, value));
  };

  // "Sign as ..." is inert until every required field is done, and pressing it then says what is
  // missing rather than doing nothing (the inert-button pattern). Re-authentication is not a
  // reason to be inert: the press is what triggers it.
  // The fields list is the better answer here even when a signature is sitting unplaced in the
  // panel, because an unplaced signature *is* one of the fields it names.
  const nudgeWhatIsMissing = () => {
    setNudge(
      remaining.length === 1
        ? `One thing is still needed: ${labelOf(remaining[0] as SigningField)}.`
        : `${remaining.length} things are still needed. They're marked in the list.`,
    );
  };

  const press = () => {
    setNudge(null);
    // A signature drawn or typed but never placed is not what any field is carrying, so signing
    // now would sign something other than what the panel is showing.
    if (panel.current?.uncommitted() === true) {
      setNudge(UNPLACED_SIGNATURE);
      return;
    }
    if (signer.requires_reauth && !verified) {
      startReauth();
      return;
    }
    sign.mutate();
  };

  const signError = sign.error;
  const sessionGone = isSessionGone(signError);
  const waiting = reauth.status === "waiting" || reauth.status === "checking";
  // The button's label is the intent confirmation in full, so every word of it has to be a word
  // the signer can check before pressing it. `onBehalfOfPhrase` is what keeps an unreadable
  // patient reference out of that sentence.
  const actingFor = onBehalfOfPhrase(signer.on_behalf_of_label);
  const signerName = `${signer.display_name}${actingFor === null ? "" : `, ${actingFor}`}`;

  return (
    <>
      <aside
        className="side-panel"
        data-testid="step-sign"
        aria-labelledby="step-sign-title"
        data-scroll-region
      >
        <div className="flex flex-col gap-3 p-3 sm:p-4">
          <StepHeading id="step-sign-title">Sign the document</StepHeading>

          {/* Re-authentication, inline, because it happens on the press and not on a screen of
              its own. Everything here is about the one thing the signer is waiting for. */}
          {waiting ? (
            <div
              role="status"
              data-testid="reauth-waiting"
              className="rounded-md bg-accent-wash px-3 py-2.5 text-sm"
            >
              <p className="flex items-center gap-2 font-semibold text-ink-900">
                <Dots /> Confirming it's you
              </p>
              <p className="mt-1 text-ink-700">
                Your records system is asking you to sign in again. Finish that and the document is
                signed straight away. There's no need to press anything else, or to refresh.
              </p>
              <Button
                variant="quiet"
                size="sm"
                className="mt-1 px-0"
                onClick={() => {
                  setPressPending(false);
                  setReauth({ status: "idle" });
                }}
              >
                Cancel
              </Button>
            </div>
          ) : null}

          {reauth.status === "timed_out" ? (
            <Notice tone="warn" alert>
              We didn't hear back in time. Nothing has been signed. Press the button below to try
              again.
            </Notice>
          ) : null}
          {reauth.status === "not_confirmed" ? (
            <Notice tone="warn" alert>
              We couldn't confirm that. Nothing has been signed. Press the button below to try
              again.
            </Notice>
          ) : null}
          {reauth.status === "lapsed" ? (
            <Notice tone="warn" alert>
              The confirmation ran out before the document was signed. Nothing has been signed.
              Press the button below and confirm once more.
            </Notice>
          ) : null}

          {signError && !sessionGone && !sign.isPending ? (
            <Notice tone="error" alert>
              {isNetworkError(signError) ? (
                <>
                  <p className="font-semibold">We couldn't reach the server.</p>
                  <p className="mt-1">
                    Your answers are still here. Check the connection, then press the button again.
                    It's safe to retry: the document can't be signed twice.
                  </p>
                </>
              ) : isReauthLapsed(signError) ? null : signError instanceof ApiError &&
                signError.status === 422 ? (
                // A 422 on this route is any of `unknown_field`, `duplicate_capture`,
                // `missing_required_field`, `no_captures` or `capture_shape_invalid`, and the
                // status alone does not say which field it was about. Telling the truth at the
                // altitude the status supports is better than a confident instruction.
                <p>
                  Something in your answers wasn't accepted, and nothing has been signed. Check the
                  fields below, then press the button again. If it keeps happening, ask a member of
                  staff for help.
                </p>
              ) : signError instanceof ApiError && signError.status === 429 ? (
                <p>Too many attempts in a short time. Please wait a minute and try again.</p>
              ) : (
                <p>
                  That didn't go through, and nothing has been signed. Please try again. If it keeps
                  happening, ask a member of staff for help.
                </p>
              )}
            </Notice>
          ) : null}

          <SignaturePanel
            ref={panel}
            session={session}
            draft={draft}
            hasSignatureField={hasSignatureField}
            needsInitials={needsInitials}
            signatureGone={signatureGone}
            onDraft={updateDraft}
          />

          <section aria-labelledby="fields-title">
            <div className="mb-1.5 flex items-baseline justify-between gap-3 px-1">
              <h2 id="fields-title" className="text-ink-900 text-sm">
                {fields.length === 1 ? "Where it goes" : "Where they go"}
              </h2>
              {/* Plain text, not a live region. `applyMark` already announces "Signature added.
                  1 left to complete.", and a status region here made a screen reader say the
                  same fact twice, in worse words. */}
              <p data-testid="fields-progress" className="text-ink-700 text-sm tabular-nums">
                <span className="font-semibold text-ink-900">
                  {done} of {fields.length}
                </span>{" "}
                done
              </p>
            </div>
            <ul className="m-0 flex list-none flex-col gap-2 p-0">
              {fields.map((field) => (
                <FieldRow
                  key={field.id}
                  pdf={pdf}
                  session={session}
                  field={field}
                  draft={draft}
                  acted={acted === field.id}
                  onApply={() => applyMark(field)}
                  onValue={(value) => setValue(field, value)}
                  onShow={() => goToPage(field.page)}
                />
              ))}
              {auto.map((field) => (
                <li key={field.id} className="rounded-lg bg-sheet px-3 py-2 text-sm shadow-sheet">
                  <p className="font-semibold text-ink-900">{labelOf(field)}</p>
                  <p className="text-ink-700 text-xs">
                    Page {field.page} · Added automatically when you sign
                  </p>
                </li>
              ))}
            </ul>
          </section>

          {signer.requires_reauth ? (
            <p className="px-1 text-ink-700 text-xs" data-testid="reauth-note">
              {verified ? (
                <span
                  data-testid="reauth-verified"
                  data-reauth-scope={signer.reauth_scope ?? undefined}
                >
                  <CheckIcon className="mr-1 text-accent-600" />
                  {confirmedHere
                    ? "Your identity is confirmed"
                    : confirmedAt !== null
                      ? `You confirmed your identity at ${confirmedAt}`
                      : "You've already confirmed your identity"}
                  {!confirmedHere && signer.reauth_scope === "span"
                    ? " for an earlier document"
                    : ""}
                  {"; this signature will be recorded under that confirmation."}
                  {coveredUntil !== null ? ` It covers this signature until ${coveredUntil}.` : ""}
                  {secondsLeft > 0 && secondsLeft <= 30
                    ? ` About ${secondsLeft} seconds left.`
                    : ""}
                </span>
              ) : (
                <span data-testid="reauth-needed">
                  Because you're signing in a professional role, your records system will ask you to
                  confirm it's you when you press the button. It takes a moment.
                </span>
              )}
            </p>
          ) : null}
        </div>
      </aside>

      {/* The press *is* the intent confirmation (addendum 3 A 3). The sentence above the button
          says so in as many words, which is what the checkbox used to say and one tap less. */}
      <ActionBar testId="sign-bar">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <div className="min-w-0 flex-1 basis-64 leading-5">
            <p className="text-ink-700 text-sm">
              By pressing this you are signing this document. It counts the same as signing on
              paper, and you will get a copy.
            </p>
            {/* Reserved: what stops the press from working, or nothing. One line on a wide
                frame, two on a phone, never cut short. */}
            <p
              id={signHint}
              role="alert"
              data-testid="sign-nudge"
              className="status-line status-wrap text-danger-600 text-sm max-sm:text-xs"
            >
              {nudge ?? ""}
            </p>
          </div>
          <div className="flex items-center gap-2 max-sm:w-full">
            <Button
              variant="quiet"
              size="sm"
              className="whitespace-nowrap max-sm:mr-auto max-sm:px-0 max-sm:text-xs"
              onClick={onPaper}
            >
              I'd rather sign on paper
            </Button>
            <Button
              size="lg"
              className="max-sm:min-w-0 max-sm:flex-1 max-sm:px-3 max-sm:text-[0.95rem] sm:min-w-[16rem]"
              data-testid="sign-button"
              inert={remaining.length > 0}
              busy={sign.isPending || waiting}
              aria-describedby={nudge ? signHint : undefined}
              onInertClick={nudgeWhatIsMissing}
              onClick={press}
            >
              {waiting
                ? "Confirming it's you…"
                : sign.isPending
                  ? "Signing"
                  : sign.isError ||
                      reauth.status === "timed_out" ||
                      reauth.status === "not_confirmed" ||
                      reauth.status === "lapsed"
                    ? "Try again"
                    : `Sign as ${signerName}`}
            </Button>
          </div>
        </div>
        <div aria-live="polite" className="sr-only">
          {sign.isPending ? "Signing the document. Please wait." : ""}
        </div>
      </ActionBar>
    </>
  );
}

// --------------------------------------------------------------------------- one field

interface FieldRowProps {
  pdf: PdfState;
  session: SigningSession;
  field: SigningField;
  draft: Draft;
  /** This is the row whose own button was last pressed, so it is the row focus belongs in. */
  acted: boolean;
  onApply: () => void;
  onValue: (value: FieldValue | null) => void;
  /** Scroll the document beside the panel to this field's page. */
  onShow: () => void;
}

/**
 * One field, with the part of the page it lands on and exactly one thing to do. This is the
 * "review your signatures" step as well as the doing of it: every applied mark is shown here,
 * in place, which is why the summary screen is gone rather than merely moved.
 */
function FieldRow({ pdf, session, field, draft, acted, onApply, onValue, onShow }: FieldRowProps) {
  const announce = useAnnounce();
  const inputId = useId();
  const textCountId = useId();
  const label = labelOf(field);
  const value = draft.values[field.id];
  const complete = isFieldComplete(field, value, draft);
  const applied = value?.type === "mark";
  const applyButton = useRef<HTMLButtonElement>(null);
  const removeButton = useRef<HTMLButtonElement>(null);
  const wasApplied = useRef(applied);

  /**
   * Pressing this row's button swaps it for a different one, so the pressed element is unmounted
   * and focus falls to the document. Put it back where the signer was working -- but only in the
   * row they pressed, and never on the first render, where a row that arrives already applied
   * (a failed submission being mended) must not steal focus from the heading.
   */
  useEffect(() => {
    if (wasApplied.current === applied) {
      return;
    }
    wasApplied.current = applied;
    if (acted) {
      (applied ? removeButton : applyButton).current?.focus?.();
    }
  }, [applied, acted]);
  const text = value?.type === "text" ? value.text : "";
  const textLeft = text.length >= TEXT_FIELD_HINT_AT ? TEXT_FIELD_MAX - text.length : null;
  const adopted = draft.adopted;

  const inField =
    applied && adopted !== null && isMarkField(field) ? (
      <MarkPreview
        adopted={adopted}
        kind={field.type === "initials" ? "initials" : "signature"}
        initials={draft.initials}
        displayName={session.signer.display_name}
        context="page"
      />
    ) : value?.type === "checkbox" && value.checked ? (
      <CheckIcon className="text-page-ink" />
    ) : value?.type === "text" ? (
      <span className="line-clamp-2 self-start px-1 text-left text-[0.7rem] text-page-ink leading-tight">
        {value.text}
      </span>
    ) : null;

  return (
    <li
      className="rounded-lg bg-sheet p-3 shadow-sheet"
      data-testid="field-row"
      data-field={field.id}
      data-done={complete}
    >
      <div className="flex items-baseline justify-between gap-2">
        {/* The control carries the field's label where it has one of its own -- a tick box and
            a text box both do -- so the row does not print it twice. */}
        <p className="min-w-0 truncate text-sm">
          {isMarkField(field) ? (
            <span className="font-semibold text-ink-900">{label}</span>
          ) : (
            <span className="text-ink-700">{field.required ? "Needed" : "Optional"}</span>
          )}
        </p>
        <button
          type="button"
          onClick={onShow}
          className="hidden shrink-0 text-accent-600 text-xs underline decoration-1 underline-offset-4 hover:text-accent-700 lg:inline"
        >
          Page {field.page}
        </button>
        <span className="shrink-0 text-ink-700 text-xs lg:hidden">Page {field.page}</span>
      </div>
      {isMarkField(field) ? (
        <p className="text-ink-700 text-xs">{field.required ? "Needed" : "Optional"}</p>
      ) : null}

      <div className="mt-2 lg:hidden">
        {pdf.status === "ready" ? (
          <FieldCloseUp
            pdf={pdf.pdf}
            field={field}
            done={complete && value !== undefined}
            maxHeight={110}
          >
            {inField}
          </FieldCloseUp>
        ) : (
          // The bytes are already in the cache; this is pdf.js parsing them. A flat grey block
          // reads as a broken image, so it breathes for the second it is there.
          <div
            className="quiet-pulse h-[110px] rounded-md bg-sunk"
            aria-hidden="true"
            data-testid="field-closeup-loading"
          />
        )}
      </div>

      <div className="mt-2">
        {isMarkField(field) ? (
          applied ? (
            <div className="flex items-center justify-between gap-3 rounded-md bg-accent-wash px-3 py-1.5">
              <p className="inline-flex items-center gap-2 font-semibold text-ink-900 text-sm">
                <CheckIcon className="text-accent-600" />
                {field.type === "initials" ? "Initials in place" : "Signature in place"}
              </p>
              <Button
                ref={removeButton}
                variant="quiet"
                size="sm"
                onClick={() => {
                  onValue(null);
                  announce(`${label} removed.`);
                }}
              >
                Remove
              </Button>
            </div>
          ) : (
            <Button ref={applyButton} className="w-full" onClick={onApply}>
              {field.type === "initials" ? "Add initials" : "Sign here"}
            </Button>
          )
        ) : null}

        {field.type === "checkbox" ? (
          <CheckRow
            checked={value?.type === "checkbox" && value.checked}
            onChange={(checked) => onValue({ type: "checkbox", checked })}
          >
            {label}
          </CheckRow>
        ) : null}

        {field.type === "text" ? (
          <div>
            <label htmlFor={inputId} className="mb-1 block font-semibold text-ink-900 text-sm">
              {label}
            </label>
            <textarea
              id={inputId}
              rows={field.rect.h > 30 ? 3 : 1}
              maxLength={TEXT_FIELD_MAX}
              aria-describedby={textLeft === null ? undefined : textCountId}
              value={text}
              onChange={(event) =>
                onValue(
                  event.target.value === "" ? null : { type: "text", text: event.target.value },
                )
              }
              className="block min-h-11 w-full resize-y rounded-md bg-paper px-3 py-2 text-ink-900 ring-1 ring-edge-strong ring-inset"
            />
            {/* Typing that simply stops is the one thing a text box must never do without
                saying so, so the room left is announced as it runs out. */}
            {textLeft !== null ? (
              <p
                id={textCountId}
                role="status"
                data-testid="text-chars-left"
                className={`mt-1 text-xs ${textLeft === 0 ? "font-medium text-danger-600" : "text-ink-700"}`}
              >
                {textLeft === 0
                  ? "That's as much as this box will take."
                  : `${textLeft} ${textLeft === 1 ? "character" : "characters"} left.`}
              </p>
            ) : null}
          </div>
        ) : null}
      </div>
    </li>
  );
}
