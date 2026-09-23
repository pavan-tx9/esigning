import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useId, useMemo, useRef, useState } from "react";
import { FieldCloseUp } from "@/components/FieldCloseUp";
import {
  Button,
  CheckIcon,
  CheckRow,
  Dots,
  Notice,
  Sheet,
  StepScreen,
  useAnnounce,
} from "@/components/ui";
import { useHostLink, useNow } from "@/flow/context";
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
  documentQueryOptions,
  isNetworkError,
  isReauthLapsed,
  isSessionGone,
  isSignatureUnavailable,
  mustReadAgain,
  postSign,
  type SigningField,
  type SigningSession,
  type SignRequest,
  type SubmissionKeys,
  sessionQueryOptions,
  signingKeys,
} from "@/lib/signing-api";
import { clockTime } from "@/lib/time";
import { type PdfState, usePdf } from "@/lib/use-pdf";

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
}

/**
 * Screen 2 of 3 (addendum 3 A): the signature, the fields, and the one press that signs.
 *
 * What was five screens -- adopt, a screen per field, a summary, a confirmation -- is one. Every
 * act that produces evidence is still its own explicit act: one press per field, and one press
 * that signs the document. What went is the duplication between them: a checkbox restating what
 * the button says, and a summary repeating what the signer had just done field by field.
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
}: SignStepProps) {
  const queryClient = useQueryClient();
  const host = useHostLink();
  const announce = useAnnounce();
  const now = useNow(1_000);
  const live = useQuery(sessionQueryOptions(locale));
  const signer = live.data?.signer ?? session.signer;

  const fields = actionableFields(session.fields);
  const auto = serverFilledFields(session.fields);
  const needsInitials = fields.some((field) => field.type === "initials");
  // Only a signature field can hold the signature they adopt: initials are their own typed text,
  // so a signer asked for initials alone has nothing to save for next time.
  const hasSignatureField = fields.some((field) => field.type === "signature");
  const remaining = remainingRequired(session.fields, draft);
  const done = fields.filter((field) => draft.values[field.id] !== undefined).length;

  // Already in the cache from the Read step: parsed once for the whole screen, never refetched
  // (each fetch of the bytes is recorded server-side as `document.presented`).
  const document_ = useQuery(documentQueryOptions());
  const pdf = usePdf(document_.data);

  const panel = useRef<SignaturePanelHandle>(null);
  const seededInitials = useRef(false);
  const [reauth, setReauth] = useState<Reauth>({ status: "idle" });
  /** Re-authenticated through the hand-off on this screen, as opposed to arriving already covered. */
  const [confirmedHere, setConfirmedHere] = useState(false);
  /** A press of "Sign as ..." waiting on the hand-off: it sends itself when the server vouches. */
  const [pressPending, setPressPending] = useState(false);
  const [nudge, setNudge] = useState<string | null>(null);
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
  // vouches, the signature goes without asking for a second tap.
  useEffect(() => {
    if (pressPending && verified && reauth.status === "idle" && !sign.isPending) {
      setPressPending(false);
      sign.mutate();
    }
  }, [pressPending, verified, reauth.status, sign.isPending, sign.mutate]);

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
   */
  const updateDraft = (next: Draft) => {
    sign.reset();
    setNudge(null);
    onDraft(next);
  };

  /** Place the signature the panel is showing in one field. The panel decides what that is. */
  const applyMark = (field: SigningField) => {
    let next = draft;
    if (draft.adopted === null) {
      const chosen = panel.current?.commit() ?? null;
      if (chosen === null) {
        return;
      }
      next = withAdopted(next, chosen, next.initials, next.save);
    }
    updateDraft(withValue(next, field.id, { type: "mark" }));
    const left = Math.max(0, remaining.length - (field.required ? 1 : 0));
    announce(
      `${field.type === "initials" ? "Initials" : "Signature"} added. ${
        left === 0 ? "Everything that's needed is filled in." : `${left} left to complete.`
      }`,
    );
  };

  const setValue = (field: SigningField, value: FieldValue | null) =>
    updateDraft(withValue(draft, field.id, value));

  // "Sign as ..." is inert until every required field is done, and pressing it then says what is
  // missing rather than doing nothing (the inert-button pattern). Re-authentication is not a
  // reason to be inert: the press is what triggers it.
  const nudgeWhatIsMissing = () => {
    setNudge(
      remaining.length === 1
        ? `One thing is still needed: ${labelOf(remaining[0] as SigningField)}.`
        : `${remaining.length} things are still needed. They're marked above.`,
    );
  };

  const press = () => {
    setNudge(null);
    if (signer.requires_reauth && !verified) {
      startReauth();
      return;
    }
    sign.mutate();
  };

  const signError = sign.error;
  const sessionGone = isSessionGone(signError);
  const waiting = reauth.status === "waiting" || reauth.status === "checking";
  const signerName = `${signer.display_name}${
    signer.on_behalf_of_label ? `, on behalf of ${signer.on_behalf_of_label}` : ""
  }`;

  return (
    <StepScreen
      testId="step-sign"
      title="Sign the document"
      lead={
        <p>
          Place your signature where{" "}
          <span className="font-semibold text-ink-900">{session.envelope.title}</span> asks for it,
          then sign. Nothing is sent until you press the button at the bottom.
        </p>
      }
    >
      <SignaturePanel
        ref={panel}
        session={session}
        draft={draft}
        hasSignatureField={hasSignatureField}
        needsInitials={needsInitials}
        signatureGone={signatureGone}
        onDraft={updateDraft}
      />

      <div className="mt-8">
        <div className="mb-3 flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
          <h2 className="text-ink-900 text-xl">
            {fields.length === 1 ? "Where it goes" : "Where they go"}
          </h2>
          <p role="status" data-testid="fields-progress" className="text-ink-700">
            <span className="font-semibold text-ink-900">
              {done} of {fields.length}
            </span>{" "}
            done
          </p>
        </div>

        <Sheet flush>
          <ul className="m-0 list-none divide-y divide-edge p-0">
            {fields.map((field) => (
              <FieldRow
                key={field.id}
                pdf={pdf}
                session={session}
                field={field}
                draft={draft}
                onApply={() => applyMark(field)}
                onValue={(value) => setValue(field, value)}
              />
            ))}
            {auto.map((field) => (
              <li key={field.id} className="p-4 sm:px-6">
                <p className="font-semibold text-ink-900">{labelOf(field)}</p>
                <p className="text-ink-700 text-sm">
                  Page {field.page} · Added automatically when you sign
                </p>
              </li>
            ))}
          </ul>
        </Sheet>
      </div>

      {/* Re-authentication, inline, because it happens on the press and not on a screen of its
          own. Everything here is about the one thing the signer is waiting for. */}
      {waiting ? (
        <div
          role="status"
          data-testid="reauth-waiting"
          className="mt-6 rounded-lg bg-accent-wash px-4 py-4"
        >
          <p className="flex items-center gap-3 font-semibold text-ink-900">
            <Dots /> Confirming it's you
          </p>
          <p className="mt-2 text-ink-700">
            Your records system is asking you to sign in again. Finish that and the document is
            signed straight away. There's no need to press anything else, or to refresh.
          </p>
          <Button
            variant="quiet"
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
        <Notice tone="warn" alert className="mt-6">
          We didn't hear back in time. Nothing has been signed. Press the button below to try again.
        </Notice>
      ) : null}
      {reauth.status === "not_confirmed" ? (
        <Notice tone="warn" alert className="mt-6">
          We couldn't confirm that. Nothing has been signed. Press the button below to try again.
        </Notice>
      ) : null}
      {reauth.status === "lapsed" ? (
        <Notice tone="warn" alert className="mt-6">
          The confirmation ran out before the document was signed. Nothing has been signed. Press
          the button below and confirm once more.
        </Notice>
      ) : null}

      {signError && !sessionGone && !sign.isPending ? (
        <Notice tone="error" alert className="mt-6">
          {isNetworkError(signError) ? (
            <>
              <p className="font-semibold">We couldn't reach the server.</p>
              <p className="mt-1">
                Your answers are still here. Check the connection, then press the button again. It's
                safe to retry: the document can't be signed twice.
              </p>
            </>
          ) : isReauthLapsed(signError) ? null : signError instanceof ApiError &&
            signError.status === 422 ? (
            <p>
              Something in your answers wasn't accepted. Choose your signature again, place it, and
              try once more.
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

      {nudge ? (
        <p id={signHint} role="alert" className="mt-6 font-medium text-danger-600">
          {nudge}
        </p>
      ) : null}

      {/* The press *is* the intent confirmation (addendum 3 A 3). The sentence above the button
          says so in as many words, which is what the checkbox used to say and one tap less. */}
      <div className="mt-6">
        <p className="text-ink-700">
          By pressing this you are signing this document. It counts the same as signing on paper,
          and you will get a copy.
        </p>
        <Button
          className="mt-3 min-h-14 w-full text-lg"
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

        {signer.requires_reauth ? (
          <p className="mt-3 text-ink-700 text-sm" data-testid="reauth-note">
            {verified ? (
              <span
                data-testid="reauth-verified"
                data-reauth-scope={signer.reauth_scope ?? undefined}
              >
                <CheckIcon className="mr-1.5 text-accent-600" />
                {confirmedHere
                  ? "Your identity is confirmed"
                  : confirmedAt !== null
                    ? `You confirmed your identity at ${confirmedAt}`
                    : "You've already confirmed your identity"}
                {!confirmedHere && signer.reauth_scope === "span" ? " for an earlier document" : ""}
                {"; this signature will be recorded under that confirmation."}
                {coveredUntil !== null ? ` It covers this signature until ${coveredUntil}.` : ""}
                {secondsLeft > 0 && secondsLeft <= 30 ? ` About ${secondsLeft} seconds left.` : ""}
              </span>
            ) : (
              <span data-testid="reauth-needed">
                Because you're signing in a professional role, your records system will ask you to
                confirm it's you when you press this. It takes a moment.
              </span>
            )}
          </p>
        ) : null}
      </div>

      <div aria-live="polite" className="sr-only">
        {sign.isPending ? "Signing the document. Please wait." : ""}
      </div>
    </StepScreen>
  );
}

// --------------------------------------------------------------------------- one field

interface FieldRowProps {
  pdf: PdfState;
  session: SigningSession;
  field: SigningField;
  draft: Draft;
  onApply: () => void;
  onValue: (value: FieldValue | null) => void;
}

/**
 * One field, with the part of the page it lands on beside it and exactly one thing to do. This is
 * the "review your signatures" step as well as the doing of it: every applied mark is shown here,
 * in place, which is why the summary screen is gone rather than merely moved.
 */
function FieldRow({ pdf, session, field, draft, onApply, onValue }: FieldRowProps) {
  const announce = useAnnounce();
  const inputId = useId();
  const textCountId = useId();
  const label = labelOf(field);
  const value = draft.values[field.id];
  const complete = isFieldComplete(field, value);
  const applied = value?.type === "mark";
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
    <li className="p-4 sm:px-6" data-testid="field-row" data-field={field.id} data-done={complete}>
      <div className="flex flex-wrap items-start gap-x-5 gap-y-4">
        <div className="min-w-0 flex-1 basis-56">
          {/* The control carries the field's label where it has one of its own -- a tick box and
              a text box both do -- so the row does not print it twice. */}
          <p className="text-ink-700 text-sm">
            Page {field.page} · {field.required ? "Needed" : "Optional"}
          </p>
          {isMarkField(field) ? <p className="mt-0.5 font-semibold text-ink-900">{label}</p> : null}

          <div className="mt-3">
            {isMarkField(field) ? (
              applied ? (
                <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg bg-accent-wash px-4 py-3">
                  <p className="inline-flex items-center gap-2 font-semibold text-ink-900">
                    <CheckIcon className="text-accent-600" />
                    {field.type === "initials" ? "Initials in place" : "Signature in place"}
                  </p>
                  <Button
                    variant="quiet"
                    onClick={() => {
                      onValue(null);
                      announce(`${label} removed.`);
                    }}
                  >
                    Remove
                  </Button>
                </div>
              ) : (
                <Button className="min-h-14 w-full" onClick={onApply}>
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
                <label htmlFor={inputId} className="mb-2 block font-semibold text-ink-900">
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
                  className="block min-h-12 w-full resize-y rounded-lg bg-paper px-4 py-2.5 text-ink-900 text-lg ring-[1.5px] ring-edge-strong ring-inset"
                />
                {/* Typing that simply stops is the one thing a text box must never do without
                    saying so, so the room left is announced as it runs out. */}
                {textLeft !== null ? (
                  <p
                    id={textCountId}
                    role="status"
                    data-testid="text-chars-left"
                    className={`mt-2 text-sm ${textLeft === 0 ? "font-medium text-danger-600" : "text-ink-700"}`}
                  >
                    {textLeft === 0
                      ? "That's as much as this box will take."
                      : `${textLeft} ${textLeft === 1 ? "character" : "characters"} left.`}
                  </p>
                ) : null}
              </div>
            ) : null}
          </div>
        </div>

        <div className="w-full max-w-[16rem] shrink-0 sm:w-56">
          {pdf.status === "ready" ? (
            <FieldCloseUp
              pdf={pdf.pdf}
              field={field}
              done={complete && value !== undefined}
              maxHeight={150}
            >
              {inField}
            </FieldCloseUp>
          ) : (
            // The bytes are already in the cache; this is pdf.js parsing them. A flat grey block
            // reads as a broken image, so it breathes for the second it is there.
            <div
              className="quiet-pulse h-[150px] rounded-lg bg-sunk"
              aria-hidden="true"
              data-testid="field-closeup-loading"
            />
          )}
        </div>
      </div>
    </li>
  );
}
