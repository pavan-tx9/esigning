import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useId, useMemo, useRef, useState } from "react";
import { Button, CheckRow, Dots, Notice, Sheet, StepScreen, useAnnounce } from "@/components/ui";
import { useHostLink, useNow } from "@/flow/context";
import { buildSignRequest, type Draft } from "@/flow/draft";
import { ApiError } from "@/lib/api";
import {
  isNetworkError,
  isReauthLapsed,
  isSessionGone,
  isSignatureUnavailable,
  mustReadAgain,
  postSign,
  type SigningSession,
  type SignRequest,
  type SubmissionKeys,
  sessionQueryOptions,
  signingKeys,
} from "@/lib/signing-api";

export const REAUTH_TIMEOUT_MS = 120_000;

type Reauth =
  | { status: "idle" }
  | { status: "waiting"; since: number }
  | { status: "checking" }
  | { status: "timed_out" }
  | { status: "not_confirmed" }
  | { status: "lapsed" };

/** A server timestamp as a wall-clock time in the language the page is in ("2:41 PM", "14:41"). */
function clockTime(iso: string, locale: string | null | undefined): string {
  const options: Intl.DateTimeFormatOptions = { hour: "numeric", minute: "2-digit" };
  try {
    return new Intl.DateTimeFormat(locale ?? undefined, options).format(new Date(iso));
  } catch {
    return new Intl.DateTimeFormat(undefined, options).format(new Date(iso));
  }
}

interface ConfirmStepProps {
  session: SigningSession;
  locale?: string | null;
  draft: Draft;
  submissionKeys: SubmissionKeys;
  onBack: () => void;
  onSigned: () => void;
  /** The document moved on under this signer: they have to read it again before they can sign. */
  onReadAgain: () => void;
  /**
   * The saved signature they applied is no longer theirs to use -- the host revoked it, or
   * another session of theirs replaced it (SPEC section 14 B). Nothing on this screen can mend
   * that, so the flow hands them back to choosing a signature and says why.
   */
  onSignatureUnavailable: () => void;
}

export function ConfirmStep({
  session,
  locale,
  draft,
  submissionKeys,
  onBack,
  onSigned,
  onReadAgain,
  onSignatureUnavailable,
}: ConfirmStepProps) {
  const queryClient = useQueryClient();
  const host = useHostLink();
  const announce = useAnnounce();
  const now = useNow(1_000);
  const live = useQuery(sessionQueryOptions(locale));
  const signer = live.data?.signer ?? session.signer;
  const [reauth, setReauth] = useState<Reauth>({ status: "idle" });
  /** Re-authenticated through the hand-off on this screen, as opposed to arriving already covered. */
  const [confirmedHere, setConfirmedHere] = useState(false);
  const [intent, setIntent] = useState(false);
  const [nudge, setNudge] = useState(false);
  const [reauthNudge, setReauthNudge] = useState(false);
  const intentHint = useId();
  const reauthHint = useId();
  const reauthButton = useRef<HTMLButtonElement>(null);

  /**
   * Whether the server holds a live re-authentication for this signer. The answer is the server's,
   * not this device's: `reauth_valid_until` is server time plus the maximum age, so a tablet whose
   * clock runs two minutes fast would read every successful confirmation as already lapsed and
   * refuse to let anyone sign. The countdown below is advisory; the server's 403 is what decides,
   * and it is handled as `reauth: lapsed`.
   *
   * SPEC section 14 C: the value covers an attestation borrowed from an earlier session of this
   * person's (a signing queue) as well as one made for this session, and `reauth_scope` says
   * which. Either way the hand-off is skipped and the screen says what the record will say.
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
        // The saved signature was revoked or replaced between this session being read and the
        // signature being sent. Confirming their identity again would not help, and the session
        // in the cache still offers a signature the server will not accept.
        void queryClient.invalidateQueries({ queryKey: signingKeys.session });
        onSignatureUnavailable();
      }
      if (error instanceof ApiError && error.status === 409) {
        // Already signed from another attempt, or the envelope moved on. The session knows.
        void queryClient.invalidateQueries({ queryKey: signingKeys.session });
      }
      if (mustReadAgain(error)) {
        // The bytes held in the cache are last revision's; the review step must show what is
        // actually being signed now, so they are dropped rather than invalidated.
        queryClient.removeQueries({ queryKey: signingKeys.document });
        onReadAgain();
      }
    },
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
          announce("Thank you. We've confirmed it's you.");
        } else {
          setReauth({ status: "not_confirmed" });
        }
      },
      () => {
        if (!cancelled) {
          setReauth({ status: "not_confirmed" });
        }
      },
    );
    return () => {
      cancelled = true;
    };
  }, [reauth.status, queryClient, announce, locale]);

  // Once the server vouches for them, the block on signing is gone and so is the message about it.
  useEffect(() => {
    if (verified) {
      setReauthNudge(false);
    }
  }, [verified]);

  useEffect(() => {
    if (reauth.status === "waiting" && now - reauth.since > REAUTH_TIMEOUT_MS) {
      setReauth({ status: "timed_out" });
    }
  }, [reauth, now]);

  const startReauth = () => {
    sign.reset();
    setReauthNudge(false);
    setReauth({ status: "waiting", since: Date.now() });
    host.post({ type: "esign:reauth_required", session_id: session.session.id });
  };

  // "Sign document" is inert until the person has both confirmed who they are (where the role
  // needs it) and ticked the intent box. Pressing it then says which of the two is still missing
  // -- re-authentication first, because the intent box is right above the button and the
  // confirmation is further up the page.
  const nudgeWhatIsMissing = () => {
    if (!verified) {
      setReauthNudge(true);
      reauthButton.current?.focus();
      return;
    }
    setNudge(true);
  };

  const signError = sign.error;
  const sessionGone = isSessionGone(signError);

  return (
    <StepScreen
      testId="step-confirm"
      title="Sign the document"
      lead={
        <p>
          This is the last step. When you press the button below, your signature is added to{" "}
          <span className="font-semibold text-ink-900">{session.envelope.title}</span> and it counts
          the same as signing on paper.
        </p>
      }
    >
      {signer.requires_reauth ? (
        <Sheet className="mb-6">
          <h2 className="text-ink-900 text-xl">First, confirm it's you</h2>
          {reauth.status === "waiting" || reauth.status === "checking" ? (
            <div role="status" className="mt-2 text-ink-700" data-testid="reauth-waiting">
              <p className="flex items-center gap-3 font-semibold text-ink-900">
                <Dots /> Waiting for you to confirm your identity
              </p>
              <p className="mt-2">
                Your records system is asking you to sign in again. Finish that, and this page will
                carry on by itself. There's no need to refresh.
              </p>
              <Button
                variant="quiet"
                className="mt-1 px-0"
                onClick={() => setReauth({ status: "idle" })}
              >
                Cancel
              </Button>
            </div>
          ) : verified && confirmedHere ? (
            <p className="mt-2 text-ink-700" data-testid="reauth-verified">
              <span aria-hidden="true">✓ </span>Confirmed, thank you. For security this lasts about
              two minutes, so please sign now.
              {secondsLeft > 0 && secondsLeft <= 30 ? ` About ${secondsLeft} seconds left.` : ""}
            </p>
          ) : verified ? (
            <>
              {/* Already covered when this screen opened: nothing to hand off. The record will say
                  which confirmation the signature rests on and when it was made, so say so here,
                  and leave the way open to make a fresh one for this document. */}
              <p
                className="mt-2 text-ink-700"
                data-testid="reauth-verified"
                data-reauth-scope={signer.reauth_scope ?? undefined}
              >
                <span aria-hidden="true">✓ </span>
                {confirmedAt !== null
                  ? `You confirmed your identity at ${confirmedAt}`
                  : "You've already confirmed your identity"}
                {signer.reauth_scope === "span" ? " for an earlier document" : ""}
                {"; this signature will be recorded under that confirmation."}
                {coveredUntil !== null ? ` It covers this signature until ${coveredUntil}.` : ""}
                {secondsLeft > 0 && secondsLeft <= 30 ? ` About ${secondsLeft} seconds left.` : ""}
              </p>
              <Button
                ref={reauthButton}
                variant="secondary"
                className="mt-4 w-full sm:w-auto"
                onClick={startReauth}
              >
                Confirm again
              </Button>
            </>
          ) : (
            <>
              {reauth.status === "timed_out" ? (
                <Notice tone="warn" alert className="mt-3">
                  We didn't hear back in time. Nothing has been signed. You can try again.
                </Notice>
              ) : null}
              {reauth.status === "not_confirmed" ? (
                <Notice tone="warn" alert className="mt-3">
                  We couldn't confirm that. Nothing has been signed. Please try again.
                </Notice>
              ) : null}
              {reauth.status === "lapsed" ? (
                <Notice tone="warn" alert className="mt-3">
                  The confirmation ran out before the document was signed. Please confirm once more.
                </Notice>
              ) : null}
              <p className="mt-2 text-ink-700">
                Because you're signing in a professional role, your records system will ask you to
                sign in again. It takes a moment.
              </p>
              <Button ref={reauthButton} className="mt-4 w-full sm:w-auto" onClick={startReauth}>
                {reauth.status === "idle" && validUntil === 0 ? "Confirm it's me" : "Try again"}
              </Button>
            </>
          )}
        </Sheet>
      ) : null}

      <CheckRow
        checked={intent}
        onChange={(next) => {
          setIntent(next);
          setNudge(false);
        }}
        describedBy={nudge ? intentHint : undefined}
        invalid={nudge}
      >
        I've read the document, and I want to sign it as {signer.display_name}
        {signer.on_behalf_of_label ? `, on behalf of ${signer.on_behalf_of_label}` : ""}.
      </CheckRow>
      {nudge ? (
        <p id={intentHint} role="alert" className="mt-2 font-medium text-danger-600">
          Tick the box to show you want to sign.
        </p>
      ) : null}

      {signError && !sessionGone && !sign.isPending ? (
        <Notice tone="error" alert className="mt-5">
          {isNetworkError(signError) ? (
            <>
              <p className="font-semibold">We couldn't reach the server.</p>
              <p className="mt-1">
                Your answers are still here. Check the connection, then press the button again. It's
                safe to retry: the document can't be signed twice.
              </p>
            </>
          ) : isReauthLapsed(signError) ? (
            <p>We need you to confirm it's you once more before signing.</p>
          ) : signError instanceof ApiError && signError.status === 422 ? (
            <p>
              Something in your answers wasn't accepted. Go back, choose your signature again, and
              then return here.
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

      {/* Every other blocked action in the flow says so on screen; this one used to speak only to
          the live region, so a clinician tapping the greyed button saw nothing happen at all. */}
      {reauthNudge && !verified ? (
        <p id={reauthHint} role="alert" className="mt-5 font-medium text-danger-600">
          Confirm it's you first, using the button above, then you can sign.
        </p>
      ) : null}

      <div className="mt-6 flex flex-wrap justify-between gap-3">
        <Button variant="secondary" onClick={onBack} inert={sign.isPending}>
          Back
        </Button>
        <Button
          className="min-h-14 flex-1 text-lg sm:flex-none sm:px-10"
          inert={!verified || !intent}
          busy={sign.isPending}
          aria-describedby={reauthNudge && !verified ? reauthHint : undefined}
          onInertClick={nudgeWhatIsMissing}
          onClick={() => sign.mutate()}
        >
          {sign.isPending ? "Signing" : sign.isError ? "Try again" : "Sign document"}
        </Button>
      </div>
      <div aria-live="polite" className="sr-only">
        {sign.isPending ? "Signing the document. Please wait." : ""}
      </div>
    </StepScreen>
  );
}
