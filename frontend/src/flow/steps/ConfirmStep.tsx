import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useId, useMemo, useState } from "react";
import { Button, CheckRow, Dots, Notice, Sheet, StepScreen, useAnnounce } from "@/components/ui";
import { useHostLink, useNow } from "@/flow/context";
import { buildCaptures, type Draft } from "@/flow/draft";
import { ApiError } from "@/lib/api";
import {
  isNetworkError,
  isSessionGone,
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

interface ConfirmStepProps {
  session: SigningSession;
  draft: Draft;
  submissionKeys: SubmissionKeys;
  onBack: () => void;
  onSigned: () => void;
}

export function ConfirmStep({
  session,
  draft,
  submissionKeys,
  onBack,
  onSigned,
}: ConfirmStepProps) {
  const queryClient = useQueryClient();
  const host = useHostLink();
  const announce = useAnnounce();
  const now = useNow(1_000);
  const live = useQuery(sessionQueryOptions());
  const signer = live.data?.signer ?? session.signer;
  const [reauth, setReauth] = useState<Reauth>({ status: "idle" });
  const [intent, setIntent] = useState(false);
  const [nudge, setNudge] = useState(false);
  const intentHint = useId();

  const validUntil = signer.reauth_valid_until ? Date.parse(signer.reauth_valid_until) : 0;
  const secondsLeft = Math.floor((validUntil - now) / 1000);
  const verified = !signer.requires_reauth || secondsLeft > 3;

  const request = useMemo<SignRequest>(
    () => ({ intent_confirmed: true, captures: buildCaptures(session.fields, draft) }),
    [session.fields, draft],
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
      if (error instanceof ApiError && error.status === 403 && signer.requires_reauth) {
        setReauth({ status: "lapsed" });
      }
      if (error instanceof ApiError && error.status === 409) {
        // Already signed from another attempt, or the envelope moved on. The session knows.
        void queryClient.invalidateQueries({ queryKey: signingKeys.session });
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
    queryClient.fetchQuery({ ...sessionQueryOptions(), staleTime: 0 }).then(
      (fresh) => {
        if (cancelled) {
          return;
        }
        const until = fresh.signer.reauth_valid_until;
        if (until !== null && Date.parse(until) > Date.now()) {
          setReauth({ status: "idle" });
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
  }, [reauth.status, queryClient, announce]);

  useEffect(() => {
    if (reauth.status === "waiting" && now - reauth.since > REAUTH_TIMEOUT_MS) {
      setReauth({ status: "timed_out" });
    }
  }, [reauth, now]);

  const startReauth = () => {
    sign.reset();
    setReauth({ status: "waiting", since: Date.now() });
    host.post({ type: "esign:reauth_required", session_id: session.session.id });
  };

  const submit = () => {
    if (!intent) {
      setNudge(true);
      return;
    }
    sign.mutate();
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
          {verified ? (
            <p className="mt-2 text-ink-700" data-testid="reauth-verified">
              <span aria-hidden="true">✓ </span>Confirmed, thank you. For security this lasts about
              two minutes, so please sign now.
              {secondsLeft <= 30 ? ` About ${Math.max(0, secondsLeft)} seconds left.` : ""}
            </p>
          ) : reauth.status === "waiting" || reauth.status === "checking" ? (
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
              {reauth.status === "lapsed" || (reauth.status === "idle" && validUntil > 0) ? (
                <Notice tone="warn" alert className="mt-3">
                  The confirmation ran out before the document was signed. Please confirm once more.
                </Notice>
              ) : null}
              <p className="mt-2 text-ink-700">
                Because you're signing in a professional role, your records system will ask you to
                sign in again. It takes a moment.
              </p>
              <Button className="mt-4 w-full sm:w-auto" onClick={startReauth}>
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
          ) : signError instanceof ApiError && signError.status === 403 ? (
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

      <div className="mt-6 flex flex-wrap justify-between gap-3">
        <Button variant="secondary" onClick={onBack} inert={sign.isPending}>
          Back
        </Button>
        <Button
          className="min-h-14 flex-1 text-lg sm:flex-none sm:px-10"
          inert={!verified || !intent}
          busy={sign.isPending}
          onClick={() => {
            if (!verified) {
              announce("Please confirm it's you first.");
              return;
            }
            submit();
          }}
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
