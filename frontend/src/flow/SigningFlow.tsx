import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  type RefObject,
  useCallback,
  useEffect,
  useMemo,
  useReducer,
  useRef,
  useState,
} from "react";
import { Button, Notice, useAnnounce } from "@/components/ui";
import { type HostLink, HostLinkContext, useNow } from "@/flow/context";
import { type Draft, emptyDraft } from "@/flow/draft";
import { flowReducer, initialFlowState, STEPS, type Step } from "@/flow/machine";
import { ConfirmStep } from "@/flow/steps/ConfirmStep";
import { ConsentStep } from "@/flow/steps/ConsentStep";
import { DeclineStep } from "@/flow/steps/DeclineStep";
import { DoneStep } from "@/flow/steps/DoneStep";
import {
  ConnectFailedScreen,
  ConnectingScreen,
  DeclinedScreen,
  ExpiredScreen,
  HandBackScreen,
  LoadFailedScreen,
  UnavailableScreen,
} from "@/flow/steps/EndScreens";
import { ReviewStep } from "@/flow/steps/ReviewStep";
import { SignStep } from "@/flow/steps/SignStep";
import { hasSessionToken, setSessionToken } from "@/lib/api";
import type { ParentChannel } from "@/lib/embed";
import {
  isNetworkError,
  type SigningSession,
  SubmissionKeys,
  sessionQueryOptions,
} from "@/lib/signing-api";

export const CONNECT_TIMEOUT_MS = 15_000;
const WARN_BEFORE_MS = 120_000;

const STEP_LABELS: Record<Step, string> = {
  review: "Read",
  consent: "Agree",
  sign: "Fill in",
  confirm: "Sign",
  done: "Done",
};

interface SigningFlowProps {
  channel: ParentChannel;
  /** The query client calls this on any 401. Wired here because only the flow knows what to do. */
  sessionGone: RefObject<() => void>;
}

export function SigningFlow({ channel, sessionGone }: SigningFlowProps) {
  const queryClient = useQueryClient();
  const announce = useAnnounce();
  const [state, dispatch] = useReducer(flowReducer, initialFlowState);
  /** The disclosure language the host asked for, validated by `embed.ts`. Chosen once, with the
   * token, and never changed afterwards: it decides which text the signer is shown and accepts. */
  const [locale, setLocale] = useState<string | null>(null);
  const [draft, setDraft] = useState<Draft>(emptyDraft);
  /**
   * Set when the server refused a signature because the document had moved on since this signer
   * read it (409 `not_viewed`). Their signer status is still `consented`, so nothing in
   * `placeFor` would ever send them back to the review step; this does, and says why.
   */
  const [readAgain, setReadAgain] = useState(false);
  const [submissionKeys] = useState(() => new SubmissionKeys());
  const reauthListeners = useRef(new Set<() => void>());
  const shell = useRef<HTMLDivElement>(null);
  const stateRef = useRef(state);
  stateRef.current = state;

  const hostLink = useMemo<HostLink>(
    () => ({
      post: (message) => channel.post(message),
      onReauthDone: (listener) => {
        reauthListeners.current.add(listener);
        return () => reauthListeners.current.delete(listener);
      },
    }),
    [channel],
  );

  /** Forget everything about this signer. Used on every ending, and always on a shared tablet. */
  const wipe = useCallback(() => {
    setSessionToken(null);
    queryClient.clear();
    setDraft(emptyDraft);
    setReadAgain(false);
    submissionKeys.reset();
  }, [queryClient, submissionKeys]);

  // ------------------------------------------------------------------ messages from the host
  useEffect(() => {
    const onMessage = (event: MessageEvent) => {
      const message = channel.accept(event);
      if (message === null) {
        return;
      }
      if (message.type === "esign:init") {
        // One token per page load. A second init is ignored rather than swapping identities.
        if (hasSessionToken() || stateRef.current.phase !== "connecting") {
          return;
        }
        setSessionToken(message.token);
        setLocale(message.locale ?? null);
        dispatch({ type: "TOKEN_RECEIVED" });
      } else {
        for (const listener of reauthListeners.current) {
          listener();
        }
      }
    };
    window.addEventListener("message", onMessage);
    return () => window.removeEventListener("message", onMessage);
  }, [channel]);

  // ------------------------------------------------------------------ connecting
  useEffect(() => {
    if (state.phase !== "connecting") {
      return;
    }
    // The host's listener may not be attached yet when we load, so say "ready" until answered.
    channel.post({ type: "esign:ready" });
    const again = window.setInterval(() => channel.post({ type: "esign:ready" }), 1_000);
    const giveUp = window.setTimeout(
      () => dispatch({ type: "CONNECT_TIMED_OUT" }),
      CONNECT_TIMEOUT_MS,
    );
    return () => {
      window.clearInterval(again);
      window.clearTimeout(giveUp);
    };
  }, [state.phase, channel]);

  // ------------------------------------------------------------------ session
  const sessionEnabled = state.phase === "loading" || state.phase === "active";
  const sessionQuery = useQuery({ ...sessionQueryOptions(locale), enabled: sessionEnabled });
  const session = sessionQuery.data;

  useEffect(() => {
    if (session !== undefined) {
      dispatch({ type: "SESSION_LOADED", session });
    }
  }, [session]);

  // The page declares the language of the text it is actually showing -- the disclosure the server
  // served -- so assistive technology can never be told "Spanish" over an English fallback.
  const servedLocale = session?.consent.locale;
  useEffect(() => {
    if (servedLocale !== undefined && servedLocale !== "") {
      document.documentElement.lang = servedLocale;
    }
  }, [servedLocale]);

  useEffect(() => {
    sessionGone.current = () => {
      const current = stateRef.current;
      // After signing, a lapsed session only means the copy can't be fetched here; the Done
      // screen says so itself. Telling someone who just signed that they "expired" would be wrong.
      if (current.phase === "active" && current.step === "done") {
        return;
      }
      dispatch({ type: "SESSION_EXPIRED" });
    };
  }, [sessionGone]);

  // ------------------------------------------------------------------ endings
  const phase = state.phase;
  useEffect(() => {
    if (phase === "expired") {
      channel.post({ type: "esign:expired" });
      wipe();
    } else if (phase === "declined") {
      channel.post({ type: "esign:declined" });
      wipe();
    } else if (phase === "unavailable" || phase === "handed_back") {
      wipe();
    }
  }, [phase, channel, wipe]);

  // ------------------------------------------------------------------ iframe height
  useEffect(() => {
    const node = shell.current;
    if (node === null || typeof ResizeObserver === "undefined") {
      return;
    }
    let last = 0;
    const observer = new ResizeObserver(() => {
      const height = Math.ceil(node.getBoundingClientRect().height);
      if (height !== last) {
        last = height;
        channel.post({ type: "esign:resize", height });
      }
    });
    observer.observe(node);
    return () => observer.disconnect();
  }, [channel]);

  const go = (step: Step) => dispatch({ type: "GO", step });

  let body: React.ReactNode;
  if (state.phase === "connecting") {
    body = <ConnectingScreen />;
  } else if (state.phase === "connect_failed") {
    body = <ConnectFailedScreen onRetry={() => dispatch({ type: "RETRY_CONNECT" })} />;
  } else if (state.phase === "declined") {
    body = <DeclinedScreen />;
  } else if (state.phase === "expired") {
    body = <ExpiredScreen />;
  } else if (state.phase === "unavailable") {
    body = <UnavailableScreen reason={state.reason} />;
  } else if (state.phase === "handed_back") {
    body = <HandBackScreen outcome={state.outcome} />;
  } else if (session === undefined || state.phase === "loading") {
    body = sessionQuery.isError ? (
      <LoadFailedScreen
        network={isNetworkError(sessionQuery.error)}
        onRetry={() => void sessionQuery.refetch()}
      />
    ) : (
      <ConnectingScreen />
    );
  } else if (state.declining) {
    body = (
      <DeclineStep
        session={session}
        onBack={() => dispatch({ type: "DECLINE_CLOSED" })}
        onDeclined={() => dispatch({ type: "DECLINED", kiosk: session.session.kiosk })}
      />
    );
  } else {
    const kiosk = session.session.kiosk;
    const steps: Record<Step, React.ReactNode> = {
      review: (
        <ReviewStep
          session={session}
          changed={readAgain}
          onContinue={() => {
            setReadAgain(false);
            go("consent");
          }}
        />
      ),
      consent: (
        <ConsentStep
          session={session}
          onContinue={() => go("sign")}
          onPreferPaper={() => dispatch({ type: "DECLINE_OPENED" })}
        />
      ),
      sign: (
        <SignStep
          session={session}
          draft={draft}
          onDraft={setDraft}
          onContinue={() => go("confirm")}
        />
      ),
      confirm: (
        <ConfirmStep
          session={session}
          locale={locale}
          draft={draft}
          submissionKeys={submissionKeys}
          onBack={() => go("sign")}
          onReadAgain={() => {
            setReadAgain(true);
            announce("The document has changed. Please read it again before you sign.");
            go("review");
          }}
          onSigned={() => {
            channel.post({ type: "esign:signed" });
            setDraft(emptyDraft);
            announce("The document has been signed.");
            dispatch({ type: "SIGNED", kiosk });
          }}
        />
      ),
      done: <DoneStep session={session} locale={locale} />,
    };
    body = steps[state.step];
  }

  const activeStep = state.phase === "active" && !state.declining ? state.step : null;
  const showPaperPath =
    session !== undefined &&
    activeStep !== null &&
    activeStep !== "done" &&
    activeStep !== "consent";

  return (
    <HostLinkContext.Provider value={hostLink}>
      <div ref={shell} className="flex flex-col">
        <Masthead session={state.phase === "active" ? session : undefined} step={activeStep} />
        <main className="w-full px-4 pt-6 pb-10 sm:px-6 sm:pt-8">
          {state.phase === "active" && session !== undefined && activeStep !== "done" ? (
            <DeadlineWatch session={session} />
          ) : null}
          {/* Keyed so each step mounts fresh and its heading takes focus. */}
          <div key={`${state.phase}:${activeStep ?? (state.phase === "active" ? "decline" : "")}`}>
            {body}
          </div>
          {showPaperPath ? (
            <p className="mx-auto mt-10 max-w-xl border-edge border-t pt-5 text-center text-ink-700">
              Changed your mind?{" "}
              <Button
                variant="quiet"
                className="px-1"
                onClick={() => dispatch({ type: "DECLINE_OPENED" })}
              >
                Stop and sign on paper instead
              </Button>
            </p>
          ) : null}
        </main>
      </div>
    </HostLinkContext.Provider>
  );
}

// --------------------------------------------------------------------------- masthead

function Masthead({ session, step }: { session: SigningSession | undefined; step: Step | null }) {
  const index = step === null ? -1 : STEPS.indexOf(step);
  return (
    <header className="border-edge border-b bg-sheet px-4 py-3 sm:px-6">
      <div className="mx-auto flex max-w-3xl flex-wrap items-end justify-between gap-x-6 gap-y-2">
        <div className="min-w-0">
          <p className="flex items-center gap-2 font-semibold text-accent-600 text-sm tracking-wide">
            <Seal /> Secure document signing
          </p>
          {session ? (
            <>
              <p className="mt-0.5 truncate font-serif text-ink-900 text-lg leading-tight">
                {session.envelope.title}
              </p>
              <p className="text-ink-700 text-sm" data-testid="signing-as">
                Signing as {session.signer.display_name} · {session.signer.role_label}
                {session.signer.on_behalf_of_label
                  ? `, on behalf of ${session.signer.on_behalf_of_label}`
                  : ""}
              </p>
            </>
          ) : null}
        </div>
        {step !== null ? (
          <nav aria-label="Progress" className="w-full sm:w-56">
            <p className="text-ink-700 text-sm" data-testid="step-progress">
              Step {index + 1} of {STEPS.length}:{" "}
              <span className="font-semibold text-ink-900">{STEP_LABELS[step]}</span>
            </p>
            <ol aria-hidden="true" className="m-0 mt-1.5 flex list-none gap-1 p-0">
              {STEPS.map((name, i) => (
                <li
                  key={name}
                  className={`h-1.5 flex-1 rounded-full ${i <= index ? "bg-accent-600" : "bg-edge"}`}
                />
              ))}
            </ol>
          </nav>
        ) : null}
      </div>
    </header>
  );
}

function Seal() {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 20 20"
      className="size-4 fill-none stroke-current"
      strokeWidth="1.8"
    >
      <path
        d="M10 2.2 3.5 4.6v4.9c0 4 2.7 6.9 6.5 8.3 3.8-1.4 6.5-4.3 6.5-8.3V4.6L10 2.2Z"
        strokeLinejoin="round"
      />
      <path d="m7.2 10 2 2 3.6-4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

// --------------------------------------------------------------------------- session deadline

/**
 * The warning that the session is about to close, and with it the adopted signature and the field
 * values in the draft. Two things it deliberately does not do:
 *
 *  - it never ends the flow. The deadline is server time; this is the device's clock, and a tablet
 *    whose clock runs half an hour fast would land a signer on "this session has ended" before
 *    they had read a word. Only the server's 401 (wired through `sessionGone`) may do that.
 *  - it does not scroll away. Review and consent are long scrollers, and the patient who needs
 *    this warning is the one who has been reading for two minutes, far below the top of the page.
 */
function DeadlineWatch({ session }: { session: SigningSession }) {
  const now = useNow(5_000);
  const deadline = Math.min(
    Date.parse(session.session.expires_at),
    Date.parse(session.envelope.expires_at),
  );
  const left = deadline - now;

  if (left > WARN_BEFORE_MS) {
    return null;
  }
  const minutes = Math.max(1, Math.ceil(left / 60_000));
  return (
    <div
      data-testid="deadline-banner"
      className="sticky top-[env(safe-area-inset-top,0px)] z-30 mx-auto mb-5 max-w-xl"
    >
      <Notice tone="warn" alert className="shadow-sheet">
        {left > 0 ? (
          <span>
            For your security, this session closes in about {minutes}{" "}
            {minutes === 1 ? "minute" : "minutes"}. If it does, it can be reopened and you can start
            again.
          </span>
        ) : (
          <span>
            For your security, this session is due to close. If it has, you'll be told when you next
            continue, and you can reopen the document and start again.
          </span>
        )}
      </Notice>
    </div>
  );
}
