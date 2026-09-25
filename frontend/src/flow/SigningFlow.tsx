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
import { Notice, useAnnounce } from "@/components/ui";
import { type HostLink, HostLinkContext, useNow } from "@/flow/context";
import { DocumentWorkspace } from "@/flow/DocumentWorkspace";
import { type Draft, emptyDraft, withoutAdopted } from "@/flow/draft";
import { flowReducer, initialFlowState, STEPS, type Step } from "@/flow/machine";
import { DeclineStep } from "@/flow/steps/DeclineStep";
import { DoneStep } from "@/flow/steps/DoneStep";
import {
  ConnectFailedScreen,
  ConnectingScreen,
  DeclinedScreen,
  ExpiredScreen,
  HandBackScreen,
  LoadFailedScreen,
  LoadingWorkspace,
  UnavailableScreen,
} from "@/flow/steps/EndScreens";
import { ReadStep } from "@/flow/steps/ReadStep";
import { SignStep } from "@/flow/steps/SignStep";
import { hasSessionToken, setSessionToken } from "@/lib/api";
import type { ParentChannel, QueuePosition } from "@/lib/embed";
import {
  isNetworkError,
  onBehalfOfPhrase,
  type SigningSession,
  SubmissionKeys,
  sessionQueryOptions,
} from "@/lib/signing-api";

export const CONNECT_TIMEOUT_MS = 15_000;
const WARN_BEFORE_MS = 120_000;
/**
 * The most content the UI asks a host for, in CSS pixels, before it would rather scroll inside
 * the frame: about one full page of a document at reading width plus the bars. `esign:resize`
 * reports the smaller of this and what is actually there (INTEGRATION.md section 3).
 */
export const NATURAL_CONTENT_MAX = 1_200;

const STEP_LABELS: Record<Step, string> = {
  read: "Read",
  sign: "Sign",
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
  /**
   * Where this document sits in a run the host is driving (addendum 3 B). Like the locale, it
   * arrives with the token and never changes: a new position means a new document, which means a
   * new `esign:init` into a freshly loaded iframe.
   */
  const [queue, setQueue] = useState<QueuePosition | null>(null);
  const [draft, setDraft] = useState<Draft>(emptyDraft);
  /**
   * How far through the document the signer has got, and whether `POST /signing/viewed` has gone.
   * Held here, not on the Read screen, because that screen is unmounted and remounted by things
   * that change neither -- the paper-path sheet, chiefly -- and losing it would charge somebody
   * another scroll through thirty pages for looking at the way out.
   */
  const [pagesSeen, setPagesSeen] = useState<ReadonlySet<number>>(() => new Set());
  const [viewedPosted, setViewedPosted] = useState(false);
  const markViewed = useCallback(() => setViewedPosted(true), []);
  /** A fresh read: the document changed, so what was displayed before is not this document. */
  const readFromScratch = useCallback(() => {
    setPagesSeen(new Set());
    setViewedPosted(false);
  }, []);
  /**
   * Set when the server refused a signature because the document had moved on since this signer
   * read it (409 `not_viewed`). Their signer status is still `consented`, so nothing in
   * `placeFor` would ever send them back to the read step; this does, and says why.
   */
  const [readAgain, setReadAgain] = useState(false);
  /**
   * Set when the server refused a signature because the saved signature applied to it is no
   * longer available (403 `adopted_signature_unavailable`): revoked by the host, or replaced from
   * another session of this person's. Nothing about the signer has changed, so only this tells the
   * signature panel to say why it is asking for a signature again.
   */
  const [signatureGone, setSignatureGone] = useState(false);
  const [submissionKeys] = useState(() => new SubmissionKeys());
  const reauthListeners = useRef(new Set<() => void>());
  const shell = useRef<HTMLDivElement>(null);
  const [toolbarNode, setToolbarNode] = useState<HTMLElement | null>(null);
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
    setSignatureGone(false);
    readFromScratch();
    submissionKeys.reset();
  }, [queryClient, submissionKeys, readFromScratch]);

  // ------------------------------------------------------------------ messages from the host
  useEffect(() => {
    const onMessage = (event: MessageEvent) => {
      const message = channel.accept(event);
      if (message === null) {
        return;
      }
      if (message.type === "esign:init") {
        const current = stateRef.current;
        /**
         * The next document of a run (addendum 3 B, INTEGRATION.md section 9): the host answers
         * `esign:next` by opening the next envelope into this same iframe. Accepted only once this
         * one is finished with -- never mid-signature, where it would be an identity swap -- and
         * everything about the finished document goes first, so nothing of one signer's session
         * can be read by the next.
         */
        const finished = current.phase === "active" && current.step === "done";
        if (!finished && (hasSessionToken() || current.phase !== "connecting")) {
          return;
        }
        if (finished) {
          wipe();
        }
        setSessionToken(message.token);
        setLocale(message.locale ?? null);
        setQueue(message.queue ?? null);
        dispatch({ type: "TOKEN_RECEIVED" });
      } else {
        for (const listener of reauthListeners.current) {
          listener();
        }
      }
    };
    window.addEventListener("message", onMessage);
    return () => window.removeEventListener("message", onMessage);
  }, [channel, wipe]);

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

  /**
   * Coming back from the paper-path detour. The step was never unmounted, so its own heading-takes
   * -focus effect will not run again: without this, closing the sheet would drop focus to the
   * document and a keyboard user would restart at the top of the page.
   */
  const wasDeclining = useRef(false);
  useEffect(() => {
    const open = state.phase === "active" && state.declining;
    if (wasDeclining.current && !open) {
      shell.current?.querySelector<HTMLElement>("[data-step-heading]")?.focus?.();
    }
    wasDeclining.current = open;
  });

  // ------------------------------------------------------------------ iframe height
  const activeStep = state.phase === "active" ? state.step : null;
  useNaturalHeight(shell, (height) => channel.post({ type: "esign:resize", height }));

  const go = (step: Step) => dispatch({ type: "GO", step });
  const openPaperPath = () => dispatch({ type: "DECLINE_OPENED" });

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
      // The same shell, with the document's place already drawn: between two documents of a run
      // the frame never goes blank.
      <LoadingWorkspace />
    );
  } else {
    const kiosk = session.session.kiosk;
    const declining = state.declining;
    if (state.step === "done") {
      body = <DoneStep session={session} locale={locale} queue={queue} />;
    } else {
      const step =
        state.step === "read" ? (
          <ReadStep
            session={session}
            changed={readAgain}
            seen={pagesSeen}
            viewedPosted={viewedPosted}
            onViewedPosted={markViewed}
            onContinue={() => {
              setReadAgain(false);
              go("sign");
            }}
            onPaper={openPaperPath}
          />
        ) : (
          <SignStep
            session={session}
            locale={locale}
            draft={draft}
            submissionKeys={submissionKeys}
            signatureGone={signatureGone}
            onDraft={(next) => {
              setDraft(next);
              // The "your saved signature is gone" notice is answered by choosing another one,
              // not by ticking a box further down the screen.
              if (next.adopted !== null) {
                setSignatureGone(false);
              }
            }}
            onReadAgain={() => {
              setReadAgain(true);
              // These are the old document's pages. Nothing about them is a claim about this one.
              readFromScratch();
              announce("The document has changed. Please read it again before you sign.");
              go("read");
            }}
            onSignatureUnavailable={() => {
              // The signature they chose is gone, so the marks made with it go too; everything
              // else they filled in stays. Nothing has been signed.
              setDraft((current) => withoutAdopted(current));
              setSignatureGone(true);
              announce("Your saved signature is no longer available. Please choose a signature.");
            }}
            onSigned={() => {
              channel.post({ type: "esign:signed" });
              setDraft(emptyDraft);
              announce("The document has been signed.");
              dispatch({ type: "SIGNED", kiosk });
            }}
            onPaper={openPaperPath}
          />
        );
      /**
       * The paper path is a detour, not a step: the workspace stays mounted behind it, hidden.
       * Replacing it would throw away everything it is holding that the draft is not -- the
       * drawn pages, the ink on the signature pad -- so somebody who opens "I'd rather sign on
       * paper" to read what it means and comes back finds everything where they left it.
       */
      body = (
        <>
          <DocumentWorkspace
            // Keyed on the document, not the step: the viewer must survive Read becoming Sign,
            // and must not survive one document becoming the next.
            key={session.envelope.id}
            session={session}
            step={state.step}
            onSeen={setPagesSeen}
            draft={draft}
            toolbarNode={toolbarNode}
            hidden={declining}
          >
            {/* Keyed so each step mounts fresh and its heading takes focus. */}
            <StepSlot key={state.step}>{step}</StepSlot>
          </DocumentWorkspace>
          {declining ? (
            <DeclineStep
              session={session}
              onBack={() => dispatch({ type: "DECLINE_CLOSED" })}
              onDeclined={() => dispatch({ type: "DECLINED", kiosk: session.session.kiosk })}
            />
          ) : null}
        </>
      );
    }
  }

  return (
    <HostLinkContext.Provider value={hostLink}>
      <div ref={shell} className="app-shell">
        <TopBar
          session={state.phase === "active" ? session : undefined}
          step={activeStep}
          queue={queue}
          toolbarRef={setToolbarNode}
        />
        <main className="relative flex min-h-0 flex-1 flex-col overflow-clip">
          {state.phase === "active" && session !== undefined && activeStep !== "done" ? (
            <DeadlineWatch session={session} />
          ) : null}
          {body}
        </main>
      </div>
    </HostLinkContext.Provider>
  );
}

/** A step's pieces, laid into the workspace grid without a wrapper of their own. */
function StepSlot({ children }: { children: React.ReactNode }) {
  return <div className="contents">{children}</div>;
}

// --------------------------------------------------------------------------- top bar

function TopBar({
  session,
  step,
  queue,
  toolbarRef,
}: {
  session: SigningSession | undefined;
  step: Step | null;
  queue: QueuePosition | null;
  toolbarRef: (node: HTMLElement | null) => void;
}) {
  const index = step === null ? -1 : STEPS.indexOf(step);
  const actingFor =
    session === undefined ? null : onBehalfOfPhrase(session.signer.on_behalf_of_label);
  return (
    <header className="top-bar" data-shell-chrome>
      <div className="flex min-h-11 items-center gap-3 px-3 sm:px-4">
        <span className="text-accent-600" title="Secure document signing">
          <Seal />
          <span className="sr-only">Secure document signing.</span>
        </span>
        <div className="min-w-0 flex-1 leading-tight">
          <p className="truncate font-semibold text-ink-900 text-sm">
            {session ? session.envelope.title : "Sign document"}
          </p>
          {session ? (
            <p className="truncate text-ink-700 text-xs" data-testid="signing-as">
              Signing as {session.signer.display_name} · {session.signer.role_label}
              {actingFor === null ? "" : `, ${actingFor}`}
            </p>
          ) : null}
        </div>
        {queue !== null ? (
          <span
            className="shrink-0 rounded-full bg-accent-wash px-2.5 py-0.5 font-semibold text-accent-700 text-xs tabular-nums"
            data-testid="queue-progress"
          >
            <span className="sr-only">Document </span>
            {queue.index} of {queue.total}
          </span>
        ) : null}
        {step !== null ? (
          <nav aria-label="Progress" className="shrink-0">
            {/* The words at every width; the pills only where there is room for them. */}
            <p className="flex items-center gap-1.5 text-xs" data-testid="step-progress">
              <span className="sr-only">
                Step {index + 1} of {STEPS.length}: {STEP_LABELS[step]}
              </span>
              {STEPS.map((name, i) => (
                <span
                  key={name}
                  aria-hidden="true"
                  className={`hidden rounded px-1.5 py-0.5 sm:inline ${
                    i === index
                      ? "bg-ink-900 font-semibold text-paper"
                      : i < index
                        ? "text-ink-700"
                        : "text-ink-500"
                  }`}
                >
                  {STEP_LABELS[name]}
                </span>
              ))}
            </p>
          </nav>
        ) : null}
        <div ref={toolbarRef} className="flex shrink-0 items-center" />
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

// --------------------------------------------------------------------------- natural height

/**
 * What `esign:resize` reports: not the frame's height, which the host chose, but what the UI
 * would like at most -- its bars plus the content of whatever region scrolls, capped so that even
 * a host that sizes the frame to the report never makes every page of a report "visible" at
 * once (INTEGRATION.md section 3). Below it the UI scrolls inside; above it there is nothing to
 * put.
 */
function useNaturalHeight(shell: RefObject<HTMLDivElement | null>, post: (height: number) => void) {
  const last = useRef(0);
  const report = useRef(post);
  report.current = post;
  useEffect(() => {
    const node = shell.current;
    if (
      node === null ||
      typeof ResizeObserver === "undefined" ||
      typeof MutationObserver === "undefined"
    ) {
      return;
    }
    const measure = () => {
      const chrome = [...node.querySelectorAll<HTMLElement>("[data-shell-chrome]")].reduce(
        (sum, element) => sum + element.getBoundingClientRect().height,
        0,
      );
      const regions = [...node.querySelectorAll<HTMLElement>("[data-scroll-region]")];
      const content = regions.reduce((max, region) => Math.max(max, region.scrollHeight), 0);
      const height = Math.ceil(chrome + Math.min(content, NATURAL_CONTENT_MAX));
      if (height > 0 && height !== last.current) {
        last.current = height;
        report.current(height);
      }
    };
    const sizes = new ResizeObserver(measure);
    const watched = new Set<Element>();
    const watch = () => {
      for (const region of node.querySelectorAll<HTMLElement>("[data-scroll-region]")) {
        for (const element of [region, region.firstElementChild]) {
          if (element !== null && !watched.has(element)) {
            watched.add(element);
            sizes.observe(element);
          }
        }
      }
      measure();
    };
    // Screens come and go as the flow moves; whichever region is there now is the one measured.
    const structure = new MutationObserver(watch);
    structure.observe(node, { childList: true, subtree: true });
    sizes.observe(node);
    watch();
    return () => {
      sizes.disconnect();
      structure.disconnect();
    };
  }, [shell]);
}

// --------------------------------------------------------------------------- session deadline

/**
 * The warning that the session is about to close, and with it the adopted signature and the field
 * values in the draft. Two things it deliberately does not do:
 *
 *  - it never ends the flow. The deadline is server time; this is the device's clock, and a tablet
 *    whose clock runs half an hour fast would land a signer on "this session has ended" before
 *    they had read a word. Only the server's 401 (wired through `sessionGone`) may do that.
 *  - it does not move anything. It floats over the top of the document region, so the reader
 *    who needs it -- two minutes in, far down a long report -- sees it without the page shifting.
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
      className="pointer-events-none absolute inset-x-0 top-2 z-30 mx-auto max-w-md px-3"
    >
      <Notice tone="warn" alert className="pointer-events-auto shadow-sheet">
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
