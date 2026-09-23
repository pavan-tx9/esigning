import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  Button,
  CheckIcon,
  Dots,
  Notice,
  prefersReducedMotion,
  Sheet,
  StepScreen,
  useAnnounce,
  useStableCallback,
} from "@/components/ui";
import { useHostLink, useNow } from "@/flow/context";
import type { QueuePosition } from "@/lib/embed";
import {
  isSessionGone,
  type SigningSession,
  sessionQueryOptions,
  signedCopyQueryOptions,
} from "@/lib/signing-api";

const SLOW_AFTER_MS = 60_000;
/** Long enough to read what is coming and stop it; short enough not to be a wait. */
export const QUEUE_COUNTDOWN_SECONDS = 4;
/** How long to wait for the host to answer `esign:next` before saying it did not happen. */
const QUEUE_OPEN_TIMEOUT_MS = 12_000;

export function DoneStep({
  session: initial,
  locale,
  queue = null,
}: {
  session: SigningSession;
  locale?: string | null;
  queue?: QueuePosition | null;
}) {
  const live = useQuery(sessionQueryOptions(locale));
  const session = live.data ?? initial;
  const waitingOn = session.other_signers.filter((other) => other.status !== "signed");
  const everyoneSigned =
    session.envelope.status === "completed_pending_seal" ||
    session.envelope.status === "sealed" ||
    (waitingOn.length === 0 && session.signer.status === "signed");
  const moreToSign = queue !== null && queue.index < queue.total;
  /** The copy of *this* document is not ready, and the frame is about to move on without it. */
  const copyPending = everyoneSigned && session.envelope.status !== "sealed";
  const stayHere = useRef<HTMLButtonElement>(null);

  return (
    <StepScreen
      testId="step-done"
      // A screen that replaces itself in four seconds has to put the way to stop it under the
      // signer's hands, not five Tab presses away behind the heading.
      focus={moreToSign ? stayHere : undefined}
      title="You've signed"
      lead={
        <p>
          Thank you, {session.signer.display_name}. Your signature on{" "}
          <span className="font-semibold text-ink-900">{session.envelope.title}</span> has been
          recorded.
        </p>
      }
    >
      {moreToSign ? (
        <NextInQueue
          queue={queue}
          envelopeId={session.envelope.id}
          copyPending={copyPending}
          stayRef={stayHere}
        />
      ) : queue !== null ? (
        <p className="mb-6 flex items-start gap-2.5 rounded-lg bg-accent-wash px-4 py-3.5 text-ink-900">
          <CheckIcon className="mt-1 text-accent-600" />
          <span data-testid="queue-finished">
            That was the last of {queue.total}. There is nothing else waiting for your signature.
          </span>
        </p>
      ) : null}

      {everyoneSigned ? (
        <SignedCopy />
      ) : (
        <WaitingOnOthers roles={waitingOn.map((o) => o.role_label)} />
      )}
    </StepScreen>
  );
}

// --------------------------------------------------------------------------- the signing queue

/**
 * Auto-advance (addendum 3 B). The host owns the queue and its tokens: all this does is count
 * down in the open and then ask, with `esign:next`, for the document the host already named.
 *
 * It is cancellable, and cancelling is a plain button of its own rather than a timer that stops
 * if you happen to touch the screen: somebody reading the sealing notice must be able to stay.
 * But a button is only an escape if it can be reached in four seconds, so focus arrives on it and
 * the countdown holds while focus is inside this card. That is what makes the four seconds
 * affordable, and it does not remove the auto-advance.
 *
 * `prefers-reduced-motion` takes the emptying bar away and nothing else. It is a preference about
 * movement, not about who is allowed the shorter path: cancelling the advance for everybody who
 * set it would charge a clinician working a queue the extra press per document that addendum 3 B
 * exists to remove, and the number in the sentence says the same thing the bar was drawing. The
 * time limit itself is answered where WCAG 2.2.1 asks for it to be -- "Stay here", under the
 * signer's hands from the moment the screen opens.
 */
function NextInQueue({
  queue,
  envelopeId,
  copyPending,
  stayRef,
}: {
  queue: QueuePosition;
  envelopeId: string;
  /** This document is still sealing, so the frame is about to move on before the copy exists. */
  copyPending: boolean;
  stayRef: React.RefObject<HTMLButtonElement | null>;
}) {
  const host = useHostLink();
  const announce = useAnnounce();
  const [left, setLeft] = useState(QUEUE_COUNTDOWN_SECONDS);
  const [stayed, setStayed] = useState(false);
  const [paused, setPaused] = useState(false);
  const [asking, setAsking] = useState(false);
  const [stalled, setStalled] = useState(false);
  const [reduced] = useState(prefersReducedMotion);
  const card = useRef<HTMLDivElement>(null);
  const asked = useRef(false);
  /**
   * Focus arrives here on its own (the screen puts it on "Stay here", below), and that arrival is
   * not the signer reaching for the brake: treating it as one would hold the countdown for
   * everybody and there would be no auto-advance left. Focus coming back afterwards is.
   */
  const arriving = useRef(true);

  /** The automatic path asks once. An explicit press is not the automatic path. */
  const ask = useStableCallback((automatic: boolean) => {
    if (automatic && asked.current) {
      return;
    }
    asked.current = true;
    setAsking(true);
    setStalled(false);
    host.post({ type: "esign:next", envelope_id: envelopeId });
  });

  useEffect(() => {
    announce(
      stayed
        ? "Signed. Choose when to open the next document."
        : `Signed. The next document opens in ${QUEUE_COUNTDOWN_SECONDS} seconds. Choose "Stay here" to stop.`,
    );
  }, [announce, stayed]);

  useEffect(() => {
    // Stopped at zero as well: a host that never opens the next document would otherwise leave
    // this counting down through zero for ever, pinned at "Opening in 0 seconds".
    if (stayed || paused || left <= 0) {
      return;
    }
    const timer = window.setInterval(() => setLeft((value) => value - 1), 1_000);
    return () => window.clearInterval(timer);
  }, [stayed, paused, left]);

  useEffect(() => {
    if (!stayed && !paused && left <= 0) {
      ask(true);
    }
  }, [stayed, paused, left, ask]);

  // Nothing came back. Say so, rather than let the frame keep asserting progress it cannot see.
  useEffect(() => {
    if (!asking) {
      return;
    }
    const timer = window.setTimeout(() => setStalled(true), QUEUE_OPEN_TIMEOUT_MS);
    return () => window.clearTimeout(timer);
  }, [asking]);

  const title = queue.next_title;
  const openLabel = title === undefined ? "Open the next document" : `Open ${title}`;
  return (
    <div
      ref={card}
      className="mb-6"
      onFocusCapture={() => {
        if (arriving.current) {
          arriving.current = false;
          return;
        }
        setPaused(true);
      }}
      onBlurCapture={(event) => {
        arriving.current = false;
        if (!card.current?.contains(event.relatedTarget as Node | null)) {
          setPaused(false);
        }
      }}
    >
      <Sheet testId="queue-next">
        <p className="text-ink-700 text-sm" data-testid="queue-position">
          Document {queue.index} of {queue.total}
        </p>
        <h2 className="mt-1 text-ink-900 text-xl">
          {title === undefined ? "Next document" : `Next: ${title}`}
        </h2>

        {asking ? (
          <>
            <p className="mt-2 flex items-center gap-3 text-ink-700" data-testid="queue-opening">
              <Dots /> Opening the next document…
            </p>
            {stalled ? (
              <p className="mt-3 text-ink-700" data-testid="queue-stalled">
                That didn't open. Go back to your list and open the next one.
              </p>
            ) : null}
            <Button
              variant="secondary"
              className="mt-4 min-h-14 w-full sm:w-auto"
              onClick={() => ask(false)}
            >
              {openLabel}
            </Button>
          </>
        ) : stayed ? (
          <>
            <p className="mt-2 text-ink-700" role="status">
              Staying here. Open the next one whenever you're ready.
            </p>
            {copyPending ? <CopyStillSealing /> : null}
            <Button
              ref={stayRef}
              className="mt-4 min-h-14 w-full sm:w-auto"
              onClick={() => ask(false)}
            >
              {openLabel}
            </Button>
          </>
        ) : (
          <>
            <p className="mt-2 text-ink-700">
              <span aria-hidden="true">
                {paused
                  ? "Held while you're here."
                  : `Opening in ${Math.max(0, left)} second${Math.max(0, left) === 1 ? "" : "s"}.`}
              </span>{" "}
              <span className="sr-only">
                {paused ? "Held while you're here." : "Opening in a few seconds."}
              </span>{" "}
              Nothing else is needed from you on this one.
            </p>
            {copyPending ? <CopyStillSealing /> : null}
            {/* A bar that empties, not a spinner: the length left is the number, drawn. It is
                decoration -- the sentence above already carries the count -- so somebody who
                asked for reduced motion simply does not get it. */}
            {reduced ? null : (
              <div
                aria-hidden="true"
                data-testid="queue-countdown-bar"
                className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-sunk"
              >
                <div
                  className="h-full rounded-full bg-accent-600 transition-[width] duration-1000 ease-linear"
                  style={{
                    width: `${(Math.max(0, left) / QUEUE_COUNTDOWN_SECONDS) * 100}%`,
                  }}
                />
              </div>
            )}
            <Button
              ref={stayRef}
              variant="secondary"
              className="mt-4 min-h-14 w-full sm:w-auto"
              onClick={() => {
                setStayed(true);
                announce("Staying on this page.");
              }}
            >
              {copyPending ? "Stay and save my copy" : "Stay here"}
            </Button>
          </>
        )}
      </Sheet>
    </div>
  );
}

/**
 * The document below is still being sealed, and in a run the frame moves on long before it is.
 * Say what is being left behind rather than let the signer find out by it vanishing.
 */
function CopyStillSealing() {
  return (
    <p className="mt-2 text-ink-700" data-testid="queue-copy-pending">
      Your copy of this one is still being finalised. The clinic keeps it with your records; stay
      here if you would like to save it yourself.
    </p>
  );
}

function WaitingOnOthers({ roles }: { roles: string[] }) {
  const unique = [...new Set(roles.map((role) => `the ${role.toLowerCase()}`))];
  const names =
    unique.length <= 1
      ? (unique[0] ?? "someone else")
      : `${unique.slice(0, -1).join(", ")} and ${unique[unique.length - 1]}`;
  return (
    <Sheet>
      <h2 className="text-ink-900 text-xl">Your part is finished</h2>
      <p className="mt-2 text-ink-700" data-testid="waiting-on-others">
        This document still needs a signature from {names}. Your copy will be available once
        everyone has signed. The clinic can give it to you, and it will appear with your records.
      </p>
      <p className="mt-3 text-ink-700">
        You don't need to do anything else. You can close this page.
      </p>
    </Sheet>
  );
}

function SignedCopy() {
  const host = useHostLink();
  const copy = useQuery(signedCopyQueryOptions());
  const [startedAt] = useState(() => Date.now());
  const now = useNow(5_000);
  const announcedSeal = useRef(false);
  const ready = copy.data?.status === "ready" ? copy.data.bytes : null;

  useEffect(() => {
    if (ready !== null && !announcedSeal.current) {
      announcedSeal.current = true;
      host.post({ type: "esign:sealed" });
    }
  }, [ready, host]);

  const url = useMemo(
    () =>
      ready === null
        ? null
        : URL.createObjectURL(
            new Blob([ready.slice().buffer as ArrayBuffer], { type: "application/pdf" }),
          ),
    [ready],
  );
  useEffect(
    () => () => {
      if (url !== null) {
        URL.revokeObjectURL(url);
      }
    },
    [url],
  );

  if (url !== null) {
    return (
      <Sheet>
        <h2 className="text-ink-900 text-xl">Your signed copy is ready</h2>
        <p className="mt-2 text-ink-700" role="status" data-testid="copy-ready">
          The document has been finalised and locked so it can't be changed. Keep a copy for your
          records.
        </p>
        <a
          href={url}
          download="signed-document.pdf"
          className="mt-4 inline-flex min-h-14 w-full items-center justify-center rounded-lg bg-accent-600 px-6 font-semibold text-lg text-on-accent hover:bg-accent-700 sm:w-auto"
        >
          Save your signed copy
        </a>
        <p className="mt-3 text-ink-700 text-sm">
          PDF document. The clinic keeps the original with your records.
        </p>
      </Sheet>
    );
  }

  if (copy.isError) {
    return isSessionGone(copy.error) ? (
      <Notice tone="info">
        Your signature is safely recorded. This session has now ended, so the copy can't be saved
        from this page. The clinic can give you one.
      </Notice>
    ) : (
      <Notice tone="warn" alert>
        <p>
          Your signature is safely recorded, but we couldn't fetch your copy just now. You can try
          again, or ask the clinic for it later.
        </p>
        <Button variant="secondary" className="mt-3" onClick={() => void copy.refetch()}>
          Try again
        </Button>
      </Notice>
    );
  }

  const slow = now - startedAt > SLOW_AFTER_MS;
  return (
    <Sheet>
      <h2 className="flex items-center gap-3 text-ink-900 text-xl">
        <Dots /> Finalising your document
      </h2>
      <p className="mt-2 text-ink-700" role="status" data-testid="copy-sealing">
        Your signature is recorded. The document is now being locked and time-stamped so it can't be
        changed. This usually takes less than a minute, and your copy will appear here when it's
        done.
      </p>
      {slow ? (
        <p className="mt-3 text-ink-700" data-testid="copy-slow">
          This is taking longer than usual. You don't have to wait: your signature is safe, and the
          clinic will have your copy once it's finished. We'll keep checking while this page is
          open.
        </p>
      ) : null}
    </Sheet>
  );
}
