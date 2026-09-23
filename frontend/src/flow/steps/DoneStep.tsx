import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  Button,
  CheckIcon,
  Dots,
  Notice,
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

  return (
    <StepScreen
      testId="step-done"
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
        <NextInQueue queue={queue} envelopeId={session.envelope.id} />
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
 */
function NextInQueue({ queue, envelopeId }: { queue: QueuePosition; envelopeId: string }) {
  const host = useHostLink();
  const announce = useAnnounce();
  const [left, setLeft] = useState(QUEUE_COUNTDOWN_SECONDS);
  const [stayed, setStayed] = useState(false);
  const asked = useRef(false);

  const ask = useStableCallback(() => {
    if (!asked.current) {
      asked.current = true;
      host.post({ type: "esign:next", envelope_id: envelopeId });
    }
  });

  useEffect(() => {
    announce(
      `Signed. The next document opens in ${QUEUE_COUNTDOWN_SECONDS} seconds. Choose "Stay here" to stop.`,
    );
  }, [announce]);

  useEffect(() => {
    if (stayed) {
      return;
    }
    const timer = window.setInterval(() => setLeft((value) => value - 1), 1_000);
    return () => window.clearInterval(timer);
  }, [stayed]);

  useEffect(() => {
    if (!stayed && left <= 0) {
      ask();
    }
  }, [stayed, left, ask]);

  const title = queue.next_title;
  return (
    <Sheet testId="queue-next" className="mb-6">
      <p className="text-ink-700 text-sm" data-testid="queue-position">
        Document {queue.index} of {queue.total}
      </p>
      <h2 className="mt-1 text-ink-900 text-xl">
        {title === undefined ? "Next document" : `Next: ${title}`}
      </h2>
      {stayed ? (
        <>
          <p className="mt-2 text-ink-700" role="status">
            Staying here. Open the next one whenever you're ready.
          </p>
          <Button className="mt-4 min-h-14 w-full sm:w-auto" onClick={ask}>
            {title === undefined ? "Open the next document" : `Open ${title}`}
          </Button>
        </>
      ) : (
        <>
          <p className="mt-2 text-ink-700">
            <span aria-hidden="true">
              Opening in {Math.max(0, left)} second{Math.max(0, left) === 1 ? "" : "s"}.
            </span>{" "}
            <span className="sr-only">Opening in a few seconds.</span> Nothing else is needed from
            you on this one.
          </p>
          {/* A bar that empties, not a spinner: the length left is the number, drawn. */}
          <div
            aria-hidden="true"
            className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-sunk"
          >
            <div
              className="h-full rounded-full bg-accent-600 transition-[width] duration-1000 ease-linear"
              style={{
                width: `${(Math.max(0, left) / QUEUE_COUNTDOWN_SECONDS) * 100}%`,
              }}
            />
          </div>
          <Button
            variant="secondary"
            className="mt-4 min-h-14 w-full sm:w-auto"
            onClick={() => {
              setStayed(true);
              announce("Staying on this page.");
            }}
          >
            Stay here
          </Button>
        </>
      )}
    </Sheet>
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
