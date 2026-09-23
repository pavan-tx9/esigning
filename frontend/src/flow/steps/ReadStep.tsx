import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useId, useRef, useState } from "react";
import { DocumentViewer, type DocumentViewerHandle } from "@/components/DocumentViewer";
import {
  Button,
  Dots,
  Notice,
  prefersReducedMotion,
  StepScreen,
  useAnnounce,
} from "@/components/ui";
import { ConsentBlock } from "@/flow/steps/ConsentBlock";
import {
  documentQueryOptions,
  isConsentNotStanding,
  isNetworkError,
  postConsent,
  postViewed,
  type SigningSession,
  type StandingConsent,
  signingKeys,
} from "@/lib/signing-api";
import { usePdf } from "@/lib/use-pdf";

const ZOOMS = [1, 1.5, 2, 3] as const;

/**
 * The pages still to be looked at, in words.
 *
 * Runs are collapsed ("pages 2 to 30") and long lists are cut short, because a document can be
 * thirty pages -- a report an EHR generated for one patient, rather than a one-page consent -- and
 * naming twenty-nine numbers fills a phone screen with a list nobody reads and pushes Continue off
 * the bottom of it. One unseen page still reads "page 7", which is what most of these say.
 */
function listPages(pages: number[]): string {
  if (pages.length <= 1) {
    return `page ${pages[0] ?? 1}`;
  }
  const runs: string[] = [];
  for (let at = 0; at < pages.length; ) {
    let end = at;
    while (end + 1 < pages.length && pages[end + 1] === (pages[end] ?? 0) + 1) {
      end += 1;
    }
    const from = pages[at];
    const to = pages[end];
    runs.push(from === to ? `${from}` : `${from} to ${to}`);
    at = end + 1;
  }
  const shown = runs.length > 4 ? [...runs.slice(0, 3), `${runs.length - 3} more`] : runs;
  if (shown.length === 1) {
    return `pages ${shown[0]}`;
  }
  return `pages ${shown.slice(0, -1).join(", ")} and ${shown[shown.length - 1]}`;
}

interface ReadStepProps {
  session: SigningSession;
  /**
   * True when the signer is here for a second look because the document changed under them
   * (another signer signed before they submitted). They are not being told off, and nothing they
   * have entered is lost: the fields they filled in are still in the draft.
   */
  changed?: boolean;
  /**
   * Which pages have been displayed, and whether the server has been told. Both are held by the
   * flow rather than this screen, because this screen is unmounted by a detour that changes
   * neither: opening the paper-path sheet and coming back must not make somebody scroll thirty
   * pages again to reach a button they had already earned.
   */
  seen: ReadonlySet<number>;
  onSeen: (seen: ReadonlySet<number>) => void;
  viewedPosted: boolean;
  onViewedPosted: () => void;
  onContinue: () => void;
}

/**
 * Screen 1 of 3 (addendum 3 A): the document, page by page, with the consent block directly under
 * the last page in the same scroll, and one button out of here.
 *
 * What the server is told is unchanged. `POST /signing/viewed` goes the moment the last page has
 * been displayed -- that claim is about the pages, not about the button -- and `POST
 * /signing/consent` goes when Continue is pressed. Merging the two screens did not merge the two
 * acts.
 */
export function ReadStep({
  session,
  changed = false,
  seen,
  onSeen,
  viewedPosted,
  onViewedPosted,
  onContinue,
}: ReadStepProps) {
  const pageCount = session.envelope.page_count;
  const queryClient = useQueryClient();
  const announce = useAnnounce();
  const viewer = useRef<DocumentViewerHandle>(null);
  const document_ = useQuery(documentQueryOptions());
  const pdf = usePdf(document_.data);
  const [current, setCurrent] = useState(1);
  const [zoomIndex, setZoomIndex] = useState(0);
  const [agreed, setAgreed] = useState(false);
  const [nudge, setNudge] = useState<string | null>(null);
  const [pageFailed, setPageFailed] = useState(false);
  const [viewedFailed, setViewedFailed] = useState(false);
  /**
   * The standing acceptance this press may lean on. It starts as whatever the session reported
   * and is dropped for good the moment the server says it is not standing after all, so the
   * fallback is one tick rather than a loop through the same refusal.
   */
  const [standing, setStanding] = useState<StandingConsent | null>(
    session.session.kiosk ? null : session.consent.standing,
  );
  const zoom = ZOOMS[zoomIndex] ?? 1;
  const zoomReadout = useId();
  const consentHint = useId();

  /**
   * `POST /signing/viewed`, sent once. The promise is held so that a Continue pressed while it is
   * still in flight waits for it rather than sending a second one, and a failure clears it so the
   * next press tries again: consent is refused until the server has been told the pages were seen.
   */
  /**
   * Anything that went wrong with Continue is said here, below the consent block. The press that
   * caused it happened in the sticky footer, which can be a long way from this, so the message
   * comes to the signer rather than waiting to be found.
   */
  const problem = useRef<HTMLDivElement>(null);
  const viewedOnce = useRef<Promise<unknown> | null>(null);
  const sendViewed = useCallback(() => {
    if (viewedPosted) {
      return Promise.resolve(null);
    }
    viewedOnce.current ??= postViewed(pageCount).then(
      (answer) => {
        setViewedFailed(false);
        onViewedPosted();
        void queryClient.invalidateQueries({ queryKey: signingKeys.session });
        return answer;
      },
      (error: unknown) => {
        viewedOnce.current = null;
        setViewedFailed(true);
        throw error;
      },
    );
    return viewedOnce.current;
  }, [pageCount, queryClient, viewedPosted, onViewedPosted]);

  const unseen = Array.from({ length: pageCount }, (_, i) => i + 1).filter((p) => !seen.has(p));
  const allSeen = unseen.length === 0;
  const consentGiven = standing !== null || agreed;

  // The claim is about the pages, so it is made when the pages have been displayed.
  useEffect(() => {
    if (allSeen) {
      void sendViewed().catch(() => {
        // Said on screen when Continue is pressed, and retried by that press.
      });
    }
  }, [allSeen, sendViewed]);

  const consent = useMutation({
    mutationFn: async () => {
      await sendViewed();
      const relied = standing?.envelope_id ?? null;
      try {
        return await postConsent(session.consent.version, session.consent.locale, relied);
      } catch (error) {
        // The reliance is no longer good (the span ran out, the version moved on). Ask plainly.
        if (relied !== null && isConsentNotStanding(error)) {
          setStanding(null);
          setAgreed(false);
          announce("Please confirm that you agree to sign this document electronically.");
        }
        throw error;
      }
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: signingKeys.session });
      onContinue();
    },
  });

  const failedToContinue = consent.isError || viewedFailed;
  useEffect(() => {
    if (failedToContinue) {
      // Optional call: this is a convenience, and a runtime without it must not take the
      // screen down on the one path where something has already gone wrong.
      problem.current?.scrollIntoView?.({
        block: "center",
        behavior: prefersReducedMotion() ? "auto" : "smooth",
      });
    }
  }, [failedToContinue]);

  const handleSeen = (next: ReadonlySet<number>) => {
    onSeen(next);
    if (next.size >= pageCount) {
      setNudge(null);
      announce("You have seen every page. You can continue when you are ready.");
    }
  };

  const changeZoom = (step: -1 | 1) => {
    const next = zoomIndex + step;
    setZoomIndex(next);
    announce(`Zoom ${Math.round((ZOOMS[next] ?? 1) * 100)} percent.`);
  };

  // The zoom buttons go inert at either end of the scale. Nothing is missing and nothing is on
  // screen to say so, so the answer is spoken: a sighted user sees the readout stop moving.
  const announceZoomLimit = (step: -1 | 1) =>
    announce(
      step === 1
        ? "The document is already at the largest size."
        : "The document is already at the smallest size.",
    );

  const goTo = (page: number) => {
    const target = Math.min(pageCount, Math.max(1, page));
    viewer.current?.goToPage(target);
    announce(`Page ${target} of ${pageCount}`);
  };

  /**
   * Pressing Continue before it can do anything. Two things can be missing and the button says
   * which: unseen pages first (and it takes the reader to the first of them), because "I have
   * looked at every page" is the claim the signature rests on and it is the one that needs the
   * document scrolled, not a tick. This is the inert-button pattern, not a dead button.
   */
  const nudgeWhatIsMissing = () => {
    if (!allSeen) {
      setNudge(`Please look at ${listPages(unseen)} before you continue.`);
      viewer.current?.goToPage(unseen[0] ?? 1);
      return;
    }
    setNudge("To continue, tick the box to show you agree. Or choose to sign on paper instead.");
  };

  const failed = document_.isError || pdf.status === "failed" || pageFailed;

  return (
    <StepScreen
      wide
      testId="step-read"
      title="Read the document"
      lead={
        <>
          <p>
            {pageCount === 1 ? "There is one page." : `There are ${pageCount} pages.`} Take as long
            as you need. You can continue once you've seen {pageCount === 1 ? "it" : "them all"}
            {/* Nothing is asked of a signer whose agreement already covers this document, so
                nothing is promised to them either. */}
            {standing === null ? ", and agreed to sign on a screen" : ""}.
          </p>
          <p className="mt-2 text-base">
            Would you rather read this on paper? A member of staff can give you a printed copy.
          </p>
        </>
      }
    >
      {changed ? (
        <Notice tone="warn" alert className="mb-5">
          <p className="font-semibold" data-testid="review-again">
            Someone else signed this while you were reading.
          </p>
          <p className="mt-1">
            You have not signed anything, and nothing you filled in is lost. Please look through the
            document as it stands now, then continue: you'll be asked to agree and sign again, with
            your answers still in place.
          </p>
        </Notice>
      ) : null}

      {failed ? (
        <Notice tone="error" alert>
          <p className="font-semibold">We couldn't show the document.</p>
          <p className="mt-1">
            {isNetworkError(document_.error)
              ? "The connection dropped. Check the connection and try again."
              : "Nothing has been signed. You can try again, or ask a member of staff for a paper copy."}
          </p>
          <Button
            variant="secondary"
            className="mt-3"
            onClick={() => {
              setPageFailed(false);
              void document_.refetch();
            }}
          >
            Try again
          </Button>
        </Notice>
      ) : pdf.status !== "ready" ? (
        <div
          role="status"
          className="grid h-64 place-items-center rounded-xl bg-sheet text-ink-700 shadow-sheet"
        >
          <span className="flex items-center gap-3">
            <Dots /> Opening the document
          </span>
        </div>
      ) : (
        <>
          {/* The zoom level is state, not decoration: it is read out on every change and named by
              both buttons, so someone who cannot see the page still knows where the zoom stands
              and when a press did nothing because it is already at the limit. */}
          <div className="mb-3 flex items-center justify-end gap-2">
            <span
              id={zoomReadout}
              role="status"
              data-testid="zoom-level"
              className="mr-1 text-ink-700 text-sm"
            >
              Zoom {Math.round(zoom * 100)}%
            </span>
            <Button
              variant="secondary"
              aria-label="Make the document smaller"
              aria-describedby={zoomReadout}
              inert={zoomIndex === 0}
              onInertClick={() => announceZoomLimit(-1)}
              onClick={() => changeZoom(-1)}
              className="px-0 text-xl"
            >
              <span aria-hidden="true">−</span>
            </Button>
            <Button
              variant="secondary"
              aria-label="Make the document larger"
              aria-describedby={zoomReadout}
              inert={zoomIndex === ZOOMS.length - 1}
              onInertClick={() => announceZoomLimit(1)}
              onClick={() => changeZoom(1)}
              className="px-0 text-xl"
            >
              <span aria-hidden="true">+</span>
            </Button>
          </div>
          <DocumentViewer
            ref={viewer}
            pdf={pdf.pdf}
            fields={session.fields}
            zoom={zoom}
            onSeen={handleSeen}
            onCurrentPage={setCurrent}
            onPageFailed={() => setPageFailed(true)}
          />

          {/* Directly under the last page, in the same scroll: what is being agreed to is still
              on the screen above it. */}
          <ConsentBlock
            consent={session.consent}
            standing={standing}
            agreed={agreed}
            onAgreed={(next) => {
              setAgreed(next);
              setNudge(null);
            }}
            invalid={nudge !== null && allSeen && !consentGiven}
            hintId={consentHint}
          />
        </>
      )}

      <div ref={problem}>
        {failedToContinue ? (
          <Notice tone="error" alert className="mt-5">
            {viewedFailed && !consent.isError ? (
              "We couldn't record that you've read the document. Press Continue to try again."
            ) : isNetworkError(consent.error) ? (
              "We couldn't reach the server. Check the connection and press Continue to sign again."
            ) : isConsentNotStanding(consent.error) ? (
              <>
                <p className="font-semibold">Please agree once more.</p>
                <p className="mt-1">
                  The agreement you gave earlier no longer covers this document, so we need it again
                  for this one. Tick the box above, then press Continue to sign.
                </p>
              </>
            ) : (
              "We couldn't record your choice. Please try again, or ask a member of staff for help."
            )}
          </Notice>
        ) : null}
      </div>

      {failed ? null : (
        <div className="sticky bottom-0 z-10 -mx-4 mt-6 border-edge border-t bg-paper/95 px-4 pt-3 pb-[max(0.75rem,env(safe-area-inset-bottom))] backdrop-blur-sm sm:-mx-6 sm:px-6">
          {nudge ? (
            <p id={consentHint} role="alert" className="mb-2 font-medium text-danger-600">
              {nudge}
            </p>
          ) : null}
          <div className="flex flex-wrap items-center gap-x-3 gap-y-2.5">
            <p
              className="min-w-[7.5rem] flex-1 text-ink-900 leading-tight"
              data-testid="page-progress"
              data-seen={[...seen].sort((x, y) => x - y).join(",")}
            >
              <span className="font-semibold">
                Page {current} of {pageCount}
              </span>
              <span className="block text-ink-700 text-sm">
                {allSeen ? "All pages seen" : `Still to see: ${listPages(unseen)}`}
              </span>
            </p>
            {pageCount > 1 ? (
              <div className="flex gap-2">
                <Button
                  variant="secondary"
                  className="px-3.5"
                  inert={current <= 1}
                  onClick={() => goTo(current - 1)}
                >
                  Previous<span className="sr-only"> page</span>
                </Button>
                <Button
                  variant="secondary"
                  className="px-3.5"
                  inert={current >= pageCount}
                  onClick={() => goTo(current + 1)}
                >
                  Next<span className="sr-only"> page</span>
                </Button>
              </div>
            ) : null}
            <Button
              className="w-full sm:w-auto"
              inert={!allSeen || !consentGiven}
              onInertClick={nudgeWhatIsMissing}
              busy={consent.isPending}
              onClick={() => consent.mutate()}
            >
              Continue to sign
            </Button>
          </div>
        </div>
      )}
    </StepScreen>
  );
}
