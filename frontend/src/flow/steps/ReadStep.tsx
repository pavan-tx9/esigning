import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useId, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { PageStrip } from "@/components/PageStrip";
import { ActionBar, Button, IconButton, Notice, StepHeading, useAnnounce } from "@/components/ui";
import { Glyph, useWorkspace } from "@/flow/DocumentWorkspace";
import { ConsentBlock } from "@/flow/steps/ConsentBlock";
import { describePages, nextUnseenPage, unseenPages } from "@/lib/reading";
import {
  isConsentNotStanding,
  isNetworkError,
  postConsent,
  postViewed,
  type SigningSession,
  type StandingConsent,
  signingKeys,
} from "@/lib/signing-api";

interface ReadStepProps {
  session: SigningSession;
  /**
   * True when the signer is here for a second look because the document changed under them
   * (another signer signed before they submitted). They are not being told off, and nothing they
   * have entered is lost: the fields they filled in are still in the draft.
   */
  changed?: boolean;
  /**
   * Whether the server has been told every page was displayed. Held by the flow rather than this
   * screen so a remount of the step (the paper-path sheet) does not send the same claim twice.
   * The pages themselves live on the workspace: the viewer's tracker is the only source.
   */
  viewedPosted: boolean;
  onViewedPosted: () => void;
  onContinue: () => void;
  onPaper: () => void;
}

/**
 * Screen 1 of 3 (addendum 3 A): the document, with the consent block directly under the last
 * page in the same scroll, and one button out of here.
 *
 * `POST /signing/viewed` goes once every page has been displayed *and* the end of the document
 * (the consent block under the last page) has been on screen -- that claim is about the pages,
 * not about the button -- and `POST /signing/consent` goes when Continue is pressed. Merging the
 * two screens did not merge the two acts.
 *
 * The rule for "displayed" is `lib/pages-seen.ts` and is not touched here. What this screen adds
 * is that the reader can see what the rule has decided -- a mark per page in the bar -- and that
 * the one button takes them to the next page it has not counted, or to the end once every page
 * has been, so a fling through a long report costs a few presses rather than a page-by-page
 * search for what was missed.
 */
export function ReadStep({
  session,
  changed = false,
  viewedPosted,
  onViewedPosted,
  onContinue,
  onPaper,
}: ReadStepProps) {
  const queryClient = useQueryClient();
  const announce = useAnnounce();
  const {
    current,
    goToPage,
    goToEnd,
    leadingNode,
    trailingNode,
    documentFailed,
    seen,
    reachedEnd,
    pageCount,
    pageCountMismatch,
  } = useWorkspace();
  const [agreed, setAgreed] = useState(false);
  const [nudge, setNudge] = useState<string | null>(null);
  const [viewedFailed, setViewedFailed] = useState(false);
  /**
   * The standing acceptance this press may lean on. It starts as whatever the session reported
   * and is dropped for good the moment the server says it is not standing after all, so the
   * fallback is one tick rather than a loop through the same refusal.
   */
  const [standing, setStanding] = useState<StandingConsent | null>(
    session.session.kiosk ? null : session.consent.standing,
  );
  const consentHint = useId();
  const announcedAllSeen = useRef(false);

  /**
   * `POST /signing/viewed`, sent once. The promise is held so that a Continue pressed while it is
   * still in flight waits for it rather than sending a second one, and a failure clears it so the
   * next press tries again: consent is refused until the server has been told the pages were seen.
   */
  const viewedOnce = useRef<Promise<unknown> | null>(null);
  const sendViewed = useCallback(() => {
    if (viewedPosted) {
      return Promise.resolve(null);
    }
    viewedOnce.current ??= postViewed(pageCount, {
      pagesSeen: Array.from({ length: pageCount }, (_, i) => i + 1),
      reachedEnd: true,
    }).then(
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

  const unseen = unseenPages(seen, pageCount);
  const allSeen = unseen.length === 0 && !pageCountMismatch;
  const next = nextUnseenPage(seen, pageCount);
  const reviewed = allSeen && reachedEnd;
  const consentGiven = standing !== null || agreed;

  // The claim is about the pages and reaching the end, so it is made when both have happened.
  useEffect(() => {
    if (reviewed) {
      void sendViewed().catch(() => {
        // Said in the bar when Continue is pressed, and retried by that press.
      });
    }
  }, [reviewed, sendViewed]);

  useEffect(() => {
    if (allSeen && pageCount > 1 && !announcedAllSeen.current) {
      announcedAllSeen.current = true;
      setNudge(null);
      announce("You have seen every page. You can continue when you are ready.");
    }
  }, [allSeen, pageCount, announce]);

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
          goToEnd();
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

  /**
   * "Next unseen page": go there, and say how much is left in words -- once. Focus stays on the
   * button, so the next press is the same press; the page is scrolled to, not focused.
   */
  const goToNextUnseen = () => {
    if (next === null) {
      return;
    }
    goToPage(next, { silent: true });
    const left = unseen.length;
    setNudge(null);
    announce(
      `Page ${next} of ${pageCount}. ${left === 1 ? "One page" : `${left} pages`} still to see: ${describePages(unseen)}.`,
    );
  };

  const goToDocumentEnd = () => {
    goToEnd();
    setNudge(null);
    announce("The end of the document. Please look at the last page, then continue.");
  };

  /**
   * Pressing Continue with every page seen but the box unticked: the button says what is missing
   * and takes the reader to the box, which sits under the last page they just read. This is the
   * inert-button pattern, not a dead button.
   */
  const nudgeConsent = () => {
    setNudge("To continue, tick the box under the last page.");
    goToEnd();
  };

  const failedToContinue = consent.isError || viewedFailed;
  const problem = pageCountMismatch
    ? "This document does not match what we were sent. Nothing has been signed. Please ask a member of staff for help."
    : failedToContinue
      ? viewedFailed && !consent.isError
        ? "We couldn't record that you've read the document. Press Continue to try again."
        : isNetworkError(consent.error)
          ? "We couldn't reach the server. Check the connection and press Continue to sign again."
          : isConsentNotStanding(consent.error)
            ? "The agreement you gave earlier no longer covers this document. Tick the box under the last page, then press Continue to sign."
            : "We couldn't record your choice. Please try again, or ask a member of staff for help."
      : null;

  const seenLabel = pageCountMismatch
    ? "The document does not match what was sent"
    : allSeen
      ? reachedEnd
        ? "All pages seen"
        : "All pages seen · go to the end"
      : `${seen.size} of ${pageCount} seen`;

  return (
    <>
      {leadingNode !== null && changed
        ? createPortal(
            <Notice tone="warn" alert className="mb-3">
              <p className="font-semibold" data-testid="review-again">
                Someone else signed this while you were reading.
              </p>
              <p className="mt-1">
                You have not signed anything, and nothing you filled in is lost. Please look through
                the document as it stands now, then continue: you'll be asked to agree and sign
                again, with your answers still in place.
              </p>
            </Notice>,
            leadingNode,
          )
        : null}

      {/* Directly under the last page, in the same scroll: what is being agreed to is still on
          the screen above it. */}
      {trailingNode !== null && !documentFailed
        ? createPortal(
            <ConsentBlock
              consent={session.consent}
              standing={standing}
              agreed={agreed}
              onAgreed={(value) => {
                setAgreed(value);
                setNudge(null);
              }}
              invalid={nudge !== null && allSeen && !consentGiven}
              hintId={consentHint}
            />,
            trailingNode,
          )
        : null}

      <ActionBar testId="step-read">
        <StepHeading id="step-read-title">Read the document</StepHeading>
        {pageCount > 1 ? (
          <PageStrip pageCount={pageCount} seen={seen} current={current} onGo={goToPage} />
        ) : null}
        <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-2">
          <div className="flex min-w-0 flex-1 basis-56 items-center gap-2">
            {pageCount > 1 ? (
              <div className="flex gap-1">
                <IconButton
                  size="lg"
                  aria-label="Previous page"
                  inert={current <= 1}
                  onClick={() => goToPage(current - 1)}
                >
                  <Glyph d="m5 12 5-5 5 5" />
                </IconButton>
                <IconButton
                  size="lg"
                  aria-label="Next page"
                  inert={current >= pageCount}
                  onClick={() => goToPage(current + 1)}
                >
                  <Glyph d="m5 8 5 5 5-5" />
                </IconButton>
              </div>
            ) : null}
            <div className="min-w-0 flex-1 leading-5">
              <p
                className="truncate text-sm"
                data-testid="page-progress"
                data-seen={[...seen].sort((x, y) => x - y).join(",")}
              >
                <span className="font-semibold text-ink-900 tabular-nums">
                  Page {current} of {pageCount}
                </span>
                <span className="text-ink-700"> · {seenLabel}</span>
              </p>
              {/* Reserved: what stops the press from working, or -- while nothing does -- the
                  paper alternative in words (SPEC section 11). One line on a wide frame, two on
                  a phone, and never cut short: a sentence that explains a failed press has to be
                  read in full. Only the problem is an alert; the standing hint is not news. */}
              <p
                id={consentHint}
                className={`status-line status-wrap text-sm max-sm:text-xs ${problem !== null ? "text-danger-600" : "text-ink-900"}`}
                data-testid="read-status"
              >
                {problem !== null || nudge !== null ? (
                  <span role="alert">{problem ?? nudge}</span>
                ) : (
                  <span className="text-ink-700">
                    Would you rather read this on paper? A member of staff can give you a printed
                    copy.
                  </span>
                )}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 max-sm:w-full">
            {/* The way out of an electronic signature is never more than one press away, on this
                screen and the next (addendum 3 A). */}
            <Button
              variant="quiet"
              size="sm"
              className="whitespace-nowrap max-sm:mr-auto max-sm:px-0 max-sm:text-xs"
              onClick={onPaper}
            >
              I'd rather sign on paper
            </Button>
            {documentFailed || pageCountMismatch ? null : next !== null ? (
              <Button
                size="lg"
                className="max-sm:min-w-0 max-sm:flex-1 max-sm:px-3 sm:min-w-[13rem]"
                data-testid="next-unseen"
                onClick={goToNextUnseen}
              >
                Next unseen page ({next})
              </Button>
            ) : !reachedEnd ? (
              <Button
                size="lg"
                className="max-sm:min-w-0 max-sm:flex-1 max-sm:px-3 sm:min-w-[13rem]"
                data-testid="go-to-end"
                onClick={goToDocumentEnd}
              >
                Go to end
              </Button>
            ) : (
              <Button
                size="lg"
                className="max-sm:min-w-0 max-sm:flex-1 max-sm:px-3 sm:min-w-[13rem]"
                inert={!consentGiven}
                onInertClick={nudgeConsent}
                busy={consent.isPending}
                onClick={() => consent.mutate()}
              >
                Continue to sign
              </Button>
            )}
          </div>
        </div>
      </ActionBar>
    </>
  );
}
