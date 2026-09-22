import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useId, useRef, useState } from "react";
import { DocumentViewer, type DocumentViewerHandle } from "@/components/DocumentViewer";
import { Button, Dots, Notice, StepScreen, useAnnounce } from "@/components/ui";
import {
  documentQueryOptions,
  isNetworkError,
  postViewed,
  type SigningSession,
  signingKeys,
} from "@/lib/signing-api";
import { usePdf } from "@/lib/use-pdf";

const ZOOMS = [1, 1.5, 2, 3] as const;

function listPages(pages: number[]): string {
  if (pages.length <= 1) {
    return `page ${pages[0] ?? 1}`;
  }
  return `pages ${pages.slice(0, -1).join(", ")} and ${pages[pages.length - 1]}`;
}

interface ReviewStepProps {
  session: SigningSession;
  /**
   * True when the signer is here for a second look because the document changed under them
   * (another signer signed before they submitted). They are not being told off, and nothing they
   * have entered is lost: the fields they filled in are still in the draft.
   */
  changed?: boolean;
  onContinue: () => void;
}

export function ReviewStep({ session, changed = false, onContinue }: ReviewStepProps) {
  const pageCount = session.envelope.page_count;
  const queryClient = useQueryClient();
  const announce = useAnnounce();
  const viewer = useRef<DocumentViewerHandle>(null);
  const document_ = useQuery(documentQueryOptions());
  const pdf = usePdf(document_.data);
  const [seen, setSeen] = useState<ReadonlySet<number>>(new Set());
  const [current, setCurrent] = useState(1);
  const [zoomIndex, setZoomIndex] = useState(0);
  const [nudge, setNudge] = useState<string | null>(null);
  const [pageFailed, setPageFailed] = useState(false);
  const zoom = ZOOMS[zoomIndex] ?? 1;
  const zoomReadout = useId();

  const viewed = useMutation({
    mutationFn: () => postViewed(pageCount),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: signingKeys.session });
      onContinue();
    },
  });

  const unseen = Array.from({ length: pageCount }, (_, i) => i + 1).filter((p) => !seen.has(p));
  const allSeen = unseen.length === 0;

  const handleSeen = (next: ReadonlySet<number>) => {
    setSeen(next);
    if (next.size >= pageCount) {
      setNudge(null);
      announce("You have seen every page. You can continue when you are ready.");
    }
  };

  const changeZoom = (step: -1 | 1) => {
    const next = zoomIndex + step;
    if (next < 0 || next >= ZOOMS.length) {
      announce(
        step === 1
          ? "The document is already at the largest size."
          : "The document is already at the smallest size.",
      );
      return;
    }
    setZoomIndex(next);
    announce(`Zoom ${Math.round((ZOOMS[next] ?? 1) * 100)} percent.`);
  };

  const goTo = (page: number) => {
    const target = Math.min(pageCount, Math.max(1, page));
    viewer.current?.goToPage(target);
    announce(`Page ${target} of ${pageCount}`);
  };

  const handleContinue = () => {
    if (!allSeen) {
      const first = unseen[0] ?? 1;
      setNudge(`Please look at ${listPages(unseen)} before you continue.`);
      viewer.current?.goToPage(first);
      return;
    }
    viewed.mutate();
  };

  const failed = document_.isError || pdf.status === "failed" || pageFailed;

  return (
    <StepScreen
      wide
      testId="step-review"
      title="Read the document"
      lead={
        <>
          <p>
            {pageCount === 1 ? "There is one page." : `There are ${pageCount} pages.`} Take as long
            as you need. You can continue once you've seen {pageCount === 1 ? "it" : "them all"}.
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
        </>
      )}

      {viewed.isError ? (
        <Notice tone="error" alert className="mt-5">
          {isNetworkError(viewed.error)
            ? "We couldn't reach the server. Check the connection and press Continue again."
            : "We couldn't record that you've read the document. Scroll through every page once more, then press Continue again."}
        </Notice>
      ) : null}

      {failed ? null : (
        <div className="sticky bottom-0 z-10 -mx-4 mt-6 border-edge border-t bg-paper/95 px-4 pt-3 pb-[max(0.75rem,env(safe-area-inset-bottom))] backdrop-blur-sm sm:-mx-6 sm:px-6">
          {nudge ? (
            <p role="alert" className="mb-2 font-medium text-danger-600">
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
                  onClick={() => current > 1 && goTo(current - 1)}
                >
                  Previous<span className="sr-only"> page</span>
                </Button>
                <Button
                  variant="secondary"
                  className="px-3.5"
                  inert={current >= pageCount}
                  onClick={() => current < pageCount && goTo(current + 1)}
                >
                  Next<span className="sr-only"> page</span>
                </Button>
              </div>
            ) : null}
            <Button
              className="w-full sm:w-auto"
              inert={!allSeen}
              busy={viewed.isPending}
              onClick={handleContinue}
            >
              Continue
            </Button>
          </div>
        </div>
      )}
    </StepScreen>
  );
}
