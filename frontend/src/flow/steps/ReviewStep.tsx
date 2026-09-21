import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
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
  onContinue: () => void;
}

export function ReviewStep({ session, onContinue }: ReviewStepProps) {
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
          <div className="mb-3 flex items-center justify-end gap-2">
            <span className="mr-1 text-ink-700 text-sm" aria-hidden="true">
              Zoom {Math.round(zoom * 100)}%
            </span>
            <Button
              variant="secondary"
              aria-label="Make the document smaller"
              inert={zoomIndex === 0}
              onClick={() => setZoomIndex((i) => Math.max(0, i - 1))}
              className="px-0 text-xl"
            >
              <span aria-hidden="true">−</span>
            </Button>
            <Button
              variant="secondary"
              aria-label="Make the document larger"
              inert={zoomIndex === ZOOMS.length - 1}
              onClick={() => setZoomIndex((i) => Math.min(ZOOMS.length - 1, i + 1))}
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
