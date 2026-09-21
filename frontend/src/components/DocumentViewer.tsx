import { type Ref, useEffect, useImperativeHandle, useMemo, useRef, useState } from "react";
import { PdfPage } from "@/components/PdfPage";
import { prefersReducedMotion, useStableCallback } from "@/components/ui";
import { rectToPercentBox } from "@/lib/geometry";
import { isSubstantiallyVisible, PagesSeenTracker } from "@/lib/pages-seen";
import { type LoadedPdf, pageText } from "@/lib/pdf";
import type { SigningField } from "@/lib/signing-api";

export interface DocumentViewerHandle {
  goToPage: (page: number) => void;
}

export interface DocumentViewerProps {
  pdf: LoadedPdf;
  fields: SigningField[];
  zoom: number;
  onSeen: (seen: ReadonlySet<number>) => void;
  onCurrentPage: (page: number) => void;
  onPageFailed: () => void;
  ref?: Ref<DocumentViewerHandle>;
}

const RATIO_STEPS = Array.from({ length: 21 }, (_, i) => i / 20);

/**
 * The whole document, one page under another, in the normal page scroll (no nested vertical
 * scroller: those are miserable on a phone). Pages are drawn as they come near the screen and
 * each is reported as seen only after it has been drawn and looked at.
 */
export function DocumentViewer({
  pdf,
  fields,
  zoom,
  onSeen,
  onCurrentPage,
  onPageFailed,
  ref,
}: DocumentViewerProps) {
  const [frame, setFrame] = useState<HTMLElement | null>(null);
  const [frameWidth, setFrameWidth] = useState(0);
  const [near, setNear] = useState<ReadonlySet<number>>(new Set([1]));
  const [texts, setTexts] = useState<Record<number, string>>({});
  const pageNodes = useRef(new Map<number, HTMLElement>());
  const heights = useRef(new Map<number, number>());
  const reportSeen = useStableCallback(onSeen);
  const reportCurrent = useStableCallback(onCurrentPage);

  const tracker = useMemo(() => new PagesSeenTracker((_, seen) => reportSeen(seen)), [reportSeen]);
  useEffect(() => () => tracker.dispose(), [tracker]);

  useEffect(() => {
    if (frame === null) {
      return;
    }
    const measure = () => setFrameWidth(Math.floor(frame.clientWidth));
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(frame);
    return () => observer.disconnect();
  }, [frame]);

  const pageCount = pdf.pages.length;

  useEffect(() => {
    if (frameWidth === 0) {
      return;
    }
    const pageOf = (target: Element) => Number((target as HTMLElement).dataset.page);
    const nearby = new IntersectionObserver(
      (entries) => {
        setNear((previous) => {
          const next = new Set(previous);
          for (const entry of entries) {
            if (entry.isIntersecting) {
              next.add(pageOf(entry.target));
            }
          }
          return next.size === previous.size ? previous : next;
        });
      },
      { rootMargin: "900px 0px" },
    );
    const visible = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          const page = pageOf(entry.target);
          const rootHeight = entry.rootBounds?.height ?? window.innerHeight;
          heights.current.set(page, entry.intersectionRect.height);
          tracker.setVisible(
            page,
            entry.isIntersecting &&
              isSubstantiallyVisible(
                entry.intersectionRatio,
                entry.intersectionRect.height,
                rootHeight,
              ),
          );
        }
        let best = 0;
        let bestHeight = 0;
        for (const [page, height] of heights.current) {
          if (height > bestHeight) {
            best = page;
            bestHeight = height;
          }
        }
        if (best > 0) {
          reportCurrent(best);
        }
      },
      { threshold: RATIO_STEPS },
    );
    for (const node of pageNodes.current.values()) {
      nearby.observe(node);
      visible.observe(node);
    }
    return () => {
      nearby.disconnect();
      visible.disconnect();
    };
  }, [frameWidth, tracker, reportCurrent]);

  // A text rendering of each page for screen readers, fetched once the page is near.
  useEffect(() => {
    let cancelled = false;
    for (const page of near) {
      if (texts[page] === undefined) {
        pageText(pdf.doc, page).then(
          (text) => {
            if (!cancelled) {
              setTexts((previous) =>
                previous[page] === undefined ? { ...previous, [page]: text } : previous,
              );
            }
          },
          () => {},
        );
      }
    }
    return () => {
      cancelled = true;
    };
  }, [near, pdf.doc, texts]);

  useImperativeHandle(ref, () => ({
    goToPage: (page: number) => {
      const node = pageNodes.current.get(page);
      if (node !== undefined) {
        node.scrollIntoView({
          behavior: prefersReducedMotion() ? "auto" : "smooth",
          block: "start",
        });
        node.focus({ preventScroll: true });
      }
    },
  }));

  const pageWidth = Math.max(0, frameWidth) * zoom;

  return (
    // When zoomed the region scrolls sideways, so it must be reachable by keyboard to be scrolled.
    <section
      ref={setFrame}
      aria-label={`Document, ${pageCount} ${pageCount === 1 ? "page" : "pages"}`}
      tabIndex={zoom > 1 ? 0 : -1}
      className="overflow-x-auto pb-2"
      data-testid="document-viewer"
    >
      <ol className="flex w-max min-w-full list-none flex-col items-center gap-5 p-0">
        {pdf.pages.map((size, index) => {
          const pageNumber = index + 1;
          const pageFields = fields.filter((field) => field.page === pageNumber);
          return (
            <li key={pageNumber} className="scroll-mt-4">
              <section
                ref={(node) => {
                  if (node === null) {
                    pageNodes.current.delete(pageNumber);
                  } else {
                    pageNodes.current.set(pageNumber, node);
                  }
                }}
                data-page={pageNumber}
                tabIndex={-1}
                aria-label={`Page ${pageNumber} of ${pageCount}`}
                className="scroll-mt-4 outline-none"
              >
                <p aria-hidden="true" className="mb-1.5 text-ink-500 text-sm">
                  Page {pageNumber} of {pageCount}
                </p>
                {frameWidth > 0 ? (
                  <PdfPage
                    doc={pdf.doc}
                    pageNumber={pageNumber}
                    size={size}
                    width={pageWidth}
                    active={near.has(pageNumber)}
                    onRendered={(page) => tracker.setRendered(page, true)}
                    onFailed={onPageFailed}
                  >
                    {pageFields.map((field) => {
                      const box = rectToPercentBox(field.rect, size);
                      return (
                        <div
                          key={field.id}
                          aria-hidden="true"
                          data-field-mark={field.id}
                          className={`absolute rounded-sm border-page-mark-edge bg-page-mark ${
                            field.rect.h > 20 ? "border-2 border-dashed" : "border"
                          }`}
                          style={{
                            left: `${box.left}%`,
                            top: `${box.top}%`,
                            width: `${box.width}%`,
                            height: `${box.height}%`,
                          }}
                        />
                      );
                    })}
                  </PdfPage>
                ) : null}
                <div className="sr-only">
                  {texts[pageNumber] ?? "The text of this page is loading."}
                  {pageFields.length > 0
                    ? ` You will be asked to complete on this page: ${pageFields.map((f) => f.label).join(", ")}.`
                    : ""}
                </div>
              </section>
            </li>
          );
        })}
      </ol>
    </section>
  );
}
