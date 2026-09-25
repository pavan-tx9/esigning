import {
  type ReactNode,
  type Ref,
  useCallback,
  useEffect,
  useImperativeHandle,
  useMemo,
  useRef,
  useState,
} from "react";
import { PdfPage } from "@/components/PdfPage";
import { prefersReducedMotion, useStableCallback } from "@/components/ui";
import type { PageSize } from "@/lib/geometry";
import { rectToPercentBox } from "@/lib/geometry";
import { isSubstantiallyVisible, PagesSeenTracker } from "@/lib/pages-seen";
import { LETTER_SIZE, type LoadedPdf, type PDFDocumentProxy, pageText } from "@/lib/pdf";
import {
  pagePixels,
  RENDER_AHEAD_PX,
  readingWidth,
  retainedWindow,
  shouldRetain,
} from "@/lib/render-budget";
import type { SigningField } from "@/lib/signing-api";

export interface DocumentViewerHandle {
  /** Scroll a page to the top of the region. `focus` moves keyboard focus onto it as well. */
  goToPage: (page: number, options?: { focus?: boolean }) => void;
  /** Scroll whatever sits under the last page (the consent block) into view. */
  goToEnd: () => void;
}

export interface DocumentViewerProps {
  /** Null while the bytes are being fetched or parsed: the pages are drawn as skeletons. */
  pdf: LoadedPdf | null;
  /** From the session, so the document has its length before the bytes arrive. */
  pageCount: number;
  fields: SigningField[];
  zoom: number;
  onSeen: (seen: ReadonlySet<number>) => void;
  onCurrentPage: (page: number) => void;
  onPageFailed: () => void;
  /** What sits in a field's box on the page: the applied mark, once there is one. */
  fieldContent?: (field: SigningField) => ReactNode;
  fieldDone?: (field: SigningField) => boolean;
  /** Before the first page, in the same scroll. */
  leading?: ReactNode;
  /** After the last page, in the same scroll: the consent block. */
  trailing?: ReactNode;
  ref?: Ref<DocumentViewerHandle>;
}

const RATIO_STEPS = Array.from({ length: 21 }, (_, i) => i / 20);
/** Space either side of the page column, so the paper never touches the frame's edge. */
const GUTTER = 16;

/**
 * The document, one page under another, in the one region of the frame that scrolls. Pages are
 * drawn as they come near the screen, a few at a time and nearest first, and kept while they
 * stay within a bounded neighbourhood of where the reader is. Each is reported as seen only
 * after it has been drawn and looked at.
 *
 * The scroll container is this component, not the window: the frame it lives in is a fixed
 * size, so the page can never grow to make the whole document "visible" at once.
 */
export function DocumentViewer(props: DocumentViewerProps) {
  // Everything below is per document -- what is drawn, what is near, the text for screen
  // readers, the heights, the seen tracker -- and a new document (the bytes arriving, or the
  // document moving on under the signer) must start all of it again. Keying the whole thing on
  // the document is what guarantees that no state of one revision survives into the next.
  const serial = useRef(0);
  const lastDoc = useRef<PDFDocumentProxy | null | undefined>(undefined);
  const doc = props.pdf?.doc ?? null;
  if (lastDoc.current !== doc) {
    lastDoc.current = doc;
    serial.current += 1;
  }
  return <DocumentViewerForDocument key={serial.current} {...props} />;
}

function DocumentViewerForDocument({
  pdf,
  pageCount,
  fields,
  zoom,
  onSeen,
  onCurrentPage,
  onPageFailed,
  fieldContent,
  fieldDone,
  leading,
  trailing,
  ref,
}: DocumentViewerProps) {
  const [scroller, setScroller] = useState<HTMLElement | null>(null);
  const [frameWidth, setFrameWidth] = useState(0);
  const [near, setNear] = useState<ReadonlySet<number>>(new Set([1]));
  const [rendered, setRendered] = useState<ReadonlySet<number>>(new Set());
  const [texts, setTexts] = useState<Record<number, string>>({});
  const pageNodes = useRef(new Map<number, HTMLElement>());
  const observers = useRef<{ nearby: IntersectionObserver; visible: IntersectionObserver } | null>(
    null,
  );
  const heights = useRef(new Map<number, number>());
  const current = useRef(1);
  const reportSeen = useStableCallback(onSeen);
  const reportCurrent = useStableCallback(onCurrentPage);

  const sizes: PageSize[] = useMemo(
    () => pdf?.pages ?? Array.from({ length: pageCount }, () => LETTER_SIZE),
    [pdf, pageCount],
  );
  const doc = pdf?.doc ?? null;

  // One tracker for the life of this document (the component is keyed on it, above).
  const tracker = useMemo(() => new PagesSeenTracker((_, seen) => reportSeen(seen)), [reportSeen]);
  useEffect(() => () => tracker.dispose(), [tracker]);
  /** Text requests already made, so a page near the screen is not asked for twice. */
  const textRequests = useRef(new Set<number>());

  useEffect(() => {
    if (scroller === null) {
      return;
    }
    const measure = () => setFrameWidth(Math.max(0, Math.floor(scroller.clientWidth) - GUTTER * 2));
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(scroller);
    return () => observer.disconnect();
  }, [scroller]);

  useEffect(() => {
    if (frameWidth === 0 || scroller === null) {
      return;
    }
    const pageOf = (target: Element) => Number((target as HTMLElement).dataset.page);
    const nearby = new IntersectionObserver(
      (entries) => {
        setNear((previous) => {
          const next = new Set(previous);
          for (const entry of entries) {
            const page = pageOf(entry.target);
            if (entry.isIntersecting) {
              next.add(page);
            } else {
              next.delete(page);
            }
          }
          return next;
        });
      },
      { root: scroller, rootMargin: `${RENDER_AHEAD_PX}px 0px` },
    );
    const visible = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          const page = pageOf(entry.target);
          const rootHeight = entry.rootBounds?.height ?? scroller.clientHeight;
          heights.current.set(page, entry.isIntersecting ? entry.intersectionRect.height : 0);
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
        if (best > 0 && best !== current.current) {
          current.current = best;
          reportCurrent(best);
        }
      },
      { root: scroller, threshold: RATIO_STEPS },
    );
    observers.current = { nearby, visible };
    for (const node of pageNodes.current.values()) {
      nearby.observe(node);
      visible.observe(node);
    }
    return () => {
      observers.current = null;
      nearby.disconnect();
      visible.disconnect();
      // Nothing is on screen once nobody is watching: a dwell timer that was running when the
      // pages went behind a sheet, or lost their width, must not complete in the dark.
      for (const page of pageNodes.current.keys()) {
        tracker.setVisible(page, false);
      }
      heights.current.clear();
    };
  }, [frameWidth, tracker, reportCurrent, scroller]);

  // A text rendering of each page for screen readers, fetched once the page is near.
  useEffect(() => {
    if (doc === null) {
      return;
    }
    for (const page of near) {
      if (textRequests.current.has(page)) {
        continue;
      }
      textRequests.current.add(page);
      pageText(doc, page).then(
        (text) => setTexts((previous) => ({ ...previous, [page]: text })),
        () => textRequests.current.delete(page),
      );
    }
  }, [near, doc]);

  const scrollTo = useCallback(
    (node: HTMLElement) => {
      if (scroller === null) {
        return;
      }
      const top = node.offsetTop - GUTTER;
      if (typeof scroller.scrollTo === "function") {
        scroller.scrollTo({ top, behavior: prefersReducedMotion() ? "auto" : "smooth" });
      } else {
        scroller.scrollTop = top;
      }
    },
    [scroller],
  );

  useImperativeHandle(
    ref,
    () => ({
      goToPage: (page: number, options = {}) => {
        const node = pageNodes.current.get(page);
        if (node !== undefined) {
          scrollTo(node);
          if (options.focus === true) {
            node.focus({ preventScroll: true });
          }
        }
      },
      goToEnd: () => {
        const node = scroller?.querySelector<HTMLElement>("[data-trailing]");
        if (node !== undefined && node !== null) {
          scrollTo(node);
        }
      },
    }),
    [scrollTo, scroller],
  );

  const pageWidth = readingWidth(frameWidth, zoom);
  const first = sizes[0] ?? LETTER_SIZE;
  const keep = retainedWindow(
    pagePixels(
      pageWidth,
      (pageWidth * first.height) / first.width,
      typeof window === "undefined" ? 1 : window.devicePixelRatio || 1,
    ),
  );

  const onRendered = useCallback(
    (page: number, isRendered: boolean) => {
      tracker.setRendered(page, isRendered);
      setRendered((previous) => {
        if (previous.has(page) === isRendered) {
          return previous;
        }
        const next = new Set(previous);
        if (isRendered) {
          next.add(page);
        } else {
          next.delete(page);
        }
        return next;
      });
    },
    [tracker],
  );

  return (
    <section
      ref={setScroller}
      aria-label={`Document, ${pageCount} ${pageCount === 1 ? "page" : "pages"}`}
      // The region is what scrolls, so it is what the keyboard scrolls: focusable, always, as a
      // scrollable region has to be for arrow and page keys to reach it.
      // biome-ignore lint/a11y/noNoninteractiveTabindex: a scroll container must be focusable
      tabIndex={0}
      className="doc-scroller"
      data-testid="document-viewer"
      data-scroll-region
    >
      <div
        className="doc-column"
        style={{ maxWidth: `${Math.max(pageWidth, 320) + GUTTER * 2}px` }}
      >
        {leading}
        <ol className="m-0 flex list-none flex-col gap-3 p-0">
          {sizes.map((size, index) => {
            const pageNumber = index + 1;
            const pageFields = fields.filter((field) => field.page === pageNumber);
            const active =
              near.has(pageNumber) ||
              (rendered.has(pageNumber) && shouldRetain(pageNumber, current.current, keep));
            return (
              <li key={pageNumber}>
                <section
                  ref={(node) => {
                    if (node === null) {
                      pageNodes.current.delete(pageNumber);
                    } else {
                      pageNodes.current.set(pageNumber, node);
                      // A page that arrives after the observers did (the sizes came in from
                      // the document) is watched from the moment it exists.
                      observers.current?.nearby.observe(node);
                      observers.current?.visible.observe(node);
                    }
                  }}
                  data-page={pageNumber}
                  tabIndex={-1}
                  aria-label={`Page ${pageNumber} of ${pageCount}`}
                  className="outline-none"
                >
                  {frameWidth > 0 ? (
                    <PdfPage
                      doc={doc}
                      pageNumber={pageNumber}
                      size={size}
                      width={pageWidth}
                      active={active}
                      priority={() => Math.abs(pageNumber - current.current)}
                      onRendered={onRendered}
                      onFailed={onPageFailed}
                    >
                      {pageFields.map((field) => {
                        const box = rectToPercentBox(field.rect, size);
                        const done = fieldDone?.(field) ?? false;
                        return (
                          <div
                            key={field.id}
                            aria-hidden="true"
                            data-field-mark={field.id}
                            className={`absolute flex items-center justify-center overflow-hidden rounded-sm ${
                              done
                                ? "border-2 border-page-done-edge bg-page-done"
                                : `border-page-mark-edge bg-page-mark ${field.rect.h > 20 ? "border-2 border-dashed" : "border"}`
                            }`}
                            style={{
                              left: `${box.left}%`,
                              top: `${box.top}%`,
                              width: `${box.width}%`,
                              height: `${box.height}%`,
                            }}
                          >
                            {fieldContent?.(field)}
                          </div>
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
        {trailing ? <div data-trailing>{trailing}</div> : null}
      </div>
    </section>
  );
}
