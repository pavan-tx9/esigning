import { useQuery } from "@tanstack/react-query";
import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
} from "react";
import { createPortal } from "react-dom";
import { DocumentViewer, type DocumentViewerHandle } from "@/components/DocumentViewer";
import { Button, CheckIcon, IconButton, useAnnounce } from "@/components/ui";
import { type Draft, isFieldComplete, isMarkField } from "@/flow/draft";
import { MarkPreview } from "@/flow/steps/MarkPreview";
import { documentQueryOptions, isNetworkError, type SigningSession } from "@/lib/signing-api";
import { type PdfState, usePdf } from "@/lib/use-pdf";

const ZOOMS = [1, 1.5, 2, 3] as const;

export interface Workspace {
  pdf: PdfState;
  /** Pages the tracker has counted as displayed, for this document only. */
  seen: ReadonlySet<number>;
  /** The consent block under the last page has been on screen. */
  reachedEnd: boolean;
  /**
   * The page count to gate on: the loaded PDF's length once it is ready, otherwise the
   * session's. `pageCountMismatch` is set when those two disagree.
   */
  pageCount: number;
  pageCountMismatch: boolean;
  /** The page with the most of itself on screen. */
  current: number;
  /**
   * Scroll to a page and say so. `silent` when the move is the screen's own, not the reader's.
   */
  goToPage: (page: number, options?: { silent?: boolean }) => void;
  /** Scroll to what sits under the last page: the consent block. */
  goToEnd: () => void;
  /** Where a step may put something before the first page, in the same scroll. */
  leadingNode: HTMLElement | null;
  /** Where a step may put something after the last page, in the same scroll. */
  trailingNode: HTMLElement | null;
  /** The bytes or a page could not be shown. The document cell says so and offers a retry. */
  documentFailed: boolean;
}

const WorkspaceContext = createContext<Workspace | null>(null);

export function useWorkspace(): Workspace {
  const value = useContext(WorkspaceContext);
  if (value === null) {
    throw new Error("useWorkspace must be used inside DocumentWorkspace");
  }
  return value;
}

interface DocumentWorkspaceProps {
  session: SigningSession;
  step: "read" | "sign";
  /** The document identity changed (new bytes, a retry): forget that viewed was posted. */
  onReviewReset: () => void;
  /** What the signer has placed so far: shown in the fields' boxes on the page itself. */
  draft: Draft;
  /** The top bar's slot for the document controls (zoom), owned by the shell. */
  toolbarNode: HTMLElement | null;
  hidden?: boolean;
  children: ReactNode;
}

/**
 * The document, and the two screens that happen around it (addendum 3 A: Read, then Sign).
 *
 * One viewer for both, kept mounted across the step change, so what was drawn while reading is
 * still drawn while signing and nothing is fetched or parsed twice. The step decides what sits
 * beside and under it: Read puts the consent block under the last page and its progress in the
 * bar; Sign puts its panel beside the document on a wide frame and over it on a narrow one.
 */
export function DocumentWorkspace({
  session,
  step,
  onReviewReset,
  draft,
  toolbarNode,
  hidden = false,
  children,
}: DocumentWorkspaceProps) {
  const sessionPageCount = session.envelope.page_count;
  const announce = useAnnounce();
  const viewer = useRef<DocumentViewerHandle>(null);
  const document_ = useQuery(documentQueryOptions());
  const pdf = usePdf(document_.data);
  const loadedPageCount =
    pdf.status === "ready" && pdf.pdf.pages.length > 0 ? pdf.pdf.pages.length : null;
  const pageCountMismatch = loadedPageCount !== null && loadedPageCount !== sessionPageCount;
  const pageCount = loadedPageCount ?? sessionPageCount;
  const [seen, setSeen] = useState<ReadonlySet<number>>(() => new Set());
  const [reachedEnd, setReachedEnd] = useState(false);
  const [current, setCurrent] = useState(1);
  const [zoomIndex, setZoomIndex] = useState(0);
  const [pageFailed, setPageFailed] = useState(false);
  const [leadingNode, setLeadingNode] = useState<HTMLElement | null>(null);
  const [trailingNode, setTrailingNode] = useState<HTMLElement | null>(null);
  const zoom = ZOOMS[zoomIndex] ?? 1;
  const zoomReadout = useId();
  const [generation, setGeneration] = useState(0);
  const lastLoadedAt = useRef(0);
  /**
   * The viewer's own state (drawn pages, the tracker) is per document. A new generation is only
   * started when bytes we already had are replaced -- a retry after a failed fetch, or a new
   * revision. The first arrival of the PDF must not wipe pages the tracker has already counted.
   */
  useEffect(() => {
    if (document_.data === undefined) {
      return;
    }
    if (lastLoadedAt.current === 0) {
      lastLoadedAt.current = document_.dataUpdatedAt;
      return;
    }
    if (document_.dataUpdatedAt === lastLoadedAt.current) {
      return;
    }
    lastLoadedAt.current = document_.dataUpdatedAt;
    setGeneration((n) => n + 1);
    setSeen(new Set());
    setReachedEnd(false);
    setCurrent(1);
    onReviewReset();
  }, [document_.data, document_.dataUpdatedAt, onReviewReset]);
  const viewerKey = `${session.envelope.id}:${generation}`;

  const goToPage = useCallback(
    (page: number, options: { silent?: boolean } = {}) => {
      const target = Math.min(pageCount, Math.max(1, page));
      viewer.current?.goToPage(target);
      if (!options.silent) {
        announce(`Page ${target} of ${pageCount}`);
      }
    },
    [pageCount, announce],
  );
  const goToEnd = useCallback(() => viewer.current?.goToEnd(), []);

  const changeZoom = (direction: -1 | 1) => {
    const next = zoomIndex + direction;
    if (next < 0 || next >= ZOOMS.length) {
      // The buttons go inert at either end of the scale. Nothing is missing and nothing is on
      // screen to say so, so the answer is spoken: a sighted user sees the readout stop moving.
      announce(
        direction === 1
          ? "The document is already at the largest size."
          : "The document is already at the smallest size.",
      );
      return;
    }
    setZoomIndex(next);
    announce(`Zoom ${Math.round((ZOOMS[next] ?? 1) * 100)} percent.`);
  };

  const documentFailed = document_.isError || pdf.status === "failed" || pageFailed;
  // Below this the sign panel takes the document's place (styles.css), and a zoom control for a
  // document nobody can see is a control that does nothing.
  const wide = useMediaQuery("(min-width: 1024px)");
  const documentShown = !hidden && !documentFailed && (step === "read" || wide);

  const workspace = useMemo<Workspace>(
    () => ({
      pdf,
      seen,
      reachedEnd,
      pageCount,
      pageCountMismatch,
      current,
      goToPage,
      goToEnd,
      leadingNode,
      trailingNode,
      documentFailed,
    }),
    [
      pdf,
      seen,
      reachedEnd,
      pageCount,
      pageCountMismatch,
      current,
      goToPage,
      goToEnd,
      leadingNode,
      trailingNode,
      documentFailed,
    ],
  );

  const fieldDone = (field: SigningSession["fields"][number]) =>
    draft.values[field.id] !== undefined && isFieldComplete(field, draft.values[field.id], draft);
  const fieldContent = (field: SigningSession["fields"][number]) => {
    const value = draft.values[field.id];
    if (value?.type === "mark" && draft.adopted !== null && isMarkField(field)) {
      return (
        <MarkPreview
          adopted={draft.adopted}
          kind={field.type === "initials" ? "initials" : "signature"}
          initials={draft.initials}
          displayName={session.signer.display_name}
          context="page"
        />
      );
    }
    if (value?.type === "checkbox" && value.checked) {
      return <CheckIcon className="text-page-ink" />;
    }
    if (value?.type === "text") {
      return (
        <span className="line-clamp-2 self-start px-1 text-left text-[0.7rem] text-page-ink leading-tight">
          {value.text}
        </span>
      );
    }
    return null;
  };

  return (
    <WorkspaceContext.Provider value={workspace}>
      <div className="workspace" data-step={step} data-testid="workspace" hidden={hidden}>
        {documentFailed ? (
          <div className="doc-scroller" data-scroll-region>
            <div className="mx-auto max-w-md px-4 py-8" role="alert">
              <p className="font-semibold text-ink-900">We couldn't show the document.</p>
              <p className="mt-1 text-ink-700 text-sm">
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
            </div>
          </div>
        ) : (
          <DocumentViewer
            key={viewerKey}
            ref={viewer}
            pdf={pdf.status === "ready" ? pdf.pdf : null}
            pageCount={pageCount}
            fields={session.fields}
            zoom={zoom}
            onSeen={setSeen}
            onReachedEnd={setReachedEnd}
            onCurrentPage={setCurrent}
            onPageFailed={() => setPageFailed(true)}
            fieldDone={fieldDone}
            fieldContent={fieldContent}
            leading={<div ref={setLeadingNode} />}
            trailing={<div ref={setTrailingNode} />}
          />
        )}
        {children}
      </div>
      {/* The zoom lives in the shell's top bar, beside the title, but it is this workspace's
          state: rendered there through a portal rather than lifted out of here. The level is read
          out on every change and named by both buttons, so someone who cannot see the page still
          knows where the zoom stands and when a press did nothing. */}
      {toolbarNode !== null && documentShown
        ? createPortal(
            <div className="flex items-center gap-1" data-testid="zoom-controls">
              <span
                id={zoomReadout}
                data-testid="zoom-level"
                className="mr-1 hidden text-ink-700 text-xs tabular-nums sm:inline"
              >
                <span className="sr-only">Zoom </span>
                {Math.round(zoom * 100)}%
              </span>
              <IconButton
                aria-label="Make the document smaller"
                aria-describedby={zoomReadout}
                inert={zoomIndex === 0}
                onInertClick={() => changeZoom(-1)}
                onClick={() => changeZoom(-1)}
              >
                <Glyph d="M5 10h10" />
              </IconButton>
              <IconButton
                aria-label="Make the document larger"
                aria-describedby={zoomReadout}
                inert={zoomIndex === ZOOMS.length - 1}
                onInertClick={() => changeZoom(1)}
                onClick={() => changeZoom(1)}
              >
                <Glyph d="M10 5v10M5 10h10" />
              </IconButton>
            </div>,
            toolbarNode,
          )
        : null}
      {/* Zero-height stand-in so the readout can be described even when the toolbar is not
          mounted yet (a test, a frame with no top bar). */}
      {toolbarNode === null ? <span id={zoomReadout} className="sr-only" /> : null}
    </WorkspaceContext.Provider>
  );
}

/** Whether a media query matches now, following it as the frame is resized. */
function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(
    () => typeof window.matchMedia !== "function" || window.matchMedia(query).matches,
  );
  useEffect(() => {
    if (typeof window.matchMedia !== "function") {
      return;
    }
    const list = window.matchMedia(query);
    const update = () => setMatches(list.matches);
    update();
    // A stand-in `matchMedia` (a test's) may answer without ever changing.
    if (typeof list.addEventListener !== "function") {
      return;
    }
    list.addEventListener("change", update);
    return () => list.removeEventListener("change", update);
  }, [query]);
  return matches;
}

/** A 20x20 stroke glyph for the icon buttons. */
export function Glyph({ d }: { d: string }) {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 20 20"
      className="size-4 fill-none stroke-current"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d={d} />
    </svg>
  );
}
