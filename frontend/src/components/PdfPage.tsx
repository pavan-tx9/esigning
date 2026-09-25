import { type ReactNode, useEffect, useRef, useState } from "react";
import type { PageSize } from "@/lib/geometry";
import { outputScale, type PDFDocumentProxy, type RenderTask, renderQueue } from "@/lib/pdf";

interface PdfPageProps {
  doc: PDFDocumentProxy | null;
  pageNumber: number;
  size: PageSize;
  /** CSS width to draw at. The height follows from the page's aspect ratio. */
  width: number;
  /**
   * Draw now, and keep what is drawn. When this goes false the canvas is released: a page far
   * from the reader gives its memory back and shows its skeleton again until it comes near.
   */
  active: boolean;
  /**
   * How urgently this page needs drawing, lower first; asked for when a render slot frees up,
   * so it should say how far the page is from the reader *now*. Zero for a close-up.
   */
  priority?: () => number;
  /** A distinct queue key where one page is drawn in more than one place (the close-ups). */
  queueKey?: string;
  onRendered?: (pageNumber: number, rendered: boolean) => void;
  onFailed?: (pageNumber: number) => void;
  /** Positioned over the page; percentages inside it are percentages of the page. */
  children?: ReactNode;
}

const zero = () => 0;

/**
 * One page on one canvas. The page is always white paper, in light and dark mode alike: it is a
 * picture of the document that will be sealed, not part of the app's chrome.
 *
 * Until it is drawn, the page is a correctly sized sheet with faint lines on it, so the document
 * has its full length from the first frame and nothing below it moves when a page arrives.
 */
export function PdfPage({
  doc,
  pageNumber,
  size,
  width,
  active,
  priority = zero,
  queueKey,
  onRendered,
  onFailed,
  children,
}: PdfPageProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [drawnWidth, setDrawnWidth] = useState(0);
  const height = Math.round((width * size.height) / size.width);
  const hasDrawn = useRef(false);
  const callbacks = useRef({ onRendered, onFailed, priority });
  callbacks.current = { onRendered, onFailed, priority };

  useEffect(() => {
    const canvas = canvasRef.current;
    if (canvas === null || width <= 0) {
      return;
    }
    if (!active || doc === null) {
      // Released: give the memory back and say so, so a page that was "seen" while drawn and is
      // then scrolled far away is not still counted as on screen and drawn.
      if (hasDrawn.current) {
        hasDrawn.current = false;
        canvas.width = 0;
        canvas.height = 0;
        setDrawnWidth(0);
        callbacks.current.onRendered?.(pageNumber, false);
      }
      return;
    }
    let cancelled = false;
    let task: RenderTask | null = null;
    const draw = async () => {
      if (cancelled) {
        return;
      }
      try {
        const page = await doc.getPage(pageNumber);
        if (cancelled) {
          return;
        }
        const cssScale = width / size.width;
        const ratio = outputScale(width, height);
        const viewport = page.getViewport({ scale: cssScale * ratio });
        // Draw off-screen and swap, so a zoom never flashes a blank page.
        const buffer = document.createElement("canvas");
        buffer.width = Math.floor(viewport.width);
        buffer.height = Math.floor(viewport.height);
        task = page.render({ canvas: buffer, viewport, background: "#ffffff" });
        await task.promise;
        if (cancelled) {
          return;
        }
        canvas.width = buffer.width;
        canvas.height = buffer.height;
        canvas.getContext("2d")?.drawImage(buffer, 0, 0);
        // The off-screen copy has done its job: on iOS a canvas keeps its backing store until it
        // is resized, and a dozen of these would count against the page's memory before GC ran.
        buffer.width = 0;
        buffer.height = 0;
        hasDrawn.current = true;
        setDrawnWidth(width);
        callbacks.current.onRendered?.(pageNumber, true);
      } catch (error) {
        if (
          !cancelled &&
          !(error instanceof Error && error.name === "RenderingCancelledException")
        ) {
          callbacks.current.onFailed?.(pageNumber);
        }
      }
    };
    // Redrawing on every pixel of a resize is wasteful; settle first.
    let scheduled: { cancel: () => void } | null = null;
    const timer = window.setTimeout(
      () => {
        scheduled = renderQueue.schedule(
          queueKey ?? `page:${pageNumber}`,
          () => callbacks.current.priority(),
          draw,
        );
      },
      hasDrawn.current ? 140 : 0,
    );
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
      scheduled?.cancel();
      task?.cancel();
    };
  }, [doc, pageNumber, width, height, size.width, active, queueKey]);

  // Going away is a release too. The viewer unmounts its pages whenever it has no width (a
  // sheet over it, the frame too narrow to show the document beside the sign panel), and a page
  // that comes back as a skeleton must not still count as drawn: "seen" is drawn *and* looked at.
  useEffect(
    () => () => {
      if (hasDrawn.current) {
        hasDrawn.current = false;
        callbacks.current.onRendered?.(pageNumber, false);
      }
    },
    [pageNumber],
  );

  return (
    <div
      className="relative overflow-hidden bg-white shadow-sheet"
      style={{ width: `${width}px`, height: `${height}px` }}
    >
      <canvas
        ref={canvasRef}
        role="img"
        aria-label={`Picture of page ${pageNumber}`}
        className="block size-full"
        data-rendered={drawnWidth > 0 || undefined}
      />
      {drawnWidth === 0 ? (
        <div
          aria-hidden="true"
          data-testid="page-skeleton"
          className="page-skeleton absolute inset-0"
          style={{ padding: `${Math.round(width * 0.11)}px ${Math.round(width * 0.1)}px` }}
        />
      ) : null}
      {children ? <div className="absolute inset-0">{children}</div> : null}
    </div>
  );
}
