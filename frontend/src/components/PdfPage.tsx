import { type ReactNode, useEffect, useRef, useState } from "react";
import type { PageSize } from "@/lib/geometry";
import { outputScale, type PDFDocumentProxy, type RenderTask } from "@/lib/pdf";

interface PdfPageProps {
  doc: PDFDocumentProxy;
  pageNumber: number;
  size: PageSize;
  /** CSS width to draw at. The height follows from the page's aspect ratio. */
  width: number;
  /** Draw now, or hold a correctly sized blank until the page is near the screen. */
  active: boolean;
  onRendered?: (pageNumber: number) => void;
  onFailed?: (pageNumber: number) => void;
  /** Positioned over the page; percentages inside it are percentages of the page. */
  children?: ReactNode;
}

/**
 * One page on one canvas. The page is always white paper, in light and dark mode alike: it is a
 * picture of the document that will be sealed, not part of the app's chrome.
 */
export function PdfPage({
  doc,
  pageNumber,
  size,
  width,
  active,
  onRendered,
  onFailed,
  children,
}: PdfPageProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [drawnWidth, setDrawnWidth] = useState(0);
  const height = (width * size.height) / size.width;
  const hasDrawn = useRef(false);
  const callbacks = useRef({ onRendered, onFailed });
  callbacks.current = { onRendered, onFailed };

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!active || canvas === null || width <= 0) {
      return;
    }
    let cancelled = false;
    let task: RenderTask | null = null;
    // Redrawing on every pixel of a resize is wasteful; settle first.
    const timer = window.setTimeout(
      async () => {
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
          hasDrawn.current = true;
          setDrawnWidth(width);
          callbacks.current.onRendered?.(pageNumber);
        } catch (error) {
          if (
            !cancelled &&
            !(error instanceof Error && error.name === "RenderingCancelledException")
          ) {
            callbacks.current.onFailed?.(pageNumber);
          }
        }
      },
      hasDrawn.current ? 140 : 0,
    );
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
      task?.cancel();
    };
  }, [doc, pageNumber, width, height, size.width, active]);

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
        <div className="absolute inset-0 grid place-items-center text-[#5b6470] text-base">
          <span className="quiet-pulse">Loading page {pageNumber}</span>
        </div>
      ) : null}
      {children ? <div className="absolute inset-0">{children}</div> : null}
    </div>
  );
}
