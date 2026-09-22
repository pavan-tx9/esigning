import { useEffect, useLayoutEffect, useState } from "react";
import { type LoadedPdf, loadPdf } from "@/lib/pdf";

export type PdfState =
  | { status: "loading" }
  | { status: "ready"; pdf: LoadedPdf }
  | { status: "failed" };

/**
 * Parse bytes that are already in the query cache. This is not server state: no request is made
 * here, it is the (async) decoding of data TanStack Query already holds.
 */
export function usePdf(bytes: Uint8Array | undefined): PdfState {
  const [state, setState] = useState<PdfState>({ status: "loading" });
  useEffect(() => {
    if (bytes === undefined) {
      return;
    }
    let cancelled = false;
    let loaded: LoadedPdf | null = null;
    setState({ status: "loading" });
    loadPdf(bytes).then(
      (pdf) => {
        if (cancelled) {
          pdf.destroy();
          return;
        }
        loaded = pdf;
        setState({ status: "ready", pdf });
      },
      () => {
        if (!cancelled) {
          setState({ status: "failed" });
        }
      },
    );
    return () => {
      cancelled = true;
      (loaded as LoadedPdf | null)?.destroy();
    };
  }, [bytes]);
  return state;
}

/**
 * Width of an element's content box, kept current. Measured in a layout effect, before the
 * browser paints: everything sized from it (the close-up of a field, a page of the document)
 * would otherwise be painted once at zero width, which reads as a blank box where the document
 * should be.
 */
export function useMeasuredWidth<T extends HTMLElement>(): [(node: T | null) => void, number] {
  const [node, setNode] = useState<T | null>(null);
  const [width, setWidth] = useState(0);
  useLayoutEffect(() => {
    if (node === null) {
      return;
    }
    const measure = () => setWidth(Math.floor(node.clientWidth));
    measure();
    if (typeof ResizeObserver === "undefined") {
      return;
    }
    const observer = new ResizeObserver(measure);
    observer.observe(node);
    return () => observer.disconnect();
  }, [node]);
  return [setNode, width];
}
