/**
 * pdf.js, loaded on demand and configured once. The worker is bundled from node_modules by Vite
 * (`?url`), so nothing is fetched from a CDN and the strict CSP holds. The legacy build is used
 * on purpose: clinic tablets are not always on a current browser.
 */

import type { PDFDocumentProxy } from "pdfjs-dist/legacy/build/pdf.mjs";
import type { PageSize } from "@/lib/geometry";

export type { PDFDocumentProxy, PDFPageProxy, RenderTask } from "pdfjs-dist/legacy/build/pdf.mjs";

export interface LoadedPdf {
  doc: PDFDocumentProxy;
  /** Displayed size of each page in points (after /Rotate), index 0 = page 1. */
  pages: PageSize[];
  destroy: () => void;
}

async function pdfjs() {
  const [lib, worker] = await Promise.all([
    import("pdfjs-dist/legacy/build/pdf.mjs"),
    import("pdfjs-dist/legacy/build/pdf.worker.min.mjs?url"),
  ]);
  lib.GlobalWorkerOptions.workerSrc = worker.default;
  return lib;
}

export async function loadPdf(bytes: Uint8Array): Promise<LoadedPdf> {
  const lib = await pdfjs();
  const task = lib.getDocument({
    // pdf.js hands the buffer to its worker, which detaches it. The cached bytes must survive.
    data: bytes.slice(),
    enableXfa: false,
    disableAutoFetch: true,
    disableStream: true,
    useSystemFonts: true,
  });
  const doc = await task.promise;
  const pages: PageSize[] = [];
  for (let n = 1; n <= doc.numPages; n += 1) {
    const page = await doc.getPage(n);
    const viewport = page.getViewport({ scale: 1 });
    pages.push({ width: viewport.width, height: viewport.height });
  }
  return {
    doc,
    pages,
    destroy: () => {
      void task.destroy();
    },
  };
}

/** Plain text of a page, for screen readers: a canvas says nothing to them. */
export async function pageText(doc: PDFDocumentProxy, pageNumber: number): Promise<string> {
  const page = await doc.getPage(pageNumber);
  const content = await page.getTextContent();
  let text = "";
  for (const item of content.items) {
    if ("str" in item) {
      text += item.str + (item.hasEOL ? "\n" : " ");
    }
  }
  return text.replace(/[ \t]+/g, " ").trim();
}

/** Canvas backing-store scale: sharp on retina, bounded so a phone does not run out of memory. */
export function outputScale(cssWidth: number, cssHeight: number): number {
  const dpr = Math.min(window.devicePixelRatio || 1, 2.5);
  const maxPixels = 9_000_000;
  const wanted = cssWidth * cssHeight * dpr * dpr;
  return wanted <= maxPixels ? dpr : Math.max(1, Math.sqrt(maxPixels / (cssWidth * cssHeight)));
}
