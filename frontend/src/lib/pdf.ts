/**
 * pdf.js, loaded on demand and configured once. The worker is bundled from node_modules by Vite
 * (`?url`), so nothing is fetched from a CDN and the strict CSP holds. The legacy build is used
 * on purpose: clinic tablets are not always on a current browser.
 */

import type { PDFDocumentProxy } from "pdfjs-dist/legacy/build/pdf.mjs";
import type { PageSize } from "@/lib/geometry";
import { backingScale } from "@/lib/render-budget";
import { RenderQueue } from "@/lib/render-queue";

export type { PDFDocumentProxy, PDFPageProxy, RenderTask } from "pdfjs-dist/legacy/build/pdf.mjs";

export interface LoadedPdf {
  doc: PDFDocumentProxy;
  /** Displayed size of each page in points (after /Rotate), index 0 = page 1. */
  pages: PageSize[];
  destroy: () => void;
}

/** US Letter, in points: what a page is assumed to be until the document says otherwise. */
export const LETTER_SIZE: PageSize = { width: 612, height: 792 };

/** One queue for every page drawn anywhere on the screen: the document and the close-ups alike. */
export const renderQueue = new RenderQueue(2);

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
    // The bytes are already here in full (`GET /signing/document` is what records that the
    // document was presented, and it is fetched once): there is nothing to stream.
    disableStream: true,
    useSystemFonts: true,
  });
  const doc = await task.promise;
  // Page sizes are needed before anything is laid out, and they are cheap: asked for together
  // rather than one after another, so a thirty-page report is ready in one round trip to the
  // worker instead of thirty.
  const pages = await Promise.all(
    Array.from({ length: doc.numPages }, async (_, index) => {
      const page = await doc.getPage(index + 1);
      const viewport = page.getViewport({ scale: 1 });
      return { width: viewport.width, height: viewport.height };
    }),
  );
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
  return backingScale(cssWidth, cssHeight, window.devicePixelRatio || 1);
}
