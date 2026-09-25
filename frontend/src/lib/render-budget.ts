/**
 * How big a page is drawn, and how many drawn pages are kept.
 *
 * A page rendered at the full width of a 1440px frame at 2.5x device pixels is a 12-megapixel
 * canvas, and a thirty-page report is thirty of them: the frame stuttered on scroll and a phone
 * ran out of memory. Everything here is a bound, chosen so a page stays sharp to read and the
 * whole document stays within what a clinic tablet can hold.
 */

/** The reading column: wider than this and lines get too long to follow, whatever the frame. */
export const READING_COLUMN_MAX = 900;
/** Device pixels per CSS pixel, at most. Text is sharp at 2; 3 costs more than it shows. */
export const MAX_BACKING_SCALE = 2;
/** Device pixels one page's canvas may hold. About 900 x 1165 CSS pixels at 1.75x. */
export const PAGE_PIXEL_BUDGET = 3_200_000;
/** Device pixels all kept canvases may hold together: a few tens of megabytes at four bytes each. */
export const RETAINED_PIXEL_BUDGET = 40_000_000;
/** How far ahead of and behind the screen pages are drawn, in CSS pixels. */
export const RENDER_AHEAD_PX = 2_000;

/** The CSS width a page is drawn at inside a frame of `frameWidth`, before zoom. */
export function readingWidth(frameWidth: number, zoom: number): number {
  return Math.max(0, Math.min(frameWidth, READING_COLUMN_MAX)) * zoom;
}

/**
 * Canvas backing-store scale for a page of the given CSS size: the device pixel ratio, capped,
 * and reduced further so the canvas stays inside the per-page pixel budget.
 *
 * Never below 1, on purpose: zoomed to 3x a page is nine million CSS pixels and over the budget
 * at any scale, and drawing it blurred would defeat the zoom. The retention window is what
 * bounds memory there -- computed from the same page size, it shrinks to the current page and
 * its neighbours (`retainedWindow`), so a zoomed document holds three canvases, not thirty.
 */
export function backingScale(
  cssWidth: number,
  cssHeight: number,
  devicePixelRatio: number,
): number {
  const wanted = Math.min(Math.max(devicePixelRatio, 1), MAX_BACKING_SCALE);
  const pixels = cssWidth * cssHeight;
  if (pixels <= 0) {
    return wanted;
  }
  const affordable = Math.sqrt(PAGE_PIXEL_BUDGET / pixels);
  return Math.max(1, Math.min(wanted, affordable));
}

/** Device pixels a page drawn at this CSS size will occupy. */
export function pagePixels(cssWidth: number, cssHeight: number, devicePixelRatio: number): number {
  const scale = backingScale(cssWidth, cssHeight, devicePixelRatio);
  return Math.floor(cssWidth * scale) * Math.floor(cssHeight * scale);
}

/**
 * How many pages either side of the current one keep their canvas once drawn. A fling through
 * the document still lands on drawn pages when the reader scrolls back, but a hundred-page
 * document never holds a hundred canvases.
 */
export function retainedWindow(perPagePixels: number): number {
  if (perPagePixels <= 0) {
    return Number.POSITIVE_INFINITY;
  }
  const pages = Math.floor(RETAINED_PIXEL_BUDGET / perPagePixels);
  // At least the current page and its neighbours, however large a page is.
  return Math.max(1, Math.floor((pages - 1) / 2));
}

/** Whether a page already drawn should keep its canvas, given where the reader is. */
export function shouldRetain(page: number, current: number, window: number): boolean {
  return Math.abs(page - current) <= window;
}
