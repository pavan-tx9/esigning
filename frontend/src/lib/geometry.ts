/**
 * Field rects arrive in PDF points with the origin at the bottom-left of the displayed page.
 * The screen's origin is top-left. Everything here is expressed as a fraction of the page, so a
 * highlight stays on its field at any zoom, any container width and any device pixel ratio.
 */

import type { Rect } from "@/lib/signing-api";

export interface PageSize {
  width: number;
  height: number;
}

export interface BoxPercent {
  left: number;
  top: number;
  width: number;
  height: number;
}

const clamp = (value: number, min: number, max: number) => Math.min(max, Math.max(min, value));

/** Where a field sits on its page, as percentages of the page box (top-left origin). */
export function rectToPercentBox(rect: Rect, page: PageSize): BoxPercent {
  const left = clamp(rect.x, 0, page.width);
  const right = clamp(rect.x + rect.w, 0, page.width);
  const bottom = clamp(rect.y, 0, page.height);
  const top = clamp(rect.y + rect.h, 0, page.height);
  return {
    left: (left / page.width) * 100,
    top: ((page.height - top) / page.height) * 100,
    width: ((right - left) / page.width) * 100,
    height: ((top - bottom) / page.height) * 100,
  };
}

export interface FieldWindow {
  /** CSS pixels per PDF point. */
  scale: number;
  /** Size of the visible window, CSS pixels. */
  width: number;
  height: number;
  /** How far the full page is shifted inside the window, CSS pixels (both <= 0). */
  offsetX: number;
  offsetY: number;
}

/**
 * A close-up of one field: the page is scaled so the field fills most of the window's width and
 * is centred, without ever showing space beyond the page edge.
 */
export function fieldWindow(
  rect: Rect,
  page: PageSize,
  containerWidth: number,
  maxHeight: number,
): FieldWindow {
  const fit = containerWidth / page.width;
  // Small fields (a 16pt tick box) are shown with their surroundings, not blown up to fill.
  // A label usually sits to the right of a tick box, so the view extends that way.
  const focusW = Math.max(rect.w, 200);
  const wanted = (containerWidth * 0.72) / focusW;
  const scale = clamp(wanted, fit, Math.max(fit, 2.4));
  const pageW = page.width * scale;
  const pageH = page.height * scale;
  const width = Math.min(containerWidth, pageW);
  const height = Math.min(pageH, Math.max(maxHeight, rect.h * scale + 96));
  const centreX = (rect.x + focusW / 2) * scale;
  const centreY = (page.height - rect.y - rect.h / 2) * scale;
  return {
    scale,
    width,
    height,
    offsetX: -clamp(centreX - width / 2, 0, pageW - width),
    offsetY: -clamp(centreY - height / 2, 0, pageH - height),
  };
}

/** Reading order: page, then top to bottom, then left to right. */
export function byReadingOrder(
  a: { page: number; rect: Rect },
  b: { page: number; rect: Rect },
): number {
  if (a.page !== b.page) {
    return a.page - b.page;
  }
  const aTop = a.rect.y + a.rect.h;
  const bTop = b.rect.y + b.rect.h;
  if (Math.abs(aTop - bTop) > 4) {
    return bTop - aTop;
  }
  return a.rect.x - b.rect.x;
}
