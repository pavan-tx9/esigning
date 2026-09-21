/**
 * A drawn signature is a list of strokes; a stroke is a list of points in CSS pixels. Keeping the
 * points (rather than only pixels on a canvas) is what makes undo, a tight crop and an honest
 * "is this actually a signature" check possible.
 */

export interface Point {
  x: number;
  y: number;
}
export type Stroke = Point[];

export interface Bounds {
  x: number;
  y: number;
  width: number;
  height: number;
}

export const PEN_WIDTH = 2.6;

export function strokeLength(stroke: Stroke): number {
  let total = 0;
  for (let i = 1; i < stroke.length; i += 1) {
    const a = stroke[i - 1];
    const b = stroke[i];
    if (a !== undefined && b !== undefined) {
      total += Math.hypot(b.x - a.x, b.y - a.y);
    }
  }
  return total;
}

export function inkLength(strokes: Stroke[]): number {
  return strokes.reduce((sum, stroke) => sum + strokeLength(stroke), 0);
}

export function strokeBounds(strokes: Stroke[], pad = PEN_WIDTH): Bounds | null {
  let minX = Number.POSITIVE_INFINITY;
  let minY = Number.POSITIVE_INFINITY;
  let maxX = Number.NEGATIVE_INFINITY;
  let maxY = Number.NEGATIVE_INFINITY;
  for (const stroke of strokes) {
    for (const p of stroke) {
      minX = Math.min(minX, p.x);
      minY = Math.min(minY, p.y);
      maxX = Math.max(maxX, p.x);
      maxY = Math.max(maxY, p.y);
    }
  }
  if (!Number.isFinite(minX)) {
    return null;
  }
  return {
    x: minX - pad,
    y: minY - pad,
    width: maxX - minX + pad * 2,
    height: maxY - minY + pad * 2,
  };
}

export type InkProblem = "empty" | "too_small";

/**
 * A blank pad, a stray dot or a short tick is not a signature. The server makes the final call
 * when it sanitises the image; this catches the obvious cases before anything is sent.
 */
export function inkProblem(strokes: Stroke[]): InkProblem | null {
  const drawn = strokes.filter((stroke) => stroke.length > 0);
  if (drawn.length === 0) {
    return "empty";
  }
  const bounds = strokeBounds(drawn, 0);
  if (bounds === null || inkLength(drawn) < 60 || Math.max(bounds.width, bounds.height) < 24) {
    return "too_small";
  }
  return null;
}

/** Drop points that barely moved: steadier lines from a shaky hand, and fewer points to draw. */
export function shouldKeepPoint(last: Point | undefined, next: Point, minDistance = 1.2): boolean {
  return last === undefined || Math.hypot(next.x - last.x, next.y - last.y) >= minDistance;
}

interface PathContext {
  beginPath(): void;
  moveTo(x: number, y: number): void;
  lineTo(x: number, y: number): void;
  quadraticCurveTo(cpx: number, cpy: number, x: number, y: number): void;
  arc(x: number, y: number, r: number, start: number, end: number): void;
  stroke(): void;
  fill(): void;
}

/**
 * Smooth a stroke by curving through the midpoints of consecutive points, with the points
 * themselves as control points. Cheap, stable, and it has no overshoot.
 */
export function traceStroke(ctx: PathContext, stroke: Stroke, dx = 0, dy = 0, scale = 1): void {
  const first = stroke[0];
  if (first === undefined) {
    return;
  }
  const at = (p: Point): Point => ({ x: (p.x - dx) * scale, y: (p.y - dy) * scale });
  if (stroke.length === 1) {
    const dot = at(first);
    ctx.beginPath();
    ctx.arc(dot.x, dot.y, (PEN_WIDTH * scale) / 2, 0, Math.PI * 2);
    ctx.fill();
    return;
  }
  ctx.beginPath();
  const start = at(first);
  ctx.moveTo(start.x, start.y);
  for (let i = 1; i < stroke.length - 1; i += 1) {
    const current = stroke[i];
    const next = stroke[i + 1];
    if (current === undefined || next === undefined) {
      continue;
    }
    const c = at(current);
    const n = at(next);
    ctx.quadraticCurveTo(c.x, c.y, (c.x + n.x) / 2, (c.y + n.y) / 2);
  }
  const last = stroke[stroke.length - 1];
  if (last !== undefined) {
    const end = at(last);
    ctx.lineTo(end.x, end.y);
  }
  ctx.stroke();
}

export interface ExportedSignature {
  dataUrl: string;
  base64: string;
  width: number;
  height: number;
}

/**
 * Render the strokes onto a fresh transparent canvas cropped to the ink, at a fixed resolution
 * that does not depend on the device's pixel ratio. Always dark ink: it is stamped onto a white
 * page whatever theme the pad was drawn in. Throws on an empty or too-small drawing.
 */
export function exportSignaturePng(strokes: Stroke[], ink = "#1b1f4a"): ExportedSignature {
  if (inkProblem(strokes) !== null) {
    throw new Error("nothing to export");
  }
  const bounds = strokeBounds(strokes);
  if (bounds === null) {
    throw new Error("nothing to export");
  }
  // Aim for ~900px on the long side: plenty for print, small enough for the upload limit.
  const scale = Math.min(4, Math.max(1, 900 / Math.max(bounds.width, bounds.height)));
  const canvas = document.createElement("canvas");
  canvas.width = Math.ceil(bounds.width * scale);
  canvas.height = Math.ceil(bounds.height * scale);
  const ctx = canvas.getContext("2d");
  if (ctx === null) {
    throw new Error("canvas unavailable");
  }
  ctx.lineCap = "round";
  ctx.lineJoin = "round";
  ctx.lineWidth = PEN_WIDTH * scale;
  ctx.strokeStyle = ink;
  ctx.fillStyle = ink;
  for (const stroke of strokes) {
    traceStroke(ctx, stroke, bounds.x, bounds.y, scale);
  }
  const dataUrl = canvas.toDataURL("image/png");
  return {
    dataUrl,
    base64: dataUrl.slice(dataUrl.indexOf(",") + 1),
    width: canvas.width,
    height: canvas.height,
  };
}
