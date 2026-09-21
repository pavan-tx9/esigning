import { describe, expect, it, vi } from "vitest";
import {
  exportSignaturePng,
  inkLength,
  inkProblem,
  type Stroke,
  shouldKeepPoint,
  strokeBounds,
  traceStroke,
} from "@/lib/strokes";

const wave: Stroke = Array.from({ length: 40 }, (_, i) => ({
  x: 20 + i * 5,
  y: 60 + Math.sin(i / 3) * 25,
}));

describe("is it a signature?", () => {
  it("rejects an empty pad", () => {
    expect(inkProblem([])).toBe("empty");
    expect(inkProblem([[]])).toBe("empty");
  });

  it("rejects a dot, a tick and a tiny scribble", () => {
    expect(inkProblem([[{ x: 5, y: 5 }]])).toBe("too_small");
    expect(
      inkProblem([
        [
          { x: 5, y: 5 },
          { x: 15, y: 12 },
        ],
      ]),
    ).toBe("too_small");
    const scribble: Stroke = Array.from({ length: 80 }, (_, i) => ({
      x: 50 + (i % 2) * 6,
      y: 50 + (i % 3) * 4,
    }));
    expect(inkProblem([scribble])).toBe("too_small");
  });

  it("accepts a real stroke", () => {
    expect(inkProblem([wave])).toBeNull();
    expect(inkLength([wave])).toBeGreaterThan(190);
  });

  it("refuses to export nothing", () => {
    expect(() => exportSignaturePng([])).toThrow();
  });
});

describe("cropping", () => {
  it("bounds hug the ink plus the pen width, wherever on the pad it was drawn", () => {
    const bounds = strokeBounds([wave], 2);
    expect(bounds?.x).toBeCloseTo(18);
    expect(bounds?.width).toBeCloseTo(195 + 4);
    expect(bounds?.height).toBeLessThan(60);
    const shifted = wave.map((p) => ({ x: p.x + 300, y: p.y + 90 }));
    expect(strokeBounds([shifted], 2)?.width).toBeCloseTo(bounds?.width ?? 0);
  });
});

describe("smoothing", () => {
  it("drops points that barely moved", () => {
    expect(shouldKeepPoint(undefined, { x: 0, y: 0 })).toBe(true);
    expect(shouldKeepPoint({ x: 0, y: 0 }, { x: 0.5, y: 0.5 })).toBe(false);
    expect(shouldKeepPoint({ x: 0, y: 0 }, { x: 2, y: 0 })).toBe(true);
  });

  it("curves through midpoints and ends exactly on the last point", () => {
    const ctx = {
      beginPath: vi.fn(),
      moveTo: vi.fn(),
      lineTo: vi.fn(),
      quadraticCurveTo: vi.fn(),
      arc: vi.fn(),
      stroke: vi.fn(),
      fill: vi.fn(),
    };
    traceStroke(
      ctx,
      [
        { x: 10, y: 10 },
        { x: 20, y: 30 },
        { x: 40, y: 10 },
      ],
      10,
      10,
      2,
    );
    expect(ctx.moveTo).toHaveBeenCalledWith(0, 0);
    expect(ctx.quadraticCurveTo).toHaveBeenCalledWith(20, 40, 40, 20);
    expect(ctx.lineTo).toHaveBeenCalledWith(60, 0);
    expect(ctx.stroke).toHaveBeenCalledOnce();
  });

  it("draws a single tap as a dot", () => {
    const ctx = {
      beginPath: vi.fn(),
      moveTo: vi.fn(),
      lineTo: vi.fn(),
      quadraticCurveTo: vi.fn(),
      arc: vi.fn(),
      stroke: vi.fn(),
      fill: vi.fn(),
    };
    traceStroke(ctx, [{ x: 4, y: 4 }]);
    expect(ctx.arc).toHaveBeenCalledOnce();
    expect(ctx.fill).toHaveBeenCalledOnce();
  });
});
