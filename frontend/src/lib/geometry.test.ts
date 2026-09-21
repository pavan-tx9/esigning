import { describe, expect, it } from "vitest";
import { byReadingOrder, fieldWindow, rectToPercentBox } from "@/lib/geometry";

const LETTER = { width: 612, height: 792 };

describe("PDF rects (origin bottom-left) on screen (origin top-left)", () => {
  it("flips the y axis: a rect near the bottom of the page is near the bottom of the screen", () => {
    const box = rectToPercentBox({ x: 72, y: 120, w: 220, h: 48 }, LETTER);
    expect(box.left).toBeCloseTo((72 / 612) * 100);
    expect(box.top).toBeCloseTo(((792 - 120 - 48) / 792) * 100);
    expect(box.width).toBeCloseTo((220 / 612) * 100);
    expect(box.height).toBeCloseTo((48 / 792) * 100);
  });

  it("is a fraction of the page, so it holds at any zoom", () => {
    const box = rectToPercentBox({ x: 306, y: 396, w: 306, h: 396 }, LETTER);
    expect(box).toEqual({ left: 50, top: 0, width: 50, height: 50 });
    for (const pageWidthPx of [328, 612, 1836]) {
      const px = (box.left / 100) * pageWidthPx;
      expect(px).toBeCloseTo(306 * (pageWidthPx / 612));
    }
  });

  it("uses the displayed page size, so a landscape or rotated page works the same way", () => {
    const box = rectToPercentBox({ x: 0, y: 0, w: 396, h: 306 }, { width: 792, height: 612 });
    expect(box).toEqual({ left: 0, top: 50, width: 50, height: 50 });
  });

  it("clips a rect that overhangs the page rather than drawing outside it", () => {
    const box = rectToPercentBox({ x: 600, y: -10, w: 100, h: 30 }, LETTER);
    expect(box.left + box.width).toBeCloseTo(100);
    expect(box.top + box.height).toBeCloseTo(100);
  });
});

describe("the field close-up", () => {
  it("keeps the whole field inside the window, on a phone and on a tablet", () => {
    const rect = { x: 72, y: 120, w: 220, h: 48 };
    for (const container of [328, 560, 760]) {
      const view = fieldWindow(rect, LETTER, container, 220);
      const left = rect.x * view.scale + view.offsetX;
      const top = (LETTER.height - rect.y - rect.h) * view.scale + view.offsetY;
      expect(left).toBeGreaterThanOrEqual(0);
      expect(left + rect.w * view.scale).toBeLessThanOrEqual(view.width + 0.01);
      expect(top).toBeGreaterThanOrEqual(0);
      expect(top + rect.h * view.scale).toBeLessThanOrEqual(view.height + 0.01);
      expect(view.width).toBeLessThanOrEqual(container);
    }
  });

  it("never shows space beyond the page edge, even for a field in a corner", () => {
    const view = fieldWindow({ x: 540, y: 10, w: 60, h: 20 }, LETTER, 360, 220);
    expect(view.offsetX).toBeLessThanOrEqual(0);
    expect(-view.offsetX + view.width).toBeLessThanOrEqual(LETTER.width * view.scale + 0.01);
    expect(-view.offsetY + view.height).toBeLessThanOrEqual(LETTER.height * view.scale + 0.01);
  });
});

describe("reading order", () => {
  it("goes by page, then down the page, then left to right", () => {
    const fields = [
      { id: "p2", page: 2, rect: { x: 0, y: 700, w: 10, h: 10 } },
      { id: "bottom", page: 1, rect: { x: 0, y: 100, w: 10, h: 10 } },
      { id: "top-right", page: 1, rect: { x: 300, y: 700, w: 10, h: 10 } },
      { id: "top-left", page: 1, rect: { x: 10, y: 702, w: 10, h: 10 } },
    ];
    expect(fields.sort(byReadingOrder).map((f) => f.id)).toEqual([
      "top-left",
      "top-right",
      "bottom",
      "p2",
    ]);
  });
});
