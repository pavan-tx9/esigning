import { describe, expect, it } from "vitest";
import {
  backingScale,
  MAX_BACKING_SCALE,
  PAGE_PIXEL_BUDGET,
  pagePixels,
  READING_COLUMN_MAX,
  readingWidth,
  retainedWindow,
  shouldRetain,
} from "@/lib/render-budget";

describe("readingWidth", () => {
  it("caps a wide frame to the reading column and lets zoom go past it", () => {
    expect(readingWidth(1440, 1)).toBe(READING_COLUMN_MAX);
    expect(readingWidth(1440, 1.5)).toBe(READING_COLUMN_MAX * 1.5);
  });

  it("fills a narrow frame", () => {
    expect(readingWidth(358, 1)).toBe(358);
  });
});

describe("backingScale", () => {
  it("is the device pixel ratio for a phone-sized page", () => {
    expect(backingScale(358, 463, 2)).toBe(2);
    expect(backingScale(358, 463, 3)).toBe(MAX_BACKING_SCALE);
  });

  it("comes down so a full-column page stays inside the pixel budget", () => {
    const scale = backingScale(900, 1165, 2);
    expect(scale).toBeLessThan(2);
    expect(scale).toBeGreaterThan(1.5);
    expect(pagePixels(900, 1165, 2)).toBeLessThanOrEqual(PAGE_PIXEL_BUDGET);
  });

  it("never goes below one, even for a page zoomed far in", () => {
    expect(backingScale(2700, 3495, 2)).toBe(1);
    expect(backingScale(100, 100, 0.5)).toBe(1);
  });
});

describe("retainedWindow", () => {
  it("keeps every page of a short document on a phone", () => {
    const perPage = pagePixels(358, 463, 2);
    expect(retainedWindow(perPage)).toBeGreaterThanOrEqual(11);
  });

  it("keeps a bounded neighbourhood of full-column pages", () => {
    const window = retainedWindow(pagePixels(900, 1165, 2));
    expect(window).toBeGreaterThanOrEqual(4);
    expect(window).toBeLessThan(12);
    expect(shouldRetain(10, 12, window)).toBe(true);
    expect(shouldRetain(1, 12 + window + 1, window)).toBe(false);
  });

  it("always keeps at least the neighbours", () => {
    expect(retainedWindow(Number.MAX_SAFE_INTEGER)).toBe(1);
  });
});
