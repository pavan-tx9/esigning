import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DWELL_MS, isSubstantiallyVisible, PagesSeenTracker } from "@/lib/pages-seen";

describe("has this page actually been displayed?", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("counts a page only once it is drawn, on screen, and has stayed there", () => {
    const seen = vi.fn();
    const tracker = new PagesSeenTracker(seen);
    tracker.setVisible(1, true);
    vi.advanceTimersByTime(DWELL_MS * 3);
    expect(seen).not.toHaveBeenCalled(); // a blank placeholder is not the document

    tracker.setRendered(1, true);
    vi.advanceTimersByTime(DWELL_MS - 1);
    expect(seen).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(seen).toHaveBeenCalledExactlyOnceWith(1, new Set([1]));
  });

  it("does not count pages flung past", () => {
    const seen = vi.fn();
    const tracker = new PagesSeenTracker(seen);
    for (const page of [1, 2, 3]) {
      tracker.setRendered(page, true);
      tracker.setVisible(page, true);
      vi.advanceTimersByTime(100);
      tracker.setVisible(page, false);
    }
    vi.advanceTimersByTime(DWELL_MS * 2);
    expect(seen).not.toHaveBeenCalled();
  });

  it("reports each page once and accumulates", () => {
    const seen = vi.fn();
    const tracker = new PagesSeenTracker(seen);
    for (const page of [1, 2]) {
      tracker.setRendered(page, true);
      tracker.setVisible(page, true);
    }
    vi.advanceTimersByTime(DWELL_MS);
    tracker.setVisible(1, false);
    tracker.setVisible(1, true);
    vi.advanceTimersByTime(DWELL_MS);
    expect(seen).toHaveBeenCalledTimes(2);
    expect(seen).toHaveBeenLastCalledWith(2, new Set([1, 2]));
  });

  it("stops counting after dispose", () => {
    const seen = vi.fn();
    const tracker = new PagesSeenTracker(seen);
    tracker.setRendered(1, true);
    tracker.setVisible(1, true);
    tracker.dispose();
    vi.advanceTimersByTime(DWELL_MS * 2);
    expect(seen).not.toHaveBeenCalled();
  });

  it("treats a zoomed page that fills the screen as visible", () => {
    expect(isSubstantiallyVisible(0.6, 300, 800)).toBe(true);
    expect(isSubstantiallyVisible(0.2, 500, 800)).toBe(true);
    expect(isSubstantiallyVisible(0.2, 200, 800)).toBe(false);
  });
});
