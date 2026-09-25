import { describe, expect, it } from "vitest";
import { describePages, nextUnseenPage, unseenPages } from "@/lib/reading";

describe("nextUnseenPage", () => {
  it("is null once every page has been seen", () => {
    expect(nextUnseenPage(new Set([1, 2, 3]), 3)).toBeNull();
  });

  it("goes on down the document when the reader has read it in order", () => {
    expect(nextUnseenPage(new Set([1, 2, 3]), 8)).toBe(4);
  });

  it("goes back for the first page a fling skipped, wherever the reader is now", () => {
    // Pages 5 and 6 were flung past; the reader is on the last page.
    expect(nextUnseenPage(new Set([1, 2, 3, 4, 7, 8]), 8)).toBe(5);
    // Page 2 was skipped early: it comes before anything further down.
    expect(nextUnseenPage(new Set([1, 7, 8, 9]), 9)).toBe(2);
  });

  it("after a fling, presses land on each remaining page in turn", () => {
    const pageCount = 22;
    const seen = new Set([1]);
    let presses = 0;
    for (let next = nextUnseenPage(seen, pageCount); next !== null; ) {
      presses += 1;
      seen.add(next); // the reader looks at the page the button took them to
      next = nextUnseenPage(seen, pageCount);
    }
    expect(presses).toBe(21);
    expect(unseenPages(seen, pageCount)).toEqual([]);
  });
});

describe("describePages", () => {
  it("names one page, a run, and a short list", () => {
    expect(describePages([7])).toBe("page 7");
    expect(describePages([2, 3, 4, 5])).toBe("pages 2 to 5");
    expect(describePages([2, 5, 6, 9])).toBe("pages 2, 5 to 6 and 9");
  });

  it("cuts a long list short", () => {
    expect(describePages([1, 3, 5, 7, 9, 11])).toBe("pages 1, 3, 5 and 3 more");
  });
});
