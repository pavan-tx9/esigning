import { describe, expect, it } from "vitest";
import { describePages, nextUnseenPage, unseenPages } from "@/lib/reading";

describe("nextUnseenPage", () => {
  it("is null once every page has been seen", () => {
    expect(nextUnseenPage(new Set([1, 2, 3]), 3, 2)).toBeNull();
  });

  it("goes on down the document from where the reader is", () => {
    expect(nextUnseenPage(new Set([1, 2, 3, 5]), 8, 3)).toBe(4);
    expect(nextUnseenPage(new Set([1, 2, 3, 4]), 8, 4)).toBe(5);
  });

  it("goes back for a page a fling skipped once everything below is seen", () => {
    // Pages 5 and 6 were flung past; the reader is now on the last page.
    expect(nextUnseenPage(new Set([1, 2, 3, 4, 7, 8]), 8, 8)).toBe(5);
  });

  it("after a fling, presses land on each remaining page in turn", () => {
    const pageCount = 22;
    const seen = new Set([1]);
    let current = 22;
    let presses = 0;
    for (let next = nextUnseenPage(seen, pageCount, current); next !== null; ) {
      presses += 1;
      current = next;
      seen.add(next); // the reader looks at the page the button took them to
      next = nextUnseenPage(seen, pageCount, current);
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
