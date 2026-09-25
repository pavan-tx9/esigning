import { act, render, screen, waitFor } from "@testing-library/react";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { DocumentViewer } from "@/components/DocumentViewer";
import { LETTER_SIZE, type LoadedPdf, type PDFDocumentProxy } from "@/lib/pdf";

/**
 * The real viewer, in jsdom, with the two browser facilities it needs stood in for: the
 * intersection observers that say what is near and what is on screen, and the width of the
 * region. pdf.js is a fake document whose renders finish when the test says so.
 *
 * What these prove is the rule the signature rests on, at the seams where the review found it
 * could be bent: a page counts as seen only while it is *drawn* and on screen for the dwell.
 * A page whose canvas was released, whose region lost its width (a sheet over it, the frame too
 * narrow for the document beside the sign panel), or which belongs to a previous revision of
 * the document, is not drawn, whatever it was a moment ago.
 */

type IOCallback = (entries: IntersectionObserverEntry[]) => void;

class FakeIntersectionObserver {
  static instances: FakeIntersectionObserver[] = [];
  readonly targets = new Set<Element>();
  constructor(
    readonly callback: IOCallback,
    readonly options: IntersectionObserverInit,
  ) {
    FakeIntersectionObserver.instances.push(this);
  }
  observe(target: Element) {
    this.targets.add(target);
  }
  unobserve(target: Element) {
    this.targets.delete(target);
  }
  disconnect() {
    this.targets.clear();
  }
  takeRecords() {
    return [];
  }
}

class FakeResizeObserver {
  static instances: FakeResizeObserver[] = [];
  constructor(readonly callback: () => void) {
    FakeResizeObserver.instances.push(this);
  }
  observe() {}
  unobserve() {}
  disconnect() {}
}

/** The region's width, as the viewer measures it. Zero is "hidden": pages unmount. */
let regionWidth = 800;
const ROOT_HEIGHT = 800;

/** The last observer of each kind: the viewer makes a new pair whenever its width changes. */
const latest = (kind: "nearby" | "visible") => {
  const wanted = FakeIntersectionObserver.instances.filter((observer) =>
    kind === "nearby" ? observer.options.rootMargin !== undefined : observer.options.threshold,
  );
  const observer = wanted[wanted.length - 1];
  if (observer === undefined) {
    throw new Error(`no ${kind} observer yet`);
  }
  return observer;
};

/** Tell the viewer how much of a page is on screen (or, for `nearby`, whether it is close). */
const intersect = (kind: "nearby" | "visible", page: number, ratio: number) => {
  const target = document.querySelector(`[data-page="${page}"]`);
  if (target === null) {
    throw new Error(`page ${page} is not mounted`);
  }
  act(() => {
    latest(kind).callback([
      {
        target,
        isIntersecting: ratio > 0,
        intersectionRatio: ratio,
        intersectionRect: { height: ROOT_HEIGHT * ratio } as DOMRectReadOnly,
        rootBounds: { height: ROOT_HEIGHT } as DOMRectReadOnly,
        boundingClientRect: {} as DOMRectReadOnly,
        time: 0,
      },
    ]);
  });
};

const resize = (width: number) => {
  regionWidth = width;
  act(() => {
    for (const observer of FakeResizeObserver.instances) {
      observer.callback();
    }
  });
};

/** A stand-in pdf.js document whose renders finish on demand. */
function fakePdf(name: string, pages = 2) {
  const pending: (() => void)[] = [];
  let auto = true;
  const doc = {
    numPages: pages,
    getPage: async (n: number) => ({
      getViewport: ({ scale }: { scale: number }) => ({ width: 612 * scale, height: 792 * scale }),
      render: () => {
        let finish: () => void = () => {};
        const promise = new Promise<void>((resolve) => {
          finish = resolve;
        });
        if (auto) {
          finish();
        } else {
          pending.push(finish);
        }
        return { promise, cancel: () => {} };
      },
      getTextContent: async () => ({
        items: [{ str: `Text of ${name} page ${n}`, hasEOL: false }],
      }),
    }),
  } as unknown as PDFDocumentProxy;
  const pdf: LoadedPdf = {
    doc,
    pages: Array.from({ length: pages }, () => LETTER_SIZE),
    destroy: () => {},
  };
  return {
    pdf,
    /** From now on renders wait until `finishRenders` is called. */
    holdRenders: () => {
      auto = false;
    },
    finishRenders: () => {
      auto = true;
      for (const finish of pending.splice(0)) {
        finish();
      }
    },
  };
}

const drawn = () => document.querySelectorAll("canvas[data-rendered]").length;
const seenSets = (onSeen: ReturnType<typeof vi.fn>) =>
  onSeen.mock.calls.map((call) => [...(call[0] as ReadonlySet<number>)].sort());
const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

let realIO: unknown;
let realRO: unknown;
let realClientWidth: PropertyDescriptor | undefined;

beforeAll(() => {
  realIO = globalThis.IntersectionObserver;
  realRO = globalThis.ResizeObserver;
  globalThis.IntersectionObserver =
    FakeIntersectionObserver as unknown as typeof IntersectionObserver;
  globalThis.ResizeObserver = FakeResizeObserver as unknown as typeof ResizeObserver;
  realClientWidth = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "clientWidth");
  Object.defineProperty(HTMLElement.prototype, "clientWidth", {
    configurable: true,
    get() {
      return regionWidth;
    },
  });
});

afterAll(() => {
  globalThis.IntersectionObserver = realIO as typeof IntersectionObserver;
  globalThis.ResizeObserver = realRO as typeof ResizeObserver;
  if (realClientWidth !== undefined) {
    Object.defineProperty(HTMLElement.prototype, "clientWidth", realClientWidth);
  }
});

let current: ReturnType<typeof fakePdf> | null = null;

beforeEach(() => {
  regionWidth = 800;
  FakeIntersectionObserver.instances = [];
  FakeResizeObserver.instances = [];
  HTMLCanvasElement.prototype.getContext = vi.fn(() => null) as never;
});

afterEach(() => {
  // The render queue is shared by every page on the screen: a render left waiting here would
  // block the next test's pages from ever being drawn.
  current?.finishRenders();
  current = null;
});

function mount(pdf: LoadedPdf, onSeen: ReturnType<typeof vi.fn>) {
  return render(
    <DocumentViewer
      pdf={pdf}
      pageCount={pdf.pages.length}
      fields={[]}
      zoom={1}
      onSeen={onSeen}
      onCurrentPage={() => {}}
      onPageFailed={() => {}}
    />,
  );
}

describe("a page counts as seen only while it is drawn and on screen", () => {
  it("is not counted while its canvas has been released, and counts again once drawn again", async () => {
    const onSeen = vi.fn();
    current = fakePdf("A");
    mount(current.pdf, onSeen);

    // Both pages come near: both are drawn. Only page 1 is looked at.
    intersect("nearby", 1, 1);
    intersect("nearby", 2, 1);
    await waitFor(() => expect(drawn()).toBe(2));
    intersect("visible", 1, 1);
    await waitFor(() => expect(seenSets(onSeen)).toContainEqual([1]), { timeout: 2_000 });

    // The region loses its width -- the paper-path sheet over it, or the sign panel taking a
    // narrow frame -- and every page goes with it, drawn or not.
    resize(0);
    expect(document.querySelectorAll("[data-page] canvas")).toHaveLength(0);

    // Back, but this time the renders take their time: the pages are skeletons.
    current.holdRenders();
    resize(800);
    intersect("nearby", 2, 1);
    intersect("visible", 2, 1);
    expect(drawn()).toBe(0);
    await wait(900);
    // Half a screen of skeleton for longer than the dwell is not "looking at page 2".
    expect(seenSets(onSeen)).not.toContainEqual([1, 2]);

    // Drawn at last, and still on screen: now it counts, after the dwell.
    current.finishRenders();
    await waitFor(() => expect(drawn()).toBeGreaterThan(0));
    await waitFor(() => expect(seenSets(onSeen)).toContainEqual([1, 2]), { timeout: 2_000 });
  });

  it("stops a dwell that was running when the pages went out of sight", async () => {
    const onSeen = vi.fn();
    current = fakePdf("A");
    mount(current.pdf, onSeen);
    intersect("nearby", 2, 1);
    await waitFor(() =>
      expect(document.querySelector('[data-page="2"] canvas[data-rendered]')).not.toBeNull(),
    );
    intersect("visible", 2, 1);
    // Before the dwell is up, a sheet covers the document.
    await wait(200);
    resize(0);
    await wait(900);
    expect(onSeen).not.toHaveBeenCalled();
  });
});

describe("a new document starts again", () => {
  it("forgets the old revision's text, drawings and seen pages", async () => {
    const onSeen = vi.fn();
    current = fakePdf("A");
    const view = mount(current.pdf, onSeen);
    intersect("nearby", 1, 1);
    await waitFor(() => expect(drawn()).toBe(1));
    await screen.findByText("Text of A page 1");
    intersect("visible", 1, 1);
    await waitFor(() => expect(seenSets(onSeen)).toContainEqual([1]), { timeout: 2_000 });
    onSeen.mockClear();

    // The document moved on under the signer: new bytes, new pages, nothing carried over.
    const next = fakePdf("B");
    current.finishRenders();
    current = next;
    next.holdRenders();
    view.rerender(
      <DocumentViewer
        pdf={next.pdf}
        pageCount={2}
        fields={[]}
        zoom={1}
        onSeen={onSeen}
        onCurrentPage={() => {}}
        onPageFailed={() => {}}
      />,
    );
    // A blind signer is not read the old revision while the new one loads.
    expect(screen.queryByText("Text of A page 1")).toBeNull();
    expect(drawn()).toBe(0);

    // The old revision's page 1 was seen; the new one's is not, until drawn and looked at.
    intersect("nearby", 1, 1);
    intersect("visible", 1, 1);
    await wait(900);
    expect(onSeen).not.toHaveBeenCalled();
    next.finishRenders();
    await screen.findByText("Text of B page 1");
    await waitFor(() => expect(seenSets(onSeen)).toContainEqual([1]), { timeout: 2_000 });
  });
});
