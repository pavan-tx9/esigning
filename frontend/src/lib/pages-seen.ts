/**
 * Which pages has this person actually had in front of them? A page counts once it has been
 * drawn AND has then stayed substantially on screen for a moment. Scrolling past a blank
 * placeholder, or flinging through the document, does not count. The server is told the number
 * of pages seen and refuses to continue unless it equals the page count.
 */

export const DWELL_MS = 700;

/** Is enough of the page on screen? Either half the page, or the page filling half the screen. */
export function isSubstantiallyVisible(
  intersectionRatio: number,
  intersectionHeight: number,
  rootHeight: number,
): boolean {
  if (intersectionRatio >= 0.5) {
    return true;
  }
  return rootHeight > 0 && intersectionHeight >= rootHeight * 0.5;
}

interface PageWatch {
  rendered: boolean;
  visible: boolean;
  timer: ReturnType<typeof setTimeout> | null;
}

export class PagesSeenTracker {
  private readonly pages = new Map<number, PageWatch>();
  private readonly seen = new Set<number>();
  private readonly onSeen: (page: number, seen: ReadonlySet<number>) => void;
  private readonly dwellMs: number;

  constructor(onSeen: (page: number, seen: ReadonlySet<number>) => void, dwellMs = DWELL_MS) {
    this.onSeen = onSeen;
    this.dwellMs = dwellMs;
  }

  private watch(page: number): PageWatch {
    let entry = this.pages.get(page);
    if (entry === undefined) {
      entry = { rendered: false, visible: false, timer: null };
      this.pages.set(page, entry);
    }
    return entry;
  }

  setRendered(page: number, rendered: boolean): void {
    this.watch(page).rendered = rendered;
    this.evaluate(page);
  }

  setVisible(page: number, visible: boolean): void {
    this.watch(page).visible = visible;
    this.evaluate(page);
  }

  private evaluate(page: number): void {
    const entry = this.watch(page);
    const qualifies = entry.rendered && entry.visible && !this.seen.has(page);
    if (qualifies && entry.timer === null) {
      entry.timer = setTimeout(() => {
        entry.timer = null;
        if (entry.rendered && entry.visible && !this.seen.has(page)) {
          this.seen.add(page);
          this.onSeen(page, new Set(this.seen));
        }
      }, this.dwellMs);
    } else if (!qualifies && entry.timer !== null) {
      clearTimeout(entry.timer);
      entry.timer = null;
    }
  }

  dispose(): void {
    for (const entry of this.pages.values()) {
      if (entry.timer !== null) {
        clearTimeout(entry.timer);
      }
    }
    this.pages.clear();
  }
}
