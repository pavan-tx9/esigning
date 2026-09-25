/**
 * Reading progress you can see and press: one mark per page, filled once that page counts as
 * seen, with the page on screen outlined. A fling through a long report leaves a row of hollow
 * marks where it went too fast, which is the whole point -- the rule for "seen" is unchanged,
 * and this is how the reader finds out what it decided before they reach the button.
 */

interface PageStripProps {
  pageCount: number;
  seen: ReadonlySet<number>;
  current: number;
  onGo: (page: number) => void;
}

/** Above this many pages the marks are too narrow to press: the strip becomes a plain meter. */
const PRESSABLE_UP_TO = 60;

export function PageStrip({ pageCount, seen, current, onGo }: PageStripProps) {
  if (pageCount <= 1) {
    return null;
  }
  if (pageCount > PRESSABLE_UP_TO) {
    return (
      <div
        role="progressbar"
        aria-label="Pages seen"
        aria-valuemin={0}
        aria-valuemax={pageCount}
        aria-valuenow={seen.size}
        className="h-1.5 w-full overflow-hidden rounded-full bg-edge"
        data-testid="page-strip"
      >
        <div
          className="h-full rounded-full bg-accent-600"
          style={{ width: `${(seen.size / pageCount) * 100}%` }}
        />
      </div>
    );
  }
  return (
    <ol
      aria-label="Pages"
      className="m-0 flex w-full list-none gap-px p-0 sm:gap-0.5"
      data-testid="page-strip"
    >
      {Array.from({ length: pageCount }, (_, index) => {
        const page = index + 1;
        const isSeen = seen.has(page);
        const isCurrent = page === current;
        return (
          <li key={page} className="min-w-0 flex-1">
            <button
              type="button"
              aria-label={`Page ${page}, ${isSeen ? "seen" : "not seen yet"}`}
              aria-current={isCurrent ? "page" : undefined}
              data-seen={isSeen || undefined}
              onClick={() => onGo(page)}
              className="group block w-full cursor-pointer touch-manipulation py-2"
            >
              <span
                className={`block h-1.5 rounded-sm transition-colors ${
                  isSeen ? "bg-accent-600" : "bg-edge group-hover:bg-edge-strong"
                } ${isCurrent ? "outline outline-2 outline-ink-900 outline-offset-1" : ""}`}
              />
            </button>
          </li>
        );
      })}
    </ol>
  );
}
