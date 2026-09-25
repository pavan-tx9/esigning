import { type KeyboardEvent, useEffect, useRef, useState } from "react";
import { useMeasuredWidth } from "@/lib/use-pdf";

/**
 * Reading progress you can see and press: one mark per page, filled once that page counts as
 * seen, with the page on screen outlined. A fling through a long report leaves a row of hollow
 * marks where it went too fast, which is the whole point -- the rule for "seen" is unchanged,
 * and this is how the reader finds out what it decided before they reach the button.
 *
 * One tab stop, whatever the page count: the marks are a roving-focus group (arrow keys move
 * between them, Home and End to the ends, Enter or Space goes to the page), so a keyboard user
 * is not walked through sixty buttons between the heading and the primary action. Each mark is
 * at least 24 CSS pixels each way; where the frame is too narrow for that, the strip is a plain
 * meter and the buttons beside it do the navigating.
 */

interface PageStripProps {
  pageCount: number;
  seen: ReadonlySet<number>;
  current: number;
  onGo: (page: number) => void;
}

/** Above this many pages the marks are too narrow to press, whatever the frame. */
const PRESSABLE_UP_TO = 60;
/** The smallest mark that can be pressed (WCAG 2.5.8), in CSS pixels. */
const MIN_TARGET = 24;

export function PageStrip({ pageCount, seen, current, onGo }: PageStripProps) {
  const [measure, width] = useMeasuredWidth<HTMLDivElement>();
  const [focused, setFocused] = useState(current);
  const marks = useRef(new Map<number, HTMLButtonElement>());
  // The roving stop follows the page on screen until the keyboard takes it somewhere else.
  const keyboardMoved = useRef(false);
  useEffect(() => {
    if (!keyboardMoved.current) {
      setFocused(current);
    }
  }, [current]);

  if (pageCount <= 1) {
    return null;
  }
  const pressable = pageCount <= PRESSABLE_UP_TO && width > 0 && width / pageCount >= MIN_TARGET;

  const onKeyDown = (event: KeyboardEvent<HTMLElement>) => {
    const step =
      event.key === "ArrowRight" || event.key === "ArrowDown"
        ? 1
        : event.key === "ArrowLeft" || event.key === "ArrowUp"
          ? -1
          : 0;
    let target: number | null = null;
    if (step !== 0) {
      target = Math.min(pageCount, Math.max(1, focused + step));
    } else if (event.key === "Home") {
      target = 1;
    } else if (event.key === "End") {
      target = pageCount;
    }
    if (target === null) {
      return;
    }
    event.preventDefault();
    keyboardMoved.current = true;
    setFocused(target);
    marks.current.get(target)?.focus();
  };

  return (
    <div ref={measure} className="w-full" data-testid="page-strip" data-pressable={pressable}>
      {pressable ? (
        <ol
          aria-label="Pages"
          className="m-0 flex w-full list-none gap-px p-0 sm:gap-0.5"
          onKeyDown={onKeyDown}
          onBlur={(event) => {
            if (!event.currentTarget.contains(event.relatedTarget as Node | null)) {
              keyboardMoved.current = false;
              setFocused(current);
            }
          }}
        >
          {Array.from({ length: pageCount }, (_, index) => {
            const page = index + 1;
            const isSeen = seen.has(page);
            const isCurrent = page === current;
            return (
              <li key={page} className="min-w-0 flex-1">
                <button
                  ref={(node) => {
                    if (node === null) {
                      marks.current.delete(page);
                    } else {
                      marks.current.set(page, node);
                    }
                  }}
                  type="button"
                  tabIndex={page === focused ? 0 : -1}
                  aria-label={`Page ${page}, ${isSeen ? "seen" : "not seen yet"}`}
                  aria-current={isCurrent ? "page" : undefined}
                  data-seen={isSeen || undefined}
                  onClick={() => onGo(page)}
                  className="group block min-h-6 w-full cursor-pointer touch-manipulation py-2"
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
      ) : (
        <div className="py-2">
          <div
            role="progressbar"
            aria-label="Pages seen"
            aria-valuemin={0}
            aria-valuemax={pageCount}
            aria-valuenow={seen.size}
            className="h-1.5 w-full overflow-hidden rounded-full bg-edge"
          >
            <div
              className="h-full rounded-full bg-accent-600 transition-[width]"
              style={{ width: `${(seen.size / pageCount) * 100}%` }}
            />
          </div>
        </div>
      )}
    </div>
  );
}
