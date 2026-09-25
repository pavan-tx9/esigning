/**
 * Reading progress, as the Read screen shows it. Which pages count as seen is decided by
 * `pages-seen.ts` and nothing here changes that rule; this is only how the result is described
 * and where the one button takes somebody who has not seen everything yet.
 */

/** The pages not yet displayed, ascending. */
export function unseenPages(seen: ReadonlySet<number>, pageCount: number): number[] {
  const out: number[] = [];
  for (let page = 1; page <= pageCount; page += 1) {
    if (!seen.has(page)) {
      out.push(page);
    }
  }
  return out;
}

/**
 * Where "Next unseen page" goes: the first unseen page at or after the one on screen, so a
 * reader working down the document keeps going down it, and otherwise the first unseen page
 * from the top, so nothing left behind by a fling is missed. `null` once everything is seen.
 */
export function nextUnseenPage(
  seen: ReadonlySet<number>,
  pageCount: number,
  current: number,
): number | null {
  const unseen = unseenPages(seen, pageCount);
  if (unseen.length === 0) {
    return null;
  }
  return unseen.find((page) => page >= current) ?? unseen[0] ?? null;
}

/**
 * The pages still to be looked at, in words.
 *
 * Runs are collapsed ("pages 2 to 30") and long lists are cut short, because a document can be
 * thirty pages and naming twenty-nine numbers fills a phone screen with a list nobody reads. One
 * unseen page still reads "page 7", which is what most of these say.
 */
export function describePages(pages: number[]): string {
  if (pages.length <= 1) {
    return `page ${pages[0] ?? 1}`;
  }
  const runs: string[] = [];
  for (let at = 0; at < pages.length; ) {
    let end = at;
    while (end + 1 < pages.length && pages[end + 1] === (pages[end] ?? 0) + 1) {
      end += 1;
    }
    const from = pages[at];
    const to = pages[end];
    runs.push(from === to ? `${from}` : `${from} to ${to}`);
    at = end + 1;
  }
  const shown = runs.length > 4 ? [...runs.slice(0, 3), `${runs.length - 3} more`] : runs;
  if (shown.length === 1) {
    return `pages ${shown[0]}`;
  }
  return `pages ${shown.slice(0, -1).join(", ")} and ${shown[shown.length - 1]}`;
}
