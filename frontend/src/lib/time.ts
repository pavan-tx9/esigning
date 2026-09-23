/**
 * Server timestamps as words on the screen. Everything here is display only: no decision in the
 * flow is ever made by comparing one of these to this device's clock, because a clinic tablet's
 * clock is nobody's promise (SPEC section 14 C).
 */

/** A server timestamp as a wall-clock time in the language the page is in ("2:41 PM", "14:41"). */
export function clockTime(iso: string, locale: string | null | undefined): string {
  const options: Intl.DateTimeFormatOptions = { hour: "numeric", minute: "2-digit" };
  try {
    return new Intl.DateTimeFormat(locale ?? undefined, options).format(new Date(iso));
  } catch {
    return new Intl.DateTimeFormat(undefined, options).format(new Date(iso));
  }
}

/** A server timestamp as a date ("14 March 2026"). */
export function calendarDate(iso: string, locale: string | null | undefined): string {
  const options: Intl.DateTimeFormatOptions = { day: "numeric", month: "long", year: "numeric" };
  try {
    return new Intl.DateTimeFormat(locale ?? undefined, options).format(new Date(iso));
  } catch {
    return new Intl.DateTimeFormat(undefined, options).format(new Date(iso));
  }
}
