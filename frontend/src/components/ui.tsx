import {
  type ButtonHTMLAttributes,
  createContext,
  type MouseEventHandler,
  type ReactNode,
  type Ref,
  type RefObject,
  useCallback,
  useContext,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
} from "react";

// --------------------------------------------------------------------------- announcements

const AnnounceContext = createContext<(message: string) => void>(() => {});

/**
 * One polite live region for the whole app. Progress ("Page 2 of 3", "2 fields left") goes here;
 * errors use role="alert" where they appear, so they are read immediately and stay visible.
 */
export function AnnouncerProvider({ children }: { children: ReactNode }) {
  const [message, setMessage] = useState("");
  const announce = useCallback((next: string) => {
    // Clearing first makes a repeated message get read again.
    setMessage("");
    window.setTimeout(() => setMessage(next), 50);
  }, []);
  return (
    <AnnounceContext.Provider value={announce}>
      {children}
      <div aria-live="polite" aria-atomic="true" className="sr-only" data-testid="announcer">
        {message}
      </div>
    </AnnounceContext.Provider>
  );
}

export const useAnnounce = () => useContext(AnnounceContext);

// --------------------------------------------------------------------------- buttons

type Variant = "primary" | "secondary" | "quiet" | "danger";
type Size = "sm" | "md" | "lg";

const base =
  "inline-flex items-center justify-center gap-2 rounded-md text-center font-semibold " +
  "leading-snug transition-colors duration-150 select-none touch-manipulation";

const sizes: Record<Size, string> = {
  sm: "min-h-9 px-3 text-sm",
  md: "min-h-11 min-w-11 px-4 text-[0.95rem]",
  lg: "min-h-12 min-w-12 px-5 text-base",
};

const variants: Record<Variant, string> = {
  primary:
    "bg-accent-600 text-on-accent hover:bg-accent-700 active:bg-accent-700 " +
    "aria-disabled:bg-sunk aria-disabled:text-ink-500 aria-disabled:ring-1 aria-disabled:ring-edge",
  secondary:
    "bg-sheet text-ink-900 ring-1 ring-edge-strong ring-inset hover:bg-sunk " +
    "aria-disabled:text-ink-500 aria-disabled:ring-edge",
  quiet:
    "text-accent-600 underline decoration-1 underline-offset-4 hover:text-accent-700 px-2 font-medium",
  danger: "bg-danger-600 text-on-accent hover:opacity-90",
};

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  /**
   * Shown but inert: `onClick` does not run. The button stays focusable and clickable — a
   * disabled button tells a keyboard or screen-reader user nothing about why it will not work —
   * so the click is turned into `onInertClick` instead, which is where the "why" is said.
   */
  inert?: boolean;
  /**
   * What an inert button does when it is pressed: the nudge that says what is still missing. Say
   * it on screen with ``role="alert"``, not only to the live region. Without one, nothing happens,
   * which is right for a button that is inert because something else is already in flight.
   */
  onInertClick?: MouseEventHandler<HTMLButtonElement>;
  busy?: boolean;
  ref?: Ref<HTMLButtonElement>;
}

export function Button({
  variant = "primary",
  size = "md",
  inert = false,
  onInertClick,
  busy = false,
  className = "",
  children,
  onClick,
  type = "button",
  ...rest
}: ButtonProps) {
  const blocked = inert || busy;
  return (
    <button
      {...rest}
      type={type}
      aria-disabled={blocked || undefined}
      aria-busy={busy || undefined}
      className={`${base} ${sizes[size]} ${variants[variant]} ${blocked ? "cursor-not-allowed" : "cursor-pointer"} ${className}`}
      onClick={(event) => {
        // A blocked button never reaches `onClick`. The guard lives here, not in each caller's
        // own `if` at the top of its handler: every action in this flow is either a step towards
        // a signature or the signature itself, and "the button looked inert and fired anyway" is
        // not a class of bug worth leaving to each call site to remember.
        if (blocked) {
          event.preventDefault();
          if (!busy) onInertClick?.(event);
          return;
        }
        onClick?.(event);
      }}
    >
      {busy ? <Dots /> : null}
      {children}
    </button>
  );
}

interface IconButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  /** Required: an icon button says nothing on its own. */
  "aria-label": string;
  /** `lg` is 44px: for the buttons a patient presses with a finger. */
  size?: "md" | "lg";
  inert?: boolean;
  onInertClick?: MouseEventHandler<HTMLButtonElement>;
  ref?: Ref<HTMLButtonElement>;
}

/** A square secondary button for one glyph: zoom, previous page, next page. */
export function IconButton({
  size = "md",
  inert = false,
  onInertClick,
  className = "",
  children,
  onClick,
  type = "button",
  ...rest
}: IconButtonProps) {
  return (
    <button
      {...rest}
      type={type}
      aria-disabled={inert || undefined}
      className={`inline-flex ${size === "lg" ? "size-11" : "size-9"} shrink-0 items-center justify-center rounded-md bg-sheet text-ink-900 ring-1 ring-edge-strong ring-inset transition-colors hover:bg-sunk aria-disabled:text-ink-500 aria-disabled:ring-edge ${inert ? "cursor-not-allowed" : "cursor-pointer"} ${className}`}
      onClick={(event) => {
        if (inert) {
          event.preventDefault();
          onInertClick?.(event);
          return;
        }
        onClick?.(event);
      }}
    >
      {children}
    </button>
  );
}

export function Dots() {
  return (
    <span aria-hidden="true" className="inline-flex gap-1">
      {[0, 1, 2].map((i) => (
        <span
          key={i}
          className="quiet-pulse size-1.5 rounded-full bg-current"
          style={{ animationDelay: `${i * 200}ms` }}
        />
      ))}
    </span>
  );
}

// --------------------------------------------------------------------------- layout

interface StepScreenProps {
  title: string;
  lead?: ReactNode;
  children?: ReactNode;
  /**
   * Somewhere other than the heading to put focus. For a screen that acts on its own after a few
   * seconds, the way to stop it has to be under the signer's hands rather than several Tab
   * presses behind the title.
   */
  focus?: RefObject<HTMLElement | null> | undefined;
  testId: string;
}

/**
 * A screen made of words: the endings, the decline sheet, the connecting state. It fills the
 * frame's middle and scrolls inside it if it must. The heading takes focus when the screen
 * appears, so a keyboard or screen-reader user always lands at the top of the new step rather
 * than wherever the last button was.
 */
export function StepScreen({ title, lead, children, focus, testId }: StepScreenProps) {
  const heading = useRef<HTMLHeadingElement>(null);
  const target = useRef(focus);
  target.current = focus;
  useEffect(() => {
    (target.current?.current ?? heading.current)?.focus({ preventScroll: true });
  }, []);
  return (
    <section
      data-testid={testId}
      aria-labelledby={`${testId}-title`}
      className="scroll-pane step-enter"
      data-scroll-region
    >
      <div className="mx-auto w-full max-w-xl px-4 py-5 sm:px-6">
        <h1
          id={`${testId}-title`}
          ref={heading}
          tabIndex={-1}
          data-step-heading
          className="text-[1.35rem] text-ink-900 leading-tight"
        >
          {title}
        </h1>
        {lead ? <div className="mt-2 text-ink-700 leading-normal">{lead}</div> : null}
        <div className="mt-4">{children}</div>
      </div>
    </section>
  );
}

/**
 * The heading of a screen that is mostly not words -- the document, the signing panel -- kept
 * for assistive technology and focus management and out of the way of the document itself.
 */
export function StepHeading({ id, children }: { id: string; children: ReactNode }) {
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    heading.current?.focus({ preventScroll: true });
  }, []);
  return (
    <h1 id={id} ref={heading} tabIndex={-1} data-step-heading className="sr-only">
      {children}
    </h1>
  );
}

/**
 * The bar at the foot of the frame that always holds the next action. Its height is its own:
 * whatever a step puts in its status line, the bar reserves the line, so the document above it
 * never moves when the state changes.
 */
export function ActionBar({
  children,
  className = "",
  testId,
}: {
  children: ReactNode;
  className?: string;
  testId?: string;
}) {
  return (
    <footer data-testid={testId} data-shell-chrome className={`action-bar ${className}`}>
      {children}
    </footer>
  );
}

interface SheetProps {
  children: ReactNode;
  className?: string;
  /** No padding of its own: for lists whose rows run edge to edge. */
  flush?: boolean;
  testId?: string;
}

export function Sheet({ children, className = "", flush = false, testId }: SheetProps) {
  return (
    <div
      data-testid={testId}
      className={`rounded-lg bg-sheet shadow-sheet ${flush ? "" : "p-4"} ${className}`}
    >
      {children}
    </div>
  );
}

type NoticeTone = "info" | "warn" | "error";

const noticeTones: Record<NoticeTone, string> = {
  info: "bg-accent-wash border-accent-600 text-ink-900",
  warn: "bg-warn-wash border-warn-edge text-ink-900",
  error: "bg-danger-wash border-danger-600 text-ink-900",
};

export function Notice({
  tone = "info",
  children,
  alert = false,
  className = "",
  testId,
}: {
  tone?: NoticeTone;
  children: ReactNode;
  alert?: boolean;
  className?: string;
  testId?: string;
}) {
  return (
    <div
      role={alert ? "alert" : undefined}
      data-testid={testId}
      className={`rounded-md border-l-[3px] px-3 py-2 text-sm leading-normal ${noticeTones[tone]} ${className}`}
    >
      {children}
    </div>
  );
}

// --------------------------------------------------------------------------- icons

/**
 * A check mark that sits on the text's centre line, unlike the ✓ glyph, which sits on the
 * baseline and looks dropped next to a label. Decorative: pair it with words.
 */
export function CheckIcon({ className = "" }: { className?: string }) {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 20 20"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={`inline-block size-[1.1em] shrink-0 align-[-0.18em] ${className}`}
    >
      <path d="M4 10.5l4 4 8-9" />
    </svg>
  );
}

// --------------------------------------------------------------------------- form rows

interface CheckRowProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
  children: ReactNode;
  describedBy?: string | undefined;
  invalid?: boolean | undefined;
}

/** A native checkbox with the whole row as its target: big, obvious, and free accessibility. */
export function CheckRow({ checked, onChange, children, describedBy, invalid }: CheckRowProps) {
  const id = useId();
  return (
    <label
      htmlFor={id}
      className={`flex min-h-11 cursor-pointer items-start gap-3 rounded-md bg-sheet p-3 ring-1 ring-inset transition-colors ${
        checked ? "bg-accent-wash ring-accent-600" : "ring-edge-strong hover:bg-sunk"
      } ${invalid ? "ring-2 ring-warn-edge" : ""}`}
    >
      <input
        id={id}
        type="checkbox"
        checked={checked}
        aria-describedby={describedBy}
        aria-invalid={invalid || undefined}
        onChange={(event) => onChange(event.target.checked)}
        className="mt-0.5 size-5 shrink-0 cursor-pointer accent-accent-600"
      />
      <span className="flex min-h-6 items-center text-ink-900 leading-snug">{children}</span>
    </label>
  );
}

export function useStableCallback<A extends unknown[], R>(fn: (...args: A) => R) {
  const ref = useRef(fn);
  ref.current = fn;
  return useMemo(
    () =>
      (...args: A) =>
        ref.current(...args),
    [],
  );
}

export function prefersReducedMotion(): boolean {
  return (
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches
  );
}
