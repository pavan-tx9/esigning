import {
  type ButtonHTMLAttributes,
  createContext,
  type ReactNode,
  type Ref,
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

const base =
  "inline-flex min-h-12 min-w-12 items-center justify-center gap-2 rounded-lg px-5 py-2.5 " +
  "text-center font-semibold text-base leading-snug transition-colors duration-150 " +
  "select-none touch-manipulation";

const variants: Record<Variant, string> = {
  primary:
    "bg-accent-600 text-on-accent hover:bg-accent-700 active:bg-accent-700 " +
    "aria-disabled:bg-sunk aria-disabled:text-ink-500 aria-disabled:ring-1 aria-disabled:ring-edge",
  secondary:
    "bg-sheet text-ink-900 ring-[1.5px] ring-edge-strong ring-inset hover:bg-sunk " +
    "aria-disabled:text-ink-500 aria-disabled:ring-edge",
  quiet: "text-accent-600 underline decoration-1 underline-offset-4 hover:text-accent-700 px-3",
  danger: "bg-danger-600 text-on-accent hover:opacity-90",
};

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  /** Shown but inert. The button stays focusable so a keyboard user can find out why. */
  inert?: boolean;
  busy?: boolean;
  ref?: Ref<HTMLButtonElement>;
}

export function Button({
  variant = "primary",
  inert = false,
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
      className={`${base} ${variants[variant]} ${blocked ? "cursor-not-allowed" : "cursor-pointer"} ${className}`}
      onClick={(event) => {
        if (busy) {
          event.preventDefault();
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
  /** Wider for the document; text screens stay at a comfortable measure. */
  wide?: boolean;
  testId: string;
}

/**
 * Every screen is one of these. The heading takes focus when the screen appears, so a keyboard
 * or screen-reader user always lands at the top of the new step rather than wherever the last
 * button was.
 */
export function StepScreen({ title, lead, children, wide = false, testId }: StepScreenProps) {
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    heading.current?.focus({ preventScroll: true });
    window.scrollTo({ top: 0 });
  }, []);
  return (
    <section
      data-testid={testId}
      aria-labelledby={`${testId}-title`}
      className={`step-enter mx-auto w-full ${wide ? "max-w-3xl" : "max-w-xl"}`}
    >
      <h1
        id={`${testId}-title`}
        ref={heading}
        tabIndex={-1}
        data-step-heading
        className="text-[1.6rem] text-ink-900 leading-tight sm:text-[1.9rem]"
      >
        {title}
      </h1>
      {lead ? (
        <div className="mt-3 text-[1.05rem] text-ink-700 leading-relaxed sm:text-lg">{lead}</div>
      ) : null}
      <div className="mt-6">{children}</div>
    </section>
  );
}

interface SheetProps {
  children: ReactNode;
  className?: string;
  /** No padding of its own: for lists whose rows run edge to edge. */
  flush?: boolean;
}

export function Sheet({ children, className = "", flush = false }: SheetProps) {
  return (
    <div className={`rounded-xl bg-sheet shadow-sheet ${flush ? "" : "p-5 sm:p-6"} ${className}`}>
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
}: {
  tone?: NoticeTone;
  children: ReactNode;
  alert?: boolean;
  className?: string;
}) {
  return (
    <div
      role={alert ? "alert" : undefined}
      className={`rounded-lg border-l-4 px-4 py-3 text-base leading-relaxed ${noticeTones[tone]} ${className}`}
    >
      {children}
    </div>
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
      className={`flex min-h-14 cursor-pointer items-start gap-4 rounded-lg bg-sheet p-4 ring-[1.5px] ring-inset transition-colors ${
        checked ? "bg-accent-wash ring-accent-600" : "ring-edge-strong hover:bg-sunk"
      }`}
    >
      <input
        id={id}
        type="checkbox"
        checked={checked}
        aria-describedby={describedBy}
        aria-invalid={invalid || undefined}
        onChange={(event) => onChange(event.target.checked)}
        className="mt-0.5 size-7 shrink-0 cursor-pointer accent-accent-600"
      />
      <span className="text-ink-900 text-lg leading-snug">{children}</span>
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
