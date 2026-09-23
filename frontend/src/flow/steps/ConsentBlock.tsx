import { useId, useState } from "react";
import { CheckIcon, CheckRow, Sheet } from "@/components/ui";
import { type DisclosureBlock, parseDisclosure } from "@/lib/disclosure";
import type { SigningSession, StandingConsent } from "@/lib/signing-api";
import { clockTime } from "@/lib/time";

/**
 * Agreeing to sign electronically, in the same scroll as the document it is about (addendum 3 A).
 * It used to be a screen of its own between reading and signing, which made the patient agree to
 * something they could no longer see. The disclosure itself is unchanged, and so is what is
 * posted: only the place it is asked has moved.
 */

/**
 * A key for each block of the disclosure. The body is immutable stored text, so the blocks never
 * reorder; the key is the block's own content, with a counter so that two identical paragraphs
 * (a repeated "Yes." for instance) still get distinct keys.
 */
const keyedBlocks = (blocks: DisclosureBlock[]) => {
  const seen = new Map<string, number>();
  return blocks.map((block) => {
    const content = block.kind === "list" ? block.items.join(" ") : block.text;
    const base = `${block.kind}:${content.slice(0, 48)}`;
    const count = seen.get(base) ?? 0;
    seen.set(base, count + 1);
    return { key: count === 0 ? base : `${base}#${count}`, block };
  });
};

/** How much of the notice stands above the fold, under its own heading. */
const COLLAPSED_BLOCKS = 2;

/**
 * One block of the stored disclosure. The text is shown exactly as it is stored; only the marker
 * that said what kind of block it is has been taken off.
 */
function Block({ block }: { block: DisclosureBlock }) {
  if (block.kind === "heading") {
    return block.level === 2 ? (
      <h3 className="pt-2 font-semibold text-ink-900 text-lg">{block.text}</h3>
    ) : (
      <h4 className="pt-1 font-semibold text-ink-900">{block.text}</h4>
    );
  }
  if (block.kind === "list") {
    return (
      <ul className="ml-5 list-disc space-y-1">
        {block.items.map((item) => (
          <li key={item.slice(0, 48)}>{item}</li>
        ))}
      </ul>
    );
  }
  return <p>{block.text}</p>;
}

interface ConsentBlockProps {
  consent: SigningSession["consent"];
  /**
   * The acceptance this one may lean on, or null to ask for a fresh tick. The caller decides:
   * a kiosk is never handed one, and a server that refused the reliance passes null from then on.
   */
  standing: StandingConsent | null;
  agreed: boolean;
  onAgreed: (agreed: boolean) => void;
  /** True when Continue was pressed without the tick: the box says so, and so does the hint. */
  invalid: boolean;
  hintId?: string | undefined;
}

export function ConsentBlock({
  consent,
  standing,
  agreed,
  onAgreed,
  invalid,
  hintId,
}: ConsentBlockProps) {
  const [open, setOpen] = useState(false);
  const noticeId = useId();
  const parsed = parseDisclosure(consent.body);
  /**
   * The stored notice names itself ("# Agreement to sign electronically"), so that line becomes
   * this section's heading rather than being printed under one of ours saying the same thing in
   * different words. Nothing is dropped: the heading is the first block, moved, not removed.
   */
  const ownTitle = parsed[0]?.kind === "heading" ? parsed[0].text : null;
  const body = keyedBlocks(ownTitle === null ? parsed : parsed.slice(1));
  // A heading with nothing under it is a broken-looking page, not a preview, so the collapsed
  // view stops before one rather than at a fixed count.
  const collapsed = body.slice(0, COLLAPSED_BLOCKS);
  while (collapsed.length > 0 && collapsed[collapsed.length - 1]?.block.kind === "heading") {
    collapsed.pop();
  }
  const shown = open ? body : collapsed;
  const hasMore = body.length > collapsed.length;

  return (
    <Sheet testId="consent-block" className="mt-8">
      <h2 lang={ownTitle === null ? undefined : consent.locale} className="text-ink-900 text-xl">
        {ownTitle ?? "Agreeing to sign electronically"}
      </h2>

      <div
        id={noticeId}
        lang={consent.locale}
        data-testid="disclosure"
        data-expanded={open ? "true" : "false"}
        className="mt-3 space-y-3 text-ink-700 leading-relaxed"
      >
        {shown.map(({ key, block }) => (
          <Block key={key} block={block} />
        ))}
      </div>

      {hasMore ? (
        // A disclosure opening in place, not a link away from the document: the signer never
        // loses their place in it, and closing it again puts the button back within reach.
        <button
          type="button"
          aria-expanded={open}
          aria-controls={noticeId}
          data-testid="disclosure-toggle"
          onClick={() => setOpen(!open)}
          className="mt-3 inline-flex min-h-12 items-center gap-2 font-semibold text-accent-600 underline decoration-1 underline-offset-4 hover:text-accent-700"
        >
          <Chevron open={open} />
          {open ? "Hide the full notice" : "Read the full notice"}
        </button>
      ) : null}

      <p className="mt-2 text-ink-500 text-sm">Version {consent.version}</p>

      <div className="mt-5">
        {standing !== null ? (
          // Consent to doing business electronically is not per document, and re-asking for it
          // between two orders in the same sitting is ritual, not evidence. The record still
          // gets its own `consent.accepted` for this envelope, naming the one it leans on.
          <p
            className="flex items-start gap-2.5 rounded-lg bg-accent-wash px-4 py-3.5 text-ink-900"
            data-testid="standing-consent"
          >
            <CheckIcon className="mt-1 text-accent-600" />
            <span>
              You agreed to sign electronically at{" "}
              <span className="font-semibold">
                {clockTime(standing.accepted_at, consent.locale)}
              </span>
              , for an earlier document in this sitting. That agreement covers this one.
            </span>
          </p>
        ) : (
          <CheckRow
            checked={agreed}
            onChange={onAgreed}
            describedBy={invalid ? hintId : undefined}
            invalid={invalid}
          >
            I agree to sign this document electronically.
          </CheckRow>
        )}
      </div>
    </Sheet>
  );
}

function Chevron({ open }: { open: boolean }) {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 20 20"
      className={`size-4 shrink-0 fill-none stroke-current transition-transform duration-150 ${open ? "-rotate-180" : ""}`}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="m5 7.5 5 5 5-5" />
    </svg>
  );
}
