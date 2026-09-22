import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useId, useState } from "react";
import { Button, CheckRow, Notice, Sheet, StepScreen } from "@/components/ui";
import { type DisclosureBlock, parseDisclosure } from "@/lib/disclosure";
import { isNetworkError, postConsent, type SigningSession, signingKeys } from "@/lib/signing-api";

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

interface ConsentStepProps {
  session: SigningSession;
  onContinue: () => void;
  onPreferPaper: () => void;
}

export function ConsentStep({ session, onContinue, onPreferPaper }: ConsentStepProps) {
  const queryClient = useQueryClient();
  const [agreed, setAgreed] = useState(false);
  const [nudge, setNudge] = useState(false);
  const hintId = useId();

  const consent = useMutation({
    mutationFn: () => postConsent(session.consent.version, session.consent.locale),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: signingKeys.session });
      onContinue();
    },
  });

  const blocks = keyedBlocks(parseDisclosure(session.consent.body));

  return (
    <StepScreen
      testId="step-consent"
      title="Signing on a screen instead of paper"
      lead={
        <p>
          Before you sign, the law asks us to check that you're happy to do this electronically.
          It's your choice. Signing on paper is always available.
        </p>
      }
    >
      <Sheet>
        <h2 className="text-ink-900 text-xl">Electronic signature disclosure</h2>
        <div
          lang={session.consent.locale}
          data-testid="disclosure"
          className="mt-3 space-y-3 text-ink-700 leading-relaxed"
        >
          {blocks.map(({ key, block }) => (
            <Block key={key} block={block} />
          ))}
        </div>
        <p className="mt-4 text-ink-500 text-sm">Version {session.consent.version}</p>
      </Sheet>

      <div className="mt-6">
        <CheckRow
          checked={agreed}
          onChange={(next) => {
            setAgreed(next);
            setNudge(false);
          }}
          describedBy={nudge ? hintId : undefined}
          invalid={nudge}
        >
          I have read this, and I agree to sign electronically.
        </CheckRow>
        {nudge ? (
          <p id={hintId} role="alert" className="mt-2 font-medium text-danger-600">
            To continue, tick the box to show you agree. Or choose to sign on paper instead.
          </p>
        ) : null}
      </div>

      {consent.isError ? (
        <Notice tone="error" alert className="mt-5">
          {isNetworkError(consent.error)
            ? "We couldn't reach the server. Check the connection and try again."
            : "We couldn't record your choice. Please try again, or ask a member of staff for help."}
        </Notice>
      ) : null}

      {/* Two choices of equal size and weight. Neither is the "real" one. */}
      <div className="mt-6 grid gap-3 sm:grid-cols-2">
        <Button
          inert={!agreed}
          onInertClick={() => setNudge(true)}
          busy={consent.isPending}
          className="min-h-14"
          onClick={() => consent.mutate()}
        >
          Agree and continue
        </Button>
        <Button variant="secondary" className="min-h-14" onClick={onPreferPaper}>
          I'd rather sign on paper
        </Button>
      </div>
    </StepScreen>
  );
}
