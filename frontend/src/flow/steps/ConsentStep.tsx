import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useId, useState } from "react";
import { Button, CheckRow, Notice, Sheet, StepScreen } from "@/components/ui";
import { isNetworkError, postConsent, type SigningSession, signingKeys } from "@/lib/signing-api";

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
    mutationFn: () => postConsent(session.consent.version),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: signingKeys.session });
      onContinue();
    },
  });

  const paragraphs = session.consent.body
    .split(/\n\s*\n/)
    .map((paragraph) => paragraph.trim())
    .filter((paragraph) => paragraph !== "");

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
        <div lang={session.consent.locale} className="mt-3 space-y-3 text-ink-700 leading-relaxed">
          {paragraphs.map((paragraph) => (
            <p key={paragraph.slice(0, 48)} className="whitespace-pre-line">
              {paragraph}
            </p>
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
          busy={consent.isPending}
          className="min-h-14"
          onClick={() => {
            if (!agreed) {
              setNudge(true);
              return;
            }
            consent.mutate();
          }}
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
