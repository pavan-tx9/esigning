import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { Button, Notice, StepScreen } from "@/components/ui";
import { isNetworkError, postDecline, type SigningSession } from "@/lib/signing-api";

interface DeclineStepProps {
  session: SigningSession;
  onDeclined: () => void;
  onBack: () => void;
}

export function DeclineStep({ session, onDeclined, onBack }: DeclineStepProps) {
  const reasons = session.decline_reasons;
  const [reason, setReason] = useState<string | null>(
    reasons.find((r) => r.code === "prefers_paper")?.code ?? null,
  );
  const [nudge, setNudge] = useState(false);

  const decline = useMutation({
    mutationFn: (code: string) => postDecline(code),
    onSuccess: onDeclined,
  });

  return (
    <StepScreen
      testId="step-decline"
      title="Stop signing on this screen"
      lead={
        <p>
          That's fine. Nothing has been signed. Tell us why, and we'll let the clinic know so they
          can help you another way.
        </p>
      }
    >
      <fieldset className="m-0 border-0 p-0">
        <legend className="mb-3 font-semibold text-ink-900 text-lg">Why are you stopping?</legend>
        <div className="grid gap-3">
          {reasons.map((option) => (
            <label
              key={option.code}
              className={`flex min-h-14 cursor-pointer items-center gap-4 rounded-lg bg-sheet p-4 ring-[1.5px] ring-inset ${
                reason === option.code ? "bg-accent-wash ring-accent-600" : "ring-edge-strong"
              }`}
            >
              <input
                type="radio"
                name="decline-reason"
                value={option.code}
                checked={reason === option.code}
                onChange={() => {
                  setReason(option.code);
                  setNudge(false);
                }}
                className="size-6 shrink-0 accent-accent-600"
              />
              <span className="text-ink-900 text-lg leading-snug">{option.label}</span>
            </label>
          ))}
        </div>
      </fieldset>

      {nudge ? (
        <p role="alert" className="mt-3 font-medium text-danger-600">
          Please choose a reason first.
        </p>
      ) : null}
      {decline.isError ? (
        <Notice tone="error" alert className="mt-5">
          {isNetworkError(decline.error)
            ? "We couldn't reach the server. Check the connection and try again."
            : "We couldn't record that. Please try again, or simply tell a member of staff."}
        </Notice>
      ) : null}

      <div className="mt-6 grid gap-3 sm:grid-cols-2">
        <Button
          variant="secondary"
          className="min-h-14"
          busy={decline.isPending}
          onClick={() => {
            if (reason === null) {
              setNudge(true);
              return;
            }
            decline.mutate(reason);
          }}
        >
          Stop and tell the clinic
        </Button>
        <Button className="min-h-14" onClick={onBack}>
          Go back to signing
        </Button>
      </div>
    </StepScreen>
  );
}
