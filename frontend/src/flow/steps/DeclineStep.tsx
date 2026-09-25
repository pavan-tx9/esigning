import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { ActionBar, Button, Notice, StepScreen } from "@/components/ui";
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

  /**
   * A decline is final: it ends the envelope for everyone, and the clinic has to issue a
   * replacement document to be signed at all (SPEC section 3). Several of the reasons on offer
   * read like "not now", so the screen has to say what actually happens before the button is
   * pressed -- it is the one irreversible action in the flow.
   */
  const pausing = reason === "needs_more_time" || reason === "wants_to_ask_a_question";

  return (
    <>
      <StepScreen
        testId="step-decline"
        title="Stop signing on this screen"
        lead={
          <>
            <p>
              Nothing has been signed, and nothing you do here is held against you. Tell us why, and
              we'll let the clinic know so they can help you another way.
            </p>
            <p className="mt-2" data-testid="decline-consequence">
              This closes the document, so it can't be signed here later. If you only need more
              time, you can leave this page open, or come back to it from your records, instead.
            </p>
          </>
        }
      >
        <fieldset className="m-0 border-0 p-0">
          <legend className="mb-2 font-semibold text-ink-900">Why are you stopping?</legend>
          <div className="grid gap-2">
            {reasons.map((option) => (
              <label
                key={option.code}
                className={`flex min-h-11 cursor-pointer items-center gap-3 rounded-md bg-sheet px-3 py-2 ring-1 ring-inset ${
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
                  className="size-5 shrink-0 accent-accent-600"
                />
                <span className="text-ink-900 leading-snug">{option.label}</span>
              </label>
            ))}
          </div>
        </fieldset>

        {pausing ? (
          <Notice tone="warn" className="mt-3" alert>
            <p data-testid="decline-pause-hint">
              You don't have to close the document for that. Going back leaves it ready to sign
              whenever you are; closing it means the clinic has to send a new one.
            </p>
          </Notice>
        ) : null}
        {decline.isError ? (
          <Notice tone="error" alert className="mt-3">
            {isNetworkError(decline.error)
              ? "We couldn't reach the server. Check the connection and try again."
              : "We couldn't record that. Please try again, or simply tell a member of staff."}
          </Notice>
        ) : null}
      </StepScreen>

      <ActionBar>
        <div className="mx-auto flex w-full max-w-xl flex-wrap items-center justify-end gap-2">
          <Button
            variant="secondary"
            className="max-sm:w-full"
            busy={decline.isPending}
            onClick={() => {
              if (reason === null) {
                setNudge(true);
                return;
              }
              decline.mutate(reason);
            }}
          >
            Close this document and tell the clinic
          </Button>
          <Button className="max-sm:w-full" onClick={onBack}>
            Go back to signing
          </Button>
        </div>
        <p
          role="alert"
          className="status-line mx-auto mt-1 w-full max-w-xl text-danger-600 text-sm"
        >
          {nudge ? "Please choose a reason first." : ""}
        </p>
      </ActionBar>
    </>
  );
}
