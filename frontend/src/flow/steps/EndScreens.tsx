import type { ReactNode } from "react";
import { Button, Dots, Sheet, StepScreen } from "@/components/ui";
import type { UnavailableReason } from "@/flow/machine";

export function ConnectingScreen() {
  return (
    <StepScreen testId="screen-connecting" title="Getting your document ready">
      <p role="status" className="flex items-center gap-3 text-ink-700 text-lg">
        <Dots /> This should only take a moment.
      </p>
    </StepScreen>
  );
}

export function ConnectFailedScreen({ onRetry }: { onRetry: () => void }) {
  return (
    <StepScreen
      testId="screen-connect-failed"
      title="We couldn't open your document"
      lead={
        <p>
          The page that brought you here didn't finish connecting. Nothing has been signed and
          nothing is lost.
        </p>
      }
    >
      <NextStep>
        Try again. If it still doesn't open, go back and start again from your records page, or ask
        a member of staff for a paper copy.
      </NextStep>
      <Button className="mt-5" onClick={onRetry}>
        Try again
      </Button>
    </StepScreen>
  );
}

export function LoadFailedScreen({ network, onRetry }: { network: boolean; onRetry: () => void }) {
  return (
    <StepScreen
      testId="screen-error"
      title="Something went wrong on our side"
      lead={
        <p>
          {network
            ? "We couldn't reach the server. The connection may have dropped."
            : "We couldn't load your document."}{" "}
          Nothing has been signed.
        </p>
      }
    >
      <NextStep>
        Try again in a moment. If it keeps happening, a member of staff can give you a paper copy to
        sign instead.
      </NextStep>
      <Button className="mt-5" onClick={onRetry}>
        Try again
      </Button>
    </StepScreen>
  );
}

export function DeclinedScreen() {
  return (
    <StepScreen
      testId="screen-declined"
      title="You chose not to sign here"
      lead={<p>That's been noted, and nothing was signed. The clinic has been told.</p>}
    >
      <NextStep>
        Let a member of staff know you'd like a paper copy, or that you have questions. You can
        close this page.
      </NextStep>
    </StepScreen>
  );
}

export function ExpiredScreen() {
  return (
    <StepScreen
      testId="screen-expired"
      title="This session has ended"
      lead={
        <p>
          For your security, signing sessions close after a while. Anything you hadn't finished was
          not signed.
        </p>
      }
    >
      <NextStep>
        Go back to your records page and open the document again, or ask a member of staff to
        restart it for you. It only takes a moment.
      </NextStep>
    </StepScreen>
  );
}

const UNAVAILABLE: Record<UnavailableReason, { title: string; body: string; next: string }> = {
  voided: {
    title: "This document was withdrawn",
    body: "The clinic cancelled this document, so it can no longer be signed. You haven't done anything wrong.",
    next: "Ask a member of staff whether there's a newer version for you to sign.",
  },
  declined_by_other: {
    title: "This document can't be signed now",
    body: "Someone else who needed to sign it chose not to, so it has been closed.",
    next: "The clinic will be in touch about what happens next. You can also ask a member of staff.",
  },
  expired_envelope: {
    title: "The time to sign this has passed",
    body: "This document had a sign-by date, and it has gone by. Nothing was signed.",
    next: "Ask the clinic to send you a new copy to sign.",
  },
};

export function UnavailableScreen({ reason }: { reason: UnavailableReason }) {
  const copy = UNAVAILABLE[reason];
  return (
    <StepScreen testId="screen-unavailable" title={copy.title} lead={<p>{copy.body}</p>}>
      <NextStep>{copy.next}</NextStep>
    </StepScreen>
  );
}

export function HandBackScreen({ outcome }: { outcome: "signed" | "declined" }) {
  return (
    <StepScreen
      testId="screen-handback"
      title={outcome === "signed" ? "Thank you. You've signed." : "Thank you. Nothing was signed."}
      lead={
        <p>
          {outcome === "signed"
            ? "Your signature has been recorded. The clinic will give you a copy of the signed document."
            : "We've let the clinic know you'd like to do this another way."}
        </p>
      }
    >
      <Sheet className="border-accent-600 border-l-4">
        <p className="font-serif text-2xl text-ink-900 leading-snug">
          Please hand this tablet back to a member of staff.
        </p>
        <p className="mt-2 text-ink-700">
          Your details have been cleared from this screen. There's nothing else you need to do.
        </p>
      </Sheet>
    </StepScreen>
  );
}

function NextStep({ children }: { children: ReactNode }) {
  return (
    <Sheet>
      <h2 className="text-ink-900 text-xl">What to do next</h2>
      <p className="mt-2 text-ink-700">{children}</p>
    </Sheet>
  );
}
