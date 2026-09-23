import { useQuery } from "@tanstack/react-query";
import { useEffect, useId, useRef, useState } from "react";
import { FieldCloseUp } from "@/components/FieldCloseUp";
import {
  Button,
  CheckIcon,
  CheckRow,
  Notice,
  Sheet,
  StepScreen,
  useAnnounce,
} from "@/components/ui";
import {
  type AdoptedSignature,
  actionableFields,
  type Draft,
  type FieldValue,
  initialsFrom,
  isFieldComplete,
  isMarkField,
  remainingRequired,
  serverFilledFields,
  TEXT_FIELD_HINT_AT,
  TEXT_FIELD_MAX,
  withAdopted,
  withValue,
} from "@/flow/draft";
import { AdoptSignature } from "@/flow/steps/AdoptSignature";
import { MarkPreview } from "@/flow/steps/MarkPreview";
import { documentQueryOptions, type SigningField, type SigningSession } from "@/lib/signing-api";
import { type PdfState, usePdf } from "@/lib/use-pdf";

type Phase = { at: "adopt" } | { at: "field"; index: number } | { at: "summary" };

const FALLBACK_LABELS: Record<SigningField["type"], string> = {
  signature: "Signature",
  initials: "Initials",
  checkbox: "Confirmation",
  text: "Your answer",
  date_signed: "Date signed",
};

export const labelOf = (field: SigningField) => field.label.trim() || FALLBACK_LABELS[field.type];

function leftMessage(count: number): string {
  if (count === 0) {
    return "Everything that's needed is filled in.";
  }
  return count === 1 ? "1 left to complete." : `${count} left to complete.`;
}

interface SignStepProps {
  session: SigningSession;
  draft: Draft;
  /**
   * True when the signer is back here because the saved signature they applied was no longer
   * available when they tried to sign (SPEC section 14 B). Nothing has been signed and nothing
   * they filled in is lost: all that is needed is a signature to use instead.
   */
  signatureGone?: boolean;
  onDraft: (draft: Draft) => void;
  onContinue: () => void;
}

export function SignStep({
  session,
  draft,
  signatureGone = false,
  onDraft,
  onContinue,
}: SignStepProps) {
  const fields = actionableFields(session.fields);
  const needsSignature = fields.some(isMarkField);
  const needsInitials = fields.some((field) => field.type === "initials");
  // Only a signature field can hold the signature they adopt: initials are their own typed text,
  // so a signer asked for initials alone has nothing to save for next time.
  const hasSignatureField = fields.some((field) => field.type === "signature");
  const remaining = remainingRequired(session.fields, draft);
  // Parsed once for the whole step, not once per field.
  const document_ = useQuery(documentQueryOptions());
  const pdf = usePdf(document_.data);

  const [phase, setPhase] = useState<Phase>(() => {
    if (needsSignature && draft.adopted === null) {
      return { at: "adopt" };
    }
    const firstOpen = fields.findIndex((f) => !isFieldComplete(f, draft.values[f.id]));
    return firstOpen === -1 || remaining.length === 0
      ? { at: "summary" }
      : { at: "field", index: firstOpen };
  });

  const adopt = (adopted: AdoptedSignature, initials: string, save: boolean) => {
    onDraft(withAdopted(draft, adopted, initials, save));
    setPhase(fields.length > 0 ? { at: "field", index: 0 } : { at: "summary" });
  };

  if (phase.at === "adopt") {
    return (
      <StepScreen
        key="adopt"
        testId="step-sign-adopt"
        title="Choose your signature"
        lead={<p>You'll choose it once, then place it wherever the document asks for it.</p>}
      >
        {signatureGone ? (
          <Notice tone="warn" alert className="mb-5">
            <p className="font-semibold" data-testid="signature-gone">
              Your saved signature is no longer available.
            </p>
            <p className="mt-1">
              It was removed or replaced, so it couldn't be used. Nothing has been signed and
              nothing else you filled in is lost. Please choose a signature below, place it again,
              and carry on.
            </p>
          </Notice>
        ) : null}
        <AdoptSignature
          displayName={session.signer.display_name}
          needsInitials={needsInitials}
          hasSignatureField={hasSignatureField}
          defaultInitials={initialsFrom(session.signer.display_name)}
          current={draft.adopted}
          currentInitials={draft.initials}
          currentSave={draft.save}
          saved={session.adopted_signature}
          kiosk={session.session.kiosk}
          locale={session.consent.locale}
          onAdopt={adopt}
        />
      </StepScreen>
    );
  }

  if (phase.at === "field") {
    const field = fields[phase.index];
    if (field !== undefined) {
      return (
        <FieldScreen
          key={field.id}
          pdf={pdf}
          session={session}
          field={field}
          index={phase.index}
          total={fields.length}
          remaining={remaining.length}
          draft={draft}
          onValue={(value) => onDraft(withValue(draft, field.id, value))}
          onBack={() =>
            setPhase(
              phase.index === 0
                ? needsSignature
                  ? { at: "adopt" }
                  : { at: "field", index: 0 }
                : { at: "field", index: phase.index - 1 },
            )
          }
          canGoBack={phase.index > 0 || needsSignature}
          onNext={() =>
            setPhase(
              phase.index + 1 < fields.length
                ? { at: "field", index: phase.index + 1 }
                : { at: "summary" },
            )
          }
        />
      );
    }
  }

  return (
    <SummaryScreen
      session={session}
      fields={fields}
      draft={draft}
      remaining={remaining}
      onEditField={(index) => setPhase({ at: "field", index })}
      onChangeSignature={() => setPhase({ at: "adopt" })}
      onContinue={onContinue}
    />
  );
}

// --------------------------------------------------------------------------- one field

interface FieldScreenProps {
  pdf: PdfState;
  session: SigningSession;
  field: SigningField;
  index: number;
  total: number;
  remaining: number;
  draft: Draft;
  canGoBack: boolean;
  onValue: (value: FieldValue | null) => void;
  onBack: () => void;
  onNext: () => void;
}

function FieldScreen({
  pdf,
  session,
  field,
  index,
  total,
  remaining,
  draft,
  canGoBack,
  onValue,
  onBack,
  onNext,
}: FieldScreenProps) {
  const announce = useAnnounce();
  const value = draft.values[field.id];
  const complete = isFieldComplete(field, value);
  const [nudge, setNudge] = useState<string | null>(null);
  const nextButton = useRef<HTMLButtonElement>(null);
  const focusNext = useRef(false);
  const inputId = useId();
  const textCountId = useId();
  const label = labelOf(field);
  const isLast = index + 1 === total;
  const applied = value?.type === "mark";
  const text = value?.type === "text" ? value.text : "";
  const textLeft = text.length >= TEXT_FIELD_HINT_AT ? TEXT_FIELD_MAX - text.length : null;

  useEffect(() => {
    if (focusNext.current && applied) {
      focusNext.current = false;
      nextButton.current?.focus();
    }
  }, [applied]);

  const apply = () => {
    focusNext.current = true;
    onValue({ type: "mark" });
    setNudge(null);
    const left = Math.max(0, remaining - (field.required ? 1 : 0));
    announce(`${field.type === "initials" ? "Initials" : "Signature"} added. ${leftMessage(left)}`);
  };

  // Pressing Next before this field is done. The button is inert, so it says what is missing
  // rather than doing nothing: a required field left empty is the commonest way to get stuck here.
  const nudgeIncomplete = () =>
    setNudge(
      field.type === "checkbox"
        ? "This box needs to be ticked before you can continue. If you don't agree with it, you can stop and sign on paper instead."
        : field.type === "text"
          ? "Please fill this in before you continue."
          : "Please add your signature here before you continue.",
    );

  const adopted = draft.adopted;
  const preview =
    value?.type === "mark" && adopted !== null && isMarkField(field) ? (
      <MarkPreview
        adopted={adopted}
        kind={field.type === "initials" ? "initials" : "signature"}
        initials={draft.initials}
        displayName={session.signer.display_name}
        context="page"
      />
    ) : value?.type === "checkbox" && value.checked ? (
      <CheckIcon className="text-page-ink" />
    ) : value?.type === "text" ? (
      <span className="line-clamp-2 self-start px-1 text-left text-[0.7rem] text-page-ink leading-tight">
        {value.text}
      </span>
    ) : null;

  return (
    <StepScreen
      testId="step-sign-field"
      title={label}
      lead={
        <p data-testid="field-progress">
          <span className="font-semibold text-ink-900">
            {index + 1} of {total}
          </span>{" "}
          · Page {field.page} · {field.required ? "Needed" : "Optional"} · {leftMessage(remaining)}
        </p>
      }
    >
      {pdf.status === "ready" ? (
        <FieldCloseUp pdf={pdf.pdf} field={field} done={complete && value !== undefined}>
          {preview}
        </FieldCloseUp>
      ) : (
        <div className="h-[220px] rounded-lg bg-sheet ring-1 ring-edge" aria-hidden="true" />
      )}
      <p className="mt-2 text-center text-ink-700 text-sm">
        The highlighted box on page {field.page} is where this goes.
      </p>

      <div className="mt-5">
        {isMarkField(field) ? (
          applied ? (
            <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg bg-accent-wash px-4 py-3">
              <p className="inline-flex items-center gap-2 font-semibold text-ink-900">
                <CheckIcon className="text-accent-600" />
                {field.type === "initials"
                  ? "Your initials are in place"
                  : "Your signature is in place"}
              </p>
              <Button
                variant="quiet"
                onClick={() => {
                  onValue(null);
                  announce("Removed.");
                }}
              >
                Remove
              </Button>
            </div>
          ) : (
            <Button className="min-h-14 w-full text-lg" onClick={apply}>
              {field.type === "initials" ? "Add my initials here" : "Sign here"}
            </Button>
          )
        ) : null}

        {field.type === "checkbox" ? (
          <CheckRow
            checked={value?.type === "checkbox" && value.checked}
            onChange={(checked) => {
              onValue({ type: "checkbox", checked });
              setNudge(null);
            }}
          >
            {label}
          </CheckRow>
        ) : null}

        {field.type === "text" ? (
          <div>
            <label htmlFor={inputId} className="mb-2 block font-semibold text-ink-900">
              {label}
              {field.required ? "" : " (optional)"}
            </label>
            <textarea
              id={inputId}
              rows={field.rect.h > 30 ? 3 : 1}
              maxLength={TEXT_FIELD_MAX}
              aria-describedby={textLeft === null ? undefined : textCountId}
              value={text}
              onChange={(event) => {
                onValue(
                  event.target.value === "" ? null : { type: "text", text: event.target.value },
                );
                setNudge(null);
              }}
              className="block min-h-12 w-full resize-y rounded-lg bg-sheet px-4 py-2.5 text-ink-900 text-lg ring-[1.5px] ring-edge-strong ring-inset"
            />
            {/* Typing that simply stops is the one thing a text box must never do without
                saying so, so the room left is announced as it runs out. */}
            {textLeft !== null ? (
              <p
                id={textCountId}
                role="status"
                data-testid="text-chars-left"
                className={`mt-2 text-sm ${textLeft === 0 ? "font-medium text-danger-600" : "text-ink-700"}`}
              >
                {textLeft === 0
                  ? "That's as much as this box will take."
                  : `${textLeft} ${textLeft === 1 ? "character" : "characters"} left.`}
              </p>
            ) : null}
          </div>
        ) : null}
      </div>

      {nudge ? (
        <p role="alert" className="mt-3 font-medium text-danger-600">
          {nudge}
        </p>
      ) : null}

      <div className="mt-6 flex flex-wrap justify-between gap-3">
        {canGoBack ? (
          <Button variant="secondary" onClick={onBack}>
            Back
          </Button>
        ) : (
          <span />
        )}
        <Button
          ref={nextButton}
          variant={complete ? "primary" : "secondary"}
          inert={!complete}
          onInertClick={nudgeIncomplete}
          onClick={onNext}
        >
          {isLast ? "Check your answers" : field.required || value !== undefined ? "Next" : "Skip"}
        </Button>
      </div>
    </StepScreen>
  );
}

// --------------------------------------------------------------------------- summary

interface SummaryScreenProps {
  session: SigningSession;
  fields: SigningField[];
  draft: Draft;
  remaining: SigningField[];
  onEditField: (index: number) => void;
  onChangeSignature: () => void;
  onContinue: () => void;
}

function SummaryScreen({
  session,
  fields,
  draft,
  remaining,
  onEditField,
  onChangeSignature,
  onContinue,
}: SummaryScreenProps) {
  const [nudge, setNudge] = useState(false);
  const auto = serverFilledFields(session.fields);
  const adopted = draft.adopted;

  return (
    <StepScreen
      testId="step-sign-summary"
      title="Check before you sign"
      lead={
        <p>This is what will be added to {session.envelope.title}. Nothing has been sent yet.</p>
      }
    >
      <Sheet flush>
        <ul className="m-0 list-none divide-y divide-edge p-0">
          {fields.map((field, index) => {
            const value = draft.values[field.id];
            return (
              <li
                key={field.id}
                className="flex flex-wrap items-center gap-x-4 gap-y-2 p-4 sm:px-6"
              >
                <div className="min-w-0 flex-1 basis-48">
                  <p className="font-semibold text-ink-900">{labelOf(field)}</p>
                  <p className="text-ink-700 text-sm">Page {field.page}</p>
                  <div className="mt-1.5 min-h-8">
                    {value?.type === "mark" && adopted !== null && isMarkField(field) ? (
                      <MarkPreview
                        adopted={adopted}
                        kind={field.type === "initials" ? "initials" : "signature"}
                        initials={draft.initials}
                        displayName={session.signer.display_name}
                        context="card"
                      />
                    ) : value?.type === "checkbox" ? (
                      <p className="text-ink-900">
                        {value.checked ? (
                          <>
                            <CheckIcon className="mr-1.5 text-accent-600" />
                            Ticked
                          </>
                        ) : (
                          "Not ticked"
                        )}
                      </p>
                    ) : value?.type === "text" ? (
                      <p className="whitespace-pre-line text-ink-900">{value.text}</p>
                    ) : (
                      <p
                        className={field.required ? "font-medium text-danger-600" : "text-ink-700"}
                      >
                        {field.required ? "Still needed" : "Left blank (optional)"}
                      </p>
                    )}
                  </div>
                </div>
                <Button
                  variant="secondary"
                  onClick={() => onEditField(index)}
                  aria-label={`Change: ${labelOf(field)}`}
                >
                  Change
                </Button>
              </li>
            );
          })}
          {auto.map((field) => (
            <li key={field.id} className="p-4 sm:px-6">
              <p className="font-semibold text-ink-900">{labelOf(field)}</p>
              <p className="text-ink-700 text-sm">
                Page {field.page} · Added automatically when you sign
              </p>
            </li>
          ))}
        </ul>
      </Sheet>

      {/* Part of what will happen when they sign, so it belongs on the screen that checks that. */}
      {draft.save && !session.session.kiosk ? (
        <p className="mt-4 text-ink-700" data-testid="summary-save-note">
          Your signature will also be saved, so it's offered the next time you sign with this
          clinic.
        </p>
      ) : null}

      {nudge && remaining.length > 0 ? (
        <p role="alert" className="mt-4 font-medium text-danger-600">
          {remaining.length === 1
            ? `One thing is still needed: ${labelOf(remaining[0] as SigningField)}.`
            : `${remaining.length} things are still needed. They're marked above.`}
        </p>
      ) : null}

      <div className="mt-6 flex flex-wrap justify-between gap-3">
        {adopted !== null ? (
          <Button variant="secondary" onClick={onChangeSignature}>
            Choose a different signature
          </Button>
        ) : (
          <span />
        )}
        <Button
          inert={remaining.length > 0}
          onInertClick={() => setNudge(true)}
          onClick={onContinue}
        >
          Continue
        </Button>
      </div>
    </StepScreen>
  );
}
